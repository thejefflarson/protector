//! Per-node **agent-liveness** (JEF-308): the live [`AgentLivenessStore`] the ingest feeds from
//! the agent's [`AgentReport`] beacons, the **expected-node set** derived from the in-cluster pod
//! informer, and the pure [`derive_runtime_coverage`] that classifies each expected node
//! healthy / degraded / blind — the honest data behind the collapsed "Runtime corroboration"
//! readiness row.
//!
//! The design point is **honesty**: a per-node "blind on node X" view must never invent data, and
//! it must never read missing data as reassuring.
//!
//!   * **Signal-flow, not pod-Ready.** A Ready agent whose eBPF probes failed to attach is still
//!     BLIND (a Ready-but-blind sensor). The agent reports `probes_loaded`, so an
//!     agent-up-but-`probes_loaded==0` node reads blind, not healthy.
//!   * **Quiet ≠ blind.** A node reporting with `signals_emitted == 0` and its probes loaded is
//!     HEALTHY-quiet — a quiet cluster is not a down sensor.
//!   * **Out-of-scope ≠ blind.** The expected-node set is exactly where the scheduler placed the
//!     agent DaemonSet (it already honoured the agent's nodeSelector/tolerations — today
//!     `kubernetes.io/arch: arm64`, JEF-295). A node the agent is NOT scheduled on has no agent
//!     pod, so it is simply absent from the expected set — out-of-scope, never blind.
//!
//! Zero-egress: liveness is derived from the observations/beacons the agent already POSTs plus the
//! in-cluster informer (JEF-131) — the agent's OTLP/metrics endpoint is never consumed.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Pod;
use protector_behavior::AgentReport;

/// The label the agent DaemonSet's pods carry (chart helper `protector.agentLabels`). We pick the
/// agent's OWN pods out of the pod informer by it, so the expected-node set is exactly the nodes
/// the scheduler placed the agent on — respecting its nodeSelector/tolerations by construction,
/// with no need to re-implement selector matching (which would drift from the chart).
const AGENT_COMPONENT_LABEL: &str = "app.kubernetes.io/component";
/// The value of [`AGENT_COMPONENT_LABEL`] on an agent pod.
const AGENT_COMPONENT_VALUE: &str = "agent";

/// One node's most-recent liveness report, held with its ingest time for the TTL.
#[derive(Debug, Clone, Copy)]
struct NodeReport {
    at: Instant,
    probes_loaded: u32,
    probes_total: u32,
    signals: u64,
}

/// A node's current liveness facts, as read out of the store (TTL already applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveNode {
    pub probes_loaded: u32,
    pub probes_total: u32,
    pub signals: u64,
}

/// The live per-node agent-liveness store: the last [`AgentReport`] seen from each node, kept only
/// while fresh (a report older than the TTL is treated as "not reporting" → blind). Thread-safe so
/// the HTTP ingest task and the engine loop share one `Arc`. Latest report per node wins.
pub struct AgentLivenessStore {
    inner: Mutex<BTreeMap<String, NodeReport>>,
    ttl: Duration,
}

impl AgentLivenessStore {
    /// Hard cap on distinct nodes retained, independent of the TTL: a bearer-holding client could
    /// otherwise flood the ingest with distinct (attacker-chosen) node names and grow this map
    /// without bound within one TTL window. A real cluster has far fewer nodes than this; at the
    /// cap a new node evicts the stalest entry, so genuine reporters are never starved.
    const MAX_NODES: usize = 4096;

    /// A store whose reports go stale after `ttl`. A node whose last beacon is older than `ttl`
    /// reads as not-reporting (blind) — freshness is a first-class correctness concern (ADR-0002):
    /// an agent that stopped beaconing must not keep reading healthy off a stale report.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
            ttl,
        }
    }

    /// Record a beacon as of now, replacing any prior report for the same node.
    pub fn record(&self, report: AgentReport) {
        self.record_at(Instant::now(), report);
    }

    /// Record a beacon as of `now` — the deterministic seam the tests drive.
    pub fn record_at(&self, now: Instant, report: AgentReport) {
        let mut inner = self.inner.lock().expect("agent-liveness mutex poisoned");
        // Prune stale entries first, then bound the map: if this is a NEW node and we're at the
        // cap, evict the stalest entry so a flood of distinct node names can't grow it unbounded.
        inner.retain(|_, r| now.duration_since(r.at) < self.ttl);
        if inner.len() >= Self::MAX_NODES
            && !inner.contains_key(&report.node)
            && let Some(oldest) = inner
                .iter()
                .min_by_key(|(_, r)| r.at)
                .map(|(node, _)| node.clone())
        {
            inner.remove(&oldest);
        }
        inner.insert(
            report.node,
            NodeReport {
                at: now,
                probes_loaded: report.probes_loaded,
                probes_total: report.probes_total,
                signals: report.signals_emitted,
            },
        );
    }

    /// The per-node facts still within the TTL as of now.
    pub fn snapshot(&self) -> BTreeMap<String, LiveNode> {
        self.snapshot_at(Instant::now())
    }

    /// The per-node facts still within the TTL as of `now`, pruning stale reports in place so a
    /// node that stopped beaconing drops out and reads blind on the next pass.
    pub fn snapshot_at(&self, now: Instant) -> BTreeMap<String, LiveNode> {
        let mut inner = self.inner.lock().expect("agent-liveness mutex poisoned");
        inner.retain(|_, r| now.duration_since(r.at) < self.ttl);
        inner
            .iter()
            .map(|(node, r)| {
                (
                    node.clone(),
                    LiveNode {
                        probes_loaded: r.probes_loaded,
                        probes_total: r.probes_total,
                        signals: r.signals,
                    },
                )
            })
            .collect()
    }
}

/// The **expected-node set** for the agent (JEF-308): the distinct nodes the agent DaemonSet's own
/// pods are scheduled on, read straight from the pod informer. Because the scheduler already
/// honoured the agent's nodeSelector/tolerations when it placed those pods, this set IS the
/// "should be running the agent" set — a node the agent isn't scheduled on simply has no agent pod
/// here, so it's out-of-scope, never blind. Pure over its input.
pub fn expected_agent_nodes(pods: &[Pod]) -> BTreeSet<String> {
    pods.iter()
        .filter(|p| is_agent_pod(p))
        .filter_map(|p| p.spec.as_ref().and_then(|s| s.node_name.clone()))
        .filter(|n| !n.is_empty())
        .collect()
}

/// Whether a pod is one of the agent DaemonSet's pods (by the component label the chart sets).
fn is_agent_pod(pod: &Pod) -> bool {
    pod.metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(AGENT_COMPONENT_LABEL))
        .map(|v| v == AGENT_COMPONENT_VALUE)
        .unwrap_or(false)
}

/// Why a node reads blind — carried so the UX can name the failure honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindReason {
    /// No fresh beacon from this expected node — the agent is gone / crashed / never came up.
    NotReporting,
    /// The agent reported but attached ZERO probes — Ready but blind.
    ProbesFailed,
}

/// One node's classified runtime-corroboration state this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Reporting with its probes loaded — contributing corroboration. `signals` may be 0
    /// (HEALTHY-quiet: a quiet node is not a down sensor).
    Healthy { signals: u64 },
    /// Reporting but only SOME probes attached — partial (degraded) coverage.
    DegradedProbes { loaded: u32, total: u32 },
    /// No live corroboration from this expected node — see [`BlindReason`].
    Blind { reason: BlindReason },
    /// Reporting from a node NOT in the expected set (agent running where it isn't scheduled) —
    /// out-of-scope, explicitly not blind.
    OutOfScope,
}

impl NodeState {
    /// Whether this node is blind (an expected node with no live corroboration).
    pub fn is_blind(self) -> bool {
        matches!(self, NodeState::Blind { .. })
    }
}

/// One node's coverage row (node name + its classified state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCoverage {
    /// The node name — UNTRUSTED-adjacent at render (escape it, never `PreEscaped`).
    pub node: String,
    pub state: NodeState,
}

/// The per-pass runtime-corroboration coverage: one [`NodeCoverage`] per expected node (plus any
/// out-of-scope reporters), the honest input the readiness row + strip chip read. Purely derived —
/// it holds no rendering and makes no decision (ADR-0016).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCoverage {
    pub nodes: Vec<NodeCoverage>,
}

impl RuntimeCoverage {
    /// How many nodes are IN SCOPE (expected) — out-of-scope reporters don't count.
    pub fn expected_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| !matches!(n.state, NodeState::OutOfScope))
            .count()
    }

    /// The blind expected nodes, by name — what the "degraded (blind on N)" ladder rung names.
    pub fn blind_nodes(&self) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| n.state.is_blind())
            .map(|n| n.node.as_str())
            .collect()
    }

    /// The expected nodes reporting only partial probes, by name.
    pub fn degraded_nodes(&self) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.state, NodeState::DegradedProbes { .. }))
            .map(|n| n.node.as_str())
            .collect()
    }

    /// How many expected nodes are blind — the count-only companion to [`blind_nodes`], for the
    /// OTLP mirror (JEF-422) which needs the number, not the names.
    ///
    /// [`blind_nodes`]: Self::blind_nodes
    pub fn blind_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.state.is_blind()).count()
    }

    /// How many expected nodes are reporting only partial probes — the count-only companion to
    /// [`degraded_nodes`], for the OTLP mirror (JEF-422).
    ///
    /// [`degraded_nodes`]: Self::degraded_nodes
    pub fn degraded_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.state, NodeState::DegradedProbes { .. }))
            .count()
    }

    /// How many expected nodes are fully healthy (probes loaded; quiet counts).
    pub fn healthy_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.state, NodeState::Healthy { .. }))
            .count()
    }

    /// Total signals the agent emitted this pass across healthy nodes.
    pub fn agent_signals(&self) -> u64 {
        self.nodes
            .iter()
            .filter_map(|n| match n.state {
                NodeState::Healthy { signals } => Some(signals),
                _ => None,
            })
            .sum()
    }

    /// Whether every expected node is fully healthy (and there is at least one expected node).
    pub fn all_healthy(&self) -> bool {
        self.expected_count() > 0
            && self
                .nodes
                .iter()
                .filter(|n| !matches!(n.state, NodeState::OutOfScope))
                .all(|n| matches!(n.state, NodeState::Healthy { .. }))
    }

    /// The set of blind node names — the finding-caveat lookup ("no live sensor on this node").
    pub fn blind_node_set(&self) -> HashSet<String> {
        self.nodes
            .iter()
            .filter(|n| n.state.is_blind())
            .map(|n| n.node.clone())
            .collect()
    }
}

/// Classify the runtime-corroboration coverage from the expected-node set and the live liveness
/// snapshot (JEF-308). Pure and total — the tested honesty core:
///
///   * an expected node with a fresh report + probes loaded ⇒ [`Healthy`] (quiet or not);
///   * an expected node reporting `probes_loaded == 0` ⇒ [`Blind`]`(ProbesFailed)` — Ready-but-blind;
///   * an expected node with only some probes ⇒ [`DegradedProbes`];
///   * an expected node with no fresh report ⇒ [`Blind`]`(NotReporting)`;
///   * a node reporting that is NOT expected ⇒ [`OutOfScope`] (never blind).
///
/// [`Healthy`]: NodeState::Healthy
/// [`Blind`]: NodeState::Blind
/// [`DegradedProbes`]: NodeState::DegradedProbes
/// [`OutOfScope`]: NodeState::OutOfScope
pub fn derive_runtime_coverage(
    expected: &BTreeSet<String>,
    live: &BTreeMap<String, LiveNode>,
) -> RuntimeCoverage {
    let mut nodes: Vec<NodeCoverage> = Vec::new();

    // Every expected node, classified against its (possibly absent) live report.
    for node in expected {
        let state = match live.get(node) {
            None => NodeState::Blind {
                reason: BlindReason::NotReporting,
            },
            Some(l) if l.probes_loaded == 0 => NodeState::Blind {
                reason: BlindReason::ProbesFailed,
            },
            Some(l) if l.probes_total > 0 && l.probes_loaded < l.probes_total => {
                NodeState::DegradedProbes {
                    loaded: l.probes_loaded,
                    total: l.probes_total,
                }
            }
            // Probes loaded (fully, or the build declares no denominator) — healthy, quiet or not.
            Some(l) => NodeState::Healthy { signals: l.signals },
        };
        nodes.push(NodeCoverage {
            node: node.clone(),
            state,
        });
    }

    // A node reporting that isn't in the expected set: out-of-scope, explicitly not blind.
    for node in live.keys() {
        if !expected.contains(node) {
            nodes.push(NodeCoverage {
                node: node.clone(),
                state: NodeState::OutOfScope,
            });
        }
    }

    nodes.sort_by(|a, b| a.node.cmp(&b.node));
    RuntimeCoverage { nodes }
}

#[cfg(test)]
mod tests;
