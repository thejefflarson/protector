//! The proven-chain output rows: the [`Finding`] (one ENTRY-rooted attack path, its evidence,
//! and the model's typed verdict) and its [`PathStep`] hops, the deterministic [`classify`]
//! disposition, and the [`Findings`] handle the engine writes each pass and the metrics mirror
//! reads.
//!
//! Pure data: no rendering. Each finding's verdict + recency are resolved from the shared
//! [`VerdictStore`] at snapshot time, so a verdict the engine just wrote is visible immediately.

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use k8s_openapi::api::core::v1::Pod;

use crate::engine::graph::SecurityGraph;
use crate::engine::observe::Snapshot;
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::reason::proof::ProvenChain;

use super::agent_liveness::{
    AgentLivenessStore, CoverageStallTracker, CoverageState, RuntimeCoverage,
    derive_runtime_coverage, expected_agent_nodes,
};
use super::evidence::EntryEvidence;
use super::recency::RecencyInfo;
use super::verdict_store::{BakeStats, ModelHealth, ReadinessConfig, VerdictStore};

/// One ENTRY-rooted proven attack path, its evidence, and the model's typed verdict — the
/// unit the engine publishes per pass (JEF-255). It carries the proven facts (topology, cut),
/// the model's inputs (evidence), and its TYPED [`Verdict`] — the single source of truth for
/// posture, so no verdict prose is ever re-parsed downstream (the JEF-255 typed-verdict SSOT).
#[derive(Debug, Clone)]
pub struct Finding {
    pub entry: String,
    pub objective: String,
    /// Whether the entry is an internet-facing FRONT DOOR — drives the breach-relevance
    /// discriminator.
    pub foothold: bool,
    /// A live runtime signal backed this chain up (ADR-0009) — the corroboration flag.
    pub corroborated: bool,
    /// The chain's **mechanical** disposition — what its minimal cut can do
    /// (auto-eligible / latent foothold / structural / durable-fix PR / forbidden /
    /// no-cut), independent of the model's exploitability call. The human-facing "is this
    /// exploitable" judgement is [`verdict`](Self::verdict), the model's own typed call
    /// (the LLM is the judge — ADR-0013).
    pub disposition: String,
    /// The single-edge cut that severs it, if one exists.
    pub cut: Option<String>,
    /// Whether the entry is internet-facing — the discriminator between a real breach
    /// path and an assume-breach access path. Only breach-relevant chains are surfaced;
    /// see [`ProvenChain::is_breach_relevant`].
    pub breach_relevant: bool,
    /// The model's TYPED adjudication, if it judged this entry (JEF-255) — the single source
    /// of truth for posture and the verbatim "why". `None` if no model was consulted. Resolved
    /// from the shared [`VerdictStore`] at [`Findings::snapshot`] time, so posture is never
    /// re-parsed from verdict prose.
    pub verdict: Option<Verdict>,
    /// The proven attack path, hop by hop (entry → … → objective). The REPRESENTATIVE
    /// (shortest) path — the row summary and the cut reference it. See [`paths`](Self::paths)
    /// for the complete set when the objective is reachable several ways.
    pub path: Vec<PathStep>,
    /// EVERY proven path to the objective (bounded, shortest-first; the first mirrors
    /// [`path`](Self::path)) — the complete reachability picture the finding detail restores
    /// (JEF-281). When an objective is reachable by several redundant paths, showing them all is
    /// what makes a no-single-edge-cut disposition legible: the redundancy IS the reason.
    pub paths: Vec<Vec<PathStep>>,
    /// `true` when more proven paths exist than the bounded set in [`paths`](Self::paths) — the
    /// detail renders a "+N more" note rather than an unbounded wall (JEF-281).
    pub paths_truncated: bool,
    /// The evidence the adjudicator weighed for this path's entry (JEF-133) — the CVEs
    /// on the entry's image and the runtime signals observed on it. Pulled from the same
    /// [`SecurityGraph::entry_evidence`] the model reads, so the evidence is the model's own
    /// inputs. ADR-0016 frames the two as divergent: CVEs are a SEVERITY/reachability input,
    /// runtime alerts the LIVE corroboration signal.
    pub evidence: EntryEvidence,
    /// The per-entry recency / Δ facts (JEF-201) — what changed for this entry since the last
    /// pass (NEW / escalated / de-escalated / unchanged-age / restored). Resolved from the
    /// shared verdict store at [`Findings::snapshot`] time, like [`verdict`](Self::verdict),
    /// so the Δ tracks the stored first-seen / posture history rather than the render clock.
    /// `None` on a row published before any recency update. Pure presentation metadata
    /// (ADR-0016).
    pub recency: Option<RecencyInfo>,
    /// The Kubernetes node the entry workload runs on (JEF-308), stamped by the engine from the
    /// snapshot when it builds the pass's findings. `None` when the entry isn't a single pod (a
    /// multi-replica workload or a non-pod entry) or its node isn't known. Used ONLY to add the
    /// blind-node caveat: a latent/propose-only finding on a node with no live sensor must not
    /// render as reassuringly calm — absence of a signal there is not evidence of safety.
    pub node: Option<String>,
}

/// One hop of a proven chain: `from -[relation]-> to`, with the **full** node keys
/// (so a consumer can derive both a short label and the node kind/shape).
#[derive(Debug, Clone)]
pub struct PathStep {
    pub from: String,
    pub relation: String,
    pub to: String,
}

/// Project a proven chain's `Link` list into the presentation-agnostic [`PathStep`] hops.
fn path_steps_of(links: &[crate::engine::reason::proof::Link]) -> Vec<PathStep> {
    links
        .iter()
        .map(|l| PathStep {
            from: l.from.0.clone(),
            relation: l.relation.clone(),
            to: l.to.0.clone(),
        })
        .collect()
}

impl Finding {
    /// Build a finding from a proven chain and the graph it was proven over. The graph is
    /// needed for the per-entry evidence blocks (JEF-133): the chain alone carries the
    /// topology, but the CVEs and runtime signals live on the entry's graph node — the same
    /// place the adjudicator reads them.
    pub fn from_chain(chain: &ProvenChain, graph: &SecurityGraph) -> Self {
        // The disposition and the displayed cut both follow the response layer's
        // containment precedence (surgical edge-cut → entry quarantine → durable-fix),
        // so the dashboard names the *same* control the engine would propose/apply.
        let containment = crate::engine::respond::containment_for(chain);
        let action = containment.as_ref().map(|(_, a)| *a);
        Finding {
            evidence: EntryEvidence::for_entry(graph, &chain.entry),
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            disposition: classify(chain, action),
            cut: containment
                .as_ref()
                .map(|(cut, _)| crate::engine::respond::cut_signature(cut)),
            breach_relevant: chain.is_breach_relevant(),
            // The verdict is the model's per-ENTRY call (JEF-157), held in the shared verdict
            // store and resolved by [`Findings::snapshot`] at read time. The published row
            // carries none of its own.
            verdict: None,
            path: path_steps_of(&chain.links),
            // The complete proven-path set (bounded, JEF-281). Fall back to the representative
            // path if the enumeration produced nothing (it always finds at least the shortest,
            // but never render an empty multi-path list).
            paths: if chain.paths.is_empty() {
                vec![path_steps_of(&chain.links)]
            } else {
                chain.paths.iter().map(|p| path_steps_of(p)).collect()
            },
            paths_truncated: chain.paths_truncated,
            recency: None,
            // Stamped by the engine after construction (it has the snapshot); the chain/graph
            // alone don't carry the entry's node.
            node: None,
        }
    }

    /// Stamp the entry's node (JEF-308) — builder-style, called by the engine when it has the
    /// snapshot to resolve the entry pod's `spec.nodeName`.
    pub fn with_node(mut self, node: Option<String>) -> Self {
        self.node = node;
        self
    }
}

/// The one disposition that routes to the remediations set: a reversible network
/// cut that meets the action bar (so it auto-applies armed, or is proposed in shadow).
pub(crate) const AUTO_ELIGIBLE: &str = "auto-eligible";

/// The chain's mechanical disposition — what its minimal cut can do, by cut type. This
/// is *not* the exploitability judgement (that's the model's [`ProvenChain::verdict`],
/// shown to humans); it's the deterministic "can we cut this, and does it meet the
/// bar" annotation. It mirrors [`super::super::respond::actuator::decide`] minus the
/// runtime-only gates (enabled class, blast radius): only a network cut (`DenyNetworkPath`)
/// auto-applies; subtractive cuts are durable GitOps fixes, an escape primitive is
/// irreversible, no single edge is no-cut.
pub(crate) fn classify(
    chain: &ProvenChain,
    action: Option<crate::engine::respond::ProposedAction>,
) -> String {
    use crate::engine::respond::ProposedAction as A;
    // JEF-284: a pod that is itself actively exploited (condition 2) is quarantined even
    // when its chain has no additive-live containment of its own — name that WHY here.
    // But when the primary containment already contains the entry with an additive-live
    // control (a surgical edge-cut or the ADR-0022 entry quarantine), that takes
    // precedence and is named by the existing arms below (matching the reconcile dedup).
    let additive_primary = action.is_some_and(|a| a.is_additive_live());
    if !additive_primary && let Some(reason) = chain.entry_quarantine_reason() {
        return reason.disposition().to_string();
    }
    match action {
        None => "no-cut",
        Some(A::RemoveEscapePrimitive) => "forbidden",
        Some(A::RevokeRbacGrant | A::RemoveSecretMount | A::RebindIdentity) => "durable-fix PR",
        // The default containment (ADR-0010): a full default-deny on the internet-facing
        // entry — distinct from the surgical edge-cut and from a durable-fix PR.
        Some(A::QuarantineEntry) => "quarantine entry (default-deny)",
        // `containment_for` never returns a workload quarantine (it is a JEF-284 sibling
        // pass, not a chain's primary containment; the per-pod WHY is named above via
        // `entry_quarantine_reason`). Handled for exhaustiveness.
        Some(A::QuarantineWorkload) => "quarantine workload (default-deny)",
        Some(A::Unclassified) => "unclassified",
        Some(A::DenyNetworkPath) => {
            if !chain.meets_action_bar() {
                if chain.is_latent_foothold() {
                    "latent foothold — propose"
                } else {
                    "structural — propose"
                }
            } else if !chain.adjudicated {
                "vetoed — propose"
            } else {
                AUTO_ELIGIBLE
            }
        }
    }
    .to_string()
}

/// The current findings snapshot, shared between the engine (writer) and the metrics
/// mirror (reader).
#[derive(Default)]
pub struct Findings {
    rows: Mutex<Vec<Finding>>,
    /// The single per-entry verdict store (JEF-157): each finding's verdict is derived
    /// from this at [`snapshot`](Self::snapshot) time, so the snapshot reflects a verdict
    /// the instant the engine writes it — never only at end-of-pass.
    verdicts: Arc<VerdictStore>,
    /// The most recent behavioral-bake snapshot (JEF-48), replaced each pass alongside
    /// the findings rows.
    bake: Mutex<BakeStats>,
    /// When the engine last completed a pass (JEF-141), surfaced as "last pass NNs ago"
    /// so a quiet/loading consumer reads as *fresh*, not broken. `None` until the first
    /// pass completes (or is seeded from the journal on boot).
    last_pass: Mutex<Option<SystemTime>>,
    /// The engine's config summary for the readiness aggregation (JEF-160) — presence/absence
    /// of each decision input, captured once at boot. Defaults to all-absent until set, so the
    /// snapshot reads as "unconfigured" rather than falsely "ready".
    readiness: Mutex<ReadinessConfig>,
    /// The LIVE model health (JEF-160), stamped by the judging loop from the LAST
    /// adjudication outcome — `0`/`1`/`2` per [`ModelHealth::as_u8`]. Cheap: no extra model
    /// call, just the result of the call the engine already makes.
    model_health: std::sync::atomic::AtomicU8,
    /// The per-node runtime-corroboration coverage (JEF-308), replaced each pass alongside the
    /// findings rows: the expected-node set classified healthy/degraded/blind against the live
    /// agent-liveness beacons. The readiness aggregation reads it to build the collapsed
    /// "Runtime corroboration" row. Defaults to empty (no expected nodes) until the first pass.
    runtime_coverage: Mutex<RuntimeCoverage>,
    /// The cross-pass coverage-stall tracker (JEF-421): remembers whether the runtime fleet was ever
    /// corroborating and how long it has been fully dark, so the loud `stalled` edge fires only on a
    /// was-covering → now-silent transition held past the debounce. Updated in lock-step with
    /// `runtime_coverage` each pass.
    stall_tracker: Mutex<CoverageStallTracker>,
    /// The most recent server-derived coarse coverage register (JEF-421) — the strip chip's
    /// covered/degraded/absent/stalled reading, decided by the [`stall_tracker`](Self::stall_tracker)
    /// this pass. Defaults to `Absent` (coverage not yet observed).
    coverage_state: Mutex<CoverageState>,
}

impl Findings {
    pub fn new() -> Self {
        Self::default()
    }

    /// The single per-entry verdict store (JEF-157), shared with the engine. The engine
    /// writes verdicts here the instant they land; [`snapshot`](Self::snapshot) reads
    /// them, so a reader never lags behind a judgement.
    pub fn verdicts(&self) -> Arc<VerdictStore> {
        self.verdicts.clone()
    }

    /// Replace the snapshot with this pass's findings.
    pub fn replace(&self, findings: Vec<Finding>) {
        *self.rows.lock().expect("findings mutex poisoned") = findings;
    }

    /// Build and publish this pass's findings from the proven chains, stamping each finding's entry
    /// node (JEF-308) from the snapshot so a latent finding on a blind node can carry its "no live
    /// sensor here" caveat. Keeps the engine's `process` free of the per-finding node resolution.
    pub fn publish_chains(
        &self,
        chains: &[ProvenChain],
        graph: &SecurityGraph,
        snapshot: &Snapshot,
    ) {
        self.replace(
            chains
                .iter()
                .map(|c| {
                    Finding::from_chain(c, graph).with_node(entry_node(&snapshot.pods, &c.entry.0))
                })
                .collect(),
        );
    }

    /// Classify the expected-node set against the live agent-liveness beacons (JEF-308) and stamp
    /// the resulting runtime-corroboration coverage. The expected set is exactly the agent
    /// DaemonSet's pods in `pods` — the scheduler already honoured the agent's nodeSelector/
    /// tolerations, so a node the agent isn't scheduled on is out-of-scope, never blind.
    pub fn stamp_runtime_coverage(&self, liveness: &AgentLivenessStore, pods: &[Pod]) {
        self.stamp_runtime_coverage_at(liveness, pods, SystemTime::now());
    }

    /// The `now`-injected seam behind [`stamp_runtime_coverage`](Self::stamp_runtime_coverage) — the
    /// deterministic clock the stall-edge tests drive. Besides publishing this pass's per-node
    /// coverage, it advances the cross-pass [`CoverageStallTracker`] (JEF-421): when a was-covering
    /// fleet has been fully dark past the debounce, the derived [`CoverageState::Stalled`] is stamped
    /// and a loud `tracing::warn!` is emitted ONCE on the transition into the stall.
    pub fn stamp_runtime_coverage_at(
        &self,
        liveness: &AgentLivenessStore,
        pods: &[Pod],
        now: SystemTime,
    ) {
        let expected = expected_agent_nodes(pods);
        let coverage = derive_runtime_coverage(&expected, &liveness.snapshot());

        let state = self
            .stall_tracker
            .lock()
            .expect("stall-tracker mutex poisoned")
            .observe(&coverage, now);

        // Swap in the new register under one lock, keeping the previous one to fire the warn on the
        // EDGE only (not every pass while stalled): a was-covering fleet has JUST gone dark.
        let mut cell = self
            .coverage_state
            .lock()
            .expect("coverage-state mutex poisoned");
        let was_stalled = matches!(&*cell, CoverageState::Stalled(_));
        if let CoverageState::Stalled(alert) = &state
            && !was_stalled
        {
            let blind = coverage.blind_nodes().len();
            tracing::warn!(
                feed = %alert.feed_label,
                blind,
                expected = coverage.expected_count(),
                last_observation = ?alert.last_observation,
                "runtime-observation coverage degraded ({blind} of {} nodes blind — protector's own sensors went dark)",
                coverage.expected_count(),
            );
        }
        *cell = state;
        drop(cell);

        self.set_runtime_coverage(coverage);
    }

    /// The most recent server-derived coarse coverage register (JEF-421) — covered / degraded /
    /// absent / stalled, decided by the stall tracker on the last pass. `Absent` until the first
    /// pass stamps coverage.
    pub fn coverage_state(&self) -> CoverageState {
        self.coverage_state
            .lock()
            .expect("coverage-state mutex poisoned")
            .clone()
    }

    /// The current findings, each with its verdict resolved from the shared verdict
    /// store (JEF-157) at read time. The published rows carry no verdict of their own;
    /// the verdict is looked up per entry here, so a verdict the engine just wrote is
    /// visible immediately — there is no end-of-pass re-publish needed to surface it.
    pub fn snapshot(&self) -> Vec<Finding> {
        self.snapshot_at(Instant::now())
    }

    /// The findings snapshot resolved against an injected `now` (JEF-201) — the seam the
    /// recency tests drive deterministically (no real sleeps). The live [`snapshot`] passes
    /// `Instant::now()`. Only the human AGE in the recency cell uses `now`; the Δ GLYPH was
    /// already computed (and stored) at pass time with the pass's clock, so it is stable
    /// across repeated reads regardless of the render-time `now`.
    ///
    /// [`snapshot`]: Self::snapshot
    pub(crate) fn snapshot_at(&self, now: Instant) -> Vec<Finding> {
        let mut rows = self.rows.lock().expect("findings mutex poisoned").clone();
        for f in &mut rows {
            // A breach-relevant finding's verdict is the model's per-entry call, the one
            // source of truth. Non-breach-relevant rows are never judged, so they keep
            // their (absent) verdict. Resolving here means publishing the rows once is
            // enough — the verdict tracks the store, not the last `replace`.
            if f.breach_relevant {
                // The TYPED verdict (JEF-255) is the single source of truth for posture — a
                // consumer derives posture from it once, never re-parsing the summary prose.
                f.verdict = self.verdicts.display_verdict(&f.entry);
                // The Δ / recency facts track the same per-entry store (JEF-201): the glyph is
                // the one computed at pass time, only the age is freshened at `now`.
                f.recency = self.verdicts.recency_for(&f.entry, now);
            }
        }
        rows
    }

    /// Replace the behavioral-bake snapshot (JEF-48) with this pass's figures.
    pub fn set_bake(&self, bake: BakeStats) {
        *self.bake.lock().expect("bake mutex poisoned") = bake;
    }

    /// The most recent behavioral-bake snapshot.
    pub fn bake(&self) -> BakeStats {
        self.bake.lock().expect("bake mutex poisoned").clone()
    }

    /// Mark a pass as just completed (JEF-141) — drives the "last pass NNs ago"
    /// freshness line. Also used to seed freshness from the journal on boot.
    pub fn mark_pass(&self, at: SystemTime) {
        *self.last_pass.lock().expect("last_pass mutex poisoned") = Some(at);
    }

    /// When the last pass completed, if any. `None` until the first pass (or journal
    /// seed).
    pub fn last_pass(&self) -> Option<SystemTime> {
        *self.last_pass.lock().expect("last_pass mutex poisoned")
    }

    /// Record the engine's config summary for the readiness aggregation (JEF-160) — set once
    /// at boot from the env/handles the engine already reads. Presence/absence only; no secret
    /// names, no values.
    pub fn set_readiness_config(&self, config: ReadinessConfig) {
        *self.readiness.lock().expect("readiness mutex poisoned") = config;
    }

    /// The engine's config summary for the readiness aggregation. Defaults to all-absent until
    /// [`set_readiness_config`](Self::set_readiness_config) is called.
    #[allow(dead_code)]
    pub fn readiness_config(&self) -> ReadinessConfig {
        *self.readiness.lock().expect("readiness mutex poisoned")
    }

    /// Stamp the LIVE model health from the LAST adjudication outcome (JEF-160). Called by
    /// the judging loop on every fresh model call (cache miss) — cheap, no extra call.
    pub fn set_model_health(&self, health: ModelHealth) {
        self.model_health
            .store(health.as_u8(), std::sync::atomic::Ordering::Relaxed);
    }

    /// The LIVE model health — the last adjudication outcome, or [`ModelHealth::Unknown`]
    /// until the model has been called this run (cold start / no model configured).
    #[allow(dead_code)]
    pub fn model_health(&self) -> ModelHealth {
        ModelHealth::from_u8(self.model_health.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Replace the per-node runtime-corroboration coverage (JEF-308) with this pass's classification.
    pub fn set_runtime_coverage(&self, coverage: RuntimeCoverage) {
        *self
            .runtime_coverage
            .lock()
            .expect("runtime-coverage mutex poisoned") = coverage;
    }

    /// The most recent runtime-corroboration coverage. Defaults to empty (no expected nodes)
    /// until the first pass stamps one.
    pub fn runtime_coverage(&self) -> RuntimeCoverage {
        self.runtime_coverage
            .lock()
            .expect("runtime-coverage mutex poisoned")
            .clone()
    }
}

/// Resolve an entry key's node (JEF-308). Only a single **Pod** entry
/// (`workload/<ns>/Pod/<name>`) maps to one node — its `spec.nodeName`. A controller workload
/// (a Deployment / DaemonSet entry, whose replicas may span nodes) or a non-pod entry stays
/// node-unattributed (`None`), so the blind-node caveat is never applied to an ambiguous row.
pub(crate) fn entry_node(pods: &[Pod], entry: &str) -> Option<String> {
    let parts: Vec<&str> = entry.split('/').collect();
    let [prefix, ns, kind, name] = parts.as_slice() else {
        return None;
    };
    if *prefix != "workload" || *kind != "Pod" {
        return None;
    }
    pods.iter()
        .find(|p| {
            p.metadata.namespace.as_deref() == Some(*ns)
                && p.metadata.name.as_deref() == Some(*name)
        })
        .and_then(|p| p.spec.as_ref().and_then(|s| s.node_name.clone()))
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::Snapshot;
    use crate::engine::observe::adapter::{build_graph, default_adapters};
    use crate::engine::reason::proof::prove;
    use serde_json::json;

    #[test]
    fn entry_node_resolves_a_pod_entry_and_none_for_ambiguous_entries() {
        // JEF-308: a single-Pod entry resolves to its node; a controller / non-pod entry doesn't.
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web-1", "namespace": "app"},
            "spec": {"nodeName": "node-a", "containers": [{"name": "c", "image": "web:1"}]}
        }))
        .unwrap();
        let pods = vec![pod];
        assert_eq!(
            entry_node(&pods, "workload/app/Pod/web-1"),
            Some("node-a".to_string())
        );
        // A Deployment entry (replicas may span nodes) is node-unattributed.
        assert_eq!(entry_node(&pods, "workload/app/Deployment/web"), None);
        // An unknown pod resolves to nothing (never guessed).
        assert_eq!(entry_node(&pods, "workload/app/Pod/missing"), None);
    }

    /// A direct breach chain: an internet-facing pod that itself mounts the secret. Its
    /// only cut is subtractive, so the default containment quarantines the entry — and the
    /// dashboard disposition must say so, distinct from an edge-cut or a durable-fix PR.
    #[test]
    fn direct_breach_disposition_is_quarantine_entry() {
        let web = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "argocd-server", "namespace": "edge", "labels": {"app": "argocd-server"}},
            "spec": {"containers": [{
                "name": "c", "image": "argo:1",
                "envFrom": [{"secretRef": {"name": "repo-creds"}}]
            }]}
        });
        let lb = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "argocd-lb", "namespace": "edge"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "argocd-server"}}
        });
        let snap = Snapshot {
            pods: vec![serde_json::from_value(web).unwrap()],
            services: vec![serde_json::from_value(lb).unwrap()],
            ..Default::default()
        };
        let graph = build_graph(&snap, &default_adapters());
        let chain = prove(&graph)
            .into_iter()
            .find(|c| c.entry.0 == "workload/edge/Pod/argocd-server")
            .expect("a direct breach chain");

        let finding = Finding::from_chain(&chain, &graph);
        assert_eq!(finding.disposition, "quarantine entry (default-deny)");
        // The displayed cut names the entry workload, never the objective secret.
        let cut = finding.cut.expect("a containment is proposed");
        assert!(
            cut.contains("workload/edge/Pod/argocd-server"),
            "cut = {cut}"
        );
        assert!(
            !cut.contains("secret/"),
            "cut must not name the objective: {cut}"
        );
    }

    /// JEF-284: an internal pod with a live on-pod alert (actively exploited, no internet
    /// path) is quarantined, and the dashboard disposition names the WHY — distinct from
    /// the entry-foothold quarantine and a durable-fix PR. Untrusted text isn't involved:
    /// the label is a fixed internal string.
    #[test]
    fn internal_active_pod_disposition_is_quarantine_actively_exploited() {
        use crate::engine::observe::{Attribution, RuntimeObservation};
        use protector_behavior::Behavior;

        let watcher = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "watcher", "namespace": "app", "labels": {"role": "watcher"}},
            "spec": {"containers": [{
                "name": "c", "image": "watcher:1",
                "envFrom": [{"secretRef": {"name": "watcher-creds"}}]
            }]}
        });
        let snap = Snapshot {
            pods: vec![serde_json::from_value(watcher).unwrap()],
            runtime_events: vec![RuntimeObservation {
                attribution: Attribution::by_namespaced_name("app", "watcher"),
                source: Some("alert".into()),
                observed_at_ms: None,
                node: None,
                behavior: Behavior::Alert {
                    rule: "Terminal shell in container".into(),
                },
            }],
            ..Default::default()
        };
        let graph = build_graph(&snap, &default_adapters());
        let chain = prove(&graph)
            .into_iter()
            .find(|c| c.entry.0 == "workload/app/Pod/watcher")
            .expect("the internal chain");

        let finding = Finding::from_chain(&chain, &graph);
        assert_eq!(finding.disposition, "quarantine — actively exploited");
        assert!(
            !finding.breach_relevant,
            "the internal chain is not breach-relevant, yet is quarantined"
        );
    }
}
