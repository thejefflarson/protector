//! The deterministic chain walk: the movement-edge BFS, the compromise gate, the
//! entry-foothold/exposure predicates, the minimal-cut helpers, and the `Link`
//! builder. Split out of the proof module root purely to keep every file under the
//! 1,000-line cap (repo CLAUDE.md). It traverses ONLY proof-grade movement edges, so
//! every step it reports is grounded in deterministic facts.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use petgraph::stable_graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;

use super::{Link, QuarantineReason, QuarantineTarget};
use crate::engine::graph::attack::{AttackRef, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{Exposure, Node, Relation, SecurityGraph, Severity};
use crate::engine::observe::exec_class::notable_exec;

/// Whether an edge is a valid attacker-movement edge for chain traversal.
pub(super) fn is_movement(relation: &Relation) -> bool {
    !matches!(relation, Relation::RunsImage)
}

/// Whether a workload is **compromisable**: it runs an image with a vulnerability
/// serious enough to assume an attacker with access to it can execute code there —
/// **exploited-in-wild (KEV) OR critical severity**. This is the per-workload
/// predicate behind both the entry foothold and the proof walk's compromise gate.
pub(super) fn compromisable(graph: &SecurityGraph, node: NodeIndex) -> bool {
    let g = graph.inner();
    g.edges(node).any(|e| {
        matches!(e.weight().relation, Relation::RunsImage)
            && matches!(
                g.node_weight(e.target()),
                Some(Node::Image(im)) if im.vulnerabilities.iter()
                    .any(|v| v.exploited_in_wild || v.severity == Severity::Critical)
            )
    })
}

/// Whether `entry` is a proven foothold: an internet-exposed workload that is
/// **compromisable** (a critical/KEV CVE) — an exploitable front door (ATT&CK T1190).
/// (This drives the propose-only latent case; auto-action still requires live
/// corroboration, ADR-0009.)
pub(super) fn entry_foothold(graph: &SecurityGraph, entry: NodeIndex) -> Option<AttackRef> {
    let exposed = matches!(
        graph.inner().node_weight(entry),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    );
    (exposed && compromisable(graph, entry)).then_some(EXPLOIT_PUBLIC_FACING)
}

/// Whether `entry` is internet-facing — a front door an external attacker can start
/// from. Drives [`ProvenChain::is_breach_relevant`].
pub(super) fn entry_exposed(graph: &SecurityGraph, entry: NodeIndex) -> bool {
    matches!(
        graph.inner().node_weight(entry),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    )
}

/// BFS over proof-grade movement edges from `start`. Returns, for every reachable
/// node, the (predecessor, edge) it was first reached by — a shortest-path tree.
/// If `excluded` is set, that one edge is skipped (used to test cuts).
pub(super) fn movement_tree(
    graph: &SecurityGraph,
    start: NodeIndex,
    excluded: Option<EdgeIndex>,
) -> HashMap<NodeIndex, (NodeIndex, EdgeIndex)> {
    let g = graph.inner();
    let mut came: HashMap<NodeIndex, (NodeIndex, EdgeIndex)> = HashMap::new();
    let mut seen: HashSet<NodeIndex> = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);

    while let Some(u) = queue.pop_front() {
        // Compromise gate (ADR-0002): you can only ACT FROM a workload you control —
        // the entry (the assumed-compromised front door) or a reached workload that is
        // itself compromisable (a critical/KEV CVE). A merely-reached, uncompromised
        // workload is a dead end: network-reaching a pod is not executing code in it,
        // so you can't assume its identity (`runs-as`), read its mounted secrets
        // (`can-read`), use its RBAC (`can-do`), or pivot onward from it. Non-workload
        // nodes (an identity you've assumed, an objective) always expand.
        let blocked = matches!(g.node_weight(u), Some(Node::Workload(_)))
            && u != start
            && !compromisable(graph, u);
        if blocked {
            continue;
        }
        for edge in g.edges(u) {
            if Some(edge.id()) == excluded {
                continue;
            }
            if !edge.weight().is_proof_grade() || !is_movement(&edge.weight().relation) {
                continue;
            }
            let v = edge.target();
            if seen.insert(v) {
                came.insert(v, (u, edge.id()));
                queue.push_back(v);
            }
        }
    }
    came
}

/// True if `target` is reachable from `start` over proof-grade movement edges with
/// `excluded` removed.
/// Whether the edge `e` is a sensible *cut* candidate — a privilege/movement edge,
/// not structural substrate (`runs-as`/`runs-image`/`scheduled-on`). Severing a
/// workload from its ServiceAccount isn't a mitigation; the meaningful cut is the
/// RBAC/network/data edge.
pub(super) fn is_cuttable_edge(graph: &SecurityGraph, e: EdgeIndex) -> bool {
    graph
        .inner()
        .edge_weight(e)
        .is_some_and(|edge| !edge.relation.is_structural())
}

pub(super) fn reachable_without(
    graph: &SecurityGraph,
    start: NodeIndex,
    target: NodeIndex,
    excluded: EdgeIndex,
) -> bool {
    movement_tree(graph, start, Some(excluded)).contains_key(&target)
}

/// Reconstruct the path entry → target from a shortest-path tree, as a list of
/// `(from, to, edge)` steps in order.
pub(super) fn path_steps(
    came: &HashMap<NodeIndex, (NodeIndex, EdgeIndex)>,
    entry: NodeIndex,
    target: NodeIndex,
) -> Vec<(NodeIndex, NodeIndex, EdgeIndex)> {
    let mut steps = Vec::new();
    let mut cur = target;
    while cur != entry {
        let (prev, edge) = came[&cur];
        steps.push((prev, cur, edge));
        cur = prev;
    }
    steps.reverse();
    steps
}

/// Whether a workload node carries **direct live on-pod runtime evidence** of
/// exploitation right now — a Falco-grade `Alert` or a hands-on-keyboard notable exec
/// (interactive shell / package manager, JEF-117). This is the "actively exploited"
/// predicate (JEF-284 condition 2): unlike [`compromisable`] (a static CVE), it is a
/// *live* signal, so it warrants quarantine regardless of the pod's network position.
/// Non-workload nodes have no runtime and are never actively exploited.
fn actively_exploited(graph: &SecurityGraph, node: NodeIndex) -> bool {
    matches!(
        graph.inner().node_weight(node),
        Some(Node::Workload(w)) if w.runtime.iter().any(|s|
            s.behavior.is_alert() || notable_exec(&s.behavior).is_some())
    )
}

/// Whether an edge relation is a **network hop** — `reaches` (lateral movement) or
/// `can-egress` (the exfil channel). These are the edges a pod is "network-reachable"
/// over from an internet foothold (JEF-284 condition 1); an identity/RBAC/data edge
/// (`runs-as`/`can-do`/`can-read`) is not a network hop.
fn is_network_hop(graph: &SecurityGraph, edge: EdgeIndex) -> bool {
    graph.inner().edge_weight(edge).is_some_and(|e| {
        matches!(
            e.relation,
            Relation::Reaches { .. } | Relation::CanEgress { .. }
        )
    })
}

/// The workloads on this chain path that qualify for a full-isolation quarantine
/// (JEF-284). Two independent, HIGH bars — full isolation of a pod is coarse, so it is
/// reserved for a pod with real *exploitation* evidence, never a merely-reached one:
///
/// 1. **Remotely exploitable** ([`QuarantineReason::RemotelyExploitable`]) — a
///    **non-entry** pod that is network-reachable from an internet foothold (the entry
///    is internet-exposed, and every hop from it to this pod is a network hop —
///    `reaches`/`can-egress`) AND is [`compromisable`] (a critical/KEV CVE running on
///    it). A popped app two hops in counts. The **entry itself is excluded** — its
///    containment is owned by the ADR-0022 precedence (`respond::containment_for`:
///    surgical edge-cut → entry quarantine), which we must not duplicate or widen.
/// 2. **Actively exploited** ([`QuarantineReason::ActivelyExploited`]) — any pod on the
///    chain (entry included) with [`actively_exploited`] live evidence, regardless of
///    network position. This is the internal hands-on-keyboard case.
///
/// The merely-reached objective never qualifies: an objective is a non-workload node
/// (a Secret) or, if a workload, one with neither a CVE nor a live signal — reached ≠
/// exploited. `ActivelyExploited` takes precedence when a pod meets both bars.
pub(super) fn quarantine_targets_on_path(
    graph: &SecurityGraph,
    entry: NodeIndex,
    steps: &[(NodeIndex, NodeIndex, EdgeIndex)],
    exposed_entry: bool,
) -> Vec<QuarantineTarget> {
    // Network-reachability from the internet foothold, hop by hop along the path: the
    // entry is a foothold iff it is internet-exposed, and a node stays network-reachable
    // only while every hop from the entry to it has been a network hop.
    let mut net_reachable: HashMap<NodeIndex, bool> = HashMap::new();
    net_reachable.insert(entry, exposed_entry);
    for &(from, to, edge) in steps {
        let reached =
            net_reachable.get(&from).copied().unwrap_or(false) && is_network_hop(graph, edge);
        net_reachable.insert(to, reached);
    }

    // Each workload node on the path, in order — the entry, then every hop target. A
    // node is visited once (a proof path is simple), so `seen` only guards defensively.
    let mut targets = Vec::new();
    let mut seen: HashSet<NodeIndex> = HashSet::new();
    for node in std::iter::once(entry).chain(steps.iter().map(|&(_, to, _)| to)) {
        if !seen.insert(node) {
            continue;
        }
        let Some(Node::Workload(w)) = graph.inner().node_weight(node) else {
            continue; // a Secret objective / an identity — never a quarantine target
        };
        // Condition 2 (live, "now") takes precedence over condition 1 (static CVE).
        let reason = if actively_exploited(graph, node) {
            QuarantineReason::ActivelyExploited
        } else if node != entry
            && net_reachable.get(&node).copied().unwrap_or(false)
            && compromisable(graph, node)
        {
            QuarantineReason::RemotelyExploitable
        } else {
            continue;
        };
        targets.push(QuarantineTarget {
            node: graph.key_of(node).expect("chain node exists"),
            labels: w.labels.clone(),
            reason,
        });
    }
    targets
}

/// The labels of the workload at `idx`, or empty for any non-workload node.
fn workload_labels(graph: &SecurityGraph, idx: NodeIndex) -> BTreeMap<String, String> {
    match graph.inner().node_weight(idx) {
        Some(Node::Workload(w)) => w.labels.clone(),
        _ => BTreeMap::new(),
    }
}

/// Build a [`Link`] for the edge `edge` running `from`→`to`.
pub(super) fn link_of(
    graph: &SecurityGraph,
    from: NodeIndex,
    to: NodeIndex,
    edge: EdgeIndex,
) -> Link {
    let relation = &graph
        .inner()
        .edge_weight(edge)
        .expect("edge exists")
        .relation;
    Link {
        from: graph.key_of(from).expect("edge source exists"),
        to: graph.key_of(to).expect("edge target exists"),
        relation: relation.label(),
        technique: relation.technique(),
        from_labels: workload_labels(graph, from),
        to_labels: workload_labels(graph, to),
    }
}
