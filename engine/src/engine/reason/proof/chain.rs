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

/// One proven path as an ordered list of `(from, to, edge)` steps — the shape both
/// [`path_steps`] and [`proven_paths`] speak in.
pub(super) type PathSteps = Vec<(NodeIndex, NodeIndex, EdgeIndex)>;

/// The maximum number of distinct proven paths we enumerate (and the dashboard renders)
/// per (entry, objective). A wide finding can be reachable by many redundant paths (the
/// exact shape that makes a chain no-single-edge-cut, JEF-281); we surface up to this many
/// as stacked hop-lists and collapse the rest to a "+N more" note, so a dense mesh never
/// produces an unbounded wall of paths. Bounds both the enumeration and the render.
pub(super) const MAX_PROVEN_PATHS: usize = 6;

/// A hard ceiling on the enumeration's exploration budget (edge relaxations) for a single
/// (entry, objective). A dense graph can hold exponentially many simple paths; this caps
/// the *work* regardless of density, so [`proven_paths`] can never blow up combinatorially
/// (JEF-281). When the budget is exhausted we stop and report `truncated`.
const PATH_ENUM_BUDGET: usize = 50_000;

/// The mutable state of a single [`proven_paths`] depth-first enumeration, kept in one
/// struct so the walk stays a method (not a free function with a long argument list).
/// `graph`/`entry`/`objective`/`cap` are fixed; the rest track the DFS, which runs on an
/// explicit work-stack (see [`PathEnum::walk`]) rather than the call stack — so an
/// adversarially deep chain can never overflow.
struct PathEnum<'g> {
    graph: &'g SecurityGraph,
    entry: NodeIndex,
    objective: NodeIndex,
    /// The most paths we keep; we collect up to `cap + 1` to *detect* truncation.
    cap: usize,
    /// The nodes currently on the DFS stack — enforces SIMPLE paths (no node repeats).
    on_path: HashSet<NodeIndex>,
    /// The steps of the path currently being built (entry → … → cursor).
    steps: PathSteps,
    /// The paths found so far (each a full entry → objective step list).
    found: Vec<PathSteps>,
    /// Remaining edge-relaxation budget — the anti-blowup valve.
    budget: usize,
    /// Set when more paths exist than `cap`, or the budget was exhausted.
    truncated: bool,
}

/// One in-progress `walk(node)` on the explicit DFS stack: the node being expanded and
/// its outgoing edges (precomputed, in `g.edges(node)` order) with a cursor. `valid` is
/// the proof-grade ∧ movement predicate the recursive form tested inline per edge; caching
/// it changes nothing about ordering or budget (the budget is still spent one relaxation
/// per edge visited, in order, in [`PathEnum::walk`]).
struct Frame {
    node: NodeIndex,
    edges: Vec<(NodeIndex, EdgeIndex, bool)>,
    idx: usize,
}

impl PathEnum<'_> {
    /// The bounded simple-path DFS from `start`, run on an **explicit work-stack** rather
    /// than the call stack (JEF-298 — stack-safe for adversarially deep chains). It records
    /// a path on reaching the objective; otherwise it expands over proof-grade movement
    /// edges, honouring the SAME compromise gate as [`movement_tree`] (you may only move
    /// *out of* a workload you control — the entry or a compromisable one), so every
    /// enumerated path is as proof-grounded as the shortest one.
    ///
    /// This is a byte-for-byte faithful transcription of the former recursion: same paths in
    /// the same order, the same per-edge budget decrement and exhaustion behaviour, the same
    /// `cap + 1` early stop, and the same simple-path (no repeated node) property. Each stack
    /// [`Frame`] is one former `walk` invocation; descending pushes a frame, and a frame that
    /// runs out of edges (or is skipped by the entry gate) is unwound with the exact
    /// `steps.pop()` / `on_path.remove()` backtracking the recursion did on return.
    fn walk(&mut self, start: NodeIndex) {
        // `open` applies the same entry checks the recursion did at the top of `walk`:
        // the `cap` early-out, the objective record, and the compromise gate. When it
        // returns `None` the call would have returned immediately (nothing to descend
        // into); when it returns a frame we push it and expand its edges.
        let Some(root) = self.open(start) else {
            return;
        };
        let mut stack = vec![root];

        while let Some(top) = stack.len().checked_sub(1) {
            if stack[top].idx < stack[top].edges.len() {
                // Budget is spent one relaxation per edge visited — including edges that
                // are non-movement or lead to an on-path node — exactly as the recursion did.
                if self.budget == 0 {
                    self.truncated = true;
                    return;
                }
                self.budget -= 1;
                let u = stack[top].node;
                let (v, edge, valid) = stack[top].edges[stack[top].idx];
                stack[top].idx += 1;
                if !valid {
                    continue;
                }
                // Skip a node already on this path (keep the path simple — no cycles).
                if !self.on_path.insert(v) {
                    continue;
                }
                self.steps.push((u, v, edge));
                match self.open(v) {
                    // Descend into `v` (the recursive `self.walk(v)` call).
                    Some(child) => stack.push(child),
                    // `walk(v)` would have returned at once (cap/objective/gate); backtrack
                    // the step we just pushed, then honour the `cap + 1` early stop.
                    None => {
                        self.steps.pop();
                        self.on_path.remove(&v);
                        if self.found.len() > self.cap {
                            return; // collected cap + 1 — the set is truncated
                        }
                    }
                }
            } else {
                // This frame's edges are exhausted: the `walk(node)` call returns. Unwind it,
                // and — for every non-root frame — do the parent's post-recursion backtrack
                // (`steps.pop()` / `on_path.remove()`) and its `cap + 1` early stop.
                let done = stack.pop().expect("top frame exists");
                if !stack.is_empty() {
                    self.steps.pop();
                    self.on_path.remove(&done.node);
                    if self.found.len() > self.cap {
                        return;
                    }
                }
            }
        }
    }

    /// Apply the recursion's top-of-`walk` entry checks for `u` and, if the call would have
    /// proceeded into the edge loop, return its [`Frame`]. Returns `None` when the recursive
    /// `walk(u)` would have returned immediately: the `cap + 1` cap is already met, `u` is the
    /// objective (the path is recorded here), or `u` is a merely-reached, uncompromised
    /// workload the compromise gate blocks (a dead end — mirrors [`movement_tree`]).
    fn open(&mut self, u: NodeIndex) -> Option<Frame> {
        // We only need `cap + 1` paths: one extra proves there are "more" than we show.
        if self.found.len() > self.cap {
            return None;
        }
        if u == self.objective {
            self.found.push(self.steps.clone());
            return None;
        }
        // Copy the reference out so the graph borrow does not alias the `&mut self` above.
        let graph = self.graph;
        let g = graph.inner();
        let blocked = matches!(g.node_weight(u), Some(Node::Workload(_)))
            && u != self.entry
            && !compromisable(graph, u);
        if blocked {
            return None;
        }
        // Precompute the outgoing edges in `g.edges(u)` order so the traversal enumerates
        // exactly what the recursion did; the budget is untouched here (spent per edge in `walk`).
        let edges = g
            .edges(u)
            .map(|edge| {
                let valid = edge.weight().is_proof_grade() && is_movement(&edge.weight().relation);
                (edge.target(), edge.id(), valid)
            })
            .collect();
        Some(Frame {
            node: u,
            edges,
            idx: 0,
        })
    }
}

/// Enumerate up to `cap` distinct proof-grade movement paths from `entry` to `objective`,
/// each grounded in the same compromise gate as [`movement_tree`]. Bounded DFS over SIMPLE
/// paths, returned shortest-first (then by node order for a stable render). The `bool` is
/// `truncated`: `true` when more than `cap` paths exist or the [`PATH_ENUM_BUDGET`] was
/// exhausted, so the caller can render a "+N more" note. This is the multi-path picture the
/// finding detail restores (JEF-281): the several redundant paths ARE the reason a chain is
/// no-single-edge-cut. Never blows up combinatorially — the budget caps total work.
pub(super) fn proven_paths(
    graph: &SecurityGraph,
    entry: NodeIndex,
    objective: NodeIndex,
    cap: usize,
) -> (Vec<PathSteps>, bool) {
    let mut state = PathEnum {
        graph,
        entry,
        objective,
        cap,
        on_path: HashSet::from([entry]),
        steps: Vec::new(),
        found: Vec::new(),
        budget: PATH_ENUM_BUDGET,
        truncated: false,
    };
    state.walk(entry);
    let mut found = state.found;
    let mut truncated = state.truncated;
    // Shortest-first, then by the (source, target) index sequence for a deterministic render.
    found.sort_by(|a, b| {
        a.len().cmp(&b.len()).then_with(|| {
            let key = |p: &[(NodeIndex, NodeIndex, EdgeIndex)]| {
                p.iter()
                    .map(|s| (s.0.index(), s.1.index()))
                    .collect::<Vec<_>>()
            };
            key(a).cmp(&key(b))
        })
    });
    // We collected up to `cap + 1` to detect "more"; trim to `cap` for the caller.
    if found.len() > cap {
        found.truncate(cap);
        truncated = true;
    }
    (found, truncated)
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
