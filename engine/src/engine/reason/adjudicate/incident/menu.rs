//! The deterministic per-incident cut-choice menu (ADR-0034 D4): the ADVISORY input the
//! model sees, rendered by pure reuse of the existing containment resolvers so the menu
//! and the mitigation ledger can never disagree on what's containable.
//!
//! One selectable line per containable on-path workload:
//! - the **entry** — mechanism via [`crate::engine::respond::containment_for`]'s ladder
//!   (surgical `DenyNetworkPath` edge-cut when an additive-reversible one exists, else
//!   `QuarantineEntry`);
//! - one **downstream** line per `ProvenChain::quarantine_targets` workload, MINUS the
//!   entry (ADR-0022 entry-exclusion) — mechanism `QuarantineWorkload`.
//!
//! Only additive-live + reversible + labeled targets are selectable (the existing
//! `quarantine_link`/`quarantine_workload_link` `None`-on-unlabeled path declines).
//! Evidence-bearing-but-uncontainable nodes collapse into one aggregate non-selectable
//! set, so the model isn't baited into naming them. The whole render is content-derived,
//! sorted, and deduped — byte-identical across passes on the same snapshot (cache-safe).
//!
//! **ADR-0040 mechanism escalation**: whichever node a line would otherwise resolve to
//! (the entry's ladder result, or a downstream's `QuarantineWorkload`) is overridden to
//! [`ProposedAction::ContainNode`] the moment [`boundary_break`] holds for that node — the
//! SAME `build_menu` pass, so the menu and the ledger's own resolution
//! (`respond::MitigationLedger::reconcile` reads back exactly the `ChosenCut` this menu
//! resolved, ADR-0034 D6) can never disagree. This is a mechanism swap only: the model
//! still names the SAME node key, never a new node/line ([`escalate`]).

use std::collections::BTreeSet;

use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::observe::health::HealthReport;
use crate::engine::reason::proof::{Link, ProvenChain, boundary_break};
use crate::engine::respond::actuator::{BlastRadius, predict_blast_radius};
use crate::engine::respond::{
    Mitigation, ProposedAction, contain_node_link, containment_for, quarantine_workload_link,
    self_severance,
};

use super::super::guards::fence;
use super::ChosenCut;

/// One line of the deterministic cut-choice menu: a node key the model may select
/// verbatim into `contain`, and the RESOLVED mechanism + cut signature determinism
/// already computed for it. The model chooses the TARGET, never the mechanism
/// (ADR-0032's "what" vs "how" rail) — this line is exactly what [`Menu::resolve`] hands
/// back once the parser accepts the node key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuLine {
    pub node: NodeKey,
    pub action: ProposedAction,
    /// The concrete edge/self-reference this line's mechanism severs — the SAME
    /// `Link` [`containment_for`]/[`quarantine_workload_link`] resolved, carried forward so a
    /// caller resolving a model-chosen node (via [`Menu::resolve`]) can build the ledger's own
    /// [`crate::engine::respond::Mitigation`] without re-deriving it from `cut_signature` alone.
    pub cut: Link,
    pub cut_signature: String,
    /// The advisory [`predict_blast_radius`] note for this line — fixed-shape, no
    /// untrusted text (a responder should weigh collateral before naming a node, but the
    /// actuator's blast gate still runs post-decision; this is advisory only).
    pub blast_note: String,
}

/// The deterministic per-incident cut-choice menu (ADR-0034 D4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Menu {
    /// Selectable lines, SORTED + deduped by node key — the membership set
    /// [`super::parse::parse_incident_decision`] checks `contain` elements against.
    pub selectable: Vec<MenuLine>,
    /// Evidence-bearing but uncontainable node keys (no labels, or no additive-live +
    /// reversible mechanism exists) — SORTED, deduped. Rendered as one aggregate,
    /// non-selectable line so the model isn't baited into naming them.
    pub uncontainable: Vec<NodeKey>,
}

impl Menu {
    /// Resolve a node key already confirmed to be on the selectable set to its
    /// menu-determined [`ChosenCut`]. Returns `None` for a node not on the menu — should
    /// never happen after [`super::parse::parse_incident_decision`]'s membership check
    /// (which rejects the WHOLE decision on any non-member first), but kept fallible
    /// rather than panicking so a caller can never construct a cut the menu didn't itself
    /// resolve.
    pub fn resolve(&self, node: &NodeKey) -> Option<ChosenCut> {
        self.selectable
            .iter()
            .find(|l| &l.node == node)
            .map(|l| ChosenCut {
                node: l.node.clone(),
                action: l.action,
                cut: l.cut.clone(),
                cut_signature: l.cut_signature.clone(),
            })
    }

    /// The selectable menu line's own node key for a normalized `contain` element, if it
    /// exact-matches — the membership guard's core check (ADR-0034 D3). Exact string
    /// match only: no fuzzy/partial matching, so a truncated or reworded key is rejected,
    /// not silently coerced.
    pub fn node_for(&self, normalized: &str) -> Option<NodeKey> {
        self.selectable
            .iter()
            .find(|l| l.node.0 == normalized)
            .map(|l| l.node.clone())
    }

    /// Render the menu into deterministic, fenced text (ADR-0034 D4 — the advisory
    /// containment-options section a later ticket splices into the incident prompt).
    /// Byte-identical across passes for the same input: every id is sorted + deduped and
    /// every mechanism/blast phrase is a fixed string, so only the fenced node keys and
    /// the numeric blast counts vary with the evidence.
    pub fn render(&self) -> String {
        let mut lines: Vec<String> = self
            .selectable
            .iter()
            .map(|l| {
                format!(
                    "  - {}: {} ({})",
                    fence(&l.node.0),
                    l.action.describe(),
                    l.blast_note
                )
            })
            .collect();
        if !self.uncontainable.is_empty() {
            let keys = self
                .uncontainable
                .iter()
                .map(|n| fence(&n.0))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "  - (evidence-bearing, not containable — do not name): {keys}"
            ));
        }
        if lines.is_empty() {
            "  (none)".to_string()
        } else {
            lines.join("\n")
        }
    }
}

/// Build the deterministic cut-choice menu for one proven chain (ADR-0034 D4). Pure reuse
/// of the existing resolvers — [`containment_for`]'s precedence ladder for the entry,
/// [`quarantine_workload_link`] for each downstream evidence-bearing workload — so the
/// menu and the ledger's own containment (`respond::MitigationLedger::reconcile`) can
/// never disagree. `model_attack` is this pass's LIVE set of workloads the model has
/// decisively named `assessment=attack` (across every entry, not just this chain's) —
/// [`boundary_break`]'s trigger (d) composes two SEPARATE decisive model calls, so it is
/// threaded through from the caller's already-live decision state rather than re-derived
/// here (see `engine::adj_pass::model_attack_set`).
pub fn build_menu(
    chain: &ProvenChain,
    graph: &SecurityGraph,
    health: &HealthReport,
    model_attack: &BTreeSet<NodeKey>,
) -> Menu {
    let mut selectable = Vec::new();
    let mut uncontainable = Vec::new();

    // Entry line: `escalate` resolves the ladder result, ESCALATED to `ContainNode` when
    // `boundary_break` holds for the entry — selectable only when what it resolved to is
    // BOTH additive-live and reversible, UNLESS it escalated (a cordon is deliberately not
    // additive-live, ADR-0040 §5, but is always selectable once escalated).
    match escalate(&chain.entry, containment_for(chain), graph, model_attack) {
        Some((cut, action)) => {
            selectable.push(menu_line(chain.entry.clone(), cut, action, graph, health));
        }
        None => uncontainable.push(chain.entry.clone()),
    }

    // Downstream lines: every evidence-bearing workload on the chain, MINUS the entry
    // (ADR-0022 entry-exclusion — the entry is governed entirely by the ladder above).
    for target in &chain.quarantine_targets {
        if target.node == chain.entry {
            continue;
        }
        let fallback =
            quarantine_workload_link(target).map(|cut| (cut, ProposedAction::QuarantineWorkload));
        match escalate(&target.node, fallback, graph, model_attack) {
            Some((cut, action)) => {
                selectable.push(menu_line(target.node.clone(), cut, action, graph, health));
            }
            None => uncontainable.push(target.node.clone()), // unlabeled — decline, never widen
        }
    }

    normalize(&mut selectable, &mut uncontainable);
    Menu {
        selectable,
        uncontainable,
    }
}

/// Resolve one menu candidate's mechanism (ADR-0040 §1): `boundary_break(node)` escalates to
/// [`ProposedAction::ContainNode`] regardless of what `fallback` (the ordinary ladder/
/// quarantine resolution) would have picked — the node's OWN evidence already proves a
/// pod-scoped policy can't contain it, so the pod-scoped mechanism is never offered
/// alongside it. `fallback` can be `None` (nothing severs the chain by an edge) and
/// escalation still applies: `boundary_break` needs only a `ScheduledOn` placement edge, no
/// edge-cut. When `boundary_break` does NOT hold, `fallback` stands, filtered to the SAME
/// additive-live + reversible bar the menu has always required (unchanged behavior).
fn escalate(
    node: &NodeKey,
    fallback: Option<(Link, ProposedAction)>,
    graph: &SecurityGraph,
    model_attack: &BTreeSet<NodeKey>,
) -> Option<(Link, ProposedAction)> {
    if boundary_break_holds(node, graph, model_attack)
        && let Some(cut) = contain_node_link(graph, node)
    {
        return Some((cut, ProposedAction::ContainNode));
    }
    fallback.filter(|(_, action)| action.is_additive_live() && action.is_reversible())
}

/// [`boundary_break`] over a [`NodeKey`] rather than a graph [`petgraph::stable_graph::NodeIndex`]
/// — `false` (never a break) for a key absent from the graph, so a stale/removed node can
/// never spuriously escalate.
fn boundary_break_holds(
    node: &NodeKey,
    graph: &SecurityGraph,
    model_attack: &BTreeSet<NodeKey>,
) -> bool {
    graph
        .index_of(node)
        .is_some_and(|idx| boundary_break(graph, idx, model_attack))
}

/// Sort + dedup a menu's two lists into the canonical shape [`Menu`] always carries, and drop
/// any uncontainable entry a selectable line also covers. Shared by [`build_menu`] and by the
/// caller that unions several chains' menus into one per-entry menu (an entry judged over
/// several objectives has several [`ProvenChain`]s) — so the SAME normalization runs
/// whether a menu comes from one chain or several, and the two can never drift.
pub(crate) fn normalize(selectable: &mut Vec<MenuLine>, uncontainable: &mut Vec<NodeKey>) {
    selectable.sort_by(|a, b| a.node.cmp(&b.node));
    selectable.dedup_by(|a, b| a.node == b.node);
    uncontainable.sort();
    uncontainable.dedup();
    // Defensive: a node can never be both selectable and uncontainable, but keep the
    // selectable line authoritative if a chain ever produced a redundant target entry.
    uncontainable.retain(|n| !selectable.iter().any(|l| &l.node == n));
}

/// Resolve one menu line: the cut signature and the advisory blast-radius note.
fn menu_line(
    node: NodeKey,
    cut: Link,
    action: ProposedAction,
    graph: &SecurityGraph,
    health: &HealthReport,
) -> MenuLine {
    let blast_note = cut_blast_note(&cut, action, graph, health);
    MenuLine {
        node,
        action,
        cut_signature: crate::engine::respond::cut_signature(&cut),
        cut,
        blast_note,
    }
}

/// The advisory blast-radius note for a cut+action pair, built the same way
/// [`crate::engine::respond::MitigationLedger::reconcile`] would build the mitigation for this
/// exact cut — empty `justifications` is fine here, `predict_blast_radius` never reads them.
/// `pub(crate)` (not private): the finding detail's cut-set panel reuses this to
/// render a model-chosen cut's note identically to how its own menu line resolved it.
///
/// [`ProposedAction::ContainNode`] is a special case (ADR-0040 §4): `predict_blast_radius`
/// walks `Relation::Reaches` edges OUT of the cut's source, which is meaningless for a
/// node-scoped cut (a `Host` has no `Reaches` edges — its damage is "every co-resident pod",
/// not a `reaches` peer set) — the honest, fixed-string damage-limitation note stands in
/// instead, never the network-cut phrasing.
pub(crate) fn cut_blast_note(
    cut: &Link,
    action: ProposedAction,
    graph: &SecurityGraph,
    health: &HealthReport,
) -> String {
    if action == ProposedAction::ContainNode {
        return contain_node_note(cut, graph);
    }
    let mitigation = Mitigation {
        cut: cut.clone(),
        action,
        justifications: Vec::new(),
    };
    blast_note(&predict_blast_radius(&mitigation, graph, health))
}

/// The fixed-string honest damage-limitation note for a [`ProposedAction::ContainNode`]
/// mitigation (ADR-0040 §4/consequences): never a clean sever — names the cordon, the
/// co-resident denies, and the human-act durable fix explicitly, with a self-severance
/// clause appended (also fixed-string) when protector's own agent/control-plane component
/// is among the node's co-resident pods ([`self_severance`]). Built by concatenating two
/// `&'static str` literals — no untrusted substrings, either way.
fn contain_node_note(cut: &Link, graph: &SecurityGraph) -> String {
    let mut note = CONTAIN_NODE_NOTE.to_string();
    if self_severance(graph, &cut.from) {
        note.push_str(CONTAIN_NODE_SELF_SEVERANCE_SUFFIX);
    }
    note
}

const CONTAIN_NODE_NOTE: &str = "damage-limitation, not a clean sever: the cordon stops \
    scheduler-driven spread, the co-resident denies stop lateral use of the node's other \
    pods, and drain/reimage/rotate is a human act";

const CONTAIN_NODE_SELF_SEVERANCE_SUFFIX: &str = "; this node also hosts one of protector's \
    OWN components — containing it will sever protector's own visibility/control of this \
    node until a human intervenes";

/// A fixed-shape, no-untrusted-text advisory note on a menu line's predicted blast
/// radius. Only the workload COUNT varies (a number, never a name) — the full collateral
/// list stays a `BlastRadius` detail for the actuator's own gate, not model-prompt text.
fn blast_note(blast: &BlastRadius) -> String {
    if blast.reachability_incomplete {
        "blast radius: reachability not fully modeled".to_string()
    } else if blast.alive_collateral.is_empty() {
        "blast radius: no alive collateral".to_string()
    } else {
        format!(
            "blast radius: {} alive workload(s) affected",
            blast.alive_collateral.len()
        )
    }
}

#[cfg(test)]
#[path = "menu_tests.rs"]
mod tests;
