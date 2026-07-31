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

use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::observe::health::HealthReport;
use crate::engine::reason::proof::{Link, ProvenChain};
use crate::engine::respond::actuator::{BlastRadius, predict_blast_radius};
use crate::engine::respond::{
    Mitigation, ProposedAction, containment_for, quarantine_workload_link,
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
/// never disagree.
pub fn build_menu(chain: &ProvenChain, graph: &SecurityGraph, health: &HealthReport) -> Menu {
    let mut selectable = Vec::new();
    let mut uncontainable = Vec::new();

    // Entry line: the ladder result, selectable only when it is BOTH additive-live and
    // reversible (a durable-fix/RBAC/mount cut, or no cut at all, is uncontainable).
    match containment_for(chain) {
        Some((cut, action)) if action.is_additive_live() && action.is_reversible() => {
            selectable.push(menu_line(chain.entry.clone(), cut, action, graph, health));
        }
        _ => uncontainable.push(chain.entry.clone()),
    }

    // Downstream lines: every evidence-bearing workload on the chain, MINUS the entry
    // (ADR-0022 entry-exclusion — the entry is governed entirely by the ladder above).
    for target in &chain.quarantine_targets {
        if target.node == chain.entry {
            continue;
        }
        match quarantine_workload_link(target) {
            Some(cut) => selectable.push(menu_line(
                target.node.clone(),
                cut,
                ProposedAction::QuarantineWorkload,
                graph,
                health,
            )),
            None => uncontainable.push(target.node.clone()), // unlabeled — decline, never widen
        }
    }

    normalize(&mut selectable, &mut uncontainable);
    Menu {
        selectable,
        uncontainable,
    }
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

/// Resolve one menu line: the cut signature and the advisory blast-radius note, built the
/// same way [`crate::engine::respond::MitigationLedger::reconcile`] would build the
/// mitigation for this exact cut — empty `justifications` is fine here, `predict_blast_radius`
/// never reads them.
fn menu_line(
    node: NodeKey,
    cut: Link,
    action: ProposedAction,
    graph: &SecurityGraph,
    health: &HealthReport,
) -> MenuLine {
    let mitigation = Mitigation {
        cut: cut.clone(),
        action,
        justifications: Vec::new(),
    };
    let blast = predict_blast_radius(&mitigation, graph, health);
    MenuLine {
        node,
        action,
        cut_signature: mitigation.cut_signature(),
        cut: mitigation.cut,
        blast_note: blast_note(&blast),
    }
}

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
