//! The ADR-0034 D5 grounding guards: every one is ADR-0029-admissible (a
//! grounding/integrity check, never a breach-decision override) and every one downgrades
//! to [`Assessment::Uncertain`] — **never `Refuted`, never a hidden line of evidence**.
//!
//! The full D5 list has FOUR members; this file implements three of them as standalone,
//! composable functions over an already-parsed [`IncidentDecision`]:
//!
//! - **menu-membership** (structural, ADR-0034 D3) lives in
//!   [`super::parse::parse_incident_decision`] itself — a non-member `contain` element
//!   degrades the decision as it's parsed, so there is nothing left to re-check here.
//! - [`guard_containment_grounding`] — a contained DOWNSTREAM node whose own evidence
//!   block carries no exploitation evidence downgrades (the entry is exempt, ADR-0022).
//! - [`guard_fabrication`] — reuses the existing anti-fabrication backstops
//!   ([`guard_fabricated_cve`], [`guard_fabricated_reachability_tag`]) over the
//!   entry+downstream union, unchanged from the 4-value verdict path.
//! - [`guard_assessment_cuts_consistency`] — a non-`Attack` assessment naming cuts is
//!   internally contradictory (also enforced earlier, in the parser, per ADR-0034 D3; this
//!   is the same check as a standalone, idempotent guard over the final decision, for a
//!   caller that assembles/re-checks decisions from elsewhere).

use crate::engine::graph::{Behavior, NodeKey, SecurityGraph};

use super::super::Verdict;
use super::super::evidence::{cve_ids_of, entry_evidence, entry_findings, retain_reachable_cves};
use super::super::guards::{guard_fabricated_cve, guard_fabricated_reachability_tag};
use super::{Assessment, IncidentDecision};

/// One node's evidence, fetched the SAME way the model-backed adjudicator's own
/// anti-fabrication backstops do (`adjudicate::model_call::downstream_backstop_evidence`) —
/// reimplemented here so the incident module stays self-contained (no engine wiring):
/// the FULL (unfiltered-by-reachability) CVE evidence lines, the observed behaviors, and
/// whether an exposed-secret finding exists.
fn node_evidence(graph: &SecurityGraph, node: &NodeKey) -> (Vec<String>, Vec<Behavior>, bool) {
    let (cves, behaviors) = entry_evidence(graph, node);
    let (secret_lines, _posture) = entry_findings(graph, node);
    (cves, behaviors, !secret_lines.is_empty())
}

/// Per-node containment grounding (ADR-0034 D5): a contained DOWNSTREAM node whose own
/// evidence block carries no exploitation evidence — no CVE observed loading at runtime, no
/// exposed secret, no observed runtime behavior — downgrades the WHOLE decision to
/// `Uncertain`. This is the "never contain a merely-reached node" rule (ADR-0022) enforced
/// as citation-grounding, one token deeper than [`guard_fabricated_cve`]: it catches a
/// downstream target that qualified for the menu via `compromisable()`'s static
/// CVE-*presence* bar (any critical/KEV CVE, not necessarily reachability-tagged
/// loaded-at-runtime — see `reason::proof::chain::compromisable`) but whose own rendered
/// block would show nothing the model could actually cite.
///
/// The **entry is EXEMPT**: any evidence anywhere on its own proven path grounds
/// containing the front door (ADR-0022) — the entry's containment is judged by the
/// `assessment` itself, not by a per-node evidence check on the entry.
pub fn guard_containment_grounding(
    decision: IncidentDecision,
    graph: &SecurityGraph,
    entry: &NodeKey,
) -> IncidentDecision {
    if decision.cuts.is_empty() {
        return decision;
    }
    let ungrounded = decision
        .cuts
        .iter()
        .any(|c| &c.node != entry && !node_has_grounding(graph, &c.node));
    if !ungrounded {
        return decision;
    }
    IncidentDecision::uncertain(
        "a contained downstream node carries no exploitation evidence in its own evidence \
         block (fabricated containment grounding)",
    )
}

/// Whether `node`'s own evidence block would show the model anything to cite: a CVE
/// observed loading at runtime (the JEF-453 exploitation-evidence filter,
/// [`retain_reachable_cves`]), an exposed secret, or any observed runtime behavior — the
/// SAME "evidenced" predicate the JEF-565 downstream prompt blocks use to choose between a
/// fenced evidence block and the "no evidence observed" one-liner.
fn node_has_grounding(graph: &SecurityGraph, node: &NodeKey) -> bool {
    let (mut cves, behaviors, has_secret) = node_evidence(graph, node);
    retain_reachable_cves(&mut cves);
    !cves.is_empty() || has_secret || !behaviors.is_empty()
}

/// Anti-fabrication (ADR-0034 D5): reuses the existing [`guard_fabricated_cve`] and
/// [`guard_fabricated_reachability_tag`] backstops, unchanged, over the entry+downstream
/// evidence union — the same grounding those two guards give the 4-value `Verdict` path.
/// Only ever acts on `Assessment::Attack` (the `Verdict::Exploitable` analogue); every
/// other assessment passes through untouched, since neither backstop has anything to
/// check without a promoting call and a reason to cite from.
pub fn guard_fabrication(
    decision: IncidentDecision,
    graph: &SecurityGraph,
    entry: &NodeKey,
    downstream: &[NodeKey],
) -> IncidentDecision {
    if decision.assessment != Assessment::Attack {
        return decision;
    }
    let mut cves = Vec::new();
    for node in std::iter::once(entry).chain(downstream.iter()) {
        let (node_cves, _behaviors, _secret) = node_evidence(graph, node);
        cves.extend(node_cves);
    }
    let real_ids = cve_ids_of(&cves);
    let verdict = guard_fabricated_cve(Verdict::Exploitable(decision.reason.clone()), &real_ids);
    let verdict = guard_fabricated_reachability_tag(verdict, &cves);
    match verdict {
        Verdict::Uncertain(reason) => IncidentDecision::uncertain(reason),
        // `guard_fabricated_cve`/`guard_fabricated_reachability_tag` only ever return the
        // verdict unchanged or downgrade it to `Uncertain` — no other arm is reachable.
        _ => decision,
    }
}

/// Assessment↔cuts consistency (ADR-0034 D3/D5): `NoAttack`/`Uncertain` with a non-empty
/// `cuts` list is internally contradictory — never route a cut off a non-attack call.
/// Downgrades to `Uncertain`, no cuts. `Attack` with an empty `cuts` list is VALID (D1 —
/// "attack, but no cut warranted") and passes through untouched, as does any already-
/// consistent decision (idempotent).
pub fn guard_assessment_cuts_consistency(decision: IncidentDecision) -> IncidentDecision {
    if decision.assessment == Assessment::Attack || decision.cuts.is_empty() {
        return decision;
    }
    IncidentDecision::uncertain("assessment/cuts inconsistency: a non-attack assessment named cuts")
}

#[cfg(test)]
#[path = "guards_tests.rs"]
mod tests;
