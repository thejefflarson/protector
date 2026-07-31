use super::super::ChosenCut;
use super::super::fixtures::{
    entry_key, store_key, store_live_signal, web_reaches_pivot_store, web_to_store_chain,
};
use super::*;
use crate::engine::respond::ProposedAction;

fn attack(reason: &str, cuts: Vec<ChosenCut>) -> IncidentDecision {
    IncidentDecision {
        assessment: Assessment::Attack,
        reason: reason.to_string(),
        cuts,
    }
}

fn cut(node: NodeKey) -> ChosenCut {
    ChosenCut {
        cut: crate::engine::reason::proof::Link {
            from: node.clone(),
            to: node.clone(),
            relation: "test".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        node,
        action: ProposedAction::QuarantineWorkload,
        cut_signature: "sig".to_string(),
    }
}

// --- guard_containment_grounding ---

/// `store` qualifies for the menu via `compromisable()`'s static CVE-*presence* bar
///  but the fixture's CVE is never tagged reachability `loaded-at-runtime`, and
/// there is no exposed secret and no runtime behavior — its OWN evidence block would show
/// nothing to cite. Containing it downgrades the whole decision.
#[test]
fn ungrounded_downstream_cut_downgrades_the_whole_decision() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let decision = attack("store is compromised", vec![cut(store_key())]);

    let out = guard_containment_grounding(decision, &graph, &chain.entry);
    assert_eq!(out.assessment, Assessment::Uncertain);
    assert!(out.cuts.is_empty());
}

/// The positive contrast: a live behavior on `store` grounds its own evidence block, so
/// containing it passes through untouched.
#[test]
fn grounded_downstream_cut_passes_through_untouched() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);
    let decision = attack("store is compromised", vec![cut(store_key())]);

    let out = guard_containment_grounding(decision.clone(), &graph, &chain.entry);
    assert_eq!(out, decision);
}

/// The ENTRY is EXEMPT from the per-node check (ADR-0022): naming it with zero of its own
/// CVE/secret/behavior evidence still passes through untouched.
#[test]
fn entry_is_exempt_from_containment_grounding() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let decision = attack("front door compromised", vec![cut(entry_key())]);

    let out = guard_containment_grounding(decision.clone(), &graph, &chain.entry);
    assert_eq!(
        out, decision,
        "the entry is exempt from the per-node evidence check"
    );
}

/// One ungrounded cut among several downgrades the WHOLE decision, not just that cut.
#[test]
fn one_ungrounded_cut_among_several_downgrades_everything() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let decision = attack(
        "compromised",
        vec![cut(entry_key()), cut(store_key())], // entry exempt, store ungrounded
    );

    let out = guard_containment_grounding(decision, &graph, &chain.entry);
    assert_eq!(out.assessment, Assessment::Uncertain);
    assert!(out.cuts.is_empty());
}

/// A decision with no cuts is left untouched (nothing to ground).
#[test]
fn empty_cuts_short_circuits() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let decision = attack("attack, no cut warranted", Vec::new());

    let out = guard_containment_grounding(decision.clone(), &graph, &chain.entry);
    assert_eq!(out, decision);
}

// --- guard_fabrication ---

/// A REAL, present CVE id passes through untouched.
#[test]
fn fabrication_guard_passes_a_real_cited_cve() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let downstream = [store_key()];
    let decision = attack("CVE-2026-0609 is running on store", Vec::new());

    let out = guard_fabrication(decision.clone(), &graph, &chain.entry, &downstream);
    assert_eq!(out, decision);
}

/// A fabricated CVE id (absent from the entry+downstream evidence) downgrades to
/// `Uncertain` with no cuts.
#[test]
fn fabrication_guard_downgrades_a_fabricated_cve() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let downstream = [store_key()];
    let decision = attack("CVE-1999-9999 is running on store", Vec::new());

    let out = guard_fabrication(decision, &graph, &chain.entry, &downstream);
    assert_eq!(out.assessment, Assessment::Uncertain);
    assert!(out.cuts.is_empty());
}

/// A fabricated `loaded-at-runtime` TAG claim (a real id, but no evidence line actually
/// carries the tag) downgrades too — the sibling backstop, one token deeper.
#[test]
fn fabrication_guard_downgrades_a_fabricated_reachability_tag() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let downstream = [store_key()];
    let decision = attack(
        "CVE-2026-0609 is [reachability: loaded-at-runtime] on store",
        Vec::new(),
    );

    let out = guard_fabrication(decision, &graph, &chain.entry, &downstream);
    assert_eq!(out.assessment, Assessment::Uncertain);
}

/// Only ever acts on `Attack` — every other assessment passes through untouched,
/// regardless of what its `reason` text says.
#[test]
fn fabrication_guard_ignores_non_attack_assessments() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let downstream = [store_key()];
    let decision = IncidentDecision::uncertain("CVE-1999-9999 mentioned but not promoting");

    let out = guard_fabrication(decision.clone(), &graph, &chain.entry, &downstream);
    assert_eq!(out, decision);
}

// --- guard_assessment_cuts_consistency ---

#[test]
fn attack_with_cuts_is_consistent() {
    let decision = attack("compromised", vec![cut(store_key())]);
    let out = guard_assessment_cuts_consistency(decision.clone());
    assert_eq!(out, decision);
}

#[test]
fn attack_with_no_cuts_is_consistent() {
    let decision = attack("attack, no cut warranted", Vec::new());
    let out = guard_assessment_cuts_consistency(decision.clone());
    assert_eq!(out, decision);
}

#[test]
fn no_attack_with_cuts_is_inconsistent_and_downgrades() {
    let decision = IncidentDecision {
        assessment: Assessment::NoAttack,
        reason: "nothing here".to_string(),
        cuts: vec![cut(store_key())],
    };
    let out = guard_assessment_cuts_consistency(decision);
    assert_eq!(out.assessment, Assessment::Uncertain);
    assert!(out.cuts.is_empty());
}

#[test]
fn uncertain_with_cuts_is_inconsistent_and_downgrades() {
    let decision = IncidentDecision {
        assessment: Assessment::Uncertain,
        reason: "not sure".to_string(),
        cuts: vec![cut(store_key())],
    };
    let out = guard_assessment_cuts_consistency(decision);
    assert_eq!(out.assessment, Assessment::Uncertain);
    assert!(out.cuts.is_empty());
}

#[test]
fn no_attack_with_no_cuts_is_consistent() {
    let decision = IncidentDecision {
        assessment: Assessment::NoAttack,
        reason: "nothing here".to_string(),
        cuts: Vec::new(),
    };
    let out = guard_assessment_cuts_consistency(decision.clone());
    assert_eq!(out, decision);
}

/// Idempotent: re-applying to an already-consistent (or already-downgraded) decision is
/// a no-op the second time.
#[test]
fn consistency_guard_is_idempotent() {
    let decision = IncidentDecision {
        assessment: Assessment::NoAttack,
        reason: "nothing here".to_string(),
        cuts: vec![cut(store_key())],
    };
    let once = guard_assessment_cuts_consistency(decision);
    let twice = guard_assessment_cuts_consistency(once.clone());
    assert_eq!(once, twice);
}
