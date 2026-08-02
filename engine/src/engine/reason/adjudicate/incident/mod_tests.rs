//! Type-level tests plus one end-to-end pipeline test wiring menu → parse → guards
//! together exactly as will (build the menu, parse a model reply against it, run
//! the grounding guards in sequence) — without touching any engine wiring itself.

use super::fixtures::{
    empty_health, store_key, store_live_signal, web_reaches_pivot_store, web_to_store_chain,
};
use super::*;

#[test]
fn uncertain_helper_produces_the_skeptic_default_shape() {
    let decision = IncidentDecision::uncertain("because reasons");
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert_eq!(decision.reason, "because reasons");
    assert!(decision.cuts.is_empty());
}

#[test]
fn assessment_values_are_distinct() {
    assert_ne!(Assessment::Attack, Assessment::NoAttack);
    assert_ne!(Assessment::Attack, Assessment::Uncertain);
    assert_ne!(Assessment::NoAttack, Assessment::Uncertain);
}

/// End-to-end: a well-formed model reply naming a genuinely grounded downstream node,
/// against the real menu for a real chain, survives every guard and resolves to the
/// menu's own action/signature.
#[test]
fn a_grounded_attack_decision_survives_the_full_guard_pipeline() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(
        chain,
        &graph,
        &empty_health(),
        &std::collections::BTreeSet::new(),
    );

    let reply = format!(
        r#"{{"assessment": "attack", "reason": "store shows a live drop-and-execute", "contain": ["{}"]}}"#,
        store_key().0,
    );
    let decision = parse_incident_decision(&reply, &menu);
    assert_eq!(decision.assessment, Assessment::Attack);
    assert_eq!(decision.cuts.len(), 1);

    let downstream = [store_key()];
    let decision = guard_containment_grounding(decision, &graph, &chain.entry);
    let decision = guard_fabrication(decision, &graph, &chain.entry, &downstream);
    let decision = guard_assessment_cuts_consistency(decision);

    assert_eq!(decision.assessment, Assessment::Attack);
    assert_eq!(decision.cuts.len(), 1);
    assert_eq!(decision.cuts[0].node, store_key());
    let expected = menu.resolve(&store_key()).expect("store is on the menu");
    assert_eq!(decision.cuts[0], expected);
}

/// The negative contrast: the SAME reply, but `store` has no live signal — its own
/// evidence block is ungrounded, so the containment-grounding guard downgrades the whole
/// pipeline output to `Uncertain`.
#[test]
fn an_ungrounded_attack_decision_is_downgraded_by_the_pipeline() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(
        chain,
        &graph,
        &empty_health(),
        &std::collections::BTreeSet::new(),
    );

    let reply = format!(
        r#"{{"assessment": "attack", "reason": "store looks compromised", "contain": ["{}"]}}"#,
        store_key().0,
    );
    let decision = parse_incident_decision(&reply, &menu);
    assert_eq!(decision.cuts.len(), 1, "store is a genuine menu member");

    let decision = guard_containment_grounding(decision, &graph, &chain.entry);
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

/// `Attack` naming the entry with an empty `contain` for everything else is the D1
/// "attack, but no cut warranted" case — survives the whole pipeline unchanged.
#[test]
fn attack_with_no_cuts_survives_the_pipeline_unchanged() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(
        chain,
        &graph,
        &empty_health(),
        &std::collections::BTreeSet::new(),
    );

    let reply =
        r#"{"assessment": "attack", "reason": "attack in progress, nothing warrants a cut yet"}"#;
    let decision = parse_incident_decision(reply, &menu);
    assert_eq!(decision.assessment, Assessment::Attack);
    assert!(decision.cuts.is_empty());

    let downstream = [store_key()];
    let decision = guard_containment_grounding(decision, &graph, &chain.entry);
    let decision = guard_fabrication(decision, &graph, &chain.entry, &downstream);
    let decision = guard_assessment_cuts_consistency(decision);

    assert_eq!(decision.assessment, Assessment::Attack);
    assert!(decision.cuts.is_empty());
}
