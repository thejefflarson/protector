use super::super::MenuLine;
use super::*;
use crate::engine::respond::ProposedAction;

fn line(node: &str, action: ProposedAction) -> MenuLine {
    let key = NodeKey(node.to_string());
    MenuLine {
        node: key.clone(),
        action,
        cut: crate::engine::reason::proof::Link {
            from: key.clone(),
            to: key,
            relation: "test".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        cut_signature: format!("sig:{node}"),
        blast_note: "blast radius: no alive collateral".to_string(),
    }
}

/// The menu a two-node incident (entry + one downstream pivot) would render.
fn sample_menu() -> Menu {
    Menu {
        selectable: vec![
            line("workload/app/Pod/store", ProposedAction::QuarantineWorkload),
            line("workload/app/Pod/web", ProposedAction::QuarantineEntry),
        ],
        uncontainable: vec![NodeKey("workload/app/Pod/other".into())],
    }
}

#[test]
fn unparseable_reply_is_uncertain_no_cuts() {
    let decision = parse_incident_decision("not json at all", &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
    assert_eq!(decision.reason, "unparseable model reply");
}

#[test]
fn empty_reply_is_uncertain_no_cuts() {
    let decision = parse_incident_decision("", &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

#[test]
fn assessment_out_of_range_is_uncertain() {
    let reply = r#"{"assessment": "maybe", "reason": "not sure", "contain": []}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
    assert_eq!(decision.reason, "not sure");
}

#[test]
fn missing_assessment_field_is_uncertain() {
    let reply = r#"{"reason": "no assessment field", "contain": []}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

#[test]
fn contain_absent_defaults_to_empty_and_attack_stands() {
    let reply = r#"{"assessment": "attack", "reason": "front door compromised"}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Attack);
    assert!(decision.cuts.is_empty());
    assert_eq!(decision.reason, "front door compromised");
}

/// ADR-0034 D1: `attack` with an explicitly-empty `contain` is VALID — "attack, but no
/// cut warranted".
#[test]
fn attack_with_explicit_empty_contain_is_valid() {
    let reply = r#"{"assessment": "attack", "reason": "attack, no cut warranted", "contain": []}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Attack);
    assert!(decision.cuts.is_empty());
}

#[test]
fn contain_non_array_is_uncertain() {
    let reply = r#"{"assessment": "attack", "reason": "x", "contain": "oops"}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

#[test]
fn contain_with_a_non_string_element_is_uncertain() {
    let reply =
        r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/web", 7]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

/// The core teeth of Option B (ADR-0034): ANY non-member element degrades the WHOLE
/// decision, even when every other element IS a real menu member — a partially
/// hallucinated list is ungrounded reasoning, not a partially-trustworthy one.
#[test]
fn one_non_member_element_degrades_the_whole_decision() {
    let reply = r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/web", "workload/app/Pod/invented"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(
        decision.cuts.is_empty(),
        "the legitimate web element must NOT survive alongside the fabricated one"
    );
}

/// The uncontainable aggregate is NOT selectable either — naming it degrades the whole
/// decision exactly like naming a node absent from the menu entirely.
#[test]
fn naming_an_uncontainable_node_degrades_the_whole_decision() {
    let reply = r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/other"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

#[test]
fn fenced_and_padded_node_key_normalizes_and_matches() {
    let reply =
        r#"{"assessment": "attack", "reason": "x", "contain": ["  <<<workload/app/Pod/web>>>  "]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Attack);
    assert_eq!(decision.cuts.len(), 1);
    assert_eq!(
        decision.cuts[0].node,
        NodeKey("workload/app/Pod/web".into())
    );
}

#[test]
fn no_attack_with_nonempty_contain_is_uncertain() {
    let reply =
        r#"{"assessment": "no_attack", "reason": "x", "contain": ["workload/app/Pod/web"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

#[test]
fn no_attack_with_empty_contain_stands() {
    let reply = r#"{"assessment": "no_attack", "reason": "nothing here", "contain": []}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::NoAttack);
    assert!(decision.cuts.is_empty());
}

#[test]
fn uncertain_with_nonempty_contain_stays_uncertain_no_cuts() {
    let reply =
        r#"{"assessment": "uncertain", "reason": "x", "contain": ["workload/app/Pod/web"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
}

/// The cuts are RESOLVED from the menu — action + cut signature come from the menu line,
/// never invented from the model's text (ADR-0034 D1).
#[test]
fn attack_with_valid_contain_resolves_cuts_from_the_menu() {
    let reply = r#"{"assessment": "attack", "reason": "compromised", "contain": ["workload/app/Pod/store"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Attack);
    assert_eq!(decision.cuts.len(), 1);
    let cut = &decision.cuts[0];
    assert_eq!(cut.node, NodeKey("workload/app/Pod/store".into()));
    assert_eq!(cut.action, ProposedAction::QuarantineWorkload);
    assert_eq!(cut.cut_signature, "sig:workload/app/Pod/store");
}

#[test]
fn duplicate_contain_elements_dedup_to_one_cut() {
    let reply = r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/web", "workload/app/Pod/web"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    assert_eq!(decision.cuts.len(), 1);
}

#[test]
fn resolved_cuts_are_sorted_by_node_key() {
    let reply = r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/web", "workload/app/Pod/store"]}"#;
    let decision = parse_incident_decision(reply, &sample_menu());
    let keys: Vec<_> = decision.cuts.iter().map(|c| c.node.0.clone()).collect();
    assert_eq!(
        keys,
        vec![
            "workload/app/Pod/store".to_string(),
            "workload/app/Pod/web".to_string()
        ]
    );
}

/// Mirrors `parse_verdict`'s tolerance for surrounding prose around the JSON object.
#[test]
fn surrounding_prose_is_tolerated() {
    let reply = format!(
        "Sure, here is my call:\n{}\nHope that helps!",
        r#"{"assessment": "attack", "reason": "front door", "contain": []}"#
    );
    let decision = parse_incident_decision(&reply, &sample_menu());
    assert_eq!(decision.assessment, Assessment::Attack);
    assert_eq!(decision.reason, "front door");
}
