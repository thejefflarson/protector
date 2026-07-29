//! ADR-0034 D6/D7 (JEF-570): `MitigationLedger::reconcile` consuming per-entry cut-choice
//! decisions end to end — the desired-set rules (model-chosen cuts / the `containment_for`
//! fallback / a confident clear) and D5's non-member whole-decision degrade reaching the
//! ledger. Split out of `tests.rs` purely to keep every file under the 1,000-line cap
//! (repo CLAUDE.md); `super::tests` covers the pre-existing containment/quarantine shapes.

use super::*;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::health::HealthReport;
use crate::engine::observe::{Attribution, RuntimeObservation, Snapshot};
use crate::engine::reason::adjudicate::incident::{
    Assessment, IncidentDecision, build_menu, parse_incident_decision,
};
use crate::engine::reason::proof::prove;
use protector_behavior::Behavior;
use serde_json::json;

/// An internet-facing `web` pod mounting a secret, with a live alert on it — breach-relevant
/// AND corroborated, so [`Mitigation::is_live_corroborated`] would clear on ANY justification
/// carrying `adjudicated: true`. The one chain a fallback proposal's `adjudicated = false`
/// stamp must override.
fn corroborated_breach_relevant_snapshot() -> Snapshot {
    let web = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "c", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    });
    let lb = json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    });
    Snapshot {
        pods: vec![serde_json::from_value(web).unwrap()],
        services: vec![serde_json::from_value(lb).unwrap()],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("alert".into()),
            observed_at_ms: None,
            node: None,
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        }],
        ..Default::default()
    }
}

fn web_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web")
        .expect("web entry chain")
}

/// D6: no decision at all ⇒ the `containment_for` FALLBACK proposes, but stamped
/// `adjudicated = false` so it can NEVER clear the auto-action gate — even though the chain
/// itself is genuinely corroborated. The human-proposal fallback is never auto-applied.
#[test]
fn fallback_proposal_is_stamped_non_auto_even_when_corroborated() {
    let graph = build_graph(
        &corroborated_breach_relevant_snapshot(),
        &default_adapters(),
    );
    let chains = prove(&graph);
    let chain = web_chain(&chains);
    assert!(chain.corroborated, "sanity: the live alert corroborates");
    assert!(chain.is_breach_relevant());

    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &BTreeMap::new());

    let mitigation = delta
        .proposed
        .iter()
        .find(|m| m.cut.from == chain.entry)
        .expect("the containment_for fallback proposes the entry");
    assert!(
        !mitigation.is_live_corroborated(),
        "D6: a fallback proposal is stamped adjudicated=false — never auto-applied, no matter \
         how corroborated the chain is"
    );
}

/// The positive contrast: a decisive `Attack` decision naming the SAME entry on the SAME
/// corroborated chain DOES clear the auto-action gate — the model's say-so, not determinism,
/// is what makes a breach-relevant cut auto-eligible now (ADR-0034).
#[test]
fn model_chosen_cut_clears_the_auto_action_gate_when_corroborated() {
    let graph = build_graph(
        &corroborated_breach_relevant_snapshot(),
        &default_adapters(),
    );
    let chains = prove(&graph);
    let chain = web_chain(&chains);

    let menu = build_menu(chain, &graph, &HealthReport::default());
    let cut = menu.resolve(&chain.entry).expect("the entry is selectable");
    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "live shell on the entry".to_string(),
            cuts: vec![cut],
        },
    );

    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    let mitigation = delta
        .proposed
        .iter()
        .find(|m| m.cut.from == chain.entry)
        .expect("the model-chosen cut proposes the entry");
    assert!(
        mitigation.is_live_corroborated(),
        "a decisive Attack naming a corroborated, breach-relevant entry clears the gate"
    );
}

/// D6: a decisive, confident `NoAttack` gets NEITHER the model cuts NOR the fallback — the
/// model cleared this entry, so there is nothing to propose to a human either.
#[test]
fn decisive_no_attack_produces_no_proposal_at_all() {
    let graph = build_graph(
        &corroborated_breach_relevant_snapshot(),
        &default_adapters(),
    );
    let chains = prove(&graph);
    let chain = web_chain(&chains);

    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::NoAttack,
            reason: "the alert is a benign debug shell, not an attacker".to_string(),
            cuts: Vec::new(),
        },
    );

    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    assert!(
        delta.proposed.iter().all(|m| m.cut.from != chain.entry),
        "a confident no_attack proposes NOTHING for the entry — no fallback either, got {:?}",
        delta.proposed
    );
}

/// D1: `Attack` with an EMPTY `contain` ("attack, but no cut warranted") is valid and routes
/// to the human-proposal fallback — it must not be treated as "no decision" in spirit (it
/// still surfaces something to review) NOR as if the model had chosen a cut (nothing is
/// auto-eligible).
#[test]
fn decisive_attack_with_empty_cuts_still_gets_the_fallback_proposal() {
    let graph = build_graph(
        &corroborated_breach_relevant_snapshot(),
        &default_adapters(),
    );
    let chains = prove(&graph);
    let chain = web_chain(&chains);

    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "attack in progress, nothing warrants a cut yet".to_string(),
            cuts: Vec::new(),
        },
    );

    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    let mitigation = delta
        .proposed
        .iter()
        .find(|m| m.cut.from == chain.entry)
        .expect("D1: attack-with-no-cuts still routes to the containment_for fallback");
    assert!(
        !mitigation.is_live_corroborated(),
        "the fallback for an empty-contain Attack is stamped non-auto too — nothing was \
         actually CHOSEN to cut"
    );
}

/// D5 end to end: a model reply naming a workload OUTSIDE the menu degrades the WHOLE
/// decision to `Uncertain` (the parser's membership guard) — which `reconcile` then treats
/// exactly like "no decision", falling back to the entry's `containment_for` proposal, never
/// the (nonexistent) cut the model tried to name.
#[test]
fn a_non_member_reply_degrades_to_uncertain_and_reconcile_falls_back() {
    let graph = build_graph(
        &corroborated_breach_relevant_snapshot(),
        &default_adapters(),
    );
    let chains = prove(&graph);
    let chain = web_chain(&chains);
    let menu = build_menu(chain, &graph, &HealthReport::default());

    let reply = r#"{"assessment": "attack", "reason": "x", "contain": ["workload/app/Pod/not-on-the-menu"]}"#;
    let decision = parse_incident_decision(reply, &menu);
    assert_eq!(
        decision.assessment,
        Assessment::Uncertain,
        "a non-member contain element degrades the whole decision (ADR-0034 D3)"
    );
    assert!(decision.cuts.is_empty());

    let mut decisions = BTreeMap::new();
    decisions.insert(chain.entry.0.clone(), decision);

    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    let mitigation = delta
        .proposed
        .iter()
        .find(|m| m.cut.from == chain.entry)
        .expect("the degraded decision falls back to containment_for, like no decision at all");
    assert!(!mitigation.is_live_corroborated());
}
