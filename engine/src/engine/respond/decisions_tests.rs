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

/// An internet-facing `web` pod that REACHES a downstream `store` pivot (a critical CVE makes
/// it a `RemotelyExploitable` quarantine candidate) which mounts the secret. The entry's OWN
/// `containment_for` default is the surgical `reaches` edge-cut — a DIFFERENT cut signature
/// than `store`'s `QuarantineWorkload` line — so a decision naming `store` produces a standing
/// cut `containment_for(chain)` would never rebuild on its own. Exactly the shape the D7
/// retirement-asymmetry bug (a fresh Uncertain silently dropping a differing-signature standing
/// cut) needs to be exercised against.
fn web_reaches_pivot_store_snapshot() -> Snapshot {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::ImageVulnerabilities;
    use std::time::SystemTime;

    let web = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
        "spec": {"containers": [{"name": "c", "image": "web:1"}]}
    });
    let lb = json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    });
    let store = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "store", "namespace": "app", "labels": {"role": "store"}},
        "spec": {
            "containers": [{
                "name": "c", "image": "store:1",
                "envFrom": [{"secretRef": {"name": "store-creds"}}]
            }]
        }
    });
    let policy = json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "store-ingress", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"role": "store"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    });
    Snapshot {
        pods: vec![
            serde_json::from_value(web).unwrap(),
            serde_json::from_value(store).unwrap(),
        ],
        services: vec![serde_json::from_value(lb).unwrap()],
        network_policies: vec![serde_json::from_value(policy).unwrap()],
        image_vulns: vec![ImageVulnerabilities {
            image: "store:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-0570".into(),
                severity: Severity::Critical,
                exploited_in_wild: false,
                epss: None,
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        ..Default::default()
    }
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

/// ADR-0034 D7 (the retirement-asymmetry SAFETY bug this test locks down): a DOWNSTREAM
/// `QuarantineWorkload` cut chosen on pass N — whose signature is NOT `containment_for`'s own
/// default for the entry (the entry's default here is the surgical `reaches` edge-cut) — must
/// still be standing on pass N+1 when the entry comes back with NO decision at all (model
/// unavailable / not yet judged / the cold-start window). A fresh Uncertain must be INERT, not
/// silently rebuild the desired set from `containment_for` and drop it into `retired` (which
/// would tear down the live isolation NetworkPolicy in enforce mode).
#[test]
fn a_downstream_cut_persists_across_a_pass_with_no_decision() {
    let graph = build_graph(&web_reaches_pivot_store_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = web_chain(&chains);
    let store = crate::engine::graph::NodeKey("workload/app/Pod/store".into());

    let menu = build_menu(chain, &graph, &HealthReport::default());
    let store_cut = menu.resolve(&store).expect("store is selectable");
    let store_signature = store_cut.cut_signature.clone();
    // Sanity: this really is a DIFFERENT signature than the entry's own containment_for
    // default — the exact shape the bug needs to be exercised against.
    let (entry_default_cut, _) = containment_for(chain).expect("entry has a default containment");
    assert_ne!(
        store_signature,
        cut_signature(&entry_default_cut),
        "sanity: the downstream cut's signature must differ from containment_for's own default"
    );

    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "store shows exploitation evidence".to_string(),
            cuts: vec![store_cut],
        },
    );
    let mut ledger = MitigationLedger::new();

    // Pass N: the model names `store` — the downstream cut goes active.
    ledger.reconcile(&chains, &decisions);
    assert!(
        ledger
            .active()
            .any(|m| m.cut_signature() == store_signature),
        "the downstream cut is active after the decisive pass"
    );

    // Pass N+1: SAME chains, but no decision for this entry at all this cycle (model down /
    // not yet re-judged). The standing downstream cut must persist — not retire.
    let delta = ledger.reconcile(&chains, &BTreeMap::new());
    assert!(
        ledger
            .active()
            .any(|m| m.cut_signature() == store_signature),
        "D7: a pass with no decision must be inert — the standing downstream cut must still be \
         active, got active={:?}",
        ledger
            .active()
            .map(Mitigation::cut_signature)
            .collect::<Vec<_>>()
    );
    assert!(
        delta
            .retired
            .iter()
            .all(|m| m.cut_signature() != store_signature),
        "the downstream cut must NOT appear in this pass's retired set, got {:?}",
        delta.retired
    );
}

/// The regression guard for the fix above: the carry-forward must not make a standing cut
/// UN-retirable. A decisive `NoAttack` on a LATER pass still clears it, exactly as D6/D7 intend.
#[test]
fn a_decisive_no_attack_still_retires_a_standing_cut() {
    let graph = build_graph(&web_reaches_pivot_store_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = web_chain(&chains);
    let store = crate::engine::graph::NodeKey("workload/app/Pod/store".into());

    let menu = build_menu(chain, &graph, &HealthReport::default());
    let store_cut = menu.resolve(&store).expect("store is selectable");
    let store_signature = store_cut.cut_signature.clone();

    let mut attack_decisions = BTreeMap::new();
    attack_decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "store shows exploitation evidence".to_string(),
            cuts: vec![store_cut],
        },
    );
    let mut ledger = MitigationLedger::new();
    ledger.reconcile(&chains, &attack_decisions);
    assert!(
        ledger
            .active()
            .any(|m| m.cut_signature() == store_signature)
    );

    // A LATER pass decisively clears the entry — the standing cut retires, same as before this
    // fix (the carry-forward only applies to Uncertain/no-decision, never to a decisive call).
    let mut clear_decisions = BTreeMap::new();
    clear_decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::NoAttack,
            reason: "store's CVE was patched and reachability closed".to_string(),
            cuts: Vec::new(),
        },
    );
    let delta = ledger.reconcile(&chains, &clear_decisions);
    assert!(
        delta
            .retired
            .iter()
            .any(|m| m.cut_signature() == store_signature),
        "a decisive NoAttack still retires the standing cut, got retired={:?}",
        delta.retired
    );
    assert!(
        !ledger
            .active()
            .any(|m| m.cut_signature() == store_signature),
        "no longer active after the decisive clear"
    );
}
