//!  (thesis-check on), resolved by does `quarantine_targets_on_path`'s
//! `RemotelyExploitable` trigger require on-pod exploitation *evidence* — a live
//! runtime signal, per the "presence ≠ exploitability, the model decides" thesis
//! (ADR-0011/0013/0016) — or does it fire on mere reachability + static CVE
//! *presence*, the exact pattern ADR-0013 forbids for the entry-foothold lane
//! ("CVE presence no longer auto-cuts")?
//!
//! ** finding:** [`quarantine_targets_on_path`]'s `RemotelyExploitable` arm is
//! `node != entry && net_reachable(node) && compromisable(node)` — [`compromisable`] is the
//! *static* CVE/KEV predicate, not [`actively_exploited`]'s live-signal one. No runtime
//! evidence, no corroboration, and no model verdict is required to become a *candidate*
//! quarantine target — that stays true, deliberately: the proof layer still proposes on
//! presence alone (a human always sees the finding).
//!
//! ** fix:** the actuator's `Mitigation::is_live_corroborated` previously
//! special-cased every `QuarantineWorkload` mitigation — including a `RemotelyExploitable`
//! one — as unconditionally auto-actionable, bypassing the `corroborated || promoted`
//! gate ADR-0013 requires for the entry lane. It now runs the SAME gate as every other
//! action: `(corroborated || promoted) && adjudicated && breach_relevant` on the pod's
//! justifying chain. A downstream `RemotelyExploitable` pod behind a clean/unpromoted edge
//! is now propose-only; an internal-only actively-exploited pod (no internet-facing entry,
//! `breach_relevant == false`) is propose-only too. This file pins both halves: the proof
//! layer still *identifies* the candidate (unchanged), the actuation layer no longer
//! *auto-acts* on it without the model gate. Split out of `tests.rs` purely to keep every
//! file under the 1,000-line cap (repo CLAUDE.md).
#![allow(unused_imports)]

use super::*;
use crate::engine::graph::Behavior;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::{RuntimeObservation, Snapshot};
use serde_json::{Value, json};

fn pod(value: Value) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

fn service(value: Value) -> k8s_openapi::api::core::v1::Service {
    serde_json::from_value(value).expect("valid Service fixture")
}

fn netpol(value: Value) -> k8s_openapi::api::networking::v1::NetworkPolicy {
    serde_json::from_value(value).expect("valid NetworkPolicy fixture")
}

/// One critical CVE on `image` — the [`compromisable`](super::chain::compromisable)
/// precondition, satisfied by *presence* alone (no runtime signal attached).
fn critical_image(image: &str) -> crate::engine::observe::ImageVulnerabilities {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use std::time::SystemTime;
    crate::engine::observe::ImageVulnerabilities {
        image: image.into(),
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2026-0322".into(),
            severity: Severity::Critical,
            exploited_in_wild: false,
            epss: None,
            sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
            ..Default::default()
        }],
    }
}

/// The e2e's pivot shape (#175): an internet-exposed `web` (a LoadBalancer
/// Service, itself carrying no CVE — the entry doesn't need one to seed
/// reachability) reaches a `store` pivot pod over an allowed NetworkPolicy hop.
/// `store` mounts a secret (the objective) and runs a critical-CVE image; `runtime`
/// is the caller's to vary — empty for "no live evidence", or one alarming signal for
/// the actively-exploited contrast case.
fn web_reaches_pivot_store_with_runtime(
    runtime: Vec<RuntimeObservation>,
) -> (crate::engine::graph::SecurityGraph, Vec<ProvenChain>) {
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let lb = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    }));
    let store = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "store", "namespace": "app", "labels": {"role": "store"}},
        "spec": {
            "containers": [{
                "name": "store", "image": "store:1",
                "envFrom": [{"secretRef": {"name": "store-creds"}}]
            }]
        }
    }));
    let policy = netpol(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "store-ingress", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"role": "store"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    }));
    let snap = Snapshot {
        pods: vec![web, store],
        services: vec![lb],
        network_policies: vec![policy],
        image_vulns: vec![critical_image("store:1")],
        runtime_events: runtime,
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let chains = prove(&graph);
    (graph, chains)
}

/// [`web_reaches_pivot_store_with_runtime`] with **no runtime events at all** — no alert,
/// no notable exec, no alarming write.
fn web_reaches_pivot_store() -> (crate::engine::graph::SecurityGraph, Vec<ProvenChain>) {
    web_reaches_pivot_store_with_runtime(Vec::new())
}

fn web_to_store_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/store-creds")
        .expect("web → store → secret chain")
}

/// ADR-0034: a breach-relevant chain's `QuarantineWorkload` mitigation is now
/// PROPOSED only when a decisive `Attack` decision named the node in `contain` — the
/// deterministic `quarantine_targets` desired-set insertion this file's tests used to rely on
/// is gone for breach-relevant chains (it stays, unchanged, for a non-breach-relevant one). So
/// these tests supply the decision the model WOULD have made naming `store`, built through the
/// real menu resolver (never hand-rolled), to isolate what they actually test: the
/// `is_live_corroborated` gate on the resulting mitigation, independent of how it got proposed.
fn decisions_naming_store(
    chain: &ProvenChain,
    graph: &crate::engine::graph::SecurityGraph,
) -> std::collections::BTreeMap<String, crate::engine::reason::adjudicate::incident::IncidentDecision>
{
    use crate::engine::observe::health::HealthReport;
    use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, build_menu};

    let store_node = crate::engine::graph::NodeKey("workload/app/Pod/store".into());
    let menu = build_menu(chain, graph, &HealthReport::default());
    let cut = menu
        .resolve(&store_node)
        .expect("store is selectable on the menu");
    let mut decisions = std::collections::BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "store shows exploitation evidence".to_string(),
            cuts: vec![cut],
        },
    );
    decisions
}

/// A pivot pod that is network-reachable from an exposed entry and carries a critical
/// CVE — but whose justifying chain has ZERO runtime/live evidence (a clean, unpromoted
/// edge) — is still IDENTIFIED as a `RemotelyExploitable` quarantine candidate at the
/// proof layer (unchanged), but ADR-0032 makes it **propose-only**: the actuator no
/// longer auto-acts on reachability + CVE presence alone, matching the entry-foothold
/// lane's ADR-0013 bar ("CVE presence no longer auto-cuts").
#[test]
fn pivot_reachable_plus_cve_alone_behind_a_clean_edge_is_propose_only() {
    let (graph, chains) = web_reaches_pivot_store();
    let chain = web_to_store_chain(&chains);

    // No runtime evidence anywhere in the snapshot ⇒ nothing is live-corroborated.
    assert!(
        !chain.corroborated,
        "no runtime signal exists on this graph — the chain must not be live-corroborated"
    );

    let store_node = crate::engine::graph::NodeKey("workload/app/Pod/store".into());
    let target = chain
        .quarantine_targets
        .iter()
        .find(|t| t.node == store_node)
        .expect(
            "reachable + critical-CVE alone still identifies the pivot pod as a quarantine \
             CANDIDATE — the proof layer's target selection is unchanged by ADR-0032",
        );
    assert_eq!(
        target.reason,
        QuarantineReason::RemotelyExploitable,
        "the trigger is the static compromisable() CVE predicate, not actively_exploited()"
    );

    // Build the mitigation the way the response layer actually does — through the
    // ledger, so the justification carries this chain's real corroborated/adjudicated/
    // breach_relevant state, not a hand-rolled empty vec. ADR-0034: a
    // breach-relevant chain's workload quarantine is proposed only when a decisive
    // Attack decision named it — supply the decision the model would have made.
    let decisions = decisions_naming_store(chain, &graph);
    let mut ledger = crate::engine::respond::MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    let mitigation = delta
        .proposed
        .iter()
        .find(|m| {
            m.action == crate::engine::respond::ProposedAction::QuarantineWorkload
                && m.cut.from == store_node
        })
        .expect("the pivot's QuarantineWorkload mitigation is proposed");
    assert!(
        !mitigation.is_live_corroborated(),
        "a downstream RemotelyExploitable pod behind a clean/unpromoted edge is \
         propose-only — it must NOT clear the auto-action gate on CVE presence alone"
    );
}

/// The positive contrast: the SAME pivot shape, but the entry now carries a live alert
/// (any "attack happening now" signal corroborates any objective). That makes the
/// justifying chain corroborated + breach-relevant + adjudicated, so the pivot's
/// `RemotelyExploitable` quarantine now DOES clear the auto-action gate — the model/
/// corroboration governs, not the pod's static CVE alone.
#[test]
fn pivot_behind_a_corroborated_breach_relevant_edge_is_auto_actionable() {
    use crate::engine::observe::Attribution;

    let (graph, chains) = web_reaches_pivot_store_with_runtime(vec![RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: Some("alert".into()),
        observed_at_ms: None,
        node: None,
        behavior: Behavior::Alert {
            rule: "Terminal shell in container".into(),
        },
    }]);
    let chain = web_to_store_chain(&chains);
    assert!(
        chain.corroborated,
        "a live alert on the entry corroborates the chain"
    );
    assert!(chain.is_breach_relevant(), "the entry is internet-facing");

    let store_node = crate::engine::graph::NodeKey("workload/app/Pod/store".into());
    // ADR-0034: supply the decisive Attack decision the model would have made
    // naming `store` — see `decisions_naming_store`.
    let decisions = decisions_naming_store(chain, &graph);
    let mut ledger = crate::engine::respond::MitigationLedger::new();
    let delta = ledger.reconcile(&chains, &decisions);
    let mitigation = delta
        .proposed
        .iter()
        .find(|m| {
            m.action == crate::engine::respond::ProposedAction::QuarantineWorkload
                && m.cut.from == store_node
        })
        .expect("the pivot's QuarantineWorkload mitigation is proposed");
    assert!(
        mitigation.is_live_corroborated(),
        "a corroborated, adjudicated, breach-relevant justifying chain clears the same \
         gate every other action clears — auto-actionable"
    );
}

/// NEGATIVE control: the entry itself is governed by the STRICTER ADR-0013 bar — a proven
/// foothold with no live signal and no model is propose-only, never auto-cut (`meets_action_bar`
/// is false). This is the exact asymmetry the characterizing test above documents: the pivot's
/// `RemotelyExploitable` bar is weaker than the entry's own foothold bar.
#[test]
fn entry_foothold_alone_does_not_meet_the_stricter_action_bar() {
    let (_graph, chains) = web_reaches_pivot_store();
    let chain = web_to_store_chain(&chains);
    assert!(
        !chain.meets_action_bar(),
        "no live corroboration and no model promotion ⇒ the entry-side action bar stays closed, \
         in contrast to the pivot's RemotelyExploitable target above"
    );
}

/// A live signal on the pivot upgrades its reason from `RemotelyExploitable` to
/// `ActivelyExploited` (precedence) — the one shape that DOES carry
/// genuine on-pod evidence, contrasted against the CVE-alone case above.
#[test]
fn pivot_with_live_signal_is_actively_exploited_not_remotely_exploitable() {
    use crate::engine::observe::Attribution;

    let (_graph, chains) = web_reaches_pivot_store_with_runtime(vec![RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "store"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: Behavior::FileWrite {
            path: "/usr/bin/dropper".into(),
        },
    }]);
    let chain = web_to_store_chain(&chains);

    let store_node = crate::engine::graph::NodeKey("workload/app/Pod/store".into());
    let target = chain
        .quarantine_targets
        .iter()
        .find(|t| t.node == store_node)
        .expect("store still qualifies for quarantine");
    assert_eq!(
        target.reason,
        QuarantineReason::ActivelyExploited,
        "live on-pod evidence takes precedence over the static RemotelyExploitable reason"
    );
}
