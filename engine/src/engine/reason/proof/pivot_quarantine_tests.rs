//! JEF-322 (thesis-check on JEF-284): does `quarantine_targets_on_path`'s
//! `RemotelyExploitable` trigger require on-pod exploitation *evidence* — a live
//! runtime signal, per the "presence ≠ exploitability, the model decides" thesis
//! (ADR-0011/0013/0016) — or does it fire on mere reachability + static CVE
//! *presence*, the exact pattern ADR-0013 forbids for the entry-foothold lane
//! ("CVE presence no longer auto-cuts")?
//!
//! **Finding: it fires on reachability + CVE presence alone.** [`quarantine_targets_on_path`]'s
//! `RemotelyExploitable` arm is `node != entry && net_reachable(node) && compromisable(node)` —
//! [`compromisable`] is the *static* CVE/KEV predicate, not [`actively_exploited`]'s live-signal
//! one. No runtime evidence, no corroboration, and no model verdict is required. Worse, the
//! actuator's `Mitigation::is_live_corroborated` treats every `QuarantineWorkload` mitigation —
//! including a `RemotelyExploitable` one — as unconditionally auto-actionable (see the comment
//! at that method), bypassing the `corroborated || promoted` gate ADR-0013 requires for the
//! entry. This file is a **characterizing** regression suite: it locks the CURRENT behavior in
//! place (so it can't silently drift further) without endorsing it. Split out of `tests.rs`
//! purely to keep every file under the 1,000-line cap (repo CLAUDE.md).
//!
//! See the ticket's structured result for the `DECISION NEEDED` writeup (model-gate the pivot
//! vs. accept deterministic pivot-quarantine as intended).
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

/// The e2e's pivot shape (JEF-300/#175): an internet-exposed `web` (a LoadBalancer
/// Service, itself carrying no CVE — the entry doesn't need one to seed
/// reachability) reaches a `store` pivot pod over an allowed NetworkPolicy hop.
/// `store` mounts a secret (the objective) and runs a critical-CVE image; `runtime`
/// is the caller's to vary — empty for "no live evidence", or one alarming signal for
/// the actively-exploited contrast case.
fn web_reaches_pivot_store_with_runtime(runtime: Vec<RuntimeObservation>) -> Vec<ProvenChain> {
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
    prove(&build_graph(&snap, &default_adapters()))
}

/// [`web_reaches_pivot_store_with_runtime`] with **no runtime events at all** — no alert,
/// no notable exec, no alarming write.
fn web_reaches_pivot_store() -> Vec<ProvenChain> {
    web_reaches_pivot_store_with_runtime(Vec::new())
}

fn web_to_store_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/store-creds")
        .expect("web → store → secret chain")
}

/// CHARACTERIZING (not endorsing): a pivot pod that is network-reachable from an
/// exposed entry and carries a critical CVE — but has ZERO runtime/live evidence —
/// is CURRENTLY promoted to a `RemotelyExploitable` quarantine target. This is the
/// exact "reachable + CVE present, no evidence" shape JEF-322 asks about; per
/// ADR-0013 ("CVE presence no longer auto-cuts") this is in tension with the
/// product thesis as applied to the entry. See the file header for the finding and
/// the ticket's `DECISION NEEDED`.
#[test]
fn pivot_reachable_plus_cve_alone_currently_promotes_to_remotely_exploitable() {
    let chains = web_reaches_pivot_store();
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
            "CURRENT behavior: reachable + critical-CVE alone promotes the pivot pod to a \
             quarantine target, with no live evidence required",
        );
    assert_eq!(
        target.reason,
        QuarantineReason::RemotelyExploitable,
        "the trigger is the static compromisable() CVE predicate, not actively_exploited()"
    );

    // The actuator's auto-action gate (`Mitigation::is_live_corroborated`) special-cases
    // every `QuarantineWorkload` mitigation as unconditionally auto-actionable — it does not
    // require this chain's own `corroborated`/`promoted`/`adjudicated` bar, unlike the entry
    // lane (ADR-0013). Asserting it here pins the actuation-side half of the same finding.
    let mitigation = crate::engine::respond::Mitigation {
        cut: crate::engine::reason::proof::Link {
            from: chain.entry.clone(),
            to: store_node.clone(),
            relation: "quarantine".into(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action: crate::engine::respond::ProposedAction::QuarantineWorkload,
        justifications: Vec::new(),
    };
    assert!(
        mitigation.is_live_corroborated(),
        "CURRENT behavior: a QuarantineWorkload mitigation is treated as auto-actionable \
         regardless of the chain's own corroboration/promotion — see is_live_corroborated"
    );
}

/// NEGATIVE control: the entry itself is governed by the STRICTER ADR-0013 bar — a proven
/// foothold with no live signal and no model is propose-only, never auto-cut (`meets_action_bar`
/// is false). This is the exact asymmetry the characterizing test above documents: the pivot's
/// `RemotelyExploitable` bar is weaker than the entry's own foothold bar.
#[test]
fn entry_foothold_alone_does_not_meet_the_stricter_action_bar() {
    let chains = web_reaches_pivot_store();
    let chain = web_to_store_chain(&chains);
    assert!(
        !chain.meets_action_bar(),
        "no live corroboration and no model promotion ⇒ the entry-side action bar stays closed, \
         in contrast to the pivot's RemotelyExploitable target above"
    );
}

/// A live signal on the pivot upgrades its reason from `RemotelyExploitable` to
/// `ActivelyExploited` (precedence, JEF-284/JEF-309) — the one shape that DOES carry
/// genuine on-pod evidence, contrasted against the CVE-alone case above.
#[test]
fn pivot_with_live_signal_is_actively_exploited_not_remotely_exploitable() {
    use crate::engine::observe::Attribution;

    let chains = web_reaches_pivot_store_with_runtime(vec![RuntimeObservation {
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
