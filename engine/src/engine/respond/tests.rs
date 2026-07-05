use super::*;
use crate::engine::observe::Snapshot;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::reason::proof::prove;
use serde_json::json;

/// A lateral chain web →reaches→ db →can-read→ secret, whose first cut is the
/// `reaches` edge → a DenyNetworkPath proposal.
fn lateral_chain_snapshot() -> Snapshot {
    let web = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
        "spec": {"containers": [{"name": "c", "image": "web:1"}]}
    });
    let db = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
        "spec": {"containers": [{
            "name": "db", "image": "db:1",
            "envFrom": [{"secretRef": {"name": "db-creds"}}]
        }]}
    });
    let policy = json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "db-ingress", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"role": "db"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    });
    Snapshot {
        pods: vec![
            serde_json::from_value(web).unwrap(),
            serde_json::from_value(db).unwrap(),
        ],
        network_policies: vec![serde_json::from_value(policy).unwrap()],
        ..Default::default()
    }
}

#[test]
fn proposes_a_mitigation_for_a_cuttable_chain() {
    let chains = prove(&build_graph(&lateral_chain_snapshot(), &default_adapters()));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    assert!(
        !delta.proposed.is_empty(),
        "a cuttable chain proposes a mitigation"
    );
    assert!(
        delta
            .proposed
            .iter()
            .any(|m| m.action == ProposedAction::DenyNetworkPath
                || m.action == ProposedAction::RemoveSecretMount),
        "the web→db→secret cut is a network or mount action"
    );
}

/// Auto-action requires an internet-facing entry: a corroborated, adjudicated
/// chain whose entry is internal-only is NOT live-actionable — the engine acts
/// on remote exploitation, not normal internal activity.
#[test]
fn auto_action_requires_a_breach_relevant_entry() {
    use crate::engine::graph::NodeKey;
    use crate::engine::graph::attack::CREDENTIAL_ACCESS;

    let justify = |breach_relevant: bool| Justification {
        entry: "workload/app/Pod/x".into(),
        objective: "secret/app/s".into(),
        attack: CREDENTIAL_ACCESS,
        foothold: false,
        corroborated: true,
        adjudicated: true,
        promoted: false,
        breach_relevant,
    };
    let mitigation = |breach_relevant: bool| Mitigation {
        cut: Link {
            from: NodeKey("workload/app/Pod/x".into()),
            to: NodeKey("workload/app/Pod/y".into()),
            relation: "reaches/Tcp".into(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action: ProposedAction::DenyNetworkPath,
        justifications: vec![justify(breach_relevant)],
    };
    assert!(
        mitigation(true).is_live_corroborated(),
        "internet-facing + corroborated ⇒ auto-actionable"
    );
    assert!(
        !mitigation(false).is_live_corroborated(),
        "internal-only corroborated ⇒ NOT auto-actionable (context, not a breach)"
    );
}

#[test]
fn reconcile_is_idempotent_then_retires_when_chains_vanish() {
    let chains = prove(&build_graph(&lateral_chain_snapshot(), &default_adapters()));
    let mut ledger = MitigationLedger::new();

    let first = ledger.reconcile(&chains);
    assert!(!first.proposed.is_empty());
    let active_after_first = ledger.active().count();

    // Same chains again: nothing new proposed, nothing retired.
    let second = ledger.reconcile(&chains);
    assert!(second.proposed.is_empty());
    assert!(second.retired.is_empty());
    assert_eq!(ledger.active().count(), active_after_first);

    // Posture improves — all chains gone. Every mitigation retires (Q5).
    let third = ledger.reconcile(&[]);
    assert!(third.proposed.is_empty());
    assert_eq!(third.retired.len(), active_after_first);
    assert_eq!(ledger.active().count(), 0);
}

// --- ADR-0010 default containment: quarantine the internet-facing entry ---

/// A LoadBalancer Service selecting `app` labels — the exposure adapter marks the
/// selected pod internet-facing (`Exposure::Internet`), making its chains
/// breach-relevant.
fn internet_lb(namespace: &str, app: &str) -> serde_json::Value {
    json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": format!("{app}-lb"), "namespace": namespace},
        "spec": {"type": "LoadBalancer", "selector": {"app": app}}
    })
}

/// A DIRECT breach chain: an internet-facing pod that itself mounts the secret
/// (`entry -can-read-> secret`). Its only cut is the subtractive mount — no
/// reversible additive edge-cut — so containment defaults to quarantining the entry.
fn direct_mount_internet_snapshot() -> Snapshot {
    let web = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "argocd-server", "namespace": "edge", "labels": {"app": "argocd-server"}},
        "spec": {"containers": [{
            "name": "c", "image": "argo:1",
            "envFrom": [{"secretRef": {"name": "repo-creds"}}]
        }]}
    });
    Snapshot {
        pods: vec![serde_json::from_value(web).unwrap()],
        services: vec![serde_json::from_value(internet_lb("edge", "argocd-server")).unwrap()],
        ..Default::default()
    }
}

/// The single QuarantineEntry mitigation in a delta (asserting exactly one).
fn only_quarantine(delta: &LedgerDelta) -> Mitigation {
    let quarantines: Vec<_> = delta
        .proposed
        .iter()
        .filter(|m| m.action == ProposedAction::QuarantineEntry)
        .collect();
    assert_eq!(
        quarantines.len(),
        1,
        "exactly one QuarantineEntry proposed, got {:?}",
        delta.proposed
    );
    quarantines[0].clone()
}

#[test]
fn direct_mount_chain_quarantines_the_entry_not_the_objective() {
    let chains = prove(&build_graph(
        &direct_mount_internet_snapshot(),
        &default_adapters(),
    ));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    let q = only_quarantine(&delta);
    // Targets ONLY the internet-facing entry (from == to == entry), never the secret.
    assert_eq!(q.cut.from.0, "workload/edge/Pod/argocd-server");
    assert_eq!(q.cut.to.0, "workload/edge/Pod/argocd-server");
    assert_eq!(
        q.cut.from_labels.get("app").map(String::as_str),
        Some("argocd-server")
    );
    assert!(
        delta
            .proposed
            .iter()
            .all(|m| !m.cut.from.0.starts_with("secret/") && !m.cut.to.0.starts_with("secret/")),
        "no mitigation ever targets the objective secret"
    );
}

#[test]
fn direct_rbac_chain_quarantines_the_entry() {
    use crate::engine::observe::SecretMeta;
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

    let app = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "watcher-server", "namespace": "edge", "labels": {"app": "watcher-server"}},
        "spec": {
            "serviceAccountName": "watcher-sa",
            "containers": [{"name": "c", "image": "watcher:1"}]
        }
    });
    let role: Role = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "reader", "namespace": "edge"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    }))
    .unwrap();
    let binding: RoleBinding = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "reader-binding", "namespace": "edge"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "watcher-sa", "namespace": "edge"}]
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![serde_json::from_value(app).unwrap()],
        services: vec![serde_json::from_value(internet_lb("edge", "watcher-server")).unwrap()],
        secrets: vec![SecretMeta {
            namespace: "edge".into(),
            name: "api-key".into(),
        }],
        roles: vec![role],
        role_bindings: vec![binding],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    let q = only_quarantine(&delta);
    // The entry pod is quarantined — never the RBAC identity or the secret.
    assert_eq!(q.cut.from.0, "workload/edge/Pod/watcher-server");
    assert_eq!(
        q.cut.from_labels.get("app").map(String::as_str),
        Some("watcher-server")
    );
}

#[test]
fn lateral_chain_with_reversible_reaches_stays_surgical() {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::ImageVulnerabilities;
    use std::time::SystemTime;

    // A REAL lateral breach: an internet-facing `web` entry reaches a
    // *compromisable* `db` (a critical CVE lets the walk pivot through it) that
    // mounts the secret. The `reaches` edge is a reversible additive edge-cut, so
    // containment stays the surgical DenyNetworkPath — quarantine is only the
    // fallback when no such edge-cut exists.
    let web = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
        "spec": {"containers": [{"name": "c", "image": "web:1"}]}
    });
    let db = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
        "spec": {"containers": [{
            "name": "db", "image": "db:1",
            "envFrom": [{"secretRef": {"name": "db-creds"}}]
        }]}
    });
    let policy = json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "db-ingress", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"role": "db"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    });
    let lb = json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    });
    let snap = Snapshot {
        pods: vec![
            serde_json::from_value(web).unwrap(),
            serde_json::from_value(db).unwrap(),
        ],
        network_policies: vec![serde_json::from_value(policy).unwrap()],
        services: vec![serde_json::from_value(lb).unwrap()],
        image_vulns: vec![ImageVulnerabilities {
            image: "db:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-0001".into(),
                severity: Severity::Critical,
                exploited_in_wild: false,
                epss: Some(0.5),
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let chains = prove(&build_graph(&snap, &default_adapters()));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    // The internet-facing web→db→secret chain is contained by the surgical reaches cut.
    assert!(
        delta
            .proposed
            .iter()
            .any(|m| m.action == ProposedAction::DenyNetworkPath
                && m.cut.relation.starts_with("reaches")
                && m.cut.from.0 == "workload/app/Pod/web"),
        "a reversible reaches edge-cut is chosen surgically, got {:?}",
        delta.proposed
    );
    // The web (internet-facing) entry is never quarantined — the edge-cut suffices.
    assert!(
        delta
            .proposed
            .iter()
            .all(|m| !(m.action == ProposedAction::QuarantineEntry
                && m.cut.from.0 == "workload/app/Pod/web")),
        "no quarantine of the entry when a surgical edge-cut suffices, got {:?}",
        delta.proposed
    );
}

#[test]
fn internal_direct_mount_is_not_quarantined() {
    // The same direct mount chain but with NO internet exposure: not breach-relevant,
    // so it stays a durable-fix (RemoveSecretMount), never a quarantine.
    let mut snap = direct_mount_internet_snapshot();
    snap.services.clear();

    let chains = prove(&build_graph(&snap, &default_adapters()));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    assert!(
        delta
            .proposed
            .iter()
            .all(|m| m.action != ProposedAction::QuarantineEntry),
        "no internet-facing entry ⇒ no quarantine"
    );
    assert!(
        delta
            .proposed
            .iter()
            .any(|m| m.action == ProposedAction::RemoveSecretMount),
        "an internal direct mount stays a durable-fix PR"
    );
}

#[test]
fn quarantine_entry_self_reverts_when_its_chain_is_gone() {
    // ADR-0017: a QuarantineEntry mitigation retires on the same lifecycle as an
    // edge-cut — keyed on the chain, it drops out when no chain still justifies it.
    let chains = prove(&build_graph(
        &direct_mount_internet_snapshot(),
        &default_adapters(),
    ));
    let mut ledger = MitigationLedger::new();

    let first = ledger.reconcile(&chains);
    let q = only_quarantine(&first);
    assert!(
        ledger
            .active()
            .any(|m| m.cut_signature() == q.cut_signature())
    );

    // Posture improves — the chain is gone. The quarantine retires (Q5).
    let retired = ledger.reconcile(&[]);
    assert!(
        retired
            .retired
            .iter()
            .any(|m| m.action == ProposedAction::QuarantineEntry
                && m.cut_signature() == q.cut_signature()),
        "the quarantine retires when its justifying chain vanishes"
    );
    assert_eq!(ledger.active().count(), 0);
}

// --- JEF-284: quarantine any pod that is remotely exploitable / actively exploited ---

use crate::engine::graph::{Provenance, Severity, Vulnerability};
use crate::engine::respond::actuator::{
    ActuationScope, BlastRadius, Decision, EnabledActions, decide,
};

/// Every `QuarantineWorkload` mitigation in a delta, by the pod it isolates.
fn workload_quarantines(delta: &LedgerDelta) -> Vec<&Mitigation> {
    delta
        .proposed
        .iter()
        .filter(|m| m.action == ProposedAction::QuarantineWorkload)
        .collect()
}

fn crit_vuln(id: &str, kev: bool) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        severity: Severity::Critical,
        exploited_in_wild: kev,
        epss: Some(0.5),
        sources: vec![Provenance::new("trivy", std::time::SystemTime::UNIX_EPOCH)],
        ..Default::default()
    }
}

/// A multi-hop breach: internet `web` -reaches-> `app1` (critical CVE) -reaches->
/// `app2` (KEV) which mounts the secret. Both `app1` and `app2` are compromisable and
/// network-reachable from the internet foothold — so both are *remotely exploitable*
/// (JEF-284 condition 1), a popped app one and two hops in.
fn multi_hop_breach_snapshot() -> Snapshot {
    use crate::engine::observe::ImageVulnerabilities;
    let pod = |name: &str, role: &str, image: &str, secret: Option<&str>| {
        let env = secret
            .map(|s| json!([{"secretRef": {"name": s}}]))
            .unwrap_or(json!([]));
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
            "spec": {"containers": [{"name": "c", "image": image, "envFrom": env}]}
        })
    };
    let ingress = |name: &str, to_role: &str, from_role: &str| {
        json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": to_role}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": from_role}}}]}]
            }
        })
    };
    let lb = json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    });
    Snapshot {
        pods: vec![
            serde_json::from_value(pod("web", "web", "web:1", None)).unwrap(),
            serde_json::from_value(pod("app1", "app1", "app1:1", None)).unwrap(),
            serde_json::from_value(pod("app2", "app2", "app2:1", Some("app2-creds"))).unwrap(),
        ],
        network_policies: vec![
            serde_json::from_value(ingress("app1-ingress", "app1", "web")).unwrap(),
            serde_json::from_value(ingress("app2-ingress", "app2", "app1")).unwrap(),
        ],
        services: vec![serde_json::from_value(lb).unwrap()],
        image_vulns: vec![
            ImageVulnerabilities {
                image: "app1:1".into(),
                vulnerabilities: vec![crit_vuln("CVE-2026-1001", false)],
            },
            ImageVulnerabilities {
                image: "app2:1".into(),
                vulnerabilities: vec![crit_vuln("CVE-2026-1002", true)],
            },
        ],
        ..Default::default()
    }
}

#[test]
fn remotely_exploitable_pods_two_hops_in_are_quarantined() {
    let chains = prove(&build_graph(
        &multi_hop_breach_snapshot(),
        &default_adapters(),
    ));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    let quarantined: Vec<String> = workload_quarantines(&delta)
        .iter()
        .map(|m| m.cut.from.0.clone())
        .collect();
    // The popped app one hop in AND the popped app two hops in are both quarantined —
    // independent compromises on the same chain (JEF-284 condition 1).
    assert!(
        quarantined.contains(&"workload/app/Pod/app2".to_string()),
        "the KEV pod two hops in is quarantined, got {quarantined:?}"
    );
    assert!(
        quarantined.contains(&"workload/app/Pod/app1".to_string()),
        "the critical-CVE pod one hop in is quarantined, got {quarantined:?}"
    );
    // The entry is governed by the ADR-0022 precedence (a surgical edge-cut here), never a
    // workload quarantine; and nothing ever targets the objective secret.
    assert!(
        !quarantined.contains(&"workload/app/Pod/web".to_string()),
        "the entry is not workload-quarantined (owned by containment_for)"
    );
    assert!(
        delta
            .proposed
            .iter()
            .all(|m| !m.cut.from.0.starts_with("secret/")),
        "no mitigation targets the objective secret"
    );
}

/// An INTERNAL pod (no internet path) that mounts a secret and has a live on-pod alert
/// — actively exploited *now* (JEF-284 condition 2). It is quarantined regardless of
/// network position, even though its chain is not breach-relevant.
fn internal_active_snapshot(with_alert: bool) -> Snapshot {
    use crate::engine::observe::{Attribution, RuntimeObservation};
    use protector_behavior::Behavior;
    let watcher = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "watcher", "namespace": "app", "labels": {"role": "watcher"}},
        "spec": {"containers": [{
            "name": "c", "image": "watcher:1",
            "envFrom": [{"secretRef": {"name": "watcher-creds"}}]
        }]}
    });
    let runtime_events = if with_alert {
        vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "watcher"),
            source: Some("falco".into()),
            observed_at_ms: None,
            node: None,
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        }]
    } else {
        vec![]
    };
    Snapshot {
        pods: vec![serde_json::from_value(watcher).unwrap()],
        runtime_events,
        ..Default::default()
    }
}

#[test]
fn internal_actively_exploited_pod_is_quarantined() {
    let chains = prove(&build_graph(
        &internal_active_snapshot(true),
        &default_adapters(),
    ));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    let quarantined: Vec<String> = workload_quarantines(&delta)
        .iter()
        .map(|m| m.cut.from.0.clone())
        .collect();
    assert!(
        quarantined.contains(&"workload/app/Pod/watcher".to_string()),
        "an internal pod with a live alert is quarantined (condition 2), got {quarantined:?}"
    );
    // No internet path: this chain is not breach-relevant, yet it is still quarantined.
    assert!(
        chains.iter().all(|c| !c.is_breach_relevant()),
        "the internal chain is deliberately not breach-relevant"
    );
}

/// The regression guard: a pod that is merely *reached* (network-reachable and clean —
/// no CVE, no alert) is NEVER quarantined. Reached ≠ exploited. Alongside it a genuinely
/// popped pod IS quarantined, so the contrast is explicit.
#[test]
fn reachable_but_clean_pod_is_not_quarantined() {
    use crate::engine::observe::ImageVulnerabilities;
    let pod = |name: &str, role: &str, image: &str, secret: Option<&str>| {
        let env = secret
            .map(|s| json!([{"secretRef": {"name": s}}]))
            .unwrap_or(json!([]));
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
            "spec": {"containers": [{"name": "c", "image": image, "envFrom": env}]}
        })
    };
    let ingress = |name: &str, to_role: &str| {
        json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": to_role}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
            }
        })
    };
    let lb = json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    });
    let snap = Snapshot {
        pods: vec![
            serde_json::from_value(pod("web", "web", "web:1", None)).unwrap(),
            // popped: KEV + mounts the secret → remotely exploitable.
            serde_json::from_value(pod("popped", "popped", "popped:1", Some("creds"))).unwrap(),
            // cleandb: reached from web, but NO CVE and NO alert → merely reached.
            serde_json::from_value(pod("cleandb", "cleandb", "cleandb:1", Some("db-creds")))
                .unwrap(),
        ],
        network_policies: vec![
            serde_json::from_value(ingress("popped-ingress", "popped")).unwrap(),
            serde_json::from_value(ingress("cleandb-ingress", "cleandb")).unwrap(),
        ],
        services: vec![serde_json::from_value(lb).unwrap()],
        image_vulns: vec![ImageVulnerabilities {
            image: "popped:1".into(),
            vulnerabilities: vec![crit_vuln("CVE-2026-2001", true)],
        }],
        ..Default::default()
    };

    let chains = prove(&build_graph(&snap, &default_adapters()));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);

    let quarantined: Vec<String> = workload_quarantines(&delta)
        .iter()
        .map(|m| m.cut.from.0.clone())
        .collect();
    assert!(
        quarantined.contains(&"workload/app/Pod/popped".to_string()),
        "the popped pod is quarantined, got {quarantined:?}"
    );
    // The merely-reached clean pod is NEVER a QUARANTINE target (it may still surface a
    // durable-fix PR for its own mount — that's a proposal to a human, not an isolation).
    assert!(
        delta
            .proposed
            .iter()
            .filter(|m| matches!(
                m.action,
                ProposedAction::QuarantineWorkload | ProposedAction::QuarantineEntry
            ))
            .all(|m| m.cut.from.0 != "workload/app/Pod/cleandb"),
        "a reached-but-clean pod must not be quarantined (reached ≠ exploited)"
    );
}

#[test]
fn workload_quarantine_is_proposed_in_audit_actuated_only_under_enforce() {
    let chains = prove(&build_graph(
        &multi_hop_breach_snapshot(),
        &default_adapters(),
    ));
    let mut ledger = MitigationLedger::new();
    let delta = ledger.reconcile(&chains);
    let mitigation = workload_quarantines(&delta)
        .into_iter()
        .find(|m| m.cut.from.0 == "workload/app/Pod/app2")
        .expect("app2 is quarantined")
        .clone();

    // No alive collateral in this snapshot's health view; keep the blast radius empty so
    // the test isolates the enable/scope gate.
    let blast = BlastRadius::default();

    // Audit default: nothing armed ⇒ PROPOSE, never actuate (byte-identical safe default).
    assert!(matches!(
        decide(
            &mitigation,
            &EnabledActions::none(),
            &ActuationScope::unscoped(),
            &blast
        ),
        Decision::Propose(_)
    ));
    // Enforce: the `network` class arms the workload quarantine; unscoped ⇒ AutoApply.
    assert_eq!(
        decide(
            &mitigation,
            &EnabledActions::from_names(["network"]),
            &ActuationScope::unscoped(),
            &blast
        ),
        Decision::AutoApply
    );
}

#[test]
fn workload_quarantine_self_reverts_when_evidence_clears() {
    let mut ledger = MitigationLedger::new();

    // Alert present → the pod is actively exploited → quarantined.
    let chains = prove(&build_graph(
        &internal_active_snapshot(true),
        &default_adapters(),
    ));
    let first = ledger.reconcile(&chains);
    let q = workload_quarantines(&first)
        .into_iter()
        .find(|m| m.cut.from.0 == "workload/app/Pod/watcher")
        .expect("watcher quarantined")
        .clone();
    assert!(
        ledger
            .active()
            .any(|m| m.cut_signature() == q.cut_signature())
    );

    // Evidence clears (no more alert) — the chain still exists (direct mount) but no
    // longer justifies the quarantine, so it retires (ADR-0017 self-revert lifecycle).
    let cleared = prove(&build_graph(
        &internal_active_snapshot(false),
        &default_adapters(),
    ));
    let delta = ledger.reconcile(&cleared);
    assert!(
        delta
            .retired
            .iter()
            .any(|m| m.action == ProposedAction::QuarantineWorkload
                && m.cut_signature() == q.cut_signature()),
        "the workload quarantine retires when its exploitation evidence clears"
    );
    assert!(
        !ledger
            .active()
            .any(|m| m.cut_signature() == q.cut_signature()),
        "no longer active after the evidence cleared"
    );
}
