//! Unit tests for the proof layer: the movement walk + compromise gate, the
//! minimal-cut detection, the foothold/exposure classification, and the corroboration
//! predicates. Split out of the proof module root purely to keep every file under the
//! 1,000-line cap (repo CLAUDE.md). `use super::*` resolves to the proof module, so the
//! tests see what the inline `mod tests` block saw; the internal helpers they exercise
//! (`compromisable`, `corroborates`) are imported from their submodules.
#![allow(unused_imports)]

use super::chain::compromisable;
use super::corroborate::corroborates;
use crate::engine::graph::Behavior;

use super::*;
use crate::engine::observe::Snapshot;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use serde_json::{Value, json};

fn pod(value: Value) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

fn netpol(value: Value) -> k8s_openapi::api::networking::v1::NetworkPolicy {
    serde_json::from_value(value).expect("valid NetworkPolicy fixture")
}

fn web(name: &str, role: &str) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
        "spec": {"containers": [{"name": "c", "image": "img:1"}]}
    })
}

/// One critical CVE on `image`, so the workload running it is *compromisable* —
/// the precondition for the proof walk to act from a reached (non-entry) workload.
fn critical_image(image: &str) -> crate::engine::observe::ImageVulnerabilities {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use std::time::SystemTime;
    crate::engine::observe::ImageVulnerabilities {
        image: image.into(),
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2026-0001".into(),
            severity: Severity::Critical,
            exploited_in_wild: false,
            epss: None,
            sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
            ..Default::default()
        }],
    }
}

/// db mounts the secret; an ingress policy allows web → db; db runs a vulnerable
/// image so it is compromisable (ADR-0002: a reached workload's secrets are only
/// in scope once it can be compromised). The proven chain from web is
/// web →(reaches) db →(can-read) secret, and — being a single linear path —
/// either edge alone cuts it.
#[test]
fn proves_lateral_chain_and_finds_single_edge_cuts() {
    let db = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
        "spec": {
            "containers": [{
                "name": "db", "image": "db:1",
                "envFrom": [{"secretRef": {"name": "db-creds"}}]
            }]
        }
    });
    let policy = netpol(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "db-ingress", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"role": "db"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    }));
    let snap = Snapshot {
        pods: vec![pod(web("web", "web")), pod(db)],
        network_policies: vec![policy],
        image_vulns: vec![critical_image("db:1")],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let lateral = chains
        .iter()
        .find(|c| c.entry.0.contains("/web") && c.links.len() == 2)
        .expect("web → db → secret chain");
    assert_eq!(lateral.strength(), 2);
    // Linear path ⇒ both edges are individually sufficient cuts.
    assert_eq!(lateral.single_edge_cuts.len(), 2);

    // db itself is an entry with a 1-link direct-read chain.
    assert!(
        chains
            .iter()
            .any(|c| c.entry.0.contains("/db") && c.links.len() == 1)
    );
}

/// web can reach the secret via two distinct workloads (db and cache), both of
/// which mount it and both compromisable (vulnerable image). No single edge on the
/// shortest path breaks reachability, so `single_edge_cuts` is empty — the honest
/// "needs more than one cut" finding.
#[test]
fn redundant_paths_have_no_single_edge_cut() {
    let mount = |name: &str, role: &str| {
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
            "spec": {
                "containers": [{
                    "name": "c", "image": "x:1",
                    "envFrom": [{"secretRef": {"name": "shared"}}]
                }]
            }
        })
    };
    // One policy selecting both backends, allowing web in.
    let policy = netpol(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "backends", "namespace": "app"},
        "spec": {
            "podSelector": {"matchLabels": {"tier": "backend"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
        }
    }));
    let mut db = mount("db", "db");
    db["metadata"]["labels"]["tier"] = json!("backend");
    let mut cache = mount("cache", "cache");
    cache["metadata"]["labels"]["tier"] = json!("backend");

    let snap = Snapshot {
        pods: vec![pod(web("web", "web")), pod(db), pod(cache)],
        network_policies: vec![policy],
        image_vulns: vec![critical_image("x:1")],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let from_web = chains
        .iter()
        .find(|c| c.entry.0.contains("/web"))
        .expect("a chain from web to the shared secret");
    assert!(
        from_web.single_edge_cuts.is_empty(),
        "redundant paths ⇒ no single edge severs the chain"
    );
    // JEF-281: the redundancy is enumerated, not collapsed to one path — BOTH proven paths
    // (web → db → secret AND web → cache → secret) are carried, so the finding detail can show
    // the complete picture. This is the exact information that explains the no-single-edge-cut
    // disposition. Bounded and not truncated on this small graph.
    assert_eq!(
        from_web.paths.len(),
        2,
        "both redundant paths to the shared secret are enumerated"
    );
    assert!(
        !from_web.paths_truncated,
        "two paths is well under the bound — nothing truncated"
    );
    // Every enumerated path starts at the web entry and ends at the shared secret objective.
    for path in &from_web.paths {
        assert_eq!(path.first().map(|l| &l.from), Some(&from_web.entry));
        assert_eq!(path.last().map(|l| &l.to), Some(&from_web.objective));
    }
    // The two paths diverge at their middle node (db vs cache) — genuinely distinct routes.
    let mids: std::collections::HashSet<&str> = from_web
        .paths
        .iter()
        .filter_map(|p| p.first().map(|l| l.to.0.as_str()))
        .collect();
    assert_eq!(
        mids.len(),
        2,
        "the two routes go through different backends"
    );
}

/// The RBAC path class: a workload assumes its ServiceAccount identity, which
/// can read a secret via RBAC. The proven chain is
/// workload →(runs-as) identity →(can-do) secret — strength 2, no network hop.
#[test]
fn proves_rbac_privilege_chain() {
    use crate::engine::observe::SecretMeta;
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

    let app = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "app", "namespace": "app"},
        "spec": {
            "serviceAccountName": "app-sa",
            "containers": [{"name": "app", "image": "app:1"}]
        }
    }));
    let role: Role = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "reader", "namespace": "app"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    }))
    .unwrap();
    let binding: RoleBinding = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "reader-binding", "namespace": "app"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "app"}]
    }))
    .unwrap();

    let snap = Snapshot {
        pods: vec![app],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "api-key".into(),
        }],
        roles: vec![role],
        role_bindings: vec![binding],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let chain = chains
        .iter()
        .find(|c| c.entry.0.contains("/app") && c.objective.0 == "secret/app/api-key")
        .expect("app → identity → secret chain");
    assert_eq!(chain.strength(), 2);
    let relations: Vec<&str> = chain.links.iter().map(|l| l.relation.as_str()).collect();
    assert_eq!(relations, vec!["runs-as", "can-do/get/secrets"]);
    // Both edges sever the path, but the structural `runs-as` is not a cut
    // candidate (you don't sever a pod from its SA) — the only cut is the RBAC
    // grant, the meaningful, durable fix.
    assert_eq!(chain.single_edge_cuts.len(), 1);
    assert_eq!(chain.single_edge_cuts[0].relation, "can-do/get/secrets");
}

/// A privileged pod scheduled on a node yields a one-link Escape-to-Host chain
/// (T1611), tagged with the Privilege Escalation tactic.
#[test]
fn proves_escape_to_host_chain_tagged_with_attack() {
    use crate::engine::graph::attack::{ESCAPE_TO_HOST, Tactic};

    let privileged = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "runner", "namespace": "ci"},
        "spec": {
            "nodeName": "node-1",
            "containers": [{
                "name": "runner", "image": "runner:1",
                "securityContext": {"privileged": true}
            }]
        }
    }));
    let snap = Snapshot {
        pods: vec![privileged],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let escape = chains
        .iter()
        .find(|c| c.objective.0 == "host/node-1")
        .expect("escape-to-host chain");
    assert_eq!(escape.entry.0, "workload/ci/Pod/runner");
    assert_eq!(escape.attack, ESCAPE_TO_HOST);
    assert_eq!(escape.attack.tactic, Tactic::PrivilegeEscalation);
    assert_eq!(escape.strength(), 1);
    assert_eq!(escape.links[0].relation, "escapes-to/privileged");
    // The single escape edge is the cut.
    assert_eq!(escape.single_edge_cuts.len(), 1);
}

/// A workload whose ServiceAccount can create pods yields an Execution / Deploy
/// Container (T1610) chain to a Capability objective — the path class KubeHound
/// models as `POD_CREATE`, here tagged in MITRE terms.
#[test]
fn proves_capability_chain_to_deploy_container() {
    use crate::engine::graph::attack::{DEPLOY_CONTAINER, Tactic};
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

    let deployer = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "deployer", "namespace": "ci"},
        "spec": {
            "serviceAccountName": "deployer-sa",
            "containers": [{"name": "c", "image": "c:1"}]
        }
    }));
    let role: Role = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "pod-creator", "namespace": "ci"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]
    }))
    .unwrap();
    let binding: RoleBinding = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "deployer-binding", "namespace": "ci"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "pod-creator"},
        "subjects": [{"kind": "ServiceAccount", "name": "deployer-sa", "namespace": "ci"}]
    }))
    .unwrap();

    let snap = Snapshot {
        pods: vec![deployer],
        roles: vec![role],
        role_bindings: vec![binding],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let chain = chains
        .iter()
        .find(|c| c.objective.0 == "capability/ns:ci/create/pods")
        .expect("deploy-container chain");
    assert_eq!(chain.entry.0, "workload/ci/Pod/deployer");
    assert_eq!(chain.attack, DEPLOY_CONTAINER);
    assert_eq!(chain.attack.tactic, Tactic::Execution);
    let relations: Vec<&str> = chain.links.iter().map(|l| l.relation.as_str()).collect();
    assert_eq!(relations, vec!["runs-as", "can-do/create/pods"]);
}

/// The entry side of the action bar: an internet-exposed (LoadBalancer) pod
/// running an image with an exploited-in-wild CVE, reaching a secret. The chain
/// is tagged with a proven foothold (T1190) and meets the structural action bar.
#[test]
fn proves_foothold_when_exposed_and_exploitable() {
    use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::{ImageVulnerabilities, SecretMeta};
    use std::time::SystemTime;

    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]
        }
    }));
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let vuln = Vulnerability {
        id: "CVE-2026-9999".into(),
        severity: Severity::Critical,
        exploited_in_wild: true,
        epss: Some(0.97),
        sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
        ..Default::default()
    };

    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![vuln],
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));

    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
    // Exposed + exploitable but no live activity ⇒ latent foothold (propose-only),
    // not live-actionable.
    assert!(chain.is_latent_foothold());
    assert!(!chain.corroborated);
    assert!(!chain.meets_action_bar());
}

/// A reachable *critical* CVE is a foothold on its own, even without KEV.
#[test]
fn critical_cve_alone_is_a_foothold() {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::{ImageVulnerabilities, SecretMeta};
    use std::time::SystemTime;

    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }));
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-0042".into(),
                severity: Severity::Critical,
                // Critical, but NOT on the KEV catalogue.
                exploited_in_wild: false,
                epss: None,
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
}

/// Adding a live runtime signal on the foothold workload supplies the final
/// predicate — the full action bar is then met.
#[test]
fn runtime_signal_completes_the_action_bar() {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::{
        Attribution, ImageVulnerabilities, RuntimeObservation, SecretMeta,
    };
    use std::time::SystemTime;

    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }));
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-9999".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: None,
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: crate::engine::graph::Behavior::Alert {
                rule: "Outbound connection to C2".into(),
            },
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert!(
        chain.corroborated,
        "runtime signal on the entry corroborates"
    );
    assert!(
        chain.meets_action_bar(),
        "foothold + corroboration = full bar"
    );
}

// ── JEF-49: per-objective corroboration from the agent's own behaviors ──
// These exercise the `corroborates(behavior, attack)` seam directly (ADR-0014):
// each behavior corroborates only the objective class whose ATT&CK tactic it
// evidences. The mapping is keyed on `attack.tactic`.
use crate::engine::graph::attack::{
    CREDENTIAL_ACCESS, ESCAPE_TO_HOST, EXFILTRATION, EXPLOIT_PUBLIC_FACING,
};

/// Internet egress corroborates an EXFILTRATION objective (T1041).
#[test]
fn network_internet_corroborates_exfiltration() {
    let behavior = Behavior::NetworkConnection {
        peer: "203.0.113.7:443".into(),
        internet: true,
    };
    assert!(corroborates(&behavior, &EXFILTRATION));
}

/// A secret read corroborates a CREDENTIAL_ACCESS objective (T1552).
#[test]
fn secret_read_corroborates_credential_access() {
    let behavior = Behavior::SecretRead {
        secret: "db-creds".into(),
        source: crate::engine::graph::SecretReadSource::Mounted,
    };
    assert!(corroborates(&behavior, &CREDENTIAL_ACCESS));
    // An API secret read (JEF-269) corroborates the same objective — the tactic, not the
    // read mechanism, is what corroborates a credential-access chain.
    assert!(corroborates(
        &Behavior::SecretRead {
            secret: "db-creds".into(),
            source: crate::engine::graph::SecretReadSource::Api,
        },
        &CREDENTIAL_ACCESS,
    ));
}

/// A library load corroborates a FOOTHOLD (Initial Access / T1190): post-JEF-75 the
/// surviving LibraryLoaded is already pruned to a vulnerable library.
#[test]
fn library_load_corroborates_foothold() {
    let behavior = Behavior::LibraryLoaded {
        name: "libssl.so.1.1".into(),
    };
    assert!(corroborates(&behavior, &EXPLOIT_PUBLIC_FACING));
}

/// NEGATIVE: a behavior whose tactic does not match the objective's technique does
/// NOT corroborate — internet egress is exfiltration evidence, not credential-access
/// evidence; an in-cluster connection is no evidence at all.
#[test]
fn behavior_does_not_corroborate_unrelated_objective() {
    // Internet egress against a credential-access objective: wrong tactic.
    assert!(!corroborates(
        &Behavior::NetworkConnection {
            peer: "203.0.113.7:443".into(),
            internet: true,
        },
        &CREDENTIAL_ACCESS,
    ));
    // A secret read against an escape-to-host objective: wrong tactic.
    assert!(!corroborates(
        &Behavior::SecretRead {
            secret: "db-creds".into(),
            source: crate::engine::graph::SecretReadSource::Mounted,
        },
        &ESCAPE_TO_HOST,
    ));
    // A library load against an exfiltration objective: wrong tactic.
    assert!(!corroborates(
        &Behavior::LibraryLoaded {
            name: "libssl.so.1.1".into(),
        },
        &EXFILTRATION,
    ));
    // An in-cluster connection is normal traffic — never corroborates, even on the
    // matching exfiltration objective.
    assert!(!corroborates(
        &Behavior::NetworkConnection {
            peer: "10.0.0.5:5432".into(),
            internet: false,
        },
        &EXFILTRATION,
    ));
}

// ── JEF-307: high-signal foothold peers corroborate a FOOTHOLD (Initial Access) ──
// A connection to a cloud-metadata/IMDS endpoint or the Kubernetes API server is the
// engine-side restoration of Falco's cloud-metadata / API-server criticals — it
// corroborates the entry foothold (T1190) and NOTHING else. Ordinary in-cluster and
// ordinary internet egress must NOT (ADR-0011 conservatism).

/// A connection to a cloud-metadata/IMDS endpoint corroborates a FOOTHOLD (T1190).
#[test]
fn imds_peer_corroborates_foothold() {
    let imds = Behavior::NetworkConnection {
        peer: "169.254.169.254:80".into(),
        internet: true,
    };
    assert!(corroborates(&imds, &EXPLOIT_PUBLIC_FACING));
}

/// A connection to the resolved Kubernetes API server corroborates a FOOTHOLD (T1190).
#[test]
fn api_server_peer_corroborates_foothold() {
    // JEF-131 resolves the apiserver ClusterIP to the `default/kubernetes` label.
    let apiserver = Behavior::NetworkConnection {
        peer: "default/kubernetes:443 (10.96.0.1)".into(),
        internet: false,
    };
    assert!(corroborates(&apiserver, &EXPLOIT_PUBLIC_FACING));
}

/// NEGATIVE: benign in-cluster traffic and ordinary internet egress do NOT corroborate a
/// foothold — a benign app talking to its own DB / the internet must never read as one.
#[test]
fn ordinary_connections_do_not_corroborate_foothold() {
    // A resolved in-cluster DB peer.
    assert!(!corroborates(
        &Behavior::NetworkConnection {
            peer: "analytics/influxdb:8086 (10.42.1.159)".into(),
            internet: false,
        },
        &EXPLOIT_PUBLIC_FACING,
    ));
    // Ordinary internet egress corroborates EXFILTRATION, never the foothold objective.
    assert!(!corroborates(
        &Behavior::NetworkConnection {
            peer: "203.0.113.7:443".into(),
            internet: true,
        },
        &EXPLOIT_PUBLIC_FACING,
    ));
    // A link-local peer that is NOT IMDS (e.g. NodeLocal DNSCache) does NOT corroborate.
    assert!(!corroborates(
        &Behavior::NetworkConnection {
            peer: "169.254.20.10:53".into(),
            internet: false,
        },
        &EXPLOIT_PUBLIC_FACING,
    ));
}

/// An *alert* still corroborates ANY objective — the broad gate must not regress.
#[test]
fn alert_still_corroborates_any_objective() {
    let alert = Behavior::Alert {
        rule: "Outbound connection to C2".into(),
    };
    assert!(corroborates(&alert, &CREDENTIAL_ACCESS));
    assert!(corroborates(&alert, &EXFILTRATION));
    assert!(corroborates(&alert, &ESCAPE_TO_HOST));
    assert!(corroborates(&alert, &EXPLOIT_PUBLIC_FACING));
}

/// A shell exec (JEF-55 interactive-shell) corroborates ANY objective like an alert
/// (JEF-117): the agent-side replacement for Falco's "terminal shell in container".
#[test]
fn shell_exec_corroborates_any_objective() {
    let shell = Behavior::ProcessExec {
        path: "/bin/bash".into(),
    };
    assert!(crate::engine::observe::exec_class::is_interactive_shell(
        &shell
    ));
    assert!(corroborates(&shell, &CREDENTIAL_ACCESS));
    assert!(corroborates(&shell, &EXFILTRATION));
    assert!(corroborates(&shell, &ESCAPE_TO_HOST));
    assert!(corroborates(&shell, &EXPLOIT_PUBLIC_FACING));
}

/// A package-manager exec (JEF-55) corroborates ANY objective like an alert (JEF-117):
/// the agent-side replacement for Falco's "package management in container".
#[test]
fn package_manager_exec_corroborates_any_objective() {
    let pkg = Behavior::ProcessExec {
        path: "/usr/bin/apt".into(),
    };
    assert!(crate::engine::observe::exec_class::is_package_manager(&pkg));
    assert!(corroborates(&pkg, &CREDENTIAL_ACCESS));
    assert!(corroborates(&pkg, &EXFILTRATION));
    assert!(corroborates(&pkg, &ESCAPE_TO_HOST));
    assert!(corroborates(&pkg, &EXPLOIT_PUBLIC_FACING));
}

/// NEGATIVE: a *bare* (non-shell, non-pkg-mgr) ProcessExec stays non-corroborating —
/// legit entrypoints exec constantly (the ADR-0011 false positive). It is model
/// evidence only, never the broad tamper-now gate (JEF-117).
#[test]
fn bare_exec_does_not_corroborate() {
    let bare = Behavior::ProcessExec {
        path: "/app/server".into(),
    };
    assert!(crate::engine::observe::exec_class::notable_exec(&bare).is_none());
    assert!(!corroborates(&bare, &CREDENTIAL_ACCESS));
    assert!(!corroborates(&bare, &EXFILTRATION));
    assert!(!corroborates(&bare, &ESCAPE_TO_HOST));
    assert!(!corroborates(&bare, &EXPLOIT_PUBLIC_FACING));
}

/// NEGATIVE: a PrivilegeChange stays non-corroborating — legit entrypoints escalate
/// (the ADR-0011 false positive). JEF-117 promotes notable execs only, not privesc.
#[test]
fn privilege_change_does_not_corroborate() {
    let priv_change = Behavior::PrivilegeChange {
        from_uid: 1000,
        to_uid: 0,
    };
    assert!(!corroborates(&priv_change, &CREDENTIAL_ACCESS));
    assert!(!corroborates(&priv_change, &EXFILTRATION));
    assert!(!corroborates(&priv_change, &ESCAPE_TO_HOST));
    assert!(!corroborates(&priv_change, &EXPLOIT_PUBLIC_FACING));
}

/// Integration check through the full `prove` path: a secret-read runtime signal on
/// an exposed, exploitable entry corroborates its CREDENTIAL_ACCESS chain to the
/// secret — the per-objective seam wired end to end (still shadow-gated for action).
#[test]
fn secret_read_signal_corroborates_credential_chain_end_to_end() {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::{
        Attribution, ImageVulnerabilities, RuntimeObservation, SecretMeta,
    };
    use std::time::SystemTime;

    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }));
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-9999".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: None,
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::SecretRead {
                secret: "session-key".into(),
                source: crate::engine::graph::SecretReadSource::Mounted,
            },
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert_eq!(chain.attack, CREDENTIAL_ACCESS);
    assert!(
        chain.corroborated,
        "a secret-read signal corroborates the credential-access objective"
    );
}

/// JEF-77, the gap this issue closes: a `LibraryLoaded` (vuln-matched by JEF-75) on an
/// internet-facing, exploitable entry corroborates the chain through the *foothold*
/// tactic (INITIAL_ACCESS / T1190), even though the objective itself is tagged
/// CREDENTIAL_ACCESS. Before the foothold-aware path this arm was dormant end-to-end.
#[test]
fn library_load_signal_corroborates_through_foothold_end_to_end() {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::{
        Attribution, ImageVulnerabilities, RuntimeObservation, SecretMeta,
    };
    use std::time::SystemTime;

    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }));
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-9999".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: None,
                // The loaded library below must match a CVE package so JEF-75 keeps it
                // (`libssl.so.1.1` and `openssl` both normalize to `ssl`).
                pkg_name: Some("openssl".into()),
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::LibraryLoaded {
                name: "libssl.so.1.1".into(),
            },
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert_eq!(chain.attack, CREDENTIAL_ACCESS);
    assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
    assert!(
        chain.corroborated,
        "a vuln-matched library load corroborates the entry's foothold (T1190)"
    );
    assert!(
        chain.meets_action_bar(),
        "foothold + foothold-corroboration = full bar"
    );
}

/// NEGATIVE (JEF-77): a chain with **no** foothold — an internal, non-exploitable
/// entry, the assume-breach case — is unaffected by the foothold-aware path. A library
/// load corroborates nothing, because the objective is CREDENTIAL_ACCESS and there is
/// no INITIAL_ACCESS foothold tactic to match against.
#[test]
fn library_load_does_not_corroborate_without_foothold() {
    use crate::engine::observe::{Attribution, RuntimeObservation, SecretMeta};
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

    // Internal pod (no internet exposure, no vuln image) reaching a secret via RBAC —
    // a chain that proves but carries no foothold.
    let app = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "app", "namespace": "app"},
        "spec": {
            "serviceAccountName": "app-sa",
            "containers": [{"name": "app", "image": "app:1"}]
        }
    }));
    let role: Role = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "reader", "namespace": "app"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    }))
    .unwrap();
    let binding: RoleBinding = serde_json::from_value(json!({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "reader-binding", "namespace": "app"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "app"}]
    }))
    .unwrap();

    let snap = Snapshot {
        pods: vec![app],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "api-key".into(),
        }],
        roles: vec![role],
        role_bindings: vec![binding],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "app"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::LibraryLoaded {
                name: "libssl.so.1.1".into(),
            },
        }],
        ..Default::default()
    };
    let chains = prove(&build_graph(&snap, &default_adapters()));
    let chain = chains
        .iter()
        .find(|c| c.entry.0.contains("/app") && c.objective.0 == "secret/app/api-key")
        .expect("app → identity → secret chain");
    assert_eq!(chain.foothold, None);
    assert!(
        !chain.corroborated,
        "with no foothold, a library load corroborates nothing"
    );
}

/// JEF-298: the path enumeration runs on an explicit work-stack, so a very deep linear
/// chain enumerates correctly and cannot overflow the call stack. We build a single long
/// path of ~20k proof-grade movement edges (well under the [`PATH_ENUM_BUDGET`] relaxation
/// ceiling) between non-workload endpoint nodes — non-workloads bypass the compromise gate,
/// isolating the traversal itself — and confirm exactly one simple path is found, in order,
/// not truncated. The former recursion would have descended ~20k frames deep here.
#[test]
fn deep_chain_enumerates_on_explicit_stack() {
    use super::chain::{MAX_PROVEN_PATHS, proven_paths};
    use crate::engine::graph::{
        Edge, Endpoint, Grade, Node, Protocol, Provenance, Relation, SecurityGraph,
    };
    use std::time::SystemTime;

    const DEPTH: usize = 20_000;

    let mut graph = SecurityGraph::new();
    let nodes: Vec<_> = (0..DEPTH)
        .map(|i| {
            graph.upsert_node(Node::Endpoint(Endpoint {
                address: format!("hop-{i}"),
            }))
        })
        .collect();
    for pair in nodes.windows(2) {
        graph.add_edge(
            pair[0],
            pair[1],
            Edge {
                relation: Relation::Reaches {
                    port: None,
                    protocol: Protocol::Tcp,
                },
                provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
                grade: Grade::Proof,
            },
        );
    }

    let (paths, truncated) = proven_paths(&graph, nodes[0], nodes[DEPTH - 1], MAX_PROVEN_PATHS);

    assert_eq!(paths.len(), 1, "one simple path down the linear chain");
    assert!(!truncated, "one path, well under the cap and budget");
    let path = &paths[0];
    assert_eq!(path.len(), DEPTH - 1, "every hop is enumerated in order");
    // The single path is exactly nodes[0] → nodes[1] → … → nodes[DEPTH-1], each step's
    // target the next step's source — the simple path down the chain, no node repeated.
    assert_eq!(path.first().map(|s| s.0), Some(nodes[0]));
    assert_eq!(path.last().map(|s| s.1), Some(nodes[DEPTH - 1]));
    for (i, step) in path.iter().enumerate() {
        assert_eq!(step.0, nodes[i]);
        assert_eq!(step.1, nodes[i + 1]);
    }
}

/// JEF-284: the two quarantine-reason dispositions are distinct, fixed labels — the
/// dashboard names remotely-exploitable vs actively-exploited separately (and both apart
/// from the entry-foothold quarantine).
#[test]
fn quarantine_reason_dispositions_are_distinct() {
    assert_eq!(
        QuarantineReason::RemotelyExploitable.disposition(),
        "quarantine — remotely exploitable"
    );
    assert_eq!(
        QuarantineReason::ActivelyExploited.disposition(),
        "quarantine — actively exploited"
    );
    assert_ne!(
        QuarantineReason::RemotelyExploitable.disposition(),
        QuarantineReason::ActivelyExploited.disposition()
    );
}
