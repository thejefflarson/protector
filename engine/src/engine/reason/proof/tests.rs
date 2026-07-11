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
    use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
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
