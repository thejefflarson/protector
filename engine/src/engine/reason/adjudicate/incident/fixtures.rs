//! Shared test fixtures for the `incident` module's unit tests (test-only). Builds proven
//! chains + their backing graph with the SAME shapes and helpers
//! `reason::proof::pivot_quarantine_tests` and `respond::tests` use, so these tests
//! exercise the exact same resolver inputs `respond::MitigationLedger::reconcile` does —
//! no bespoke graph-building path that could drift from what `menu::build_menu` actually
//! resolves in production.

use serde_json::{Value, json};

use crate::engine::graph::{Behavior, NodeKey, SecurityGraph};
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::health::HealthReport;
use crate::engine::observe::{Attribution, ImageVulnerabilities, RuntimeObservation, Snapshot};
use crate::engine::reason::proof::{ProvenChain, prove};

pub(super) fn pod(value: Value) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

pub(super) fn service(value: Value) -> k8s_openapi::api::core::v1::Service {
    serde_json::from_value(value).expect("valid Service fixture")
}

pub(super) fn netpol(value: Value) -> k8s_openapi::api::networking::v1::NetworkPolicy {
    serde_json::from_value(value).expect("valid NetworkPolicy fixture")
}

/// One critical CVE on `image` — the `compromisable()` precondition (satisfied
/// by *presence* alone, no runtime signal attached, no reachability-tag guarantee).
pub(super) fn critical_image(image: &str) -> ImageVulnerabilities {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use std::time::SystemTime;
    ImageVulnerabilities {
        image: image.into(),
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2026-0609".into(),
            severity: Severity::Critical,
            exploited_in_wild: false,
            epss: None,
            sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
            ..Default::default()
        }],
    }
}

/// The e2e pivot shape (shared with `reason::proof::pivot_quarantine_tests`): an
/// internet-exposed `web` entry reaches a `store` pivot pod over an allowed
/// NetworkPolicy hop. `store` mounts a secret (the objective) and runs a critical-CVE
/// image, so it qualifies as a `RemotelyExploitable` quarantine CANDIDATE
/// (the entry-foothold lane's static-CVE-*presence* bar) even with zero runtime evidence — exactly the
/// grounding gap [`super::guards::guard_containment_grounding`] exists to catch (its CVE
/// is real but never reachability-tagged `loaded-at-runtime`, so its own evidence block
/// shows nothing to cite).
///
/// `store_labels`: whether `store` carries a Pod label. An unlabeled pivot is an
/// evidence-bearing but UNCONTAINABLE node (`quarantine_workload_link` declines,
/// ADR-0022) — the target's NetworkPolicy selector is `{}` (matches all pods in the
/// namespace) regardless, so reachability is unaffected by the toggle.
pub(super) fn web_reaches_pivot_store(
    runtime: Vec<RuntimeObservation>,
    store_labels: bool,
) -> (SecurityGraph, Vec<ProvenChain>) {
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
    let store_metadata = if store_labels {
        json!({"name": "store", "namespace": "app", "labels": {"role": "store"}})
    } else {
        json!({"name": "store", "namespace": "app"})
    };
    let store = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": store_metadata,
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
            "podSelector": {},
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

pub(super) fn web_to_store_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/store-creds")
        .expect("web → store → secret chain")
}

pub(super) fn entry_key() -> NodeKey {
    NodeKey("workload/app/Pod/web".into())
}

pub(super) fn store_key() -> NodeKey {
    NodeKey("workload/app/Pod/store".into())
}

pub(super) fn empty_health() -> HealthReport {
    HealthReport::default()
}

/// A live alarming signal on `store` (upgrades it from `RemotelyExploitable` to
/// `ActivelyExploited`/309) — genuinely GROUNDED evidence (a real behavior in
/// its own block), the positive contrast to the CVE-presence-alone case.
pub(super) fn store_live_signal() -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "store"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: Behavior::FileWrite {
            path: "/usr/bin/dropper".into(),
        },
    }
}

/// A chain whose entry is INTERNAL-only (no internet-facing Service) with a direct RBAC
/// read on the objective secret: `containment_for` finds no additive-live+reversible
/// rung (RBAC is subtractive, and rung 2 requires `is_breach_relevant()`), so its ONLY
/// containment is the durable-fix fallback (`RevokeRbacGrant`) — the entry-uncontainable
/// menu shape [`super::menu::build_menu`] must aggregate rather than offer as selectable.
pub(super) fn internal_only_rbac_chain() -> (SecurityGraph, Vec<ProvenChain>) {
    use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

    let app = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "internal-app", "namespace": "edge", "labels": {"app": "internal-app"}},
        "spec": {
            "serviceAccountName": "internal-sa",
            "containers": [{"name": "c", "image": "internal:1"}]
        }
    }));
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
        "subjects": [{"kind": "ServiceAccount", "name": "internal-sa", "namespace": "edge"}]
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![app],
        roles: vec![role],
        role_bindings: vec![binding],
        secrets: vec![crate::engine::observe::SecretMeta {
            namespace: "edge".into(),
            name: "api-key".into(),
        }],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let chains = prove(&graph);
    (graph, chains)
}

pub(super) fn internal_rbac_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/edge/Pod/internal-app")
        .expect("internal-app RBAC chain")
}

/// A DIRECT breach chain (mirrors `respond::tests::direct_mount_internet_snapshot`): an
/// internet-facing pod that itself mounts the secret — no `reaches` edge exists, so the
/// only rung `containment_for` can reach is the ENTRY QUARANTINE (rung 2), never the
/// surgical edge-cut (rung 1). The positive contrast to the pivot fixture above, whose
/// `reaches` edge stays the narrower surgical cut.
pub(super) fn direct_mount_entry_chain() -> (SecurityGraph, Vec<ProvenChain>) {
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "argocd-server", "namespace": "edge", "labels": {"app": "argocd-server"}},
        "spec": {"containers": [{
            "name": "c", "image": "argo:1",
            "envFrom": [{"secretRef": {"name": "repo-creds"}}]
        }]}
    }));
    let lb = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "argocd-server-lb", "namespace": "edge"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "argocd-server"}}
    }));
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let chains = prove(&graph);
    (graph, chains)
}

pub(super) fn direct_mount_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/edge/Pod/argocd-server")
        .expect("argocd-server direct-mount chain")
}
