//! ADR-0038 coverage: route-forwarded backends promote through a live controller,
//! orphan routes don't (the fail-safe direction), chains compose one further hop via
//! the bounded fixpoint, and the ADR-0012 declared annotation still wins when there
//! is no in-cluster Ingress at all. These are graph-level tests — several drive the
//! full `reason::proof::prove` walk — precisely to demonstrate the promoted fact
//! reuses the *existing* entry lane with no new evidence class or graph relation, as
//! ADR-0038 requires. None of them touch `reason::proof`'s own test files.

use super::*;
use crate::engine::graph::{Provenance, Severity, Vulnerability};
use crate::engine::observe::ImageVulnerabilities;
use crate::engine::observe::adapter::test_support::pod;
use crate::engine::reason::proof::prove;
use k8s_openapi::api::core::v1::Service;
use serde_json::{Value, json};
use std::time::SystemTime;

fn service(value: Value) -> Service {
    serde_json::from_value(value).expect("valid Service fixture")
}

fn ingress(value: Value) -> Ingress {
    serde_json::from_value(value).expect("valid Ingress fixture")
}

fn ingress_class(value: Value) -> IngressClass {
    serde_json::from_value(value).expect("valid IngressClass fixture")
}

/// A LoadBalancer-fronted controller pod, live at `ip` for `class_name`
/// (controller identity `controller`), plus the `IngressClass` object it serves.
fn live_controller(
    namespace: &str,
    class_name: &str,
    controller: &str,
    ip: &str,
) -> (Service, Vec<Value>) {
    let svc = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": format!("{class_name}-controller"), "namespace": namespace},
        "spec": {"type": "LoadBalancer", "selector": {"app": format!("{class_name}-controller")}},
        "status": {"loadBalancer": {"ingress": [{"ip": ip}]}}
    }));
    let controller_pod = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": format!("{class_name}-controller-pod"), "namespace": namespace,
            "labels": {"app": format!("{class_name}-controller")}
        },
        "spec": {"containers": [{"name": "c", "image": "controller:1"}]}
    });
    let class = json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
        "metadata": {"name": class_name},
        "spec": {"controller": controller}
    });
    (svc, vec![controller_pod, class])
}

fn workload_exposure(graph: &SecurityGraph, namespace: &str, name: &str) -> Exposure {
    match graph.node(
        graph
            .index_of(&workload_node(namespace, name).key())
            .unwrap(),
    ) {
        Some(Node::Workload(w)) => w.exposure,
        other => panic!("expected a Workload node, got {other:?}"),
    }
}

/// A route-forwarded backend of a live internet-exposed controller is promoted to
/// `Exposure::Internet` and — carrying a critical CVE — proves an EXPLOIT_PUBLIC_FACING
/// foothold, exactly the existing edge-CVE entry lane (ADR-0038's whole point: zero new
/// evidence class, zero new prompt vocabulary).
#[test]
fn route_forwarded_backend_of_live_controller_becomes_a_proven_entry() {
    use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;

    let (controller_svc, controller_extras) =
        live_controller("edge", "nginx", "k8s.io/ingress-nginx", "203.0.113.10");
    let web_ingress = ingress(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "web-ingress", "namespace": "app"},
        "spec": {
            "ingressClassName": "nginx",
            "rules": [{"host": "web.example.com", "http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "web-svc", "port": {"number": 80}}}}
            ]}}]
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.10"}]}}
    }));
    let web_svc = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-svc", "namespace": "app"},
        "spec": {"type": "ClusterIP", "selector": {"app": "web"}}
    }));
    // Mounts a secret directly, so proving has a recognized objective to reach —
    // mirrors `reason::proof`'s own `proves_foothold_when_exposed_and_exploitable`
    // fixture shape.
    let web_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]
        }
    }));

    let snap = Snapshot {
        pods: vec![pod(controller_extras[0].clone()), web_pod],
        services: vec![controller_svc, web_svc],
        ingresses: vec![web_ingress],
        ingress_classes: vec![ingress_class(controller_extras[1].clone())],
        secrets: vec![crate::engine::observe::SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-1111".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: None,
                sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let graph = build_graph(&snap, &default_adapters());
    assert_eq!(workload_exposure(&graph, "app", "web"), Exposure::Internet);

    let chains = prove(&graph);
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web")
        .expect("route-forwarded backend is a proven entry");
    assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
}

/// An Ingress with no live internet-exposed controller does NOT promote its
/// backend — the ADR-0038 fail-safe (under-promote) direction. Covers both orphan
/// shapes: a class that doesn't resolve, and a resolvable class whose controller
/// never actually claimed this Ingress (no matching live address).
#[test]
fn orphan_ingress_does_not_promote() {
    let unresolved_class = ingress(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "typo-ingress", "namespace": "app"},
        "spec": {
            "ingressClassName": "does-not-exist",
            "rules": [{"http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "orphan-a-svc", "port": {"number": 80}}}}
            ]}}]
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.99"}]}}
    }));
    let not_live = ingress(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "unclaimed-ingress", "namespace": "app"},
        "spec": {
            "ingressClassName": "nginx",
            "rules": [{"http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "orphan-b-svc", "port": {"number": 80}}}}
            ]}}]
        }
        // No status.loadBalancer at all: the controller has never actually served it.
    }));
    let (controller_svc, controller_extras) =
        live_controller("edge", "nginx", "k8s.io/ingress-nginx", "203.0.113.10");

    let backend = |name: &str, role: &str| {
        (
            service(json!({
                "apiVersion": "v1", "kind": "Service",
                "metadata": {"name": format!("{role}-svc"), "namespace": "app"},
                "spec": {"type": "ClusterIP", "selector": {"app": role}}
            })),
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": "app", "labels": {"app": role}},
                "spec": {"containers": [{"name": "c", "image": "x:1"}]}
            })),
        )
    };
    let (svc_a, pod_a) = backend("orphan-a", "orphan-a");
    let (svc_b, pod_b) = backend("orphan-b", "orphan-b");

    let snap = Snapshot {
        pods: vec![pod(controller_extras[0].clone()), pod_a, pod_b],
        services: vec![controller_svc, svc_a, svc_b],
        ingresses: vec![unresolved_class, not_live],
        ingress_classes: vec![ingress_class(controller_extras[1].clone())],
        ..Default::default()
    };

    // Each has an ordinary ClusterIP-selecting Service, so base ExposureAdapter marks
    // them ClusterExposed — the assertion is that they stay BELOW Internet (never
    // promoted), not that they're fully unexposed.
    let graph = build_graph(&snap, &default_adapters());
    assert_eq!(
        workload_exposure(&graph, "app", "orphan-a"),
        Exposure::ClusterExposed
    );
    assert_eq!(
        workload_exposure(&graph, "app", "orphan-b"),
        Exposure::ClusterExposed
    );
}

/// A backend promoted to `Exposure::Internet` by one route can itself anchor a
/// FURTHER route it serves ("chains compose", ADR-0038) — the bounded fixpoint
/// re-checks live-controller status against the graph's current exposure facts, not
/// just the facts ExposureAdapter computed before this adapter ran. `gateway-svc`'s
/// `status.loadBalancer` is set here purely to model "gateway now also routes
/// traffic on this address" for the test — the mechanism under test is the
/// fixpoint's re-derivation, not a claim about which Service types get such status
/// in a real cluster.
#[test]
fn chains_compose_one_further_hop() {
    let (outer_svc, outer_extras) =
        live_controller("edge", "outer", "vendor/outer", "198.51.100.1");
    let outer_ingress = ingress(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "outer-ingress", "namespace": "edge"},
        "spec": {
            "ingressClassName": "outer",
            "rules": [{"http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "gateway-svc", "port": {"number": 80}}}}
            ]}}]
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.1"}]}}
    }));
    // Not internet-exposed on its own (ClusterIP) — only the outer route promotes it.
    let gateway_svc = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "gateway-svc", "namespace": "edge"},
        "spec": {"type": "ClusterIP", "selector": {"app": "gateway"}},
        "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.9"}]}}
    }));
    let gateway_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "gateway", "namespace": "edge", "labels": {"app": "gateway"}},
        "spec": {"containers": [{"name": "c", "image": "gateway:1"}]}
    }));

    let inner_class = ingress_class(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
        "metadata": {"name": "inner"},
        "spec": {"controller": "vendor/inner"}
    }));
    let inner_ingress = ingress(json!({
        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
        "metadata": {"name": "inner-ingress", "namespace": "edge"},
        "spec": {
            "ingressClassName": "inner",
            "rules": [{"http": {"paths": [
                {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "app-svc", "port": {"number": 80}}}}
            ]}}]
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.9"}]}}
    }));
    let app_svc = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "app-svc", "namespace": "edge"},
        "spec": {"type": "ClusterIP", "selector": {"app": "inner-app"}}
    }));
    let app_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "inner-app", "namespace": "edge", "labels": {"app": "inner-app"}},
        "spec": {"containers": [{"name": "c", "image": "app:1"}]}
    }));

    let snap = Snapshot {
        pods: vec![pod(outer_extras[0].clone()), gateway_pod, app_pod],
        services: vec![outer_svc, gateway_svc, app_svc],
        ingresses: vec![outer_ingress, inner_ingress],
        ingress_classes: vec![ingress_class(outer_extras[1].clone()), inner_class],
        ..Default::default()
    };

    let graph = build_graph(&snap, &default_adapters());
    assert_eq!(
        workload_exposure(&graph, "edge", "gateway"),
        Exposure::Internet
    );
    // The second hop only promotes because the fixpoint re-checked gateway's
    // freshly-promoted exposure — proving the chain actually composed.
    assert_eq!(
        workload_exposure(&graph, "edge", "inner-app"),
        Exposure::Internet
    );
}

/// With no in-cluster Ingress at all, the ADR-0012 off-cluster declaration (e.g.
/// cloudflared) is untouched — this adapter contributes nothing and never overrides
/// or interferes with the declared annotation.
#[test]
fn cloudflared_annotation_still_wins_with_no_in_cluster_ingress() {
    let tunnel_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "tunneled", "namespace": "app", "labels": {"app": "tunneled"}},
        "spec": {"containers": [{"name": "c", "image": "tunneled:1"}]}
    }));
    let tunnel_svc = service(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {
            "name": "tunneled-svc", "namespace": "app",
            "annotations": {"protector.jeffl.es/exposure": "internet"}
        },
        "spec": {"type": "ClusterIP", "selector": {"app": "tunneled"}}
    }));

    let snap = Snapshot {
        pods: vec![tunnel_pod],
        services: vec![tunnel_svc],
        ..Default::default()
    };

    let graph = build_graph(&snap, &default_adapters());
    assert_eq!(
        workload_exposure(&graph, "app", "tunneled"),
        Exposure::Internet
    );
}

/// A regression for the RBAC/API gap `observe::ingress_availability` degrades
/// through: when the Ingress/IngressClass watch is Forbidden or the API is absent,
/// `run_watch`/`Snapshot::observe` degrade to an empty `ingresses`/`ingress_classes`
/// pair (never abort the snapshot). At the graph layer that's indistinguishable from
/// a cluster with no Ingress objects at all — this proves an entirely unrelated,
/// pre-existing structural chain (a plain workload mounting a secret directly, no
/// exposure/Ingress involved whatsoever) still proves cleanly through `build_graph`
/// + `prove` with that empty pair, exactly the assertion the e2e regression checked.
#[test]
fn degraded_ingress_availability_does_not_disturb_an_unrelated_structural_chain() {
    let web_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]
        }
    }));
    let snap = Snapshot {
        pods: vec![web_pod],
        secrets: vec![crate::engine::observe::SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        // The exact state degraded observation produces: no Ingress data at all.
        ingresses: Vec::new(),
        ingress_classes: Vec::new(),
        ..Default::default()
    };

    let graph = build_graph(&snap, &default_adapters());
    let chains = prove(&graph);
    assert!(
        chains
            .iter()
            .any(|c| c.entry.0 == "workload/app/Pod/web"
                && c.objective.0 == "secret/app/session-key"),
        "web → session-key must still prove with a degraded/empty Ingress snapshot"
    );
}
