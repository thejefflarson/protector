use super::*;
use crate::engine::observe::Snapshot;
use serde_json::json;

fn pod(value: serde_json::Value) -> Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

fn service(value: serde_json::Value) -> Service {
    serde_json::from_value(value).expect("valid Service fixture")
}

/// A snapshot with one pod (10.42.1.159) and one service (10.43.0.10) — the fixture
/// the resolution tests probe against.
fn fixture() -> Snapshot {
    Snapshot {
        pods: vec![pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "influxdb-0", "namespace": "analytics"},
            "spec": {"containers": [{"name": "influxdb", "image": "influxdb:2"}]},
            "status": {"podIP": "10.42.1.159"}
        }))],
        services: vec![service(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "influxdb", "namespace": "analytics"},
            "spec": {"clusterIP": "10.43.0.10", "clusterIPs": ["10.43.0.10"]}
        }))],
        ..Default::default()
    }
}

#[test]
fn pod_ip_resolves_to_namespace_name() {
    let index = IpIndex::from_snapshot(&fixture());
    let resolved = index.resolve("10.42.1.159").expect("pod IP is indexed");
    assert_eq!(resolved.namespace, "analytics");
    assert_eq!(resolved.name, "influxdb-0");
    assert_eq!(resolved.kind, PeerKind::Pod);
}

#[test]
fn service_cluster_ip_resolves_to_namespace_name() {
    let index = IpIndex::from_snapshot(&fixture());
    let resolved = index
        .resolve("10.43.0.10")
        .expect("service ClusterIP is indexed");
    assert_eq!(resolved.namespace, "analytics");
    assert_eq!(resolved.name, "influxdb");
    assert_eq!(resolved.kind, PeerKind::Service);
}

#[test]
fn unknown_ip_does_not_resolve() {
    let index = IpIndex::from_snapshot(&fixture());
    assert!(index.resolve("8.8.8.8").is_none());
}

#[test]
fn headless_service_clusterip_none_is_not_indexed() {
    // A headless Service carries the literal "None" — not a real address, so it must
    // not land in the index (and an empty string is skipped too).
    let snap = Snapshot {
        services: vec![service(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "headless", "namespace": "app"},
            "spec": {"clusterIP": "None", "clusterIPs": ["None"]}
        }))],
        ..Default::default()
    };
    let index = IpIndex::from_snapshot(&snap);
    assert!(index.is_empty(), "headless ClusterIP 'None' is not indexed");
    assert!(index.resolve("None").is_none());
}

#[test]
fn pod_wins_a_collision_with_a_service() {
    // Pathological: a Service and a Pod sharing an IP. The concrete Pod is the more
    // specific answer, so it wins (Pods are indexed after Services).
    let snap = Snapshot {
        pods: vec![pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns"},
            "spec": {"containers": [{"name": "c", "image": "i:1"}]},
            "status": {"podIP": "10.0.0.1"}
        }))],
        services: vec![service(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "s", "namespace": "ns"},
            "spec": {"clusterIP": "10.0.0.1"}
        }))],
        ..Default::default()
    };
    let index = IpIndex::from_snapshot(&snap);
    assert_eq!(index.resolve("10.0.0.1").unwrap().kind, PeerKind::Pod);
}
