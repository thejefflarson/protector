use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{Pod, Service};
use serde_json::json;

use super::{GRACE_TTL, PeerResolutionMemo};
use crate::engine::observe::Snapshot;
use crate::engine::observe::ip_index::IpIndex;

fn pod(value: serde_json::Value) -> Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

fn service(value: serde_json::Value) -> Service {
    serde_json::from_value(value).expect("valid Service fixture")
}

/// A snapshot with one pod (10.42.1.159) and one service (10.43.0.10) — the same fixture
/// the pure index tests use, so the memo's HIT behavior is checked against known objects.
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

/// Resolve a single peer through a fresh memo (no prior state) — the memo behaves exactly
/// like the pure per-pass resolution for every case that isn't a grace-bridged miss.
fn resolve_fresh(index: &IpIndex, peer: &str, internet: bool) -> String {
    PeerResolutionMemo::new().resolve_peer(index, peer, internet, Instant::now())
}

// --- The pure per-pass resolution behaviors (memo with no prior state) -----------------

#[test]
fn rewrites_a_pod_peer_with_raw_ip_kept_for_forensics() {
    let index = IpIndex::from_snapshot(&fixture());
    assert_eq!(
        resolve_fresh(&index, "10.42.1.159:8086", false),
        "analytics/influxdb-0:8086 (10.42.1.159)"
    );
}

#[test]
fn rewrites_a_service_cluster_ip() {
    let index = IpIndex::from_snapshot(&fixture());
    assert_eq!(
        resolve_fresh(&index, "10.43.0.10:8086", false),
        "analytics/influxdb:8086 (10.43.0.10)"
    );
}

#[test]
fn leaves_an_unknown_ip_raw() {
    // An unresolvable IP with no prior resolution must stay EXACTLY raw — never guess.
    let index = IpIndex::from_snapshot(&fixture());
    assert_eq!(
        resolve_fresh(&index, "10.99.0.1:443", false),
        "10.99.0.1:443"
    );
}

#[test]
fn leaves_internet_peers_raw() {
    let index = IpIndex::from_snapshot(&fixture());
    // Even an IP that *happens* to be indexed isn't rewritten when flagged internet.
    assert_eq!(
        resolve_fresh(&index, "10.42.1.159:8086", true),
        "10.42.1.159:8086"
    );
    assert_eq!(resolve_fresh(&index, "1.2.3.4:443", true), "1.2.3.4:443");
}

#[test]
fn leaves_a_non_ip_port_peer_untouched() {
    let index = IpIndex::from_snapshot(&fixture());
    assert_eq!(resolve_fresh(&index, "just-a-host", false), "just-a-host");
    assert_eq!(resolve_fresh(&index, "10.42.1.159", false), "10.42.1.159");
}

#[test]
fn ipv6_bracketed_peer_resolves() {
    let snap = Snapshot {
        pods: vec![pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web-0", "namespace": "app"},
            "spec": {"containers": [{"name": "web", "image": "web:1"}]},
            "status": {"podIP": "fd00::1", "podIPs": [{"ip": "fd00::1"}]}
        }))],
        ..Default::default()
    };
    let index = IpIndex::from_snapshot(&snap);
    assert_eq!(
        resolve_fresh(&index, "[fd00::1]:5432", false),
        "app/web-0:5432 (fd00::1)"
    );
}

// --- JEF-375: stable rendering across a transient informer miss ------------------------

#[test]
fn transient_index_miss_reuses_last_known_resolution() {
    // The bug: the SAME cluster peer flips between passes because the informer index
    // transiently misses the pod and the resolver drops to raw IP. The memo must keep
    // the rendering identical across the miss (no name<->IP flip, no prompt-hash churn).
    let mut memo = PeerResolutionMemo::new();
    let now = Instant::now();

    // Pass 1: the pod IS in the informer index — resolves to the name and is memoized.
    let hit = IpIndex::from_snapshot(&fixture());
    let first = memo.resolve_peer(&hit, "10.42.1.159:8086", false, now);
    assert_eq!(first, "analytics/influxdb-0:8086 (10.42.1.159)");

    // Pass 2: the informer transiently MISSES the pod (empty index this pass). Without
    // the memo this would drop to raw "10.42.1.159:8086"; with it, the SAME token holds.
    let miss = IpIndex::default();
    let second = memo.resolve_peer(
        &miss,
        "10.42.1.159:8086",
        false,
        now + Duration::from_secs(5),
    );
    assert_eq!(
        second, first,
        "a transient index miss must not flip a known cluster peer's rendering"
    );
}

#[test]
fn a_never_resolved_peer_stays_raw_on_a_miss() {
    // A genuinely NEW peer the index has never resolved must render raw — the memo never
    // fabricates a name for an IP it hasn't seen resolved (ticket non-goal: new peers
    // must still appear and re-judge legitimately).
    let mut memo = PeerResolutionMemo::new();
    let empty = IpIndex::default();
    assert_eq!(
        memo.resolve_peer(&empty, "10.42.9.9:8443", false, Instant::now()),
        "10.42.9.9:8443"
    );
}

#[test]
fn resolution_reverts_to_raw_after_the_grace_window() {
    // A truly departed peer (index keeps missing past the grace TTL) reverts to raw, so
    // the memo can't pin a stale name forever.
    let mut memo = PeerResolutionMemo::new();
    let t0 = Instant::now();
    let hit = IpIndex::from_snapshot(&fixture());
    assert_eq!(
        memo.resolve_peer(&hit, "10.42.1.159:8086", false, t0),
        "analytics/influxdb-0:8086 (10.42.1.159)"
    );

    let miss = IpIndex::default();
    // Just past the grace window → the memo no longer bridges; peer renders raw again.
    let expired = t0 + GRACE_TTL + Duration::from_secs(1);
    assert_eq!(
        memo.resolve_peer(&miss, "10.42.1.159:8086", false, expired),
        "10.42.1.159:8086"
    );
}

#[test]
fn a_reused_ip_re_resolves_to_the_new_object() {
    // If an IP is reused by a different object, an index hit overwrites the memo — the
    // memo always reflects the freshest confirmed resolution, never a stale one.
    let mut memo = PeerResolutionMemo::new();
    let now = Instant::now();
    let first = IpIndex::from_snapshot(&fixture());
    assert_eq!(
        memo.resolve_peer(&first, "10.42.1.159:8086", false, now),
        "analytics/influxdb-0:8086 (10.42.1.159)"
    );

    // Same IP now belongs to a different pod.
    let reassigned = Snapshot {
        pods: vec![pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web-7", "namespace": "frontend"},
            "spec": {"containers": [{"name": "web", "image": "web:1"}]},
            "status": {"podIP": "10.42.1.159"}
        }))],
        ..Default::default()
    };
    let second = IpIndex::from_snapshot(&reassigned);
    assert_eq!(
        memo.resolve_peer(
            &second,
            "10.42.1.159:8086",
            false,
            now + Duration::from_secs(1)
        ),
        "frontend/web-7:8086 (10.42.1.159)"
    );
}

#[test]
fn prune_drops_only_entries_past_the_grace_window() {
    let mut memo = PeerResolutionMemo::new();
    let t0 = Instant::now();
    let hit = IpIndex::from_snapshot(&fixture());
    memo.resolve_peer(&hit, "10.42.1.159:8086", false, t0);

    // Prune within the window keeps the entry (a later miss still bridges).
    memo.prune(t0 + Duration::from_secs(10));
    let miss = IpIndex::default();
    assert_eq!(
        memo.resolve_peer(
            &miss,
            "10.42.1.159:8086",
            false,
            t0 + Duration::from_secs(11)
        ),
        "analytics/influxdb-0:8086 (10.42.1.159)"
    );

    // Prune past the window drops it → a later miss falls back to raw.
    memo.prune(t0 + GRACE_TTL + Duration::from_secs(1));
    assert_eq!(
        memo.resolve_peer(
            &miss,
            "10.42.1.159:8086",
            false,
            t0 + GRACE_TTL + Duration::from_secs(2)
        ),
        "10.42.1.159:8086"
    );
}
