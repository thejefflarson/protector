//! Tests for the per-node agent-liveness honesty core (JEF-308): the expected-node set from the
//! informer, and the healthy / degraded / blind / out-of-scope / quiet≠blind classification.

use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Pod;
use protector_behavior::AgentReport;
use serde_json::json;

use super::*;

/// An agent DaemonSet pod on `node`, carrying the component label the chart sets.
fn agent_pod(name: &str, node: &str) -> Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": "protector",
            "labels": {"app.kubernetes.io/component": "agent"}
        },
        "spec": {"nodeName": node, "containers": [{"name": "agent", "image": "agent:1"}]}
    }))
    .unwrap()
}

/// A NON-agent workload pod on `node` (no agent component label).
fn app_pod(name: &str, node: &str) -> Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app", "labels": {"app": "web"}},
        "spec": {"nodeName": node, "containers": [{"name": "c", "image": "web:1"}]}
    }))
    .unwrap()
}

fn report(node: &str, probes_loaded: u32, probes_total: u32, signals: u64) -> AgentReport {
    AgentReport {
        node: node.into(),
        probes_loaded,
        probes_total,
        signals_emitted: signals,
        observed_at_ms: None,
    }
}

#[test]
fn expected_set_is_where_the_agent_is_scheduled_only() {
    // The scheduler already honoured the agent's nodeSelector/tolerations (JEF-295 arm64), so the
    // expected set is exactly the agent pods' nodes. A node running only a non-agent workload
    // (an amd64 node the agent isn't scheduled on) is NOT expected — out-of-scope, not blind.
    let pods = vec![
        agent_pod("agent-a", "node-a"),
        agent_pod("agent-b", "node-b"),
        app_pod("web-1", "node-c"),
    ];
    let expected = expected_agent_nodes(&pods);
    assert!(expected.contains("node-a"));
    assert!(expected.contains("node-b"));
    assert!(
        !expected.contains("node-c"),
        "a node the agent isn't scheduled on is out-of-scope, never blind"
    );
    assert_eq!(expected.len(), 2);
}

#[test]
fn reporting_node_with_probes_loaded_is_healthy() {
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 6, 6, 9));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert_eq!(cov.expected_count(), 1);
    assert_eq!(cov.healthy_count(), 1);
    assert!(cov.blind_nodes().is_empty());
    assert!(cov.all_healthy());
    assert_eq!(cov.agent_signals(), 9);
    assert_eq!(cov.nodes[0].state, NodeState::Healthy { signals: 9 });
}

#[test]
fn quiet_node_is_healthy_not_blind() {
    // The load-bearing honesty case: a node reporting with ZERO signals but its probes loaded is
    // HEALTHY-quiet — a quiet cluster must never read as a down sensor.
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 6, 6, 0));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert!(cov.blind_nodes().is_empty(), "quiet ≠ blind");
    assert!(cov.all_healthy());
    assert_eq!(cov.nodes[0].state, NodeState::Healthy { signals: 0 });
}

#[test]
fn expected_node_not_reporting_is_blind_and_named() {
    // node-b should run the agent but no beacon arrived — blind, and named so the UX can say which.
    let expected: BTreeSet<String> = ["node-a".into(), "node-b".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 6, 6, 3));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert_eq!(cov.blind_nodes(), vec!["node-b"]);
    assert!(!cov.all_healthy());
    let b = cov.nodes.iter().find(|n| n.node == "node-b").unwrap();
    assert_eq!(
        b.state,
        NodeState::Blind {
            reason: BlindReason::NotReporting
        }
    );
}

#[test]
fn probes_failed_to_load_is_blind_despite_reporting() {
    // Ready but blind: the agent reports but attached ZERO probes.
    // Pod-Ready would read healthy; signal-flow reads it blind.
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 0, 6, 0));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert_eq!(cov.blind_nodes(), vec!["node-a"]);
    assert_eq!(
        cov.nodes[0].state,
        NodeState::Blind {
            reason: BlindReason::ProbesFailed
        }
    );
    assert!(cov.blind_node_set().contains("node-a"));
}

#[test]
fn partial_probes_are_degraded_not_blind() {
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 4, 6, 2));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert!(cov.blind_nodes().is_empty());
    assert_eq!(cov.degraded_nodes(), vec!["node-a"]);
    assert_eq!(
        cov.nodes[0].state,
        NodeState::DegradedProbes {
            loaded: 4,
            total: 6
        }
    );
}

#[test]
fn a_stale_report_prunes_and_reads_blind() {
    // A node that stopped beaconing must not keep reading healthy off a stale report — past the
    // TTL it prunes out and reads blind (freshness is correctness, ADR-0002).
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 6, 6, 5));

    // Within the window: healthy.
    let fresh =
        derive_runtime_coverage(&expected, &store.snapshot_at(t0 + Duration::from_secs(60)));
    assert!(fresh.all_healthy());
    // Past the TTL: pruned → blind (not reporting).
    let stale =
        derive_runtime_coverage(&expected, &store.snapshot_at(t0 + Duration::from_secs(121)));
    assert_eq!(stale.blind_nodes(), vec!["node-a"]);
}

#[test]
fn a_reporting_non_expected_node_is_out_of_scope_not_blind() {
    // A beacon from a node NOT in the expected set (agent running where it isn't scheduled) reads
    // out-of-scope — never blind, and it doesn't count toward the expected total.
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 6, 6, 1));
    store.record_at(t0, report("node-x", 6, 6, 1));

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0));
    assert_eq!(
        cov.expected_count(),
        1,
        "out-of-scope doesn't inflate the expected total"
    );
    assert!(cov.blind_nodes().is_empty());
    let x = cov.nodes.iter().find(|n| n.node == "node-x").unwrap();
    assert_eq!(x.state, NodeState::OutOfScope);
}

#[test]
fn the_store_is_bounded_against_a_distinct_node_flood() {
    // A bearer-holding client can't grow the store without bound by flooding distinct node names:
    // at the cap a new node evicts the stalest entry.
    let store = AgentLivenessStore::new(Duration::from_secs(300));
    let t0 = Instant::now();
    for i in 0..(AgentLivenessStore::MAX_NODES + 100) {
        store.record_at(
            t0 + Duration::from_millis(i as u64),
            report(&format!("n{i}"), 6, 6, 0),
        );
    }
    assert_eq!(
        store.snapshot_at(t0 + Duration::from_secs(1)).len(),
        AgentLivenessStore::MAX_NODES
    );
}

#[test]
fn latest_report_per_node_wins() {
    // A newer beacon supersedes an older one for the same node (blind → healthy on recovery).
    let expected: BTreeSet<String> = ["node-a".into()].into_iter().collect();
    let store = AgentLivenessStore::new(Duration::from_secs(120));
    let t0 = Instant::now();
    store.record_at(t0, report("node-a", 0, 6, 0)); // blind
    store.record_at(t0 + Duration::from_secs(1), report("node-a", 6, 6, 4)); // recovered

    let cov = derive_runtime_coverage(&expected, &store.snapshot_at(t0 + Duration::from_secs(1)));
    assert!(cov.all_healthy());
    assert_eq!(cov.agent_signals(), 4);
}
