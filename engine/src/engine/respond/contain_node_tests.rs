//! Unit coverage for [`contain_node_link`] and [`self_severance`] (ADR-0040 §4/§5's
//! proposal-surface primitives) — split into its own file since `respond::tests` is already
//! near the 1,000-line cap (CLAUDE.md).

use super::*;
use crate::engine::observe::Snapshot;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use serde_json::json;

fn scheduled_pod(
    name: &str,
    node_name: &str,
    labels: serde_json::Value,
) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app", "labels": labels},
        "spec": {
            "nodeName": node_name,
            "containers": [{"name": name, "image": format!("{name}:1")}]
        }
    }))
    .expect("valid Pod fixture")
}

fn unscheduled_pod(name: &str) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app"},
        "spec": {"containers": [{"name": name, "image": format!("{name}:1")}]}
    }))
    .expect("valid Pod fixture")
}

#[test]
fn contain_node_link_targets_the_scheduled_host_self_referentially() {
    let snap = Snapshot {
        pods: vec![scheduled_pod("victim", "node-1", json!({}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = NodeKey("workload/app/Pod/victim".into());

    let link = contain_node_link(&graph, &x).expect("victim is scheduled on node-1");
    let host = NodeKey("host/node-1".into());
    assert_eq!(link.from, host);
    assert_eq!(link.to, host);
    assert_eq!(link.relation, CONTAIN_NODE_RELATION);
    assert!(
        link.from_labels.is_empty() && link.to_labels.is_empty(),
        "a cordon acts on the node object, not a pod selector — nothing to widen"
    );
}

#[test]
fn contain_node_link_is_none_for_an_unscheduled_workload() {
    let snap = Snapshot {
        pods: vec![unscheduled_pod("pending")],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = NodeKey("workload/app/Pod/pending".into());
    assert!(contain_node_link(&graph, &x).is_none());
}

#[test]
fn contain_node_link_is_none_for_a_node_key_absent_from_the_graph() {
    let graph = crate::engine::graph::SecurityGraph::new();
    let x = NodeKey("workload/app/Pod/nonexistent".into());
    assert!(contain_node_link(&graph, &x).is_none());
}

/// ADR-0040 §5's "at most one node cordoned concurrently" rail: two co-resident
/// boundary-broken workloads must resolve to the SAME cut signature — one containment
/// proposal, never a duplicate cut per named workload.
#[test]
fn two_co_resident_workloads_collapse_onto_one_contain_node_signature() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("a", "node-1", json!({})),
            scheduled_pod("b", "node-1", json!({})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let a = contain_node_link(&graph, &NodeKey("workload/app/Pod/a".into())).unwrap();
    let b = contain_node_link(&graph, &NodeKey("workload/app/Pod/b".into())).unwrap();
    assert_eq!(cut_signature(&a), cut_signature(&b));
}

#[test]
fn self_severance_is_true_when_the_agent_daemonset_shares_the_host() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({})),
            scheduled_pod(
                "protector-agent-xyz",
                "node-1",
                json!({"app.kubernetes.io/component": "agent"}),
            ),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    assert!(self_severance(&graph, &NodeKey("host/node-1".into())));
}

#[test]
fn self_severance_is_true_when_the_engine_deployment_shares_the_host() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({})),
            scheduled_pod(
                "protector-0",
                "node-1",
                json!({"app.kubernetes.io/name": "protector"}),
            ),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    assert!(self_severance(&graph, &NodeKey("host/node-1".into())));
}

#[test]
fn self_severance_is_false_when_only_ordinary_pods_share_the_host() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({})),
            scheduled_pod("neighbor", "node-1", json!({"role": "cache"})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    assert!(!self_severance(&graph, &NodeKey("host/node-1".into())));
}

#[test]
fn self_severance_is_false_for_a_host_absent_from_the_graph() {
    let graph = crate::engine::graph::SecurityGraph::new();
    assert!(!self_severance(&graph, &NodeKey("host/nonexistent".into())));
}
