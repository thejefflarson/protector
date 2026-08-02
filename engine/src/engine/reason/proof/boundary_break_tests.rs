//! Unit coverage for [`boundary_break`] (ADR-0040 §3): one positive/negative pair per
//! trigger, plus the negatives the ADR calls out explicitly — uid 0 alone is not a
//! break, an `EscapesTo` edge alone is not a break, and a single co-resident pod does
//! not trigger the multi-pod-spread shape.

use std::collections::BTreeSet;

use super::*;
use crate::engine::graph::{Behavior, NodeKey, SecretReadSource};
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::{Attribution, RuntimeObservation, Snapshot};
use serde_json::{Value, json};

fn pod(value: Value) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

fn signal(namespace: &str, name: &str, behavior: Behavior) -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_namespaced_name(namespace, name),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior,
    }
}

fn plain_pod(
    name: &str,
    node_name: Option<&str>,
    host_pid: bool,
) -> k8s_openapi::api::core::v1::Pod {
    let mut spec = json!({"containers": [{"name": name, "image": format!("{name}:1")}]});
    if let Some(n) = node_name {
        spec["nodeName"] = json!(n);
    }
    if host_pid {
        spec["hostPID"] = json!(true);
    }
    pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app"},
        "spec": spec
    }))
}

fn workload_index(graph: &crate::engine::graph::SecurityGraph, name: &str) -> NodeIndex {
    graph
        .index_of(&NodeKey::workload("app", "Pod", name))
        .expect("workload node exists")
}

// --- (a) host-path SecretRead ---

#[test]
fn host_path_secret_read_is_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", None, false)],
        runtime_events: vec![signal(
            "app",
            "victim",
            Behavior::SecretRead {
                secret: "/etc/shadow".into(),
                source: SecretReadSource::HostPath,
            },
        )],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(boundary_break(&graph, x, &BTreeSet::new()));
}

#[test]
fn a_mounted_secret_read_is_not_a_break() {
    // A k8s-Secret mount read stays inside the pod boundary — only the on-HOST
    // credential-path class (SecretReadSource::HostPath) counts.
    let snap = Snapshot {
        pods: vec![plain_pod("victim", None, false)],
        runtime_events: vec![signal(
            "app",
            "victim",
            Behavior::SecretRead {
                secret: "app-secret".into(),
                source: SecretReadSource::Mounted,
            },
        )],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(!boundary_break(&graph, x, &BTreeSet::new()));
}

// --- (b) root PrivilegeChange AND an EscapesTo edge ---

#[test]
fn root_escalation_together_with_an_escape_edge_is_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", Some("node-1"), true)], // hostPID ⇒ EscapesTo
        runtime_events: vec![signal(
            "app",
            "victim",
            Behavior::PrivilegeChange {
                from_uid: 1000,
                to_uid: 0,
            },
        )],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(boundary_break(&graph, x, &BTreeSet::new()));
}

#[test]
fn root_escalation_alone_without_an_escape_edge_is_not_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", Some("node-1"), false)], // no escape primitive
        runtime_events: vec![signal(
            "app",
            "victim",
            Behavior::PrivilegeChange {
                from_uid: 1000,
                to_uid: 0,
            },
        )],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(
        !boundary_break(&graph, x, &BTreeSet::new()),
        "uid 0 alone must not be a break — ADR-0040 §3(b)"
    );
}

#[test]
fn an_escape_edge_alone_without_root_escalation_is_not_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", Some("node-1"), true)], // hostPID, no PrivilegeChange
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(
        !boundary_break(&graph, x, &BTreeSet::new()),
        "an EscapesTo edge alone must not be a break — ADR-0040 §3(b)"
    );
}

// --- (c) PtraceAttach / ModuleLoad ---

#[test]
fn ptrace_attach_is_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", None, false)],
        runtime_events: vec![signal("app", "victim", Behavior::PtraceAttach)],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(boundary_break(&graph, x, &BTreeSet::new()));
}

#[test]
fn module_load_is_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", None, false)],
        runtime_events: vec![signal("app", "victim", Behavior::ModuleLoad)],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(boundary_break(&graph, x, &BTreeSet::new()));
}

#[test]
fn an_ordinary_exec_is_not_a_break() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", None, false)],
        runtime_events: vec![signal(
            "app",
            "victim",
            Behavior::ProcessExec {
                path: "/usr/bin/app".into(),
                exe_anon_inode: false,
            },
        )],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(!boundary_break(&graph, x, &BTreeSet::new()));
}

// --- (d) ≥2 co-resident pods, both decisive-attack AND actively exploited ---

fn co_resident_pods(node_name: &str) -> Snapshot {
    Snapshot {
        pods: vec![
            plain_pod("a", Some(node_name), false),
            plain_pod("b", Some(node_name), false),
        ],
        ..Default::default()
    }
}

fn attack_alert(namespace: &str, name: &str) -> RuntimeObservation {
    signal(
        namespace,
        name,
        Behavior::Alert {
            rule: "Terminal shell in container".into(),
        },
    )
}

#[test]
fn two_co_resident_confirmed_and_exploited_pods_is_a_break() {
    let mut snap = co_resident_pods("node-1");
    snap.runtime_events = vec![attack_alert("app", "a"), attack_alert("app", "b")];
    let graph = build_graph(&snap, &default_adapters());
    let a = workload_index(&graph, "a");
    let model_attack: BTreeSet<NodeKey> = [
        NodeKey::workload("app", "Pod", "a"),
        NodeKey::workload("app", "Pod", "b"),
    ]
    .into_iter()
    .collect();
    assert!(boundary_break(&graph, a, &model_attack));
}

#[test]
fn a_single_co_resident_pod_does_not_trigger_multi_pod_spread() {
    // Only `a` is compromised — `b` shares the host but carries neither a model
    // attack call nor live evidence.
    let mut snap = co_resident_pods("node-1");
    snap.runtime_events = vec![attack_alert("app", "a")];
    let graph = build_graph(&snap, &default_adapters());
    let a = workload_index(&graph, "a");
    let model_attack: BTreeSet<NodeKey> =
        [NodeKey::workload("app", "Pod", "a")].into_iter().collect();
    assert!(
        !boundary_break(&graph, a, &model_attack),
        "a single co-resident pod must not trigger trigger (d) — ADR-0040 §3(d)"
    );
}

#[test]
fn both_co_resident_pods_model_named_but_neither_actively_exploited_is_not_a_break() {
    let snap = co_resident_pods("node-1"); // no runtime events at all
    let graph = build_graph(&snap, &default_adapters());
    let a = workload_index(&graph, "a");
    let model_attack: BTreeSet<NodeKey> = [
        NodeKey::workload("app", "Pod", "a"),
        NodeKey::workload("app", "Pod", "b"),
    ]
    .into_iter()
    .collect();
    assert!(
        !boundary_break(&graph, a, &model_attack),
        "a decisive model attack call without live evidence never satisfies trigger (d)"
    );
}

#[test]
fn both_co_resident_pods_actively_exploited_but_neither_model_named_is_not_a_break() {
    let mut snap = co_resident_pods("node-1");
    snap.runtime_events = vec![attack_alert("app", "a"), attack_alert("app", "b")];
    let graph = build_graph(&snap, &default_adapters());
    let a = workload_index(&graph, "a");
    assert!(
        !boundary_break(&graph, a, &BTreeSet::new()),
        "live evidence without a decisive model attack call never satisfies trigger (d)"
    );
}

#[test]
fn an_unscheduled_workload_has_no_host_to_share_and_cannot_trigger_multi_pod_spread() {
    let snap = Snapshot {
        pods: vec![plain_pod("a", None, false)], // never scheduled — no ScheduledOn edge
        runtime_events: vec![attack_alert("app", "a")],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let a = workload_index(&graph, "a");
    let model_attack: BTreeSet<NodeKey> =
        [NodeKey::workload("app", "Pod", "a")].into_iter().collect();
    assert!(!boundary_break(&graph, a, &model_attack));
}

#[test]
fn a_clean_workload_never_breaks_the_boundary() {
    let snap = Snapshot {
        pods: vec![plain_pod("victim", Some("node-1"), false)],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let x = workload_index(&graph, "victim");
    assert!(!boundary_break(&graph, x, &BTreeSet::new()));
}
