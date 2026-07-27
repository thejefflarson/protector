//! JEF-320, end-to-end through the [`super::RuntimeAdapter`]: a raw `FileRead` of a
//! well-known on-host credential path attaches to the workload as a `SecretRead` with
//! [`crate::engine::graph::SecretReadSource::HostPath`], and the FP-scoping this ticket
//! relies on (container/entry context only — no bare host process) holds through the
//! real attribution-resolution pipeline, not just the classifier in isolation (see
//! `engine::observe::host_credential_class`'s own unit tests for the path-matching
//! table). Kept in its own file rather than growing `enrich/tests.rs` further (repo file-
//! size convention).

use super::*;
use crate::engine::observe::{RuntimeObservation, Snapshot};
use serde_json::json;

fn pod(value: serde_json::Value) -> Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

/// `app/web`, with a stable UID, and no Secret volume mounts — the fixture for these
/// tests (a k8s-mounted secret would already be covered by `secret_for_path`; these
/// paths are deliberately NOT under any mount).
fn web_pod_with_uid(uid: &str) -> Pod {
    pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "uid": uid},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }))
}

/// A `FileRead` of `path`, attributed to a pod UID (the eBPF agent's real attribution
/// path — the FP-scoping mechanism this ticket relies on).
fn file_read_by_uid(uid: &str, path: &str) -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_pod_uid(uid),
        source: Some("protector-agent".into()),
        observed_at_ms: None,
        node: None,
        behavior: Behavior::FileRead { path: path.into() },
    }
}

/// The `SecretRead` behaviors attached to the (single) workload in `graph`, as
/// `(secret, source)` pairs.
fn secret_reads_of(
    graph: &crate::engine::graph::SecurityGraph,
) -> Vec<(String, crate::engine::graph::SecretReadSource)> {
    graph
        .inner()
        .node_weights()
        .find_map(|n| match n {
            Node::Workload(w) => Some(
                w.runtime
                    .iter()
                    .filter_map(|o| match &o.behavior {
                        Behavior::SecretRead { secret, source } => Some((secret.clone(), *source)),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .expect("workload node exists")
}

#[test]
fn on_host_credential_read_attaches_as_secret_read_with_host_path_source() {
    // The host shadow file, read by a process inside app/web (attributed by cgroup UID —
    // the agent's real path) → a SecretRead with SecretReadSource::HostPath, corroborating
    // CredentialAccess (JEF-320). This is the ticket's core end-to-end wire.
    let snap = Snapshot {
        pods: vec![web_pod_with_uid("uid-1")],
        runtime_events: vec![file_read_by_uid("uid-1", "/etc/shadow")],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    assert_eq!(
        secret_reads_of(&graph),
        vec![(
            "/etc/shadow".to_string(),
            crate::engine::graph::SecretReadSource::HostPath
        )]
    );
}

#[test]
fn ssh_and_cloud_credential_reads_also_attach_end_to_end() {
    let snap = Snapshot {
        pods: vec![web_pod_with_uid("uid-1")],
        runtime_events: vec![
            file_read_by_uid("uid-1", "/root/.ssh/id_rsa"),
            file_read_by_uid("uid-1", "/root/.aws/credentials"),
        ],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let mut got = secret_reads_of(&graph);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![
            (
                "/root/.aws/credentials".to_string(),
                crate::engine::graph::SecretReadSource::HostPath
            ),
            (
                "/root/.ssh/id_rsa".to_string(),
                crate::engine::graph::SecretReadSource::HostPath
            ),
        ]
    );
}

#[test]
fn a_benign_file_read_is_dropped_not_a_secret_read() {
    // A read that is neither a k8s Secret mount nor a known on-host credential path is
    // dropped entirely — it must not silently attach as SOME evidence.
    let snap = Snapshot {
        pods: vec![web_pod_with_uid("uid-1")],
        runtime_events: vec![file_read_by_uid("uid-1", "/etc/hosts")],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    assert!(secret_reads_of(&graph).is_empty());
}

#[test]
fn a_credential_read_with_no_resolvable_pod_attribution_never_attaches() {
    // FP-scoping (JEF-320): a `FileRead` attributed by a pod UID the engine has never
    // observed — the shape a genuine host-system daemon's event would have, since it
    // isn't in any pod's cgroup — resolves to nothing and is dropped upstream, before the
    // host-credential classifier ever runs. No workload exists to attach it to either.
    let snap = Snapshot {
        pods: vec![web_pod_with_uid("uid-1")],
        runtime_events: vec![file_read_by_uid("uid-unknown-host-process", "/etc/shadow")],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    assert_eq!(
        secret_reads_of(&graph),
        Vec::<(String, crate::engine::graph::SecretReadSource)>::new()
    );
}
