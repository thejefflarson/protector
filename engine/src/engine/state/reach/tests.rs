//! Unit tests for the adversary-reach annotation (ADR-0040). The judge-prompt-absence
//! regression lives with the adjudicator's own tests
//! (`reason::adjudicate::tests::reach_absence`), not here — this file only covers the
//! annotation's own computation and rendering.

use std::time::SystemTime;

use super::*;
use crate::engine::graph::{
    Capability, Edge, Exposure, Node, Protocol, Provenance, Scope, SecretRef, SecurityGraph,
    Workload,
};
use crate::engine::reason::proof::prove;

fn edge(relation: Relation) -> Edge {
    Edge {
        relation,
        provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
    }
}

fn workload(ns: &str, name: &str, persistent: bool) -> Node {
    Node::Workload(Workload {
        namespace: ns.into(),
        name: name.into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internet,
        runtime: Vec::new(),
        persistent,
        misconfigs: vec![],
        rbac_findings: vec![],
    })
}

// ---- SecretPurpose::infer ---------------------------------------------------------------

#[test]
fn secret_purpose_infers_each_closed_vocabulary_category_from_name_heuristics() {
    assert_eq!(
        SecretPurpose::infer("argocd-token-abc12"),
        SecretPurpose::ServiceAccountToken
    );
    assert_eq!(
        SecretPurpose::infer("wildcard-tls"),
        SecretPurpose::TlsPrivateKey
    );
    assert_eq!(SecretPurpose::infer("regcred"), SecretPurpose::RegistryPull);
    assert_eq!(
        SecretPurpose::infer("aws-credentials"),
        SecretPurpose::CloudProviderCredential
    );
    assert_eq!(
        SecretPurpose::infer("db-password"),
        SecretPurpose::DatabaseCredential
    );
    assert_eq!(
        SecretPurpose::infer("my-app-config"),
        SecretPurpose::GenericOpaque
    );
}

// ---- ReachAnnotation::for_entry ----------------------------------------------------------

/// A graph with one entry that directly mounts a database-credential secret and can reach a
/// persistent data-store workload, a dangerous RBAC capability, and the internet egress
/// endpoint — one of each of the three reach dimensions ADR-0040 names.
fn full_reach_graph() -> (SecurityGraph, NodeKey) {
    let mut g = SecurityGraph::new();
    let entry = workload("app", "web", false);
    let entry_key = entry.key();
    let e = g.upsert_node(entry);

    let secret = g.upsert_node(Node::Secret(SecretRef {
        namespace: "app".into(),
        name: "db-password".into(),
    }));
    g.add_edge(e, secret, edge(Relation::CanRead));

    let store = workload("app", "cache", true);
    let store_idx = g.upsert_node(store);
    g.add_edge(
        e,
        store_idx,
        edge(Relation::Reaches {
            port: Some(6379),
            protocol: Protocol::Tcp,
        }),
    );

    let cap = g.upsert_node(Node::Capability(Capability {
        verb: "create".into(),
        resource: "pods".into(),
        scope: Scope::Cluster,
    }));
    g.add_edge(
        e,
        cap,
        edge(Relation::CanDo {
            verb: "create".into(),
            resource: "pods".into(),
        }),
    );

    let internet = g.upsert_node(Node::Endpoint(crate::engine::graph::Endpoint {
        address: "internet".into(),
    }));
    g.add_edge(
        e,
        internet,
        edge(Relation::CanEgress {
            via: "annotation".into(),
        }),
    );

    (g, entry_key)
}

#[test]
fn for_entry_counts_data_stores_capabilities_and_egress_from_proven_chains() {
    let (graph, entry) = full_reach_graph();
    let chains = prove(&graph);

    let ann = ReachAnnotation::for_entry(&graph, &entry, &chains)
        .expect("entry is a known workload node");

    assert_eq!(ann.secret_purposes, vec![SecretPurpose::DatabaseCredential]);
    assert_eq!(ann.data_stores, 1);
    assert_eq!(ann.capabilities, 1);
    assert!(ann.egress);
}

#[test]
fn for_entry_returns_none_for_an_unknown_or_non_workload_node() {
    let (graph, _entry) = full_reach_graph();
    let chains = prove(&graph);
    let unknown = NodeKey("workload/app/Pod/does-not-exist".into());
    assert!(ReachAnnotation::for_entry(&graph, &unknown, &chains).is_none());

    // A Secret node is a known key but not a workload — never annotated.
    let secret_key = NodeKey("secret/app/db-password".into());
    assert!(ReachAnnotation::for_entry(&graph, &secret_key, &chains).is_none());
}

#[test]
fn for_entry_is_the_honest_empty_state_for_a_workload_with_no_reach() {
    let mut g = SecurityGraph::new();
    let lone = workload("app", "quiet", false);
    let entry_key = lone.key();
    g.upsert_node(lone);
    let chains = prove(&g);

    let ann = ReachAnnotation::for_entry(&g, &entry_key, &chains).expect("known workload");
    assert!(ann.secret_purposes.is_empty());
    assert_eq!(ann.data_stores, 0);
    assert_eq!(ann.capabilities, 0);
    assert!(!ann.egress);
    assert_eq!(
        ann.line(),
        "if compromised, this workload grants the attacker no additional reach beyond itself"
    );
}

// ---- ReachAnnotation::line — value-free rendering ----------------------------------------

#[test]
fn line_is_value_free_categories_and_counts_only() {
    let ann = ReachAnnotation {
        secret_purposes: vec![
            SecretPurpose::DatabaseCredential,
            SecretPurpose::ServiceAccountToken,
        ],
        data_stores: 2,
        capabilities: 1,
        egress: true,
    };
    let line = ann.line();
    assert!(line.contains("database-credential secret"));
    assert!(line.contains("service-account-token secret"));
    assert!(line.contains("2 reachable data stores"));
    assert!(line.contains("1 reachable RBAC capability"));
    assert!(line.contains("an internet egress path"));
    // Never a secret/workload NAME — the whole point of "value-free".
    assert!(!line.contains("db-password"));
    assert!(!line.contains("workload/"));
    assert!(!line.contains("secret/"));
}

#[test]
fn line_pluralizes_singular_counts_correctly() {
    let ann = ReachAnnotation {
        secret_purposes: vec![],
        data_stores: 1,
        capabilities: 2,
        egress: false,
    };
    let line = ann.line();
    assert!(line.contains("1 reachable data store"));
    assert!(!line.contains("1 reachable data stores"));
    assert!(line.contains("2 reachable RBAC capabilities"));
}
