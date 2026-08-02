//! ADR-0040's load-bearing invariant: the adversary-reach annotation is a PRESENTATION
//! annotation and must NEVER enter the judge prompt — *context-not-evidence*
//! (ADR-0029/ADR-0034) is enforced by ABSENCE, the only guard with no failure mode. This
//! file is the regression: it builds a fixture whose reach annotation is non-trivial (a
//! mounted secret, a reachable data store, a reachable RBAC capability, and an internet
//! egress path all present) and asserts the rendered line — and every one of its
//! closed-vocabulary category tokens — never appears in ANY judge-prompt build path.

use super::super::*;
use super::objectives_of;
use crate::engine::graph::{
    Capability, Edge, Endpoint, Exposure, Node, NodeKey, Protocol, Provenance, Relation, Scope,
    SecretRef, SecurityGraph, Workload,
};
use crate::engine::reason::proof::prove;
use crate::engine::state::ReachAnnotation;
use std::time::SystemTime;

/// An internet-facing entry that directly mounts a database-credential secret and can reach
/// a persistent data-store workload, a dangerous RBAC capability, and the internet egress
/// endpoint — one of each of the three reach dimensions ADR-0040 names, so the reach line
/// this fixture produces is maximally non-trivial (every clause populated). Returns the
/// graph and the entry's own key (rather than relying on chain iteration order).
fn fixture() -> (SecurityGraph, NodeKey) {
    let edge = |relation| Edge {
        relation,
        provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
    };
    let workload = |ns: &str, name: &str, persistent: bool| {
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
    };

    let mut g = SecurityGraph::new();
    let entry_node = workload("app", "web", false);
    let entry_key = entry_node.key();
    let entry = g.upsert_node(entry_node);

    let secret = g.upsert_node(Node::Secret(SecretRef {
        namespace: "app".into(),
        name: "db-password".into(),
    }));
    g.add_edge(entry, secret, edge(Relation::CanRead));

    let store = g.upsert_node(workload("app", "cache", true));
    g.add_edge(
        entry,
        store,
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
        entry,
        cap,
        edge(Relation::CanDo {
            verb: "create".into(),
            resource: "pods".into(),
        }),
    );

    let internet = g.upsert_node(Node::Endpoint(Endpoint {
        address: "internet".into(),
    }));
    g.add_edge(
        entry,
        internet,
        edge(Relation::CanEgress {
            via: "annotation".into(),
        }),
    );

    (g, entry_key)
}

/// Every category word the closed vocabulary (ADR-0040) can render, plus the line's own
/// framing phrase — the full set of tokens a judge prompt must never contain.
fn reach_tokens(line: &str) -> Vec<String> {
    // Sanity: the fixture's line must actually exercise every clause, or this test would
    // pass for the wrong reason (an empty/trivial line proves nothing).
    assert!(line.contains("database-credential"), "line = {line}");
    assert!(line.contains("reachable data store"), "line = {line}");
    assert!(line.contains("reachable RBAC capabilit"), "line = {line}");
    assert!(line.contains("internet egress path"), "line = {line}");
    vec![
        line.to_string(),
        "database-credential".to_string(),
        "reachable data store".to_string(),
        "reachable RBAC capabilit".to_string(),
        "internet egress path".to_string(),
        "if compromised, this workload grants the attacker".to_string(),
    ]
}

/// The reach line — and every one of its tokens — never appears in [`build_judgment_prompt`],
/// the non-delta judge-prompt build path.
#[test]
fn reach_line_never_appears_in_build_judgment_prompt() {
    let (graph, entry) = fixture();
    let chains = prove(&graph);
    let ann = ReachAnnotation::for_entry(&graph, &entry, &chains).expect("known workload entry");
    let line = ann.line();
    let tokens = reach_tokens(&line);

    let objectives: Vec<_> = chains
        .iter()
        .filter(|c| c.entry == entry)
        .flat_map(objectives_of)
        .collect();
    let prompt = build_judgment_prompt(&entry, &objectives, &graph);

    for token in &tokens {
        assert!(
            !prompt.contains(token.as_str()),
            "judge prompt must never contain the reach annotation, found {token:?}"
        );
    }
}

/// As above, for [`build_delta_prompt_asn`] (the delta-aware build the live engine's earlier
/// callers used) — the second judge-prompt assembly path.
#[test]
fn reach_line_never_appears_in_build_delta_prompt_asn() {
    let (graph, entry) = fixture();
    let chains = prove(&graph);
    let ann = ReachAnnotation::for_entry(&graph, &entry, &chains).expect("known workload entry");
    let line = ann.line();
    let tokens = reach_tokens(&line);

    let objectives: Vec<_> = chains
        .iter()
        .filter(|c| c.entry == entry)
        .flat_map(objectives_of)
        .collect();
    let asn = crate::engine::observe::asn::AsnDb::empty();
    let build = build_delta_prompt_asn(&entry, &objectives, &graph, &asn, None, &[]);

    for token in &tokens {
        assert!(
            !build.prompt.contains(token.as_str()),
            "delta judge prompt must never contain the reach annotation, found {token:?}"
        );
    }
}

/// As above, for [`build_delta_prompt_with_menu_asn`] — the LIVE engine's only delta-prompt
/// entry point (`Engine::process`), the exact bytes the model is sent.
#[test]
fn reach_line_never_appears_in_build_delta_prompt_with_menu_asn() {
    let (graph, entry) = fixture();
    let chains = prove(&graph);
    let ann = ReachAnnotation::for_entry(&graph, &entry, &chains).expect("known workload entry");
    let line = ann.line();
    let tokens = reach_tokens(&line);

    let objectives: Vec<_> = chains
        .iter()
        .filter(|c| c.entry == entry)
        .flat_map(objectives_of)
        .collect();
    let asn = crate::engine::observe::asn::AsnDb::empty();
    let menu = incident::Menu::default();
    let build =
        build_delta_prompt_with_menu_asn(&entry, &objectives, &graph, &asn, None, &[], &menu);

    for token in &tokens {
        assert!(
            !build.prompt.contains(token.as_str()),
            "live judge prompt must never contain the reach annotation, found {token:?}"
        );
    }
}
