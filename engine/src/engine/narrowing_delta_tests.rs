//! Tests for the ADR-0041 §6 narrowing-delta comparator, kept in their own `*_tests.rs` file
//! (repo CLAUDE.md: tests count toward the 1,000-line cap). Both fixtures build the
//! corroborated/uncorroborated `ProvenChain` states DIRECTLY (rather than routing through
//! `reason::proof::corroborate::corroborated_for`), per the ticket's note: the current blanket
//! notable-exec arm corroborates every objective on ANY entry with a shell/pkg-mgr exec, so a
//! real uncorroborated-with-notable-exec breach-relevant chain can't be produced from the
//! live pipeline until the narrowing (a separate change) lands. `compute` itself only reads
//! `entry`/`objective`/`attack`/`exposed_entry`/`corroborated`, so hand-building the chain
//! exercises exactly what it reads without depending on that narrowing.

use super::*;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::graph::{
    Behavior, Exposure, Node, NodeKey, Provenance, RuntimeSignal, Workload,
};

/// A `web` entry workload whose runtime carries a shell exec — optionally alongside an
/// in-window internet egress, mirroring the reverse-shell shape's evidence without needing
/// the shape's own window-matching logic (irrelevant to this comparator, which only reads
/// `ProvenChain::corroborated`).
fn web_entry_graph(with_egress: bool) -> SecurityGraph {
    let mut graph = SecurityGraph::new();
    let mut runtime = vec![RuntimeSignal {
        behavior: Behavior::ProcessExec {
            path: "/bin/bash".into(),
            exe_anon_inode: false,
        },
        provenance: Provenance::new("agent", std::time::SystemTime::UNIX_EPOCH),
    }];
    if with_egress {
        runtime.push(RuntimeSignal {
            behavior: Behavior::NetworkConnection {
                peer: "1.2.3.4:4444".into(),
                internet: true,
            },
            provenance: Provenance::new("agent", std::time::SystemTime::UNIX_EPOCH),
        });
    }
    graph.upsert_node(Node::Workload(Workload {
        namespace: "app".into(),
        name: "web".into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internet,
        runtime,
        persistent: false,
        misconfigs: Vec::new(),
        rbac_findings: Vec::new(),
    }));
    graph
}

/// A breach-relevant chain over the `web` entry, `corroborated` set directly by the caller —
/// the state under test, independent of how corroboration is actually derived.
fn web_chain(corroborated: bool) -> ProvenChain {
    ProvenChain {
        entry: NodeKey::workload("app", "Pod", "web"),
        objective: NodeKey::workload("app", "Secret", "session-key"),
        attack: CREDENTIAL_ACCESS,
        foothold: None,
        corroborated,
        adjudicated: true,
        promoted: false,
        exposed_entry: true,
        verdict: None,
        links: Vec::new(),
        paths: Vec::new(),
        paths_truncated: false,
        single_edge_cuts: Vec::new(),
        quarantine_targets: Vec::new(),
    }
}

/// Shell exec present, chain uncorroborated (no in-window egress — the plain bare-shell case,
/// ADR-0011's on-call-engineer false positive under the narrowed shapes): the counter fires —
/// this IS one of the cases the old blanket arm would have corroborated.
#[test]
fn shell_exec_uncorroborated_chain_fires() {
    let graph = web_entry_graph(false);
    let chains = vec![web_chain(false)];

    let records = compute(&graph, &chains);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].entry, "workload/app/Pod/web");
    assert_eq!(records[0].objective, "workload/app/Secret/session-key");
    assert_eq!(records[0].technique_id, CREDENTIAL_ACCESS.technique_id);
}

/// Shell exec present, chain corroborated (e.g. the in-window egress shape fired): NOT a
/// narrowing delta — the chain would be corroborated either way, so the old blanket arm's
/// recall isn't backstopping anything here. No fire.
#[test]
fn shell_exec_corroborated_chain_does_not_fire() {
    let graph = web_entry_graph(true);
    let chains = vec![web_chain(true)];

    let records = compute(&graph, &chains);

    assert!(records.is_empty());
}

/// A notable exec absent from the entry's runtime never fires, corroborated or not — the
/// comparator is scoped to the notable-exec shape, not every uncorroborated chain.
#[test]
fn no_notable_exec_never_fires() {
    let graph = SecurityGraph::new();
    let chains = vec![web_chain(false)];

    let records = compute(&graph, &chains);

    assert!(records.is_empty());
}

/// A notable exec on an entry whose chain is NOT breach-relevant (an internal-only entry)
/// never fires — the parity matrix only concerns internet-facing paths (matches the scope of
/// the `corroborations` metric it sits beside).
#[test]
fn non_breach_relevant_entry_never_fires() {
    let graph = web_entry_graph(false);
    let mut chain = web_chain(false);
    chain.exposed_entry = false;

    let records = compute(&graph, &[chain]);

    assert!(records.is_empty());
}
