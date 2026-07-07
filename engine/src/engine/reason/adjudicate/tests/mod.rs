//! Unit tests for the adjudicator: the prompt-injection fences, the anti-fabrication
//! backstop, the verdict-cache fingerprint, prompt rendering, and the model-call path.
//! Split out of the adjudicate module into grouped submodules purely to keep every file
//! under the 1,000-line cap (repo CLAUDE.md). `use super::*` resolves to the adjudicate
//! module, so the tests see exactly what the inline `mod tests` block saw; the shared
//! fixtures live here and are reused by both groups.
#![allow(unused_imports)]

use super::*;
use crate::engine::graph::attack::{AttackRef, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{
    Behavior, Edge, Exposure, Image, Node, NodeKey, Provenance, Relation, SecurityGraph, Severity,
    Trust, Vulnerability, Workload,
};
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::{Attribution, ImageVulnerabilities, RuntimeObservation, Snapshot};
use crate::engine::reason::proof::{ProvenChain, prove};
use serde_json::json;
use std::time::SystemTime;

mod group_1;
mod group_2;
mod group_3;
mod sections;

/// The (objective, technique) list for a chain — the shape `judge` now takes.
pub(super) fn objectives_of(chain: &ProvenChain) -> Vec<(NodeKey, AttackRef)> {
    vec![(chain.objective.clone(), chain.attack)]
}

/// A minimal internet-facing workload running one image whose single vulnerability is
/// `vuln` — the smallest graph that drives `entry_evidence`/`build_judgment_prompt`.
/// Returns the graph and the entry key.
pub(super) fn graph_with_vuln(vuln: Vulnerability) -> (SecurityGraph, NodeKey) {
    graph_with_vulns(vec![vuln])
}

/// As [`graph_with_vuln`], but the entry's image carries the whole `vulns` list — used to
/// drive the per-entry aggregate free-text budget (JEF-106), where MANY CVEs together must
/// stay bounded even when each per-field cap holds.
pub(super) fn graph_with_vulns(vulns: Vec<Vulnerability>) -> (SecurityGraph, NodeKey) {
    let mut g = SecurityGraph::new();
    let wl = Node::Workload(Workload {
        namespace: "app".into(),
        name: "web".into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internet,
        runtime: Vec::new(),
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    });
    let entry_key = wl.key();
    let e = g.upsert_node(wl);
    let img = g.upsert_node(Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("web:1".into()),
        trust: Trust::Unknown,
        vulnerabilities: vulns,
        exposed_secrets: vec![],
    }));
    g.add_edge(
        e,
        img,
        Edge {
            relation: Relation::RunsImage,
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
        },
    );
    (g, entry_key)
}

/// A minimal internet-facing workload carrying the given runtime `behaviors` (no CVEs) —
/// drives the behavior side of `entry_evidence`/`build_judgment_prompt`. Used to verify the
/// prompt re-applies the engine's notable-exec annotation (JEF-113) now that
/// `Behavior::summary` returns the bare path.
pub(super) fn graph_with_behaviors(behaviors: Vec<Behavior>) -> (SecurityGraph, NodeKey) {
    use crate::engine::graph::RuntimeSignal;
    let runtime = behaviors
        .into_iter()
        .map(|behavior| RuntimeSignal {
            behavior,
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
        })
        .collect();
    let mut g = SecurityGraph::new();
    let wl = Node::Workload(Workload {
        namespace: "app".into(),
        name: "web".into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internet,
        runtime,
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    });
    let entry_key = wl.key();
    g.upsert_node(wl);
    (g, entry_key)
}

pub(super) fn critical_cve(id: &str) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

/// Build a graph with one internet-facing entry `workload/<ns>/Pod/web` that reaches a
/// single database objective, and return `(graph, entry_key, objectives)`. No image, so
/// no CVE; no runtime events, so no alert — the only possible ground is the objective's
/// tenancy/tactic. `db_ns`/`db_name` and `attack` choose which ground (if any) holds.
pub(super) fn entry_reaching_db(
    entry_ns: &str,
    db_ns: &str,
    db_name: &str,
    attack: AttackRef,
) -> (SecurityGraph, NodeKey, Vec<(NodeKey, AttackRef)>) {
    use crate::engine::graph::{Edge, Exposure, Node, Protocol, Relation, SecurityGraph, Workload};
    let proof = |relation| Edge {
        relation,
        provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
    };
    let workload = |ns: &str, name: &str| {
        Node::Workload(Workload {
            namespace: ns.into(),
            name: name.into(),
            kind: "Pod".into(),
            labels: Default::default(),
            meshed: false,
            exposure: Exposure::Internet,
            runtime: Vec::new(),
            persistent: false,
            misconfigs: vec![],
            rbac_findings: vec![],
        })
    };
    let mut g = SecurityGraph::new();
    let entry = workload(entry_ns, "web");
    let entry_key = entry.key();
    let e = g.upsert_node(entry);
    let db = workload(db_ns, db_name);
    let db_key = db.key();
    let d = g.upsert_node(db);
    g.add_edge(
        e,
        d,
        proof(Relation::Reaches {
            port: Some(5432),
            protocol: Protocol::Tcp,
        }),
    );
    (g, entry_key, vec![(db_key, attack)])
}
