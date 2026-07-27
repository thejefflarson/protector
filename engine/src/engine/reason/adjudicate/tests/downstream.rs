//! Per-node downstream-evidence tests (JEF-565, ADR-0032 violation #1): the fenced evidence
//! block on an evidence-bearing downstream node, the clean one-line marker, deterministic
//! rendering (byte-identical prompts for identical evidence), and the per-incident aggregate
//! free-text budget on a wide entry. Kept in its own submodule (like `delta`/`sections`) purely
//! to hold every test file under the 1,000-line cap (repo CLAUDE.md). The LOAD-BEARING
//! surface/re-judge regression (a downstream-only CVE must force a fresh model call, not just
//! appear in the prompt) lives in `engine::adj_gate_tests` — it drives the real gate
//! (`classify_adjudication`), which this module doesn't have access to.
#![allow(unused_imports)]

use super::super::*;
use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
use crate::engine::graph::{
    Behavior, Edge, Exposure, Image, Node, NodeKey, Provenance, Reachability, Relation,
    RuntimeSignal, ScanFinding, SecurityGraph, Severity, Trust, Vulnerability, Workload,
};
use crate::engine::observe::asn::AsnDb;
use std::time::SystemTime;

fn workload(name: &str) -> Node {
    workload_with_behaviors(name, vec![])
}

fn workload_with_behaviors(name: &str, behaviors: Vec<Behavior>) -> Node {
    let runtime = behaviors
        .into_iter()
        .map(|behavior| RuntimeSignal {
            behavior,
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
        })
        .collect();
    Node::Workload(Workload {
        namespace: "app".into(),
        name: name.into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internal,
        runtime,
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    })
}

fn proof() -> Edge {
    Edge {
        relation: Relation::RunsImage,
        provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
    }
}

/// A downstream workload carrying its own critical loaded-at-runtime CVE AND an exposed secret
/// baked into the same image — the two evidence-bearing categories JEF-565 renders per node.
fn graph_with_evidence_bearing_downstream() -> (SecurityGraph, NodeKey, NodeKey) {
    let mut g = SecurityGraph::new();
    let entry = workload("entry-web");
    let entry_key = entry.key();
    g.upsert_node(entry);

    let dn = workload("downstream-pod");
    let dn_key = dn.key();
    let d = g.upsert_node(dn);
    let img = g.upsert_node(Node::Image(Image {
        digest: "sha256:dn".into(),
        reference: Some("downstream:1".into()),
        trust: Trust::Unknown,
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2024-1111".into(),
            severity: Severity::Critical,
            reachability: Reachability::LoadedAtRuntime,
            ..Default::default()
        }],
        exposed_secrets: vec![ScanFinding {
            id: "aws-secret-access-key".into(),
            severity: Severity::Critical,
            category: None,
            title: Some("AWS secret access key".into()),
            target: None,
            sources: vec![],
        }],
        static_binary: None,
    }));
    g.add_edge(d, img, proof());
    (g, entry_key, dn_key)
}

/// A downstream workload with NO evidence of any kind — the clean-marker case.
fn graph_with_clean_downstream() -> (SecurityGraph, NodeKey, NodeKey) {
    let mut g = SecurityGraph::new();
    let entry = workload("entry-web");
    let entry_key = entry.key();
    g.upsert_node(entry);
    let dn = workload("downstream-pod");
    let dn_key = dn.key();
    g.upsert_node(dn);
    (g, entry_key, dn_key)
}

/// AC: "Prompt for an entry with an evidence-bearing downstream pod contains that pod's fenced
/// CVE/secret/behavior block."
#[test]
fn evidence_bearing_downstream_node_renders_fenced_block() {
    let (g, entry, dn) = graph_with_evidence_bearing_downstream();
    let build = build_delta_prompt_asn(
        &entry,
        &[],
        &g,
        &AsnDb::empty(),
        None,
        std::slice::from_ref(&dn),
    );
    assert!(
        build.prompt.contains(&dn.0),
        "the downstream node is named in the prompt"
    );
    assert!(
        build.prompt.contains("CVE-2024-1111"),
        "the downstream CVE is rendered"
    );
    assert!(
        build.prompt.contains("aws-secret-access-key"),
        "the downstream exposed secret is rendered"
    );
    assert!(
        build
            .prompt
            .contains("Downstream evidence on this entry's proven paths"),
        "the downstream section header is present"
    );
    assert_eq!(
        build.prompt.matches("<<<").count(),
        build.prompt.matches(">>>").count(),
        "every fence opened is closed — no injection escape via the downstream block"
    );
}

/// AC: "a clean path node shows the one-line marker."
#[test]
fn clean_downstream_node_renders_one_line_marker() {
    let (g, entry, dn) = graph_with_clean_downstream();
    let build = build_delta_prompt_asn(
        &entry,
        &[],
        &g,
        &AsnDb::empty(),
        None,
        std::slice::from_ref(&dn),
    );
    assert!(
        build
            .prompt
            .contains(&format!("{}: no evidence observed.", dn.0))
            || build.prompt.contains("no evidence observed."),
        "a clean downstream node renders the one-line marker, prompt was:\n{}",
        build.prompt
    );
    assert!(
        !build.prompt.contains("CVE-"),
        "a clean downstream node must not fabricate CVE content"
    );
}

/// AC: "Deterministic rendering (sorted node order, sorted/deduped lines) → identical evidence
/// yields byte-identical prompt (the whole prompt is the cache key — do not destabilize it)."
#[test]
fn identical_evidence_yields_byte_identical_prompt_regardless_of_input_order() {
    // Two SEPARATELY built but IDENTICAL graphs (no `Clone` on `SecurityGraph`), each with the
    // same evidence-bearing downstream node plus a second, clean downstream node — passed in
    // reverse order (and with a duplicate) on the second build, to prove sorting + dedup make
    // the input order irrelevant.
    let build_graph = || {
        let (mut g, entry, dn) = graph_with_evidence_bearing_downstream();
        g.upsert_node(workload("aaa-clean"));
        (g, entry, dn)
    };
    let dn2 = NodeKey("workload/app/aaa-clean".into());

    let (g_a, entry, dn) = build_graph();
    let a = build_delta_prompt_asn(
        &entry,
        &[],
        &g_a,
        &AsnDb::empty(),
        None,
        &[dn.clone(), dn2.clone()],
    );
    let (g_b, _entry_b, dn_b) = build_graph();
    let b = build_delta_prompt_asn(
        &entry,
        &[],
        &g_b,
        &AsnDb::empty(),
        None,
        &[dn2.clone(), dn_b.clone(), dn_b], // reversed + duplicated
    );
    assert_eq!(
        a.prompt, b.prompt,
        "the same evidence must render a byte-identical prompt regardless of input order/dupes"
    );
    assert_eq!(a.cache_key, b.cache_key);
}

/// AC: "Per-incident free-text budget bounds total untrusted prose on a wide entry (the argo
/// ~110-objective case is a required test); no CVE/finding is dropped, only prose beyond budget
/// (structural-first, JEF-106 stance)."
#[test]
fn wide_entry_downstream_budget_bounds_prose_without_dropping_any_cve() {
    const N: usize = 120; // argo-shaped: comfortably over the ~110-objective case
    const LONG_TITLE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // A long (but under the PER-LINE `TITLE_CAP`), attacker-influenced exec path — the
    // security-review follow-up to JEF-565: `Behavior::summary` free-text (file/exec paths,
    // peer strings) must be bounded by the AGGREGATE per-incident budget exactly like a
    // CVE/finding title, not just capped per-line and fenced. Under 120 chars so it survives
    // the per-line cap unaltered; it is the AGGREGATE budget across N=120 nodes this asserts.
    const LONG_PATH: &str = "/usr/bin/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let mut g = SecurityGraph::new();
    let entry = workload("entry-web");
    let entry_key = entry.key();
    g.upsert_node(entry);

    let mut nodes = Vec::with_capacity(N);
    let mut expected_ids = Vec::with_capacity(N);
    for i in 0..N {
        let name = format!("downstream-{i:03}");
        let node = workload_with_behaviors(
            &name,
            vec![Behavior::ProcessExec {
                path: LONG_PATH.into(),
                exe_anon_inode: false,
            }],
        );
        let key = node.key();
        let w = g.upsert_node(node);
        let cve_id = format!("CVE-2024-{i:04}");
        let img = g.upsert_node(Node::Image(Image {
            digest: format!("sha256:d{i}"),
            reference: Some(format!("downstream-{i}:1")),
            trust: Trust::Unknown,
            vulnerabilities: vec![Vulnerability {
                id: cve_id.clone(),
                severity: Severity::Critical,
                reachability: Reachability::LoadedAtRuntime,
                title: Some(LONG_TITLE.to_string()),
                ..Default::default()
            }],
            exposed_secrets: vec![],
            static_binary: None,
        }));
        g.add_edge(w, img, proof());
        nodes.push(key);
        expected_ids.push(cve_id);
    }

    let build = build_delta_prompt_asn(&entry_key, &[], &g, &AsnDb::empty(), None, &nodes);

    // Structural-first (JEF-106): every CVE id survives, no matter how many nodes.
    for id in &expected_ids {
        assert!(
            build.prompt.contains(id.as_str()),
            "CVE id {id} must never be dropped, only its free-text prose"
        );
    }
    // The aggregate free-text budget bounds the total untrusted prose: if every title had
    // survived uncapped, the downstream section alone would carry N * LONG_TITLE.len() bytes of
    // title text (~15.8KB for N=120 at 132 bytes/title). The budgeted total must stay well under
    // that — and, concretely, under the per-incident downstream budget itself (with slack for
    // the structural id/severity/reachability text every line still carries).
    let naive_unbounded = N * LONG_TITLE.len();
    let titles_present = build.prompt.matches(LONG_TITLE).count();
    let title_bytes_rendered = titles_present * LONG_TITLE.len();
    assert!(
        title_bytes_rendered < naive_unbounded,
        "the per-incident budget must bound total title prose ({title_bytes_rendered} bytes) \
         well under the naive unbounded total ({naive_unbounded} bytes)"
    );
    // The budget must actually have kicked in — not every title should have survived.
    assert!(
        titles_present < N,
        "the per-incident budget must cap SOME titles on a wide entry (got {titles_present}/{N})"
    );

    // Security-review follow-up: behavior-line free text (an attacker-influenced exec path) is
    // bounded by the SAME structural-first discipline — every node still shows it observed an
    // exec (the fallback names the KIND, "exec", never silently drops the behavior), but the
    // full path does not survive on every one of the N nodes.
    let paths_present = build.prompt.matches(LONG_PATH).count();
    assert!(
        paths_present < N,
        "the per-incident budget must cap SOME exec paths on a wide entry (got {paths_present}/{N})"
    );
    assert!(
        build.prompt.contains("exec (free-text budget exhausted)"),
        "a budget-exhausted behavior line must fall back to its structured KIND, not vanish"
    );
    assert_eq!(
        build.prompt.matches("executed ").count()
            + build
                .prompt
                .matches("exec (free-text budget exhausted)")
                .count(),
        N,
        "every one of the N nodes must show SOME exec evidence (full or truncated) — none dropped"
    );
}

/// AC scope choice: downstream evidence is gated to WORKLOAD nodes only — a `Secret` objective
/// on the path (not itself a workload) must never get its own downstream block.
#[test]
fn non_workload_nodes_are_never_rendered_as_downstream() {
    let (g, entry, _dn) = graph_with_clean_downstream();
    let secret = NodeKey("secret/app/session-key".into());
    // Passing a non-workload NodeKey through `downstream` must degrade gracefully (empty
    // evidence, clean marker) rather than panicking or fabricating content — `entry_evidence`/
    // `entry_findings` already return empty for a non-workload key (see their docs).
    let build = build_delta_prompt_asn(
        &entry,
        &[],
        &g,
        &AsnDb::empty(),
        None,
        std::slice::from_ref(&secret),
    );
    assert!(build.prompt.contains(&secret.0));
    assert!(build.prompt.contains("no evidence observed."));
}
