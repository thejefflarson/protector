//! Tests for the findings view_model mapping + urgency sort, split into its own file to keep
//! the mapper under the 1,000-line cap (CLAUDE.md).

use super::*;
use crate::engine::dashboard::view_model::props::DeltaProps;
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{
    CveEvidence, Delta, EntryEvidence, Finding, Judgement, PathStep, RecencyInfo,
};

/// A minimal breach-relevant finding with a typed verdict, for the mapping tests.
fn finding(entry: &str, objective: &str, verdict: Option<Verdict>) -> Finding {
    Finding {
        entry: entry.to_string(),
        objective: objective.to_string(),
        foothold: true,
        corroborated: false,
        disposition: "auto-eligible".into(),
        cut: None,
        breach_relevant: true,
        verdict,
        path: vec![PathStep {
            from: entry.to_string(),
            relation: "reaches/Tcp/5432".into(),
            to: objective.to_string(),
        }],
        paths: vec![],
        paths_truncated: false,
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

#[test]
fn only_breach_relevant_rows_are_surfaced() {
    let mut keep = finding(
        "endpoint/internet",
        "secret/app/db",
        Some(Verdict::Confirmed),
    );
    keep.foothold = true;
    let mut drop = finding("workload/app/Pod/x", "secret/app/y", None);
    drop.breach_relevant = false;
    let rows = map_findings(&[keep, drop], &[]);
    assert_eq!(rows.len(), 1);
}

#[test]
fn urgency_sort_puts_live_breach_first_cleared_last() {
    let live = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    let promoted = finding(
        "endpoint/b",
        "secret/x",
        Some(Verdict::Exploitable("RCE".into())),
    );
    let cleared = finding(
        "endpoint/c",
        "secret/x",
        Some(Verdict::Refuted("internal".into())),
    );
    let awaiting = finding("endpoint/d", "secret/x", None);
    let rows = map_findings(&[cleared, awaiting, promoted, live], &[]);
    let order: Vec<Posture> = rows.iter().map(|r| r.posture).collect();
    assert_eq!(
        order,
        vec![
            Posture::Breach,   // live-corroborated
            Posture::Breach,   // model-promoted
            Posture::Awaiting, // awaiting
            Posture::Cleared,  // calm tail
        ]
    );
    // The live breach outranks the promoted one (live_tag).
    assert_eq!(rows[0].live_tag, LiveTag::Live);
    assert_eq!(rows[1].live_tag, LiveTag::Judged);
}

#[test]
fn escalation_outranks_awaiting() {
    let mut escalated = finding(
        "endpoint/e",
        "secret/x",
        Some(Verdict::Refuted("now safe".into())),
    );
    escalated.recency = Some(RecencyInfo {
        delta: Delta::Escalated,
        age_secs: Some(5),
    });
    let awaiting = finding("endpoint/a", "secret/x", None);
    let rows = map_findings(&[awaiting, escalated], &[]);
    // The escalation (rank 2) sorts before the awaiting row (rank 4).
    assert!(matches!(rows[0].delta, DeltaProps::Escalated));
}

#[test]
fn evidence_summary_counts_and_kev() {
    let mut f = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    f.evidence.cves = vec![
        CveEvidence {
            id: "CVE-1".into(),
            severity: "critical".into(),
            score: Some("9.8".into()),
            kev: true,
            epss: Some("90%".into()),
            reachability: "loaded-at-runtime".into(),
            fix: "no fix available".into(),
            title: Some("bad".into()),
        },
        CveEvidence {
            id: "CVE-2".into(),
            severity: "high".into(),
            score: None,
            kev: false,
            epss: None,
            reachability: "unknown".into(),
            fix: "fix available: 2.0".into(),
            title: None,
        },
    ];
    let rows = map_findings(&[f], &[]);
    assert_eq!(rows[0].evidence_summary.cve_count, 2);
    assert!(rows[0].evidence_summary.kev);
    assert!(!rows[0].evidence.is_empty());
}

#[test]
fn empty_evidence_is_flagged_empty() {
    let f = finding("endpoint/a", "secret/x", None);
    let rows = map_findings(&[f], &[]);
    assert!(rows[0].evidence.is_empty());
    assert!(rows[0].evidence_summary.is_empty());
}

#[test]
fn fanout_collapses_a_high_objective_entry() {
    // One entry reaching many objectives collapses to a single fan-out row.
    let mut rows = Vec::new();
    for i in 0..20 {
        rows.push(finding(
            "endpoint/argocd",
            &format!("secret/app/s{i}"),
            Some(Verdict::Refuted("cleared".into())),
        ));
    }
    let mapped = map_findings(&rows, &[]);
    let argo: Vec<_> = mapped.iter().filter(|r| r.entry == "argocd").collect();
    assert_eq!(argo.len(), 1, "fan-out collapses to one row");
    assert_eq!(argo[0].fanout, Some(20));
}

#[test]
fn judgement_prompt_is_attached_by_entry() {
    let f = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    let judgements = vec![Judgement {
        entry: "endpoint/a".into(),
        objectives: 1,
        verdict: "Confirmed".into(),
        prompt: Some("the prompt".into()),
        reply: Some("the reply".into()),
    }];
    let rows = map_findings(&[f], &judgements);
    assert_eq!(rows[0].judgement.prompt.as_deref(), Some("the prompt"));
    assert_eq!(rows[0].judgement.reply.as_deref(), Some("the reply"));
}

#[test]
fn path_props_carry_node_glyphs_and_mark_the_cut() {
    // A two-hop path: internet-facing workload → db → secret, with the first edge as the cut.
    let mut f = finding(
        "deployment/edge/api",
        "secret/app/db-creds",
        Some(Verdict::Confirmed),
    );
    f.foothold = true;
    f.path = vec![
        PathStep {
            from: "deployment/edge/api".into(),
            relation: "reaches/Tcp/5432".into(),
            to: "statefulset/app/db".into(),
        },
        PathStep {
            from: "statefulset/app/db".into(),
            relation: "mounts".into(),
            to: "secret/app/db-creds".into(),
        },
    ];
    f.cut = Some("deployment/edge/api -[reaches/Tcp/5432]-> statefulset/app/db".into());
    let rows = map_findings(&[f], &[]);
    let path = &rows[0].path;
    assert_eq!(path.len(), 2);
    // The foothold entry node reads as the internet front door (🌐), not its bare kind.
    assert_eq!(path[0].from_glyph, "\u{1F310}");
    // Each node carries its kind glyph (secret ⇒ 🔑).
    assert_eq!(path[1].to_glyph, "\u{1F511}");
    // The severable edge is marked; the structural `mounts` edge is not the cut.
    assert!(path[0].is_cut);
    assert!(!path[1].is_cut);
}

#[test]
fn multi_path_marks_edges_shared_across_all_paths() {
    // JEF-281: an objective reachable two ways through a common first hop (a shared bottleneck)
    // then divergent second hops. The shared edge must be marked in BOTH paths; the divergent
    // edges must not — that marking is what makes redundancy (and the cut/no-cut reason) legible.
    let mut f = finding(
        "deployment/edge/gw",
        "secret/app/creds",
        Some(Verdict::Confirmed),
    );
    f.cut = None;
    let shared = PathStep {
        from: "deployment/edge/gw".into(),
        relation: "reaches/Tcp/443".into(),
        to: "deployment/app/hub".into(),
    };
    let path_a = vec![
        shared.clone(),
        PathStep {
            from: "deployment/app/hub".into(),
            relation: "reaches/Tcp/5432".into(),
            to: "secret/app/creds".into(),
        },
    ];
    let path_b = vec![
        shared.clone(),
        PathStep {
            from: "deployment/app/hub".into(),
            relation: "reaches/Tcp/6379".into(),
            to: "secret/app/creds".into(),
        },
    ];
    f.paths = vec![path_a, path_b];
    let rows = map_findings(&[f], &[]);
    let paths = &rows[0].paths;
    assert_eq!(paths.len(), 2, "both proven paths are mapped, not just one");
    // The common first hop is a shared bottleneck in both routes...
    assert!(
        paths[0][0].shared,
        "the common edge is marked shared in path A"
    );
    assert!(
        paths[1][0].shared,
        "the common edge is marked shared in path B"
    );
    // ...while the divergent second hops are not shared.
    assert!(!paths[0][1].shared);
    assert!(!paths[1][1].shared);
}

#[test]
fn single_path_finding_falls_back_and_marks_no_shared_edge() {
    // A lone-path finding (the common case) sets no `paths`; the mapper falls back to the
    // representative path so a chain always renders, and nothing is marked shared.
    let f = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    let rows = map_findings(&[f], &[]);
    assert_eq!(
        rows[0].paths.len(),
        1,
        "a lone path still renders (fallback)"
    );
    assert!(rows[0].paths[0].iter().all(|h| !h.shared));
}

#[test]
fn verdict_summary_is_the_models_verbatim_words() {
    let f = finding(
        "endpoint/a",
        "secret/x",
        Some(Verdict::Exploitable("CVE reachable".into())),
    );
    let rows = map_findings(&[f], &[]);
    assert_eq!(
        rows[0].verdict_summary.as_deref(),
        Some("exploitable — CVE reachable")
    );
}

// ---------------------------------------------------------------------------
// Item 2 — finding_id is collision-free: distinct entry keys that slugify to the
// SAME string must get DISTINCT row ids (so the whole-row toggle opens its own
// detail row, not a different one).
// ---------------------------------------------------------------------------

#[test]
fn distinct_entries_that_slugify_alike_get_distinct_ids() {
    // `secret/app/db` and `secret-app-db` both slugify to `secret-app-db` under the old
    // non-alphanumeric → `-` rule, so the old finding_id collided. The hash suffix separates them.
    let a = finding("secret/app/db", "secret/x", Some(Verdict::Confirmed));
    let b = finding("secret-app-db", "secret/x", Some(Verdict::Confirmed));
    let rows = map_findings(&[a, b], &[]);
    assert_eq!(rows.len(), 2, "two distinct entries stay two rows");
    assert_ne!(
        rows[0].id, rows[1].id,
        "distinct entries that slugify alike must NOT share a DOM id (item 2)"
    );
}

#[test]
fn finding_id_is_stable_across_renders() {
    // The id must be deterministic so the JS's persisted open-state keying survives a poll swap.
    let f1 = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    let f2 = finding("endpoint/a", "secret/x", Some(Verdict::Confirmed));
    let r1 = map_findings(&[f1], &[]);
    let r2 = map_findings(&[f2], &[]);
    assert_eq!(
        r1[0].id, r2[0].id,
        "the same entry always yields the same id"
    );
}

// ---------------------------------------------------------------------------
// Item 5 — pod replicas of one owning workload collapse to a single `×N` row
// carrying the worst posture; unrelated pods and standalone pods never merge.
// ---------------------------------------------------------------------------

#[test]
fn statefulset_replicas_collapse_to_one_row_with_worst_posture() {
    // Three StatefulSet replicas (`name-<ordinal>`) of one workload — one Confirmed (worst), two
    // cleared. They must fold to ONE ×3 row carrying the BREACH posture.
    let r0 = finding(
        "workload/analytics/Pod/murmurify-aggregator-0",
        "secret/analytics/db",
        Some(Verdict::Refuted("internal".into())),
    );
    let r1 = finding(
        "workload/analytics/Pod/murmurify-aggregator-1",
        "secret/analytics/db",
        Some(Verdict::Confirmed), // the worst posture in the group
    );
    let r2 = finding(
        "workload/analytics/Pod/murmurify-aggregator-2",
        "secret/analytics/db",
        Some(Verdict::Refuted("internal".into())),
    );
    let rows = map_findings(&[r0, r1, r2], &[]);
    assert_eq!(rows.len(), 1, "three replicas collapse to one row");
    assert_eq!(rows[0].replicas, Some(3), "the row carries the ×3 count");
    assert_eq!(
        rows[0].posture,
        Posture::Breach,
        "the merged row carries the worst/most-urgent posture among the group"
    );
    assert_eq!(
        rows[0].entry, "analytics/murmurify-aggregator",
        "the row is relabeled with the owning workload, not a single pod"
    );
}

#[test]
fn deployment_replicas_collapse_by_owning_workload() {
    // Deployment pods: `name-<rs-hash>-<pod-hash>`. Two replicas of one Deployment fold to one row.
    let a = finding(
        "workload/web/Pod/storefront-7d9f8c6b5d-x9k2p",
        "secret/web/session",
        Some(Verdict::Refuted("internal".into())),
    );
    let b = finding(
        "workload/web/Pod/storefront-7d9f8c6b5d-7m4qz",
        "secret/web/session",
        Some(Verdict::Refuted("internal".into())),
    );
    let rows = map_findings(&[a, b], &[]);
    assert_eq!(rows.len(), 1, "two deployment replicas collapse to one row");
    assert_eq!(rows[0].replicas, Some(2));
    assert_eq!(rows[0].entry, "web/storefront");
}

#[test]
fn unrelated_pods_do_not_merge() {
    // Two pods in different workloads (different names) must STAY two rows — never merge unrelated.
    let a = finding(
        "workload/web/Pod/storefront-7d9f8c6b5d-x9k2p",
        "secret/web/session",
        Some(Verdict::Confirmed),
    );
    let b = finding(
        "workload/web/Pod/checkout-5c4b3a2f1e-q7w2e",
        "secret/web/cart",
        Some(Verdict::Confirmed),
    );
    let rows = map_findings(&[a, b], &[]);
    assert_eq!(rows.len(), 2, "unrelated pods are never merged");
    assert!(rows.iter().all(|r| r.replicas.is_none()));
}

#[test]
fn standalone_pod_stays_a_single_row() {
    // A bare pod with no controller replica suffix is left individual (conservative).
    let f = finding(
        "workload/ops/Pod/debug-shell",
        "secret/ops/kubeconfig",
        Some(Verdict::Confirmed),
    );
    let rows = map_findings(&[f], &[]);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].replicas, None,
        "a standalone pod carries no ×N count"
    );
    assert_eq!(rows[0].entry, "ops/Pod/debug-shell", "and is not relabeled");
}

#[test]
fn a_single_replica_named_pod_is_not_collapsed() {
    // Only ONE pod matching a controller pattern (no sibling) must not collapse — it's not a set.
    let f = finding(
        "workload/web/Pod/lonely-7d9f8c6b5d-x9k2p",
        "secret/web/x",
        Some(Verdict::Confirmed),
    );
    let rows = map_findings(&[f], &[]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].replicas, None, "a lone pod is not a replica set");
}

#[test]
fn finding_id_unit_helpers() {
    // The workload-group derivation is conservative: it only fires on a clear controller pattern.
    assert_eq!(
        workload_group_key("analytics/Pod/murmurify-aggregator-0").as_deref(),
        Some("analytics/Pod/murmurify-aggregator")
    );
    assert_eq!(
        workload_group_key("web/Pod/storefront-7d9f8c6b5d-x9k2p").as_deref(),
        Some("web/Pod/storefront")
    );
    // A bare pod, a non-Pod kind, and a malformed label all decline to group.
    assert_eq!(workload_group_key("ops/Pod/debug-shell"), None);
    assert_eq!(workload_group_key("web/Deployment/storefront-x"), None);
    assert_eq!(workload_group_key("endpoint/internet"), None);
}
