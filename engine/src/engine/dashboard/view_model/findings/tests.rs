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
