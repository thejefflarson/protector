//! Tests for the Action view_model mapping (the merged Trust + Activity shaping): the Report →
//! proposed-cuts/left-alone shaping with its headline counts, the reversion ages, the judgement
//! ring, and the honest journal-empty vs none-in-window distinction.

use super::*;
use crate::engine::state::{Judgement, LeftAloneEntry, Report, ReversionRecord, WouldActEntry};

fn would_act(entry: &str, open: bool, short_lived: bool, coverage_gap: bool) -> WouldActEntry {
    WouldActEntry {
        entry: entry.into(),
        episodes: 2,
        would_act_decisions: 3,
        max_lifetime_secs: 240,
        open,
        short_lived,
        coverage_gap,
        last_verdict: "exploitable — RCE reachable".into(),
    }
}

fn strip() -> StatusStripProps {
    // A minimal strip; the action mapper does not inspect it, just carries it.
    StatusStripProps {
        cluster: "prod".into(),
        armed: false,
        model_judging: true,
        warming_up: false,
        model_attached: true,
        coverage: vec![],
        last_pass: None,
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 0,
        escalated_count: 0,
    }
}

#[test]
fn maps_proposed_cuts_left_alone_counts_and_formats_window_and_lifetime() {
    let report = Report {
        window_secs: 7 * 24 * 3600,
        short_lived_secs: 300,
        decisions_in_window: 5,
        journal_empty: false,
        would_act: vec![
            would_act("web", true, false, false),
            would_act("api", false, true, false),
            would_act("cron", false, false, true),
        ],
        left_alone: vec![LeftAloneEntry {
            entry: "marketing".into(),
            verdict: "not exploitable — internal only".into(),
        }],
    };
    let v = build_at(strip(), &report, &[], &[], 0);
    assert_eq!(v.window_human, "7d");
    assert_eq!(v.would_act_count, 3);
    assert_eq!(v.short_lived_count, 1);
    assert_eq!(v.coverage_gap_count, 1);
    assert_eq!(v.left_alone_count, 1);
    assert!(!v.journal_empty);
    // The lifetime is human-formatted (240s ⇒ "4m").
    assert_eq!(v.would_act[0].max_lifetime, "4m");
    // The classification flags pass straight through (the lifecycle status the section tags).
    assert!(v.would_act[0].open);
    assert!(v.would_act[1].short_lived);
    assert!(v.would_act[2].coverage_gap);
}

#[test]
fn journal_empty_is_preserved_distinct_from_none_in_window() {
    // journal_empty = true (no history at all) is distinct from an empty would_act/left_alone with
    // journal_empty = false (history, but nothing in this window).
    let empty = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 0,
        journal_empty: true,
        would_act: vec![],
        left_alone: vec![],
    };
    let v = build_at(strip(), &empty, &[], &[], 0);
    assert!(v.journal_empty);
    assert_eq!(v.would_act_count, 0);
    assert_eq!(v.left_alone_count, 0);

    let none_in_window = Report {
        journal_empty: false,
        ..empty
    };
    let v2 = build_at(strip(), &none_in_window, &[], &[], 0);
    assert!(
        !v2.journal_empty,
        "history exists, just none in this window"
    );
}

fn report_with_history() -> Report {
    Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 1,
        journal_empty: false,
        would_act: vec![],
        left_alone: vec![],
    }
}

#[test]
fn reversion_age_is_formatted_relative_to_now_and_counted() {
    let now_ms = 10_000_000u64;
    let reversions = vec![ReversionRecord {
        cut: "web -[reaches]-> db".into(),
        reason: "breach condition cleared".into(),
        at_ms: now_ms - 90_000, // 90s ago
    }];
    let v = build_at(strip(), &report_with_history(), &reversions, &[], now_ms);
    assert_eq!(v.reversions.len(), 1);
    assert_eq!(v.reverted_count, 1);
    assert_eq!(v.reversions[0].age, "1m"); // 90s ⇒ 1m bucket
    assert_eq!(v.reversions[0].reason, "breach condition cleared");
}

#[test]
fn a_future_or_skewed_reversion_clamps_to_zero_age() {
    let now_ms = 1_000u64;
    let reversions = vec![ReversionRecord {
        cut: "web -[reaches]-> db".into(),
        reason: "skew".into(),
        at_ms: now_ms + 5_000, // "in the future" — clock skew
    }];
    let v = build_at(strip(), &report_with_history(), &reversions, &[], now_ms);
    assert_eq!(v.reversions[0].age, "0s");
}

#[test]
fn judgement_preserves_absent_prompt_and_reply_honestly() {
    let judgements = vec![
        Judgement {
            entry: "web".into(),
            objectives: 1,
            verdict: "Exploitable".into(),
            prompt: Some("the prompt".into()),
            reply: Some("the reply".into()),
        },
        Judgement {
            entry: "api".into(),
            objectives: 3,
            verdict: "Uncertain".into(),
            prompt: None, // pre-filter decided
            reply: None,  // timed out
        },
    ];
    let v = build_at(strip(), &report_with_history(), &[], &judgements, 0);
    assert_eq!(v.judgements.len(), 2);
    assert_eq!(v.judgements[0].prompt.as_deref(), Some("the prompt"));
    assert_eq!(v.judgements[0].reply.as_deref(), Some("the reply"));
    // The absent prompt/reply stay None so the component can render the honest "no prompt"/"no
    // reply" lines (never a blank).
    assert!(v.judgements[1].prompt.is_none());
    assert!(v.judgements[1].reply.is_none());
    assert_eq!(v.judgements[1].objectives, 3);
}

#[test]
fn empty_logs_yield_empty_vecs_and_zero_counts() {
    let v = build_at(strip(), &report_with_history(), &[], &[], 0);
    assert!(v.reversions.is_empty());
    assert!(v.judgements.is_empty());
    assert_eq!(v.reverted_count, 0);
}
