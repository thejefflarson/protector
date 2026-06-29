//! Tests for the Trust view_model mapping: the Report→Props shaping, the headline counts, and the
//! honest journal-empty vs none-in-window distinction.

use super::*;
use crate::engine::state::{LeftAloneEntry, Report, WouldActEntry};

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
    // A minimal strip; the trust mapper does not inspect it, just carries it.
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
fn maps_counts_and_formats_window_and_lifetime() {
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
    let v = build(strip(), &report);
    assert_eq!(v.window_human, "7d");
    assert_eq!(v.would_act_count, 3);
    assert_eq!(v.short_lived_count, 1);
    assert_eq!(v.coverage_gap_count, 1);
    assert_eq!(v.left_alone_count, 1);
    assert!(!v.journal_empty);
    // The lifetime is human-formatted (240s ⇒ "4m").
    assert_eq!(v.would_act[0].max_lifetime, "4m");
    // The classification flags pass straight through.
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
    let v = build(strip(), &empty);
    assert!(v.journal_empty);
    assert_eq!(v.would_act_count, 0);
    assert_eq!(v.left_alone_count, 0);

    let none_in_window = Report {
        journal_empty: false,
        ..empty
    };
    let v2 = build(strip(), &none_in_window);
    assert!(
        !v2.journal_empty,
        "history exists, just none in this window"
    );
}
