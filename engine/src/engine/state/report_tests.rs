//! Tests for the would-have-acted report aggregation, split into its own file to keep
//! `report.rs` under the repo's 1,000-line cap (CLAUDE.md). 's realignment to the typed
//! ADR-0034 contract is the focus: would-act classification now reads `Decision::Incident`'s
//! `assessment` + `cuts`, never the legacy `Decision::Breach` verdict prose.

use super::*;

/// A legacy breach decision — verdict PROSE only, no typed cut-choice line. Exactly what a
/// pre-ADR-0034 journal (or an entry the model never re-judged post-upgrade) holds.
fn breach(at_ms: u64, entry: &str, verdict: &str) -> JournalEntry {
    JournalEntry {
        at_ms,
        decision: Decision::Breach {
            entry: entry.to_string(),
            objectives: 1,
            verdict: verdict.to_string(),
            coverage: None,
            fingerprint: None,
            verdict_typed: None,
        },
    }
}

/// A typed cut-choice decision (ADR-0034 D8) — the classification source realigns to.
fn incident(
    at_ms: u64,
    entry: &str,
    assessment: Assessment,
    cuts: &[&str],
    reason: &str,
) -> JournalEntry {
    JournalEntry {
        at_ms,
        decision: Decision::Incident {
            entry: entry.to_string(),
            objectives: 1,
            assessment,
            reason: reason.to_string(),
            cuts: cuts
                .iter()
                .map(|n| JournaledCut {
                    node: n.to_string(),
                    cut_signature: format!("{n} -[cut]-> {n}"),
                })
                .collect(),
            fingerprint: "fp".to_string(),
        },
    }
}

#[test]
fn aggregate_would_acts_only_when_the_typed_decision_is_attack_with_a_nonempty_cut_set() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    let entries = vec![
        incident(
            now_ms - 600_000,
            "web",
            Assessment::Attack,
            &["workload/app/Pod/web"],
            "RCE reaches the objective",
        ),
        breach(now_ms - 600_000, "web", "exploitable — RCE"),
        breach(now_ms - 300_000, "web", "exploitable — RCE"),
    ];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(report.would_act_count(), 1);
    assert_eq!(report.left_alone_count(), 0);
    assert_eq!(report.attack_no_cut_count(), 0);
    let w = &report.would_act[0];
    assert_eq!(w.entry, "web");
    assert!(w.open, "still the latest decision → open episode");
    assert!(!w.short_lived, "an open episode is never short-lived");
    assert_eq!(w.episodes, 1);
    assert_eq!(w.would_act_decisions, 2);
    assert_eq!(w.contained_nodes, vec!["workload/app/Pod/web".to_string()]);
    assert_eq!(w.last_verdict, "RCE reaches the objective");
}

/// The bug fixes: a Breach line whose verdict PROSE starts with "exploitable" must NOT
/// count as a would-act when no typed `Incident` line ever backed it (a pre-ADR-0034 journal, or
/// an entry the model never re-judged after the upgrade) — it replays display-only.
#[test]
fn prose_alone_never_inflates_the_would_act_count_without_a_typed_incident_line() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    let entries = vec![breach(
        now_ms - 60_000,
        "legacy",
        "exploitable — CVE reachable",
    )];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(
        report.would_act_count(),
        0,
        "no typed Incident line ever backed this entry — prose alone must never count"
    );
    assert_eq!(report.attack_no_cut_count(), 0);
    // Pre-schema history still replays — as the honest, quiet "left alone" tail, never a
    // fabricated would-act.
    assert_eq!(report.left_alone_count(), 1);
    assert_eq!(report.left_alone[0].entry, "legacy");
}

#[test]
fn aggregate_classifies_a_cleared_path_as_left_alone() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    let entries = vec![
        incident(
            now_ms - 60_000,
            "api",
            Assessment::NoAttack,
            &[],
            "internal only",
        ),
        breach(now_ms - 60_000, "api", "not exploitable — internal only"),
    ];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(report.would_act_count(), 0);
    assert_eq!(report.left_alone_count(), 1);
    assert_eq!(report.left_alone[0].entry, "api");
}

#[test]
fn aggregate_marks_a_short_lived_episode() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    // An episode that opened then cleared within a minute (< the 5-minute threshold): a typed
    // Attack+cuts decision, then a typed NoAttack decision closing it.
    let entries = vec![
        incident(
            now_ms - 120_000,
            "web",
            Assessment::Attack,
            &["workload/app/Pod/web"],
            "RCE reaches the objective",
        ),
        breach(now_ms - 120_000, "web", "exploitable — RCE"),
        incident(now_ms - 90_000, "web", Assessment::NoAttack, &[], "patched"),
        breach(now_ms - 90_000, "web", "not exploitable — patched"),
    ];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(report.would_act_count(), 1);
    assert!(report.would_act[0].short_lived);
    assert_eq!(report.short_lived_count(), 1);
}

/// ADR-0034 D1: `attack` with an EMPTY `contain` is a VALID, distinct decision — "attack, but no
/// cut warranted" — never a would-act (nothing stands ready to isolate) and never silently
/// folded into the calm left-alone tail (the model did NOT clear the path).
#[test]
fn attack_with_no_cuts_is_its_own_honest_class() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    let entries = vec![
        incident(
            now_ms - 60_000,
            "web",
            Assessment::Attack,
            &[],
            "real attack, no cut warranted",
        ),
        breach(
            now_ms - 60_000,
            "web",
            "exploitable — real attack, no cut warranted",
        ),
    ];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(report.would_act_count(), 0);
    assert_eq!(report.left_alone_count(), 0);
    assert_eq!(report.attack_no_cut_count(), 1);
    assert_eq!(report.attack_no_cut[0].entry, "web");
    assert_eq!(
        report.attack_no_cut[0].reason,
        "real attack, no cut warranted"
    );
}

/// The headline `would_act_count` is the DISTINCT contained-node count, not the entry count: two
/// entries whose decisions together name three cut lines but only two distinct nodes (one
/// shared) must report 2, not 3 and not the 2-row count coincidentally matching here — the
/// dedup is asserted directly against a row whose OWN cut set has two nodes.
#[test]
fn would_act_count_counts_distinct_contained_nodes_not_entries() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let now_ms = 10_000_000;
    let entries = vec![
        incident(
            now_ms - 60_000,
            "web",
            Assessment::Attack,
            &["workload/app/Pod/web"],
            "front door compromised",
        ),
        breach(
            now_ms - 60_000,
            "web",
            "exploitable — front door compromised",
        ),
        incident(
            now_ms - 60_000,
            "api",
            Assessment::Attack,
            &["workload/app/Pod/web", "workload/app/Pod/db-proxy"],
            "front door compromised, pivots to db-proxy",
        ),
        breach(
            now_ms - 60_000,
            "api",
            "exploitable — front door compromised, pivots to db-proxy",
        ),
    ];
    let report = aggregate_report(
        &entries,
        now,
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert_eq!(report.would_act.len(), 2, "two entries would have acted");
    assert_eq!(
        report.would_act_count(),
        2,
        "only two DISTINCT nodes across both entries — 'workload/app/Pod/web' is shared"
    );
}

#[test]
fn empty_journal_reports_journal_empty() {
    let report = aggregate_report(
        &[],
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    );
    assert!(report.journal_empty);
    assert_eq!(report.decisions_in_window, 0);
}
