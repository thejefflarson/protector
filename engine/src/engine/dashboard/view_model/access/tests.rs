//! Tests for the "Access" view_model mapping (JEF-490): the TIER-AWARE redaction of the audit rows
//! to the caller's OWN tier is the crux — a redacted-tier viewer never learns the target of a raw
//! pull; a forensic/raw viewer does. Plus: the bulk-scope label is shown to everyone, the raw
//! keyline flag tracks the pull's tier, and the durable flag / pull count flow through honestly.

use super::*;
use crate::engine::dashboard::view_model::props::{AccessTier, StatusStripProps};
use crate::engine::mcp::{EffectiveTier, WORKLOAD_IDENTITY_WITHHELD};

fn strip() -> StatusStripProps {
    // A minimal strip; the access mapper does not inspect it, just carries it.
    StatusStripProps {
        cluster: "prod".into(),
        armed: false,
        model_judging: true,
        warming_up: false,
        model_attached: true,
        coverage: vec![],
        coverage_alert: None,
        last_pass: None,
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 0,
        escalated_count: 0,
        signing_regression_breach: 0,
        signing_regression_uncertain: 0,
        auth_mode: crate::engine::dashboard::view_model::props::AuthMode::EdgeOnly,
    }
}

fn record(subject: &str, entry: &str, tool: &str, tier: EffectiveTier) -> AccessRecord {
    AccessRecord {
        subject: subject.into(),
        entry: entry.into(),
        tool: tool.into(),
        tier,
        time_unix_secs: unix_now().saturating_sub(30),
    }
}

/// A raw pull of a specific crown-jewel entry — the row whose target must NOT leak to a lower tier.
fn raw_pull() -> AccessRecord {
    record(
        "alice@corp.example",
        "workload/app/Pod/web",
        "explain_verdict",
        EffectiveTier::Raw,
    )
}

#[test]
fn a_redacted_viewer_never_sees_a_raw_pulls_target_only_the_sentinel() {
    let view = build(strip(), Tier::Redacted, &[raw_pull()], true);
    assert_eq!(view.pulls.len(), 1);
    let row = &view.pulls[0];
    // The who/tool/tier are visible (an operator may see THAT a raw pull happened, and by whom)…
    assert_eq!(row.who, "alice@corp.example");
    assert_eq!(row.tool, "explain_verdict");
    assert_eq!(row.tier, AccessTier::Raw);
    assert!(row.raw, "a raw pull carries the loud keyline flag");
    // …but the TARGET is withheld — the SAME sentinel the tool emits, never the workload identity.
    assert_eq!(row.target, WORKLOAD_IDENTITY_WITHHELD);
    assert_ne!(
        row.target, "workload/app/Pod/web",
        "the crown-jewel target must not leak to a redacted-tier viewer"
    );
    // The caller's own chip is redacted, and only the redacted reveal-row is held.
    assert_eq!(view.tier, AccessTier::Redacted);
    let held: Vec<AccessTier> = view
        .reveals
        .iter()
        .filter(|r| r.held)
        .map(|r| r.tier)
        .collect();
    assert_eq!(held, vec![AccessTier::Redacted]);
}

#[test]
fn a_forensic_viewer_sees_a_raw_pulls_workload_target() {
    let view = build(strip(), Tier::Forensic, &[raw_pull()], true);
    let row = &view.pulls[0];
    assert_eq!(
        row.target, "workload/app/Pod/web",
        "forensic+ unlocks the workload identity target"
    );
    assert!(
        row.raw,
        "the pull's own tier is still raw (the keyline stands)"
    );
    assert_eq!(view.tier, AccessTier::Forensic);
}

#[test]
fn a_raw_viewer_sees_the_target_and_holds_every_reveal_row() {
    let view = build(strip(), Tier::Raw, &[raw_pull()], true);
    assert_eq!(view.pulls[0].target, "workload/app/Pod/web");
    assert!(
        view.reveals.iter().all(|r| r.held),
        "a raw-tier caller holds every tier level"
    );
}

#[test]
fn the_bulk_scope_label_is_shown_to_every_tier() {
    // A bulk forensic pull's target is the fixed scope label — it leaks nothing, so even a
    // redacted-tier viewer sees it verbatim (never the workload sentinel).
    let bulk = record(
        "bob@corp.example",
        BULK_SCOPE,
        "list_findings",
        EffectiveTier::Forensic,
    );
    let view = build(strip(), Tier::Redacted, &[bulk], false);
    assert_eq!(view.pulls[0].target, BULK_SCOPE);
    assert!(!view.pulls[0].raw, "a forensic pull is not a raw keyline");
}

#[test]
fn durable_flag_and_pull_list_flow_through() {
    let empty = build(strip(), Tier::Raw, &[], true);
    assert!(empty.pulls.is_empty());
    assert!(empty.durable);

    let populated = build(strip(), Tier::Raw, &[raw_pull(), raw_pull()], false);
    assert_eq!(populated.pulls.len(), 2);
    assert!(!populated.durable, "in-memory reports non-durable honestly");
}
