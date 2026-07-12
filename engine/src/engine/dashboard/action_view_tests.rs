//! Render-level tests for the dashboard's Action / Readiness secondary views: the persistent
//! strip + 4-tab nav, the three lifecycle sections (proposed cuts → left alone → judgement
//! audit), the honest journal-empty/none-in-window states, per-input readiness rows, and the
//! escaping of untrusted verdict/reversion/judgement prose. Split out of `tests.rs` purely to
//! keep every file under the 1,000-line cap (CLAUDE.md). They drive the view_model + components
//! directly (no HTTP, no engine), so they are fast and pure. Shared readiness/finding fixtures
//! come from `super::tests`, matching the sibling `*_tests.rs` pattern.

use std::time::SystemTime;

use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{
    Finding, Judgement, LeftAloneEntry, ModelHealth, ReadinessConfig, Report, ReversionRecord,
    RuntimeCoverage, WouldActEntry, derive_readiness,
};

use super::PreactTabs;
use super::page;
use super::tests::{breach_finding, judging_readiness};
use super::view_model::{
    build_action_view, build_findings_view, build_readiness_view, build_status_strip,
};

/// Build the persistent strip from a given findings snapshot (for the secondary-view tests).
fn strip_from(findings: &[Finding]) -> super::view_model::props::StatusStripProps {
    build_status_strip(
        "prod".into(),
        findings,
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    )
}

/// Build an Action view over the given report, with no reversions/judgements (the trust-only cases).
fn action_view_for(report: &Report) -> super::view_model::props::ActionViewProps {
    build_action_view(strip_from(&[]), report, &[], &[])
}

#[test]
fn secondary_views_carry_the_persistent_strip_and_nav_without_phase2_badge() {
    // The Action page (a real view) carries the strip + the 4-tab nav, and the phase-2 badge
    // is gone from the nav.
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 0,
        journal_empty: true,
        would_act: vec![],
        left_alone: vec![],
    };
    let html = page::action_page(&action_view_for(&report), PreactTabs::default()).into_string();
    assert!(!html.contains("phase 2"), "the phase-2 badge is gone");
    assert!(html.contains("Findings"), "the nav still offers Findings");
    assert!(html.contains("Action"), "and the merged Action tab");
    // The old Trust/Activity labels are gone from the nav.
    assert!(!html.contains(">Trust<"), "no Trust nav label remains");
    assert!(
        !html.contains(">Activity<"),
        "no Activity nav label remains"
    );
    assert!(html.contains("model judging"), "the strip is present");
}

#[test]
fn action_view_has_the_three_lifecycle_sections_in_order() {
    // Proposed cuts → left alone → judgement audit, top to bottom.
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 0,
        journal_empty: false,
        would_act: vec![],
        left_alone: vec![],
    };
    let html = page::action_page(&action_view_for(&report), PreactTabs::default()).into_string();
    let proposed = html.find("proposed cuts").expect("proposed cuts section");
    let cleared = html
        .find("left alone (cleared)")
        .expect("left alone section");
    let audit = html
        .find("judgement audit")
        .expect("judgement audit section");
    assert!(
        proposed < cleared && cleared < audit,
        "the sections render in lifecycle order: proposed cuts → left alone → judgement audit"
    );
}

#[test]
fn action_view_distinguishes_journal_empty_from_none_in_window() {
    // journal_empty ⇒ the "no decisions journaled yet" honest state.
    let empty = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 0,
        journal_empty: true,
        would_act: vec![],
        left_alone: vec![],
    };
    let html = page::action_page(&action_view_for(&empty), PreactTabs::default()).into_string();
    assert!(
        html.contains("no decisions journaled yet"),
        "an empty journal reads as no-history, not all-clear"
    );
    assert!(html.contains("not an all-clear"));

    // History, but none in window ⇒ the "none in the last …" honest state instead.
    let none_in_window = Report {
        journal_empty: false,
        ..empty
    };
    let html2 =
        page::action_page(&action_view_for(&none_in_window), PreactTabs::default()).into_string();
    assert!(
        !html2.contains("no decisions journaled yet"),
        "history exists, so it is NOT the journal-empty state"
    );
    assert!(html2.contains("none in the last"), "it is none-in-window");
}

#[test]
fn action_view_renders_proposed_cuts_and_left_alone_with_lifecycle_status() {
    let report = Report {
        window_secs: 7 * 24 * 3600,
        short_lived_secs: 300,
        decisions_in_window: 4,
        journal_empty: false,
        would_act: vec![
            WouldActEntry {
                entry: "deployment/edge/api".into(),
                episodes: 1,
                would_act_decisions: 2,
                max_lifetime_secs: 600,
                open: true,
                short_lived: false,
                coverage_gap: false,
                last_verdict: "exploitable — KEV RCE reachable".into(),
            },
            WouldActEntry {
                entry: "deployment/cron/job".into(),
                episodes: 1,
                would_act_decisions: 1,
                max_lifetime_secs: 30,
                open: false,
                short_lived: true,
                coverage_gap: true,
                last_verdict: "exploitable — but cleared in 30s".into(),
            },
        ],
        left_alone: vec![LeftAloneEntry {
            entry: "deployment/web/marketing".into(),
            verdict: "not exploitable — internal only".into(),
        }],
    };
    let html = page::action_page(&action_view_for(&report), PreactTabs::default()).into_string();
    assert!(html.contains("proposed cuts"));
    assert!(html.contains("left alone (cleared)"));
    // Lifecycle status words ride alongside the glyph (meaning never by colour alone).
    assert!(
        html.contains("would cut") && html.contains("still standing"),
        "the open episode carries the would-cut-open lifecycle status"
    );
    assert!(
        html.contains("likely false positive"),
        "the short-lived one"
    );
    assert!(html.contains("scrutinise"), "the coverage-gap one");
    assert!(html.contains("cleared"), "the left-alone half");
    // Untrusted verdict prose + node keys are present (escaped by maud).
    assert!(html.contains("deployment/edge/api"));
}

#[test]
fn action_view_renders_reverted_cuts_under_proposed_with_honest_empty() {
    // A self-reverted cut appears in the proposed-cuts section as the reverted tail of the lifecycle.
    let now_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 1,
        journal_empty: false,
        would_act: vec![],
        left_alone: vec![],
    };
    let reversions = vec![ReversionRecord {
        cut: "deployment/edge/legacy -[reaches/Tcp/8080]-> service/admin".into(),
        reason: "breach condition cleared".into(),
        at_ms: now_ms.saturating_sub(90_000),
    }];
    let v = build_action_view(strip_from(&[]), &report, &reversions, &[]);
    let html = page::action_page(&v, PreactTabs::default()).into_string();
    assert!(html.contains("reverted"), "the reverted tag");
    assert!(html.contains("breach condition cleared"), "the reason");

    // Empty reversions ⇒ the honest "no cuts reverted yet" line, never a blank.
    let v2 = build_action_view(strip_from(&[]), &report, &[], &[]);
    let html2 = page::action_page(&v2, PreactTabs::default()).into_string();
    assert!(html2.contains("no cuts reverted yet"));
}

#[test]
fn readiness_view_renders_a_row_per_input_with_enable_instruction() {
    // A model attached but KEV absent: the Readiness view shows the KEV row's "enable with" var.
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 0, // absent
        epss_count: 5,
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
        checking_images: 0,
    };
    let readiness = derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &RuntimeCoverage::default(),
    );
    let v = build_readiness_view(strip_from(&[]), &readiness);
    let html = page::readiness_page(&v, PreactTabs::default()).into_string();
    assert!(html.contains("decision inputs"), "the section heading");
    assert!(html.contains("KEV catalogue"), "the KEV row label");
    // The absent KEV row surfaces the env var to enable it (the per-feed how-to-enable surface).
    assert!(html.contains("PROTECTOR_KEV_FILE"));
    assert!(
        html.contains("enable with"),
        "framed as an action for a gap"
    );
    // State carried by word, not colour alone.
    assert!(html.contains("absent"));
    assert!(html.contains("present"), "covered inputs read present");
}

#[test]
fn action_view_renders_judgement_audit_with_honest_empties() {
    // With data: the judgement renders in the judgement-audit section.
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 1,
        journal_empty: false,
        would_act: vec![],
        left_alone: vec![],
    };
    let judgements = vec![Judgement {
        entry: "deployment/edge/api".into(),
        objectives: 1,
        verdict: "Exploitable".into(),
        prompt: Some("the prompt".into()),
        reply: None, // timed out ⇒ honest "no reply"
    }];
    let v = build_action_view(strip_from(&[]), &report, &[], &judgements);
    let html = page::action_page(&v, PreactTabs::default()).into_string();
    assert!(html.contains("judgement audit"));
    assert!(html.contains("deployment/edge/api"), "the judged entry");
    assert!(
        html.contains("no reply"),
        "an absent reply renders the honest no-reply line, never a blank"
    );

    // Empty: the judgement section renders its honest empty state, not a blank.
    let empty = build_action_view(strip_from(&[]), &report, &[], &[]);
    let html2 = page::action_page(&empty, PreactTabs::default()).into_string();
    assert!(html2.contains("no judgements recorded"));
}

#[test]
fn secondary_view_strip_stays_non_green_when_findings_hold_a_breach() {
    // The persistent strip must reflect the REAL cluster posture on a secondary tab: a breach in
    // Findings keeps the Action strip out of the green all-clear (invariant #1, carried everywhere).
    let breach = breach_finding("endpoint/a", Verdict::Confirmed);
    let strip = build_status_strip(
        "prod".into(),
        &[breach],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    assert_eq!(
        strip.breach_count, 1,
        "the strip carries the true breach count"
    );
    assert!(
        !strip.all_clear(),
        "a breach forbids the green all-clear on any tab"
    );
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 0,
        journal_empty: true,
        would_act: vec![],
        left_alone: vec![],
    };
    let html = page::action_page(
        &build_action_view(strip, &report, &[], &[]),
        PreactTabs::default(),
    )
    .into_string();
    assert!(
        !html.contains("all clear"),
        "the Action tab's strip never reads all-clear while Findings holds a breach"
    );
}

#[test]
fn untrusted_text_is_escaped_in_the_action_view() {
    let evil = "<script>alert('x')</script>";
    // An untrusted would-act verdict + entry key, an untrusted reversion reason + cut, and an
    // untrusted judgement prompt — all three sections at once.
    let report = Report {
        window_secs: 3600,
        short_lived_secs: 300,
        decisions_in_window: 1,
        journal_empty: false,
        would_act: vec![WouldActEntry {
            entry: evil.into(),
            episodes: 1,
            would_act_decisions: 1,
            max_lifetime_secs: 10,
            open: true,
            short_lived: false,
            coverage_gap: false,
            last_verdict: format!("exploitable {evil}"),
        }],
        left_alone: vec![LeftAloneEntry {
            entry: evil.into(),
            verdict: format!("cleared {evil}"),
        }],
    };
    let reversions = vec![ReversionRecord {
        cut: format!("cut {evil}"),
        reason: format!("reason {evil}"),
        at_ms: 0,
    }];
    let judgements = vec![Judgement {
        entry: evil.into(),
        objectives: 1,
        verdict: "x".into(),
        prompt: Some(format!("prompt {evil}")),
        reply: Some(format!("reply {evil}")),
    }];
    let html = page::action_page(
        &build_action_view(strip_from(&[]), &report, &reversions, &judgements),
        PreactTabs::default(),
    )
    .into_string();
    assert!(
        !html.contains("<script>alert"),
        "raw script must not reach output"
    );
    assert!(html.contains("&lt;script&gt;"), "it is escaped");
}

#[test]
fn fragment_has_no_document_shell() {
    let view = build_findings_view(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let frag = page::findings_fragment(&view, PreactTabs::default()).into_string();
    assert!(!frag.contains("<!DOCTYPE"), "a fragment carries no doctype");
    assert!(!frag.contains("<html"), "nor a document element");
    // But it does carry the strip (so a poll refreshes coverage/freshness).
    assert!(frag.contains("strip"));
}
