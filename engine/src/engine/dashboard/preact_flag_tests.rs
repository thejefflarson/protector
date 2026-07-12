//! The per-tab Preact-flag RENDER tests (ADR-0025 / JEF-397): the Findings page emits the client
//! MOUNT POINT (`<div id="dash-root" data-tab="findings">`) with the maud table OMITTED when the
//! tab is flagged Preact, and the FULL maud table with NO mount when it is not (the default).
//! The status strip stays SERVER-RENDERED in BOTH cases (first-paint honesty must never depend on
//! JS) — the flag swaps only the view body under the nav.

use std::time::SystemTime;

use crate::engine::reason::adjudicate::Verdict;

use super::PreactTabs;
use super::page;
use super::tests::{breach_finding, judging_readiness};
use super::view_model::build_findings_view;
use super::view_model::props::{
    ActionViewProps, AdmissionViewProps, AlertsViewProps, FindingsViewProps, ReadinessViewProps,
    StatusStripProps, Tab,
};

/// A one-breach Findings view — enough to render a real maud table (so the mount-vs-table swap is
/// observable) with a live, judging strip.
fn one_breach_view() -> FindingsViewProps {
    let f = breach_finding("endpoint/web", Verdict::Confirmed);
    build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    )
}

#[test]
fn flag_off_renders_the_maud_table_and_no_mount_point() {
    // Default: the maud body renders; there is no client mount point.
    let view = one_breach_view();
    let html = page::findings_page(&view, PreactTabs::default()).into_string();
    assert!(
        html.contains("table class=\"findings\""),
        "flag OFF renders the server maud findings table"
    );
    assert!(
        !html.contains("id=\"dash-root\""),
        "flag OFF emits NO Preact mount point"
    );
}

#[test]
fn flag_on_renders_the_mount_point_and_omits_the_maud_table() {
    // Flipped on: the findings body is the client mount point; the maud table is gone.
    let view = one_breach_view();
    let html = page::findings_page(&view, PreactTabs::parse("findings")).into_string();
    assert!(
        html.contains("id=\"dash-root\""),
        "flag ON emits the Preact mount point"
    );
    assert!(
        html.contains("data-tab=\"findings\""),
        "the mount point stamps the active tab for the client"
    );
    assert!(
        !html.contains("table class=\"findings\""),
        "flag ON omits the server maud findings table (the client renders it)"
    );
}

#[test]
fn the_status_strip_stays_server_rendered_under_the_flag() {
    // The load-bearing invariant: even with Findings on the client, the honesty strip is
    // server-rendered in the initial document, so a JS failure can never leave a stale green.
    let view = one_breach_view();
    let html = page::findings_page(&view, PreactTabs::parse("findings")).into_string();
    assert!(
        html.contains("class=\"strip\""),
        "the persistent status strip is server-rendered even when the body is the client mount"
    );
    // And the nav is still server-rendered so the tabs paint without JS.
    assert!(
        html.contains("class=\"tabs\""),
        "the tab nav is server-rendered above the mount"
    );
}

#[test]
fn flagging_another_tab_does_not_affect_findings() {
    // Naming a DIFFERENT tab leaves Findings on maud — the flag is per-tab and Findings is the only
    // ported view in JEF-397.
    let view = one_breach_view();
    let html = page::findings_page(&view, PreactTabs::parse("alerts")).into_string();
    assert!(
        html.contains("table class=\"findings\""),
        "flagging `alerts` must not turn Findings into the client mount"
    );
    assert!(!html.contains("id=\"dash-root\""));
    assert!(!PreactTabs::parse("alerts").is_preact(Tab::Findings));
}

// ----- JEF-400: the four secondary views (Alerts / Action / Readiness / Admission) ------------
//
// Each ships behind the SAME per-tab flag: flag OFF renders its maud body with no mount point;
// flag ON emits the `#dash-root` client mount (stamped `data-tab` + `data-preact-tabs`) and OMITS
// the maud body. The status strip stays server-rendered in BOTH cases. A shared strip (borrowed
// from the one-breach findings view) frames each minimal secondary view.

/// The server strip to frame the secondary views under test.
fn a_strip() -> StatusStripProps {
    one_breach_view().strip
}

fn an_alerts_view() -> AlertsViewProps {
    AlertsViewProps {
        strip: a_strip(),
        alerts: Vec::new(),
        blind_caveat: None,
    }
}

fn an_action_view() -> ActionViewProps {
    ActionViewProps {
        strip: a_strip(),
        window_human: "7d".into(),
        journal_empty: false,
        decisions_in_window: 0,
        would_act: Vec::new(),
        reversions: Vec::new(),
        left_alone: Vec::new(),
        judgements: Vec::new(),
        would_act_count: 0,
        short_lived_count: 0,
        coverage_gap_count: 0,
        left_alone_count: 0,
        reverted_count: 0,
    }
}

fn a_readiness_view() -> ReadinessViewProps {
    ReadinessViewProps {
        strip: a_strip(),
        rows: Vec::new(),
    }
}

fn an_admission_view() -> AdmissionViewProps {
    AdmissionViewProps {
        strip: a_strip(),
        admitted: 0,
        audited: 0,
        denied: 0,
        total: 0,
        signing: Vec::new(),
        rows: Vec::new(),
    }
}

/// A secondary-view flag case: `(off_html, on_html, maud_marker)` for one tab. Each assertion is the
/// same shape as Findings' — the only per-tab variation is which maud class marks the server body.
fn assert_flag_swaps(off_html: &str, on_html: &str, maud_marker: &str, tab_token: &str) {
    // OFF: the maud body renders; no mount point.
    assert!(
        off_html.contains(maud_marker),
        "flag OFF renders the server maud body (`{maud_marker}`)"
    );
    assert!(
        !off_html.contains("id=\"dash-root\""),
        "flag OFF emits NO Preact mount point"
    );
    // ON: the client mount point; the maud body is gone.
    assert!(
        on_html.contains("id=\"dash-root\""),
        "flag ON emits the Preact mount point"
    );
    assert!(
        on_html.contains(&format!("data-tab=\"{tab_token}\"")),
        "the mount stamps the active tab `{tab_token}` for the client"
    );
    assert!(
        on_html.contains(&format!("data-preact-tabs=\"{tab_token}\"")),
        "the mount lists the flagged tabs so the client swaps only among them"
    );
    assert!(
        !on_html.contains(maud_marker),
        "flag ON omits the server maud body (`{maud_marker}`) — the client renders it"
    );
    // The strip stays server-rendered under the flag (first-paint honesty), both cases.
    assert!(
        on_html.contains("class=\"strip\""),
        "the status strip is server-rendered even when the body is the client mount"
    );
}

#[test]
fn alerts_swaps_maud_body_for_the_mount_under_the_flag() {
    let v = an_alerts_view();
    assert_flag_swaps(
        &page::alerts_page(&v, PreactTabs::default()).into_string(),
        &page::alerts_page(&v, PreactTabs::parse("alerts")).into_string(),
        "view-alerts",
        "alerts",
    );
}

#[test]
fn action_swaps_maud_body_for_the_mount_under_the_flag() {
    let v = an_action_view();
    assert_flag_swaps(
        &page::action_page(&v, PreactTabs::default()).into_string(),
        &page::action_page(&v, PreactTabs::parse("action")).into_string(),
        "view-action",
        "action",
    );
}

#[test]
fn readiness_swaps_maud_body_for_the_mount_under_the_flag() {
    let v = a_readiness_view();
    assert_flag_swaps(
        &page::readiness_page(&v, PreactTabs::default()).into_string(),
        &page::readiness_page(&v, PreactTabs::parse("readiness")).into_string(),
        "view-readiness",
        "readiness",
    );
}

#[test]
fn admission_swaps_maud_body_for_the_mount_under_the_flag() {
    let v = an_admission_view();
    assert_flag_swaps(
        &page::admission_page(&v, PreactTabs::default()).into_string(),
        &page::admission_page(&v, PreactTabs::parse("admission")).into_string(),
        "view-admission",
        "admission",
    );
}

#[test]
fn each_secondary_flag_is_independent_and_default_off() {
    // Flipping ONE secondary tab leaves the others on maud, and the default flips none — the PR
    // ships dark (no operator-visible change until an explicit flag flip).
    let only_alerts = PreactTabs::parse("alerts");
    assert!(only_alerts.is_preact(Tab::Alerts));
    for other in [Tab::Findings, Tab::Action, Tab::Readiness, Tab::Admission] {
        assert!(
            !only_alerts.is_preact(other),
            "{other:?} must stay maud when only `alerts` is flagged"
        );
    }
    for tab in [
        Tab::Findings,
        Tab::Alerts,
        Tab::Action,
        Tab::Readiness,
        Tab::Admission,
    ] {
        assert!(
            !PreactTabs::default().is_preact(tab),
            "{tab:?} must default OFF — the PR ships dark"
        );
    }
}

#[test]
fn the_mount_lists_every_flagged_tab_for_the_client_swap() {
    // With several tabs flagged, the mount's `data-preact-tabs` carries them all (space-separated,
    // in tab order) so the client intercepts a swap ONLY among the client-rendered tabs.
    let tabs = PreactTabs::parse("findings,readiness,admission");
    let html = page::readiness_page(&a_readiness_view(), tabs).into_string();
    assert!(
        html.contains("data-preact-tabs=\"findings readiness admission\""),
        "the mount lists every flagged tab in order, got: {html}"
    );
    // A non-flagged tab is absent from the list (a swap to it stays a full server navigation).
    assert!(!tabs.is_preact(Tab::Alerts));
    assert!(!tabs.is_preact(Tab::Action));
}
