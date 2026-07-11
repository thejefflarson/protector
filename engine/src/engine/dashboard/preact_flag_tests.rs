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
use super::view_model::props::{FindingsViewProps, Tab};

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
