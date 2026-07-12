//! Page-shell tests for the Preact-only dashboard (ADR-0025 / JEF-398).
//!
//! After the v4 cutover the page emits — for EVERY tab — the SERVER-RENDERED shell (the persistent
//! status strip + the 5-tab nav) wrapping the Preact `#dash-root` mount point. The view BODY is no
//! longer server-rendered; the client reconciles it from `/api/{tab}.json`. These tests pin that
//! contract:
//!
//! - every tab renders the `#dash-root` mount with the right `data-tab` token (no maud body);
//! - the persistent strip + nav stay SERVER-RENDERED (calm-when-blind first paint never depends on
//!   JS) — a warming/blind strip NEVER paints the green all-clear in the first document;
//! - the shell is flag-free (no `data-preact-tabs`, no maud-vs-Preact branch).
//!
//! The per-row / per-view honesty guarantees (never-green-when-blind, empty⇒explicit-none, escaping)
//! now live at the JSON-props boundary (`view_model::props::serialize_tests`, `api_json_tests`) and
//! in the client `vitest` suite — the seam the client actually consumes.

use std::time::SystemTime;

use super::page;
use super::view_model::build_status_strip;
use super::view_model::props::Tab;
use crate::engine::state::{
    ModelHealth, Readiness, ReadinessConfig, RuntimeCoverage, derive_readiness,
};

const TABS: [Tab; 5] = [
    Tab::Findings,
    Tab::Alerts,
    Tab::Action,
    Tab::Readiness,
    Tab::Admission,
];

/// A fully-covered, actively-judging readiness — the only state that can honestly go green.
fn judging_readiness() -> Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
        checking_images: 0,
    };
    derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &RuntimeCoverage::default(),
    )
}

/// A warming (no completed pass) readiness — not honestly calm.
fn warming_readiness() -> Readiness {
    derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        None,
        &RuntimeCoverage::default(),
    )
}

#[test]
fn every_tab_renders_the_dash_root_mount_with_its_token() {
    let strip = build_status_strip(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    for tab in TABS {
        let html = page::page(&strip, tab).into_string();
        assert!(
            html.contains("id=\"dash-root\""),
            "{tab:?} must render the Preact mount point"
        );
        assert!(
            html.contains(&format!("data-tab=\"{}\"", tab.token())),
            "{tab:?} stamps its token so the client's first paint matches the document"
        );
    }
}

#[test]
fn the_shell_is_flag_free_and_carries_no_maud_body() {
    // The per-tab flag is gone (JEF-398): the mount carries no `data-preact-tabs` list — every tab
    // is client-rendered, so the client intercepts every swap.
    let strip = build_status_strip(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::page(&strip, Tab::Findings).into_string();
    assert!(
        !html.contains("data-preact-tabs"),
        "no per-tab flag list — every tab is Preact now"
    );
    // No maud view body leaks into the shell (the table/detail markup is client-only now).
    assert!(!html.contains("row-detail"), "no maud findings body");
    assert!(!html.contains("class=\"chain\""), "no maud path chain");
}

#[test]
fn the_strip_and_nav_stay_server_rendered_on_every_tab() {
    let strip = build_status_strip(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    for tab in TABS {
        let html = page::page(&strip, tab).into_string();
        assert!(
            html.contains("header"),
            "{tab:?} server-renders the strip header"
        );
        assert!(html.contains("nav"), "{tab:?} server-renders the tab nav");
        // The active tab is marked in the server nav so the first paint highlights correctly.
        assert!(
            html.contains("tab-active"),
            "{tab:?} marks the active nav tab server-side"
        );
    }
}

#[test]
fn a_warming_strip_never_paints_a_green_all_clear_in_the_first_document() {
    // Calm-when-blind first paint (ADR-0025): the SERVER-rendered strip must never claim all-clear
    // before any JS runs when the model is warming/blind — the safety-critical honesty signal never
    // depends on the client bundle.
    let strip = build_status_strip("prod".into(), &[], &[], &warming_readiness(), None);
    let html = page::page(&strip, Tab::Findings).into_string();
    assert!(
        !html.contains("all clear"),
        "a warming dashboard's server first paint must never claim all-clear"
    );
    assert!(
        html.contains("warming up"),
        "the honest warming banner paints server-side"
    );
}

#[test]
fn a_judging_empty_strip_can_paint_the_honest_green() {
    // The complement: an actively-judging, fully-covered strip IS allowed to read all-clear in the
    // server first paint — greenness is honest only in this state (the token is server-derived).
    let strip = build_status_strip(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::page(&strip, Tab::Findings).into_string();
    assert!(
        html.contains("all clear") || html.contains("model judging"),
        "an actively-judging strip reads the honest calm register server-side"
    );
}
