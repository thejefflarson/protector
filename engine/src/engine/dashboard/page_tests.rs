//! Page-shell tests for the ROOT-ONLY dashboard document (JEF-408, superseding ADR-0025's
//! server-rendered strip/nav).
//!
//! The page now emits — for EVERY tab — a ROOT-ONLY body: just the Preact `#dash-root` mount point
//! (carrying its `data-tab` token) + the deferred bundle `<script>`. ALL body HTML — the status
//! strip, the tab nav, and the view body — is client-rendered from `/api/{tab}.json`. These tests
//! pin that contract:
//!
//! - every tab renders the `#dash-root` mount with the right `data-tab` token;
//! - the body carries NO server-rendered strip (`.strip`) or nav (`.tabs`) — those moved to the
//!   client (JEF-408);
//! - the `<head>` still carries the cluster label in the `<title>` (head metadata is not body HTML);
//! - the shell is flag-free (no `data-preact-tabs`, no maud-vs-Preact branch).
//!
//! The honesty guarantees (never-green-when-blind, all-clear / watching / judging-state tokens) now
//! live entirely at the JSON-props boundary (`view_model::props::serialize_tests`, `api_json_tests`)
//! and in the client `vitest` suite — a blank pre-fetch body is honest (absent ≠ green).

use super::page;
use super::view_model::props::Tab;

const TABS: [Tab; 6] = [
    Tab::Findings,
    Tab::Alerts,
    Tab::Action,
    Tab::Readiness,
    Tab::Admission,
    Tab::Access,
];

#[test]
fn every_tab_renders_the_dash_root_mount_with_its_token() {
    for tab in TABS {
        let html = page::page("prod", tab).into_string();
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
fn the_body_is_root_only_no_server_strip_or_nav() {
    // JEF-408: the LAST server-rendered body parts (the status strip + the tab nav) moved to the
    // client. The body must carry NO `.strip` header and NO `.tabs` nav — only the mount + script.
    for tab in TABS {
        let html = page::page("prod", tab).into_string();
        assert!(
            !html.contains("class=\"strip\""),
            "{tab:?}: the status strip is client-rendered now — no server `.strip`"
        );
        assert!(
            !html.contains("class=\"tabs\"") && !html.contains("nav.tabs"),
            "{tab:?}: the tab nav is client-rendered now — no server `.tabs`"
        );
        // No server-rendered strip axis / headline leaks into the shell either.
        assert!(
            !html.contains("model judging") && !html.contains("all clear"),
            "{tab:?}: no server-rendered judging axis — the strip is client-only"
        );
    }
}

#[test]
fn the_head_still_carries_the_cluster_in_the_title() {
    // Head metadata is NOT body HTML — the `<title>` keeps the cluster label so the browser tab and
    // history read correctly before any JS runs.
    let html = page::page("prod-east", Tab::Findings).into_string();
    assert!(
        html.contains("<title>protector \u{2014} prod-east</title>"),
        "the head title carries the cluster label: {html}"
    );
}

#[test]
fn the_shell_is_flag_free_and_carries_no_maud_body() {
    // The per-tab flag is gone (JEF-398): no `data-preact-tabs` list — every tab is client-rendered.
    let html = page::page("prod", Tab::Findings).into_string();
    assert!(
        !html.contains("data-preact-tabs"),
        "no per-tab flag list — every tab is Preact now"
    );
    // No maud view body leaks into the shell (the table/detail markup is client-only now).
    assert!(!html.contains("row-detail"), "no maud findings body");
    assert!(!html.contains("class=\"chain\""), "no maud path chain");
}

#[test]
fn the_shell_loads_the_bundle_same_origin() {
    // The client bundle is loaded same-origin (no CDN — zero egress) and deferred so the mount
    // exists when it runs.
    let html = page::page("prod", Tab::Findings).into_string();
    assert!(
        html.contains("src=\"/assets/dashboard.js\""),
        "the shell loads the built bundle from its own origin"
    );
    assert!(
        html.contains("href=\"/assets/dashboard.css\""),
        "the shell links the same-origin stylesheet"
    );
}
