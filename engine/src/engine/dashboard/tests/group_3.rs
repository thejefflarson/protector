#![allow(unused_imports)]
//! Render-level findings tests (JEF-202): the expanded card body, the dense-table rows, the
//! tier split, and the collapsed graph — asserted against the migrated maud components via
//! the `card_body` / `row_html` / `render_html` helpers (JEF-205). The pure Props-shaping
//! logic (verdict gist, attention rank, what-to-do, CVE blocks) lives in the
//! `view_model::findings` and `components::findings` test modules.
use super::*;
use crate::engine::dashboard::model::*;
use crate::engine::dashboard::page::FINDINGS_COLS;
use crate::engine::dashboard::page::{render_fragment, render_html};
use crate::engine::dashboard::view_model::readiness_data::*;
use crate::engine::dashboard::view_model::report_data::*;
use crate::engine::dashboard::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{Advisory, NodeKey, Reachability, Severity, Vulnerability};
use crate::engine::reason::proof::Link;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn expanded_card_body_is_verdict_first_with_rail_todo_and_aria() {
    // JEF-202: the EXPANDED row body keeps the full card — the verbatim model words lead,
    // then the proof rail, then the what-to-do, then the graph (collapsed-by-default, with
    // its aria-label preserved).
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        true,
        Some("not exploitable — authorized RBAC, no CVE"),
    );
    let html = card_body("workload/app/Pod/web", &[&f]);
    assert!(html.contains("[SAFE]"), "the posture chip carries text");
    assert!(html.contains("chip-safe"));
    assert!(html.contains("not exploitable — authorized RBAC, no CVE"));
    assert!(html.contains("proven facts"));
    assert!(html.contains("internet-reachable"));
    assert!(html.contains("what to do:"));
    assert!(html.contains("Revoke the `get/secrets` RBAC grant"));
    assert!(html.contains("re-checks next pass"));
    assert!(html.contains("data-aria=\""));
    assert!(html.contains("Attack-path graph"));
    let chip_at = html.find("[SAFE]").unwrap();
    let graph_at = html.find("class=\"mermaid\"").unwrap();
    assert!(chip_at < graph_at, "the verdict leads the card body");
}

#[test]
fn expanded_card_body_awaiting_state_is_honest_not_clear() {
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        None,
    );
    let html = card_body("workload/app/Pod/web", &[&f]);
    assert!(html.contains("[awaiting judgement]"));
    assert!(html.contains("chip-awaiting"));
    assert!(html.contains("hasn't reached this entry yet"));
}

#[test]
fn certainty_rail_renders_entry_relation_and_cve_facts() {
    // The rail facts (internet-reachability + the humanized terminal relation) render in the
    // card body, and the CVE fact reads from the entry evidence (not the prose verdict).
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        Some("not exploitable — even though CVE-2021-44228 is on the image, RBAC denies it"),
    );
    let html = card_body("workload/app/Pod/web", &[&f]);
    assert!(html.contains("internet-reachable"));
    assert!(html.contains("mounts (direct read)"));
    // No CVE evidence ⇒ the honest-empty rail fact, NOT scraped from the prose CVE id.
    assert!(
        html.contains("no KEV or critical CVE"),
        "honest-empty rail: {html}"
    );
    assert!(html.contains("lower-severity CVEs not shown"));
    assert!(
        !html.contains("CVE present"),
        "prose CVE must not fabricate a fact"
    );

    // With real CVE evidence the rail reports the counts and never says none.
    let mut g = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "auto-eligible",
        "can-read",
        true,
        Some("exploitable — reachable over the network"),
    );
    g.evidence = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::Critical, false),
            cve("CVE-2021-0003", Severity::High, false),
        ],
        runtime: vec![],
    };
    let ghtml = card_body("workload/app/Pod/web", &[&g]);
    assert!(ghtml.contains("CVE present") && ghtml.contains("<b>3</b> known vulns"));
    assert!(ghtml.contains("2 critical") && ghtml.contains("1 KEV-listed"));
}

#[test]
fn what_to_do_escapes_injected_object_names_in_the_card() {
    // JEF-179: the injected names are untrusted node keys — HTML-escaped by the maud detail
    // component so a crafted name can't break out of the rendered card.
    let mut durable = finding(
        "workload/app/Pod/web",
        "secret/app/<img src=x onerror=alert(1)>",
        "durable-fix PR",
        "can-read",
        true,
        None,
    );
    durable.path[1].to = "secret/app/<img src=x onerror=alert(1)>".into();
    let html = card_body("workload/app/Pod/web", &[&durable]);
    assert!(!html.contains("<img"), "raw tag must not survive: {html}");
    assert!(
        html.contains("&lt;img"),
        "name must be HTML-escaped: {html}"
    );
}

#[test]
fn safe_broad_row_reads_working_as_intended_and_calm_class() {
    let entry = "workload/argocd/Pod/argocd-server";
    let fs = broad_findings(
        entry,
        Some("not exploitable — authorized RBAC, no CVE, no behavior"),
    );
    let refs: Vec<&Finding> = fs.iter().collect();
    let html = row_html(entry, &refs);
    assert!(html.contains("working as intended"), "{html}");
    assert!(!html.contains("Broadly privileged, working as intended"));
    assert!(!html.contains("broad-lead muted") && !html.contains("breadth muted"));
    assert!(html.contains("f-calm"), "calm row class applied");
    assert!(html.contains("[SAFE]"));
    assert!(!html.contains("breadth is severity"));
    assert!(!html.contains("severity, not urgency"));
    assert!(!html.contains("not urgency"));
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn awaiting_broad_card_shows_the_honest_broad_note() {
    let entry = "workload/argocd/Pod/argocd-server";
    let fs = broad_findings(entry, None);
    let refs: Vec<&Finding> = fs.iter().collect();
    let html = card_body(entry, &refs);
    assert!(html.contains("Broad reach — the model hasn't finished judging this one"));
    assert!(html.contains("Wide access isn't itself a break-in"));
    assert!(!html.contains("working as intended"));
    let row = row_html(entry, &refs);
    assert!(!row.contains("f-calm"), "awaiting is not a calm row");
    assert!(!row.contains("working as intended"));
    assert!(!html.contains("breadth is severity") && !html.contains("not urgency"));
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn breach_broad_row_is_not_softened() {
    let entry = "workload/argocd/Pod/argocd-server";
    let breach = broad_findings(
        entry,
        Some("exploitable — CVE-2021-44228 reaches everything"),
    );
    let brefs: Vec<&Finding> = breach.iter().collect();
    let bhtml = row_html(entry, &brefs);
    assert!(
        !bhtml.contains("working as intended"),
        "a breach is not softened"
    );
    assert!(!bhtml.contains("f-calm"), "a breach row is not calm-green");
    assert!(!bhtml.contains("breadth is severity"));
}

#[test]
fn context_tier_collapses_to_one_summary_row() {
    let f = ranked_finding("workload/argo/Pod/ctx", "structural — propose", false, None);
    let html = render_html(
        &[f],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        html.contains("ctx-summary"),
        "context collapses to a summary row"
    );
    assert!(html.contains("ctx-toggle"), "with a group toggle");
    assert!(
        html.contains("ctx-row"),
        "the context rows ride behind the group"
    );
    assert!(html.contains(">context<"), "the context tier label shows");
    assert!(
        html.contains("<tr hidden class=\"ctx-row f-row"),
        "context rows are hidden until the group is opened: {html}"
    );
}

#[test]
fn rows_carry_their_tier_label_and_expand_control() {
    let f = ranked_finding(
        "workload/app/Pod/web",
        "auto-eligible",
        false,
        Some("exploitable — boom"),
    );
    let html = row_html("workload/app/Pod/web", &[&f]);
    assert!(html.contains(">flagged<"), "the flagged tier label shows");
    assert!(
        html.contains("<button class=\"row-toggle\""),
        "button expand control"
    );
    assert!(
        html.contains("aria-expanded=\"false\""),
        "aria-expanded present"
    );
    assert!(
        html.contains("aria-controls=\""),
        "aria-controls wires the detail row"
    );
    assert!(
        html.contains(&format!(
            "class=\"f-detail\" hidden><td colspan=\"{FINDINGS_COLS}\""
        )),
        "hidden colspan detail row: {html}"
    );

    let w = ranked_finding("workload/app/Pod/web", "structural — propose", true, None);
    let whtml = row_html("workload/app/Pod/web", &[&w]);
    assert!(whtml.contains(">watch<"), "the watch tier label shows");
}

#[test]
fn graph_is_collapsed_by_default_in_every_card_body() {
    let entry = "workload/app/Pod/web";

    let f = ranked_finding(
        entry,
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let fhtml = card_body(entry, &[&f]);
    assert!(
        fhtml.contains("class=\"mermaid\""),
        "flagged still has a graph"
    );
    assert!(
        graph_is_collapsed(&fhtml),
        "flagged graph is collapsed by default"
    );
    assert!(
        fhtml.contains("show attack path"),
        "names the attack path: {fhtml}"
    );

    let w = ranked_finding(entry, "structural — propose", true, None);
    let whtml = card_body(entry, &[&w]);
    assert!(graph_is_collapsed(&whtml), "watch graph is collapsed");
    assert!(whtml.contains("show attack path"));

    let entry_b = "workload/argocd/Pod/argocd-server";
    let broad = broad_findings(entry_b, Some("not exploitable — authorized RBAC"));
    let brefs: Vec<&Finding> = broad.iter().collect();
    let bhtml = card_body(entry_b, &brefs);
    assert!(graph_is_collapsed(&bhtml), "broad graph is collapsed");
    assert!(
        bhtml.contains("show what it can reach"),
        "names the reach: {bhtml}"
    );
    assert!(
        bhtml.contains("data-aria=\""),
        "aria label preserved through collapse"
    );
}

#[test]
fn trust_line_is_absent_from_the_polled_region() {
    let trust_needle = "How protector decides:";
    let f = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let frag = render_fragment(
        std::slice::from_ref(&f),
        false,
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        !frag.contains(trust_needle) && !frag.contains("how protector decides"),
        "no trust line in the polled region: {frag}"
    );
    let html = render_html(
        &[f],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert_eq!(
        html.matches("how protector decides").count(),
        1,
        "exactly one header pointer in the full page"
    );
    assert!(
        html.contains("<details class=\"howto\">"),
        "header pointer present"
    );
    let pointer_at = html.find("<details class=\"howto\">").unwrap();
    let region_at = html.find("id=\"findings-region\"").unwrap();
    assert!(
        region_at < pointer_at,
        "the pointer sits after the findings region container, in the static header"
    );
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn render_html_splits_findings_into_attention_and_watching_tables() {
    let flagged = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let context = {
        let mut f = ranked_finding("workload/argo/Pod/srv", "structural — propose", false, None);
        f.entry = "workload/argo/Pod/srv".into();
        f
    };
    let findings = vec![flagged, context];
    let html = render_html(
        &findings,
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    let needs = html
        .find("Needs attention")
        .expect("needs-attention section");
    let watching = html.find("Watching").expect("watching section");
    assert!(needs < watching, "Needs attention precedes Watching");
    assert!(html.contains("<table class=\"findings\">"), "dense table");
    assert!(html.contains("<th scope=\"col\">tier</th>"), "table header");
    assert!(html.contains(">flagged<"), "the flagged tier label appears");
    assert!(
        html.contains("ctx-summary") && html.contains("ctx-row"),
        "the context tier collapses to one group summary row"
    );
}
