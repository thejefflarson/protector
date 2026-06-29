//! Render-level tests for the dashboard: the honesty invariants asserted against the actual
//! emitted HTML (brief §9), plus escaping and the honest empty/awaiting/blind states. These
//! drive the view_model + components directly (no HTTP, no engine), so they are fast and pure.

use std::time::SystemTime;

use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{
    BakeStats, EntryEvidence, Finding, Judgement, ModelHealth, PathStep, Readiness,
    ReadinessConfig, derive_readiness,
};

use super::page;
use super::view_model::{build_findings_view, build_status_strip};

/// A readiness snapshot for a fully-covered, actively-judging model.
fn judging_readiness() -> Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
    };
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    derive_readiness(&config, ModelHealth::Ok, &bake, Some(SystemTime::now()))
}

/// A readiness snapshot for a warming (no pass yet) engine — not honestly calm.
fn warming_readiness() -> Readiness {
    derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        &BakeStats::default(),
        None,
    )
}

/// A readiness snapshot for an attached-but-timed-out model — blind, not calm.
fn timed_out_readiness() -> Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
    };
    derive_readiness(
        &config,
        ModelHealth::Timeout,
        &BakeStats::default(),
        Some(SystemTime::now()),
    )
}

fn breach_finding(entry: &str, verdict: Verdict) -> Finding {
    Finding {
        entry: entry.to_string(),
        objective: "secret/app/db-creds".to_string(),
        foothold: true,
        corroborated: matches!(verdict, Verdict::Confirmed),
        disposition: "auto-eligible".into(),
        cut: Some(format!("{entry} -[reaches/Tcp/5432]-> secret/app/db-creds")),
        breach_relevant: true,
        verdict: Some(verdict),
        path: vec![PathStep {
            from: entry.to_string(),
            relation: "reaches/Tcp/5432".into(),
            to: "secret/app/db-creds".into(),
        }],
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

// ---------------------------------------------------------------------------
// Invariant #1 — !model_judging or warming_up ⇒ never the green all-clear path.
// ---------------------------------------------------------------------------

#[test]
fn warming_empty_never_renders_all_clear() {
    let view = build_findings_view("prod".into(), &[], &[], &warming_readiness(), None);
    let html = page::findings_page(&view).into_string();
    assert!(
        !html.contains("all clear"),
        "a warming dashboard must never claim all-clear"
    );
    assert!(html.contains("warming up"), "it states it is warming");
    assert!(
        html.contains("not an all-clear"),
        "and is explicit that warming is not safety"
    );
}

#[test]
fn timed_out_empty_never_renders_all_clear() {
    let view = build_findings_view(
        "prod".into(),
        &[],
        &[],
        &timed_out_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(!html.contains("all clear"));
    assert!(html.contains("not answering") || html.contains("unjudged"));
}

#[test]
fn judging_empty_is_the_only_state_that_says_all_clear() {
    let view = build_findings_view(
        "prod".into(),
        &[],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(
        html.contains("all clear"),
        "an empty list IS all-clear when the model is judging"
    );
    assert!(html.contains("model judging"));
}

#[test]
fn judging_but_awaiting_entry_is_watching_not_all_clear() {
    // Refinement A: green/all-clear is forbidden when ANY entry is still awaiting, even though
    // the model is actively judging. The strip shows the elevated "watching" state instead.
    let mut awaiting = breach_finding("endpoint/a", Verdict::Confirmed);
    awaiting.verdict = None; // no verdict yet ⇒ Awaiting
    let view = build_findings_view(
        "prod".into(),
        &[awaiting],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(
        !html.contains("all clear"),
        "an awaiting entry forbids the green all-clear"
    );
    assert!(
        html.contains("watching"),
        "it is the elevated watching state instead"
    );
    assert!(html.contains("not yet all-clear"));
}

#[test]
fn judging_but_uncertain_entry_is_not_all_clear() {
    // Refinement A: an Uncertain entry likewise forbids the green all-clear.
    let f = breach_finding("endpoint/a", Verdict::Uncertain("timed out".into()));
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(
        !html.contains("all clear"),
        "an uncertain entry forbids the green all-clear"
    );
    // The watching reading is present on the strip (the model is up but not finished).
    assert!(html.contains("watching"));
}

// ---------------------------------------------------------------------------
// Invariant #2 — Uncertain & awaiting never map to the cleared/green token.
// ---------------------------------------------------------------------------

#[test]
fn uncertain_and_awaiting_rows_are_not_green() {
    let findings = vec![
        breach_finding("endpoint/a", Verdict::Uncertain("timed out".into())),
        breach_finding("endpoint/b", Verdict::Confirmed), // ensure a non-empty table
    ];
    // An awaiting row (no verdict).
    let mut awaiting = breach_finding("endpoint/c", Verdict::Confirmed);
    awaiting.verdict = None;
    let mut all = findings;
    all.push(awaiting);
    let view = build_findings_view(
        "prod".into(),
        &all,
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The uncertain/awaiting rows carry their own (non-cleared) posture tokens.
    assert!(html.contains("rail-uncertain"));
    assert!(html.contains("rail-awaiting"));
    assert!(html.contains("awaiting judgement"));
    // They must NOT be wearing the cleared chip.
    assert!(!html.contains("chip-cleared\""), "no cleared chip leaked");
}

#[test]
fn awaiting_row_carries_the_elevated_treatment_hooks() {
    // Refinement B: an un-judged (awaiting) entry must render the elevated chip + a row the CSS
    // can tint (data-posture="awaiting") — slightly elevated, not calm slate. Meaning stays
    // carried by glyph + word too (never colour alone).
    let mut awaiting = breach_finding("endpoint/a", Verdict::Confirmed);
    awaiting.verdict = None;
    let view = build_findings_view(
        "prod".into(),
        &[awaiting],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(
        html.contains("data-posture=\"awaiting\""),
        "the row exposes the awaiting hook the tint CSS targets"
    );
    assert!(
        html.contains("chip-awaiting"),
        "the chip carries the ochre tone"
    );
    // Meaning not by colour alone: the word stays.
    assert!(html.contains("awaiting judgement"));
}

// ---------------------------------------------------------------------------
// Invariant #3 — empty evidence renders explicit "none", never a blank.
// ---------------------------------------------------------------------------

#[test]
fn empty_evidence_renders_no_evidence_not_blank() {
    let f = breach_finding("endpoint/a", Verdict::Confirmed); // default (empty) evidence
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(html.contains("no evidence"), "the row says 'no evidence'");
}

// ---------------------------------------------------------------------------
// Invariant #6 — untrusted free-text is escaped at render.
// ---------------------------------------------------------------------------

#[test]
fn untrusted_verdict_prose_is_escaped() {
    let evil = "<script>alert('x')</script>";
    let f = breach_finding("endpoint/a", Verdict::Exploitable(evil.to_string()));
    let judgements = vec![Judgement {
        entry: "endpoint/a".into(),
        objectives: 1,
        verdict: "Exploitable".into(),
        prompt: Some(format!("prompt with {evil}")),
        reply: Some(format!("reply with {evil}")),
    }];
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &judgements,
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(
        !html.contains("<script>alert"),
        "a raw <script> must never reach the output"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "it is HTML-escaped instead"
    );
}

// ---------------------------------------------------------------------------
// Strip + nav smoke.
// ---------------------------------------------------------------------------

#[test]
fn stub_pages_carry_the_persistent_strip_and_nav() {
    let strip = build_status_strip("prod".into(), &judging_readiness(), Some(SystemTime::now()));
    let html =
        page::stub_page(&strip, super::view_model::props::Tab::Trust, "trust blurb").into_string();
    assert!(html.contains("phase 2"), "stub is labelled phase 2");
    assert!(html.contains("Findings"), "the nav still offers Findings");
    assert!(html.contains("model judging"), "the strip is present");
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
    let frag = page::findings_fragment(&view).into_string();
    assert!(!frag.contains("<!DOCTYPE"), "a fragment carries no doctype");
    assert!(!frag.contains("<html"), "nor a document element");
    // But it does carry the strip (so a poll refreshes coverage/freshness).
    assert!(frag.contains("strip"));
}
