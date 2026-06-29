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
// Empty evidence renders NOTHING — no implied-absent "no evidence" text in the
// row, and no empty evidence section in the detail panel (per-finding-evidence
// "none" rule dropped; the model-judging / coverage honesty invariants are
// unaffected and asserted elsewhere).
// ---------------------------------------------------------------------------

#[test]
fn empty_evidence_renders_nothing_not_an_absent_marker() {
    let f = breach_finding("endpoint/a", Verdict::Confirmed); // default (empty) evidence
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // No implied-absent text anywhere (row cluster or detail panel).
    assert!(
        !html.contains("no evidence"),
        "no implied-absent 'no evidence' text renders for an empty finding"
    );
    assert!(
        !html.contains("evidence-none"),
        "the 'no evidence' marker element is gone"
    );
    // The detail panel omits the evidence section entirely when there is none.
    assert!(
        !html.contains("evidence-block"),
        "an empty evidence section is omitted from the detail panel"
    );
}

// ---------------------------------------------------------------------------
// Row expand — the first-column +/- toggle (replaces the old "why" pulldown).
// ---------------------------------------------------------------------------

#[test]
fn finding_row_has_first_column_expander_toggle() {
    let f = breach_finding("endpoint/a", Verdict::Confirmed);
    let id = f.entry.clone();
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The expander is a button with aria-expanded (accessibility gate), starting collapsed.
    assert!(
        html.contains("class=\"expander\""),
        "the first column carries the +/- expander button"
    );
    assert!(
        html.contains("aria-expanded=\"false\""),
        "the expander exposes a collapsed aria-expanded state"
    );
    // It controls the paired detail row by id.
    assert!(
        html.contains("aria-controls=\"detail-"),
        "the expander points at its detail row via aria-controls"
    );
    assert!(
        html.contains("id=\"detail-"),
        "the detail row carries the controlled id"
    );
    // The detail panel still renders inside the row-detail (just no <details>/why summary now).
    assert!(html.contains("row-detail"), "the detail row is present");
    let _ = id;
}

#[test]
fn finding_row_drops_the_old_why_pulldown() {
    let f = breach_finding("endpoint/a", Verdict::Confirmed);
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The "why — verdict, path, evidence" summary text is gone.
    assert!(
        !html.contains("verdict, path, evidence"),
        "the old why-pulldown summary text must not render"
    );
    // The row itself is no longer a <details data-finding> wrapper; the toggle is the row.
    assert!(
        !html.contains("<details data-finding"),
        "the per-row <details data-finding> wrapper is gone"
    );
}

// ---------------------------------------------------------------------------
// Item 3 — the proven path renders as a vertical chain diagram, not a text line.
// ---------------------------------------------------------------------------

#[test]
fn proven_path_renders_as_a_vertical_chain_with_marked_cut() {
    // breach_finding builds a single-hop path whose hop IS the cut signature.
    let f = breach_finding("endpoint/a", Verdict::Confirmed);
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The chain container + node/edge structure (not the old flat hop-list).
    assert!(
        html.contains("class=\"chain\""),
        "the path is a chain diagram"
    );
    assert!(html.contains("chain-node"), "it has node lines");
    assert!(html.contains("chain-edge"), "it has labelled edge lines");
    // The entry and objective nodes are tagged at the ends of the chain.
    assert!(html.contains("chain-entry"), "the entry node is emphasized");
    assert!(
        html.contains("chain-objective"),
        "the objective node is emphasized"
    );
    // The severable edge carries the prominent ✂ cut-here marker (the actionable heart).
    assert!(html.contains("chain-edge-cut"), "the cut edge is marked");
    assert!(
        html.contains("cut here"),
        "with an explicit 'cut here' label"
    );
    assert!(html.contains("\u{2702}"), "and the scissors glyph");
}

#[test]
fn proven_path_is_honest_when_no_cut_exists() {
    // A finding without a cut still renders the chain, but no edge is marked severable.
    let mut f = breach_finding("endpoint/a", Verdict::Confirmed);
    f.cut = None;
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(html.contains("class=\"chain\""), "still a chain diagram");
    assert!(
        !html.contains("chain-edge-cut"),
        "no edge is marked severable when there is no single-edge cut"
    );
    // And the proposed-cut section states the honest no-single-edge-cut message.
    assert!(html.contains("no single-edge cut"));
}

#[test]
fn proven_path_cascades_as_an_indented_staircase() {
    // A multi-hop path: each successive hop must sit one indent step deeper than the one above,
    // so the chain reads as a staircase (entry flush at step 0, then 1, 2, 3 …).
    let mut f = breach_finding("endpoint/a", Verdict::Confirmed);
    f.path = vec![
        PathStep {
            from: "endpoint/a".into(),
            relation: "reaches/Tcp/443".into(),
            to: "svc/web".into(),
        },
        PathStep {
            from: "svc/web".into(),
            relation: "reaches/Tcp/8080".into(),
            to: "svc/api".into(),
        },
        PathStep {
            from: "svc/api".into(),
            relation: "reaches/Tcp/5432".into(),
            to: "secret/app/db-creds".into(),
        },
    ];
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The entry node sits flush (step 0); each deeper hop carries an increasing step class.
    assert!(html.contains("chain-step-0"), "the entry node is at step 0");
    assert!(
        html.contains("chain-step-1"),
        "the first hop is indented one step"
    );
    assert!(
        html.contains("chain-step-2"),
        "the second hop is indented deeper"
    );
    assert!(
        html.contains("chain-step-3"),
        "the third hop is indented deeper still — a staircase"
    );
    // The indent is class-driven, never an inline style (no-inline-style guard).
    assert!(
        !html.contains("style="),
        "the staircase indent uses depth classes, not inline style"
    );
}

// ---------------------------------------------------------------------------
// Item 4 — no standalone LIVE? column; the live/judged tag rides in the posture chip.
// ---------------------------------------------------------------------------

#[test]
fn live_column_is_dropped_and_tag_rides_in_the_posture_chip() {
    let live = breach_finding("endpoint/a", Verdict::Confirmed); // ⇒ live
    let judged = breach_finding("endpoint/b", Verdict::Exploitable("RCE".into())); // ⇒ judged
    let view = build_findings_view(
        "prod".into(),
        &[live, judged],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    // The standalone column header is gone.
    assert!(
        !html.contains("LIVE?"),
        "the LIVE? column header is dropped"
    );
    assert!(!html.contains("col-live"), "no LIVE? column cell");
    // The breach rows carry their inline tag.
    assert!(html.contains("subtag-live"), "the live tag rides inline");
    assert!(
        html.contains("subtag-judged"),
        "the judged tag rides inline"
    );
    // No em-dash noise: the old subtag-none placeholder is gone.
    assert!(
        !html.contains("subtag-none"),
        "non-breach rows carry no dash-noise sub-tag"
    );
    // The detail row now spans 7 columns (was 8 with the LIVE? column).
    assert!(
        html.contains("colspan=\"7\""),
        "the detail row spans 7 columns"
    );
    assert!(!html.contains("colspan=\"8\""), "no longer 8 columns");
}

#[test]
fn non_breach_rows_carry_no_live_subtag() {
    // A cleared row is not a breach ⇒ no live/judged sub-tag at all (no dash).
    let cleared = breach_finding("endpoint/a", Verdict::Refuted("internal".into()));
    let view = build_findings_view(
        "prod".into(),
        &[cleared],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();
    assert!(!html.contains("subtag-live"));
    assert!(!html.contains("subtag-judged"));
    assert!(!html.contains("subtag-none"));
}

// ---------------------------------------------------------------------------
// Item 1 — SHADOW reads as a warning chip; ENFORCE stays calm.
// ---------------------------------------------------------------------------

#[test]
fn shadow_mode_renders_the_warning_pill() {
    // judging_readiness is armed:false ⇒ SHADOW.
    let strip = build_status_strip("prod".into(), &judging_readiness(), Some(SystemTime::now()));
    let html = page::stub_page(&strip, super::view_model::props::Tab::Findings, "x").into_string();
    assert!(html.contains("mode-shadow warn"), "shadow is the warn pill");
    assert!(html.contains("SHADOW"), "labelled SHADOW");
    assert!(html.contains("\u{26A0}"), "carries the ⚠ warning glyph");
    assert!(
        html.contains("proposes, never acts"),
        "states it only proposes"
    );
    assert!(
        !html.contains("ENFORCE"),
        "not the enforce reading in shadow"
    );
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
