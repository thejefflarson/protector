//! Per-finding recency / Δ column tests (JEF-201). The recency clock is INJECTED (the store
//! methods + `Findings::snapshot_at` all take a `now: Instant`), so every case below is
//! deterministic with NO real sleeps: a later `now` is built with `base + Duration`.
//!
//! Coverage: the store's posture-diff (NEW / escalated / de-escalated / unchanged), that the
//! Δ glyph is STORED (so it survives the `/fragment` poll — a re-snapshot at a later `now`
//! does not flicker a steady row to NEW), that a journal-restored entry reads `Restored`
//! (never NEW), and the view-model cell/tally shaping + the row component's `aria-label`.

use super::breach_finding;
use crate::engine::dashboard::Findings;
use crate::engine::dashboard::components::findings::row as row_component;
use crate::engine::dashboard::model::VerdictStore;
use crate::engine::dashboard::recency::{Delta, RecencyInfo, StoredPosture};
use crate::engine::dashboard::view_model::findings::Tier;
use crate::engine::dashboard::view_model::findings::{
    RecencyTally, endpoint_props, recency_cell, recency_tally,
};
use crate::engine::reason::adjudicate::Verdict;
use std::time::{Duration, Instant};

const WEB: &str = "workload/app/Pod/web";

fn breach() -> StoredPosture {
    StoredPosture::Breach
}
fn safe() -> StoredPosture {
    StoredPosture::Safe
}

/// First sight of a key this run is NEW, regardless of the posture it lands on.
#[test]
fn first_sight_is_new() {
    let store = VerdictStore::new();
    let t0 = Instant::now();
    store.record_recency(WEB, safe(), t0);
    assert_eq!(store.recency_for(WEB, t0).unwrap().delta, Delta::New);
}

/// A posture WORSENING between passes escalates (↑); de-escalating reverses (↓); steady is
/// unchanged. The first pass is NEW, then the diff drives the glyph.
#[test]
fn posture_changes_drive_escalation_and_de_escalation() {
    let store = VerdictStore::new();
    let t0 = Instant::now();
    // Pass 1: first sight, Safe → NEW.
    store.record_recency(WEB, safe(), t0);
    // Pass 2: Safe → Breach → escalated.
    let t1 = t0 + Duration::from_secs(30);
    store.record_recency(WEB, breach(), t1);
    assert_eq!(store.recency_for(WEB, t1).unwrap().delta, Delta::Escalated);
    // Pass 3: Breach → Breach → unchanged.
    let t2 = t1 + Duration::from_secs(30);
    store.record_recency(WEB, breach(), t2);
    assert_eq!(store.recency_for(WEB, t2).unwrap().delta, Delta::Unchanged);
    // Pass 4: Breach → Safe → de-escalated (a cut lifted / cleared).
    let t3 = t2 + Duration::from_secs(30);
    store.record_recency(WEB, safe(), t3);
    assert_eq!(
        store.recency_for(WEB, t3).unwrap().delta,
        Delta::DeEscalated
    );
}

/// AC: recency survives the `/fragment` 30s poll — it is derived from the STORED first_seen /
/// last_delta, not from render time. A re-read at a much later `now` (no new pass) keeps the
/// same NEW glyph; only the human age advances. No flicker to NEW-every-poll.
#[test]
fn recency_survives_the_fragment_poll() {
    let store = VerdictStore::new();
    let t0 = Instant::now();
    store.record_recency(WEB, breach(), t0); // NEW this pass.

    // The poll re-reads MUCH later with no intervening pass.
    let poll1 = t0 + Duration::from_secs(30);
    let poll2 = t0 + Duration::from_secs(120);
    assert_eq!(store.recency_for(WEB, poll1).unwrap().delta, Delta::New);
    assert_eq!(store.recency_for(WEB, poll2).unwrap().delta, Delta::New);
    // The age advances with `now`, but the GLYPH does not change between polls.
    let a1 = store.recency_for(WEB, poll1).unwrap().age_secs.unwrap();
    let a2 = store.recency_for(WEB, poll2).unwrap().age_secs.unwrap();
    assert!(a2 > a1, "age advances across polls: {a1} -> {a2}");
}

/// AC: a journal-restored entry must NOT be mislabeled NEW. It reads `Restored` until a live
/// pass re-judges it; its age is suppressed (its first_seen is synthetic).
#[test]
fn restored_entry_is_not_new() {
    let store = VerdictStore::new();
    let boot = Instant::now();
    store.seed_restored(WEB, "exploitable — from before restart".into(), boot);

    let info = store
        .recency_for(WEB, boot + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        info.delta,
        Delta::Restored,
        "restored reads Restored, not NEW"
    );
    assert_eq!(
        info.age_secs, None,
        "a restored age is synthetic, suppressed"
    );

    // The first LIVE pass after restore still reads Restored (it existed before this run),
    // and only then diffs normally.
    let p1 = boot + Duration::from_secs(30);
    store.record_recency(WEB, breach(), p1);
    assert_eq!(store.recency_for(WEB, p1).unwrap().delta, Delta::Restored);
    let p2 = p1 + Duration::from_secs(30);
    store.record_recency(WEB, breach(), p2);
    assert_eq!(
        store.recency_for(WEB, p2).unwrap().delta,
        Delta::Unchanged,
        "after one live pass the restored entry diffs like any other"
    );
}

/// The findings snapshot resolves recency onto each breach-relevant finding (JEF-201), like
/// the verdict — and `snapshot_at` lets the test inject `now`. The NEW glyph stored at pass
/// time is the same on a later snapshot (no flicker).
#[test]
fn snapshot_resolves_recency_and_does_not_flicker() {
    let findings = Findings::new();
    let store = findings.verdicts();
    findings.replace(vec![breach_finding(WEB)]);

    let t0 = Instant::now();
    store.set_display(WEB, Verdict::Exploitable("RCE reaches the secret".into()));
    store.record_recency(WEB, breach(), t0);

    let snap = findings.snapshot_at(t0 + Duration::from_secs(1));
    let r = snap[0].recency.expect("recency resolved onto the finding");
    assert_eq!(r.delta, Delta::New);

    // A later snapshot (the poll) keeps NEW — the glyph is stored, not render-derived.
    let later = findings.snapshot_at(t0 + Duration::from_secs(90));
    assert_eq!(later[0].recency.unwrap().delta, Delta::New);
}

/// The view-model cell shaping: each Δ maps to a glyph, a words-only aria-label (AC #4), and a
/// tone class. The unchanged cell shows the age (not a glyph) and still names the meaning.
#[test]
fn recency_cell_carries_meaning_in_words() {
    let new = recency_cell(Some(&RecencyInfo {
        delta: Delta::New,
        age_secs: Some(5),
    }));
    assert_eq!(new.glyph, "NEW");
    assert_eq!(new.aria_label, "new this pass");
    assert_eq!(new.tone, "rc-new");

    let up = recency_cell(Some(&RecencyInfo {
        delta: Delta::Escalated,
        age_secs: Some(5),
    }));
    assert_eq!(up.glyph, "↑");
    assert_eq!(up.aria_label, "escalated since last pass");
    assert_eq!(up.tone, "rc-up");

    let down = recency_cell(Some(&RecencyInfo {
        delta: Delta::DeEscalated,
        age_secs: Some(5),
    }));
    assert_eq!(down.glyph, "↓");
    assert_eq!(down.aria_label, "de-escalated since last pass");

    // Steady: the cell shows the age in place of a glyph; the aria-label names it.
    let steady = recency_cell(Some(&RecencyInfo {
        delta: Delta::Unchanged,
        age_secs: Some(125),
    }));
    assert_eq!(steady.glyph, "2m");
    assert_eq!(steady.aria_label, "unchanged, first seen 2m ago");
    assert_eq!(steady.tone, "rc-steady");

    // No recency yet → a quiet steady cell, never a spurious NEW.
    let none = recency_cell(None);
    assert_eq!(none.tone, "rc-steady");
    assert_ne!(none.glyph, "NEW");
}

/// The region tally counts per ENDPOINT (not per finding) over the rendered groups: one new,
/// one newly-flagged (escalated), and a steady endpoint counts toward neither.
#[test]
fn region_tally_counts_new_and_newly_flagged_per_endpoint() {
    let mk = |delta: Delta| {
        let mut f = breach_finding(WEB);
        f.recency = Some(RecencyInfo {
            delta,
            age_secs: Some(10),
        });
        f
    };
    let new = mk(Delta::New);
    let esc = mk(Delta::Escalated);
    let steady = mk(Delta::Unchanged);
    let new_g = [&new];
    let esc_g = [&esc];
    let steady_g = [&steady];
    let groups: Vec<&[&_]> = vec![&new_g, &esc_g, &steady_g];

    let tally = recency_tally(groups);
    assert_eq!(
        tally,
        RecencyTally {
            new: 1,
            newly_flagged: 1
        }
    );
    assert!(!tally.is_empty());
    assert!(RecencyTally::default().is_empty());
}

/// The row component renders the Δ cell with the glyph AND the words-only aria-label (AC #4):
/// meaning never rides on the glyph/color alone.
#[test]
fn row_renders_delta_cell_with_aria_label() {
    let mut f = breach_finding(WEB);
    f.recency = Some(RecencyInfo {
        delta: Delta::Escalated,
        age_secs: Some(10),
    });
    let bind = [&f];
    let props = endpoint_props(WEB, &bind, Tier::Flagged, None);
    let html = row_component(&props.row).into_string();
    assert!(html.contains("c-delta"), "row has the Δ cell: {html}");
    assert!(
        html.contains("aria-label=\"escalated since last pass\""),
        "Δ meaning is in the aria-label (AC #4): {html}"
    );
    assert!(html.contains('↑'), "Δ glyph is rendered: {html}");
    // No ADR-/JEF- token leaks into rendered output (JEF-201 / repo guard).
    assert!(
        !html.contains("ADR-") && !html.contains("JEF-"),
        "no refs: {html}"
    );
}
