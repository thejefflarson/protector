//! Tests for the layered adjudication re-judge gate (ADR-0023 / JEF-391, over JEF-390 / JEF-234).
//! `classify_adjudication` reads only the verdict store, so these drive it directly with a real
//! [`state::VerdictStore`] and a hand-built [`PendingEntry`] — no full engine. Extracted to a
//! sibling file to keep `adj_gate.rs` under the file-size cap (CLAUDE.md).

use std::time::Instant;

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
use crate::engine::reason::adjudicate::{JudgedSurface, PromptSections, Verdict};

/// A minimal [`PendingEntry`] for `entry`/`fingerprint` — the only fields the gate reads. The
/// prompt/sections/surface/objectives are irrelevant to the classification decision.
fn pending(entry: &str, fingerprint: &str) -> PendingEntry {
    PendingEntry {
        entry_key: entry.to_string(),
        entry: NodeKey(entry.to_string()),
        objectives: vec![(NodeKey("secret/app/x".into()), EXPLOIT_PUBLIC_FACING)],
        prompt: "unused".into(),
        fingerprint: fingerprint.to_string(),
        sections: PromptSections {
            runtime: "r".into(),
            cves: "c".into(),
            secrets: "s".into(),
            posture: "p".into(),
            objectives: "o".into(),
            entry: "e".into(),
        },
        chain: "ch".into(),
        surface: JudgedSurface::default(),
        idxs: vec![0],
    }
}

fn baseline(verdict: Verdict) -> state::VerdictBaseline {
    state::VerdictBaseline {
        surface: JudgedSurface::default(),
        verdict,
    }
}

/// First judgment: no baseline ⇒ the delta build reports ADDITIVE, so a fresh (empty) store
/// re-judges — there is nothing decisive to serve yet.
#[test]
fn first_judgment_no_baseline_judges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp1");
    assert!(matches!(
        classify_adjudication(&store, &p, true, None, Instant::now()),
        AdjGate::Judge
    ));
}

/// An ADDITIVE delta against a decisive baseline re-judges (something NEW must be evaluated) —
/// it is NOT served from the baseline, even though a baseline exists.
#[test]
fn additive_delta_rejudges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp-new");
    let base = baseline(Verdict::Refuted("prior".into()));
    assert!(matches!(
        classify_adjudication(&store, &p, true, Some(&base), Instant::now()),
        AdjGate::Judge
    ));
}

/// A PURELY SUBTRACTIVE delta (nothing added since the baseline) HOLDS the prior decisive
/// verdict — no fresh model call — and warms the LRU under the current fingerprint so the
/// settled state HITS next pass.
#[test]
fn subtractive_delta_holds_prior_verdict() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp-shrunk");
    let base = baseline(Verdict::Exploitable("held".into()));

    let out = classify_adjudication(&store, &p, false, Some(&base), Instant::now());
    match out {
        AdjGate::Resolved { verdict, held } => {
            assert!(
                held,
                "a subtractive hold is a HELD serve, not a plain LRU hit"
            );
            assert_eq!(verdict, Verdict::Exploitable("held".into()));
        }
        other => panic!("expected a held serve, got {other:?}"),
    }
    // The hold warmed the LRU: the same fingerprint now HITS directly (no model call).
    assert_eq!(
        store.cached_for("entry", "fp-shrunk"),
        Some(Verdict::Exploitable("held".into())),
        "the held verdict is cached under the current fingerprint"
    );
}

/// Fail-safe: `!additive` with NO baseline (should be unreachable — a missing baseline is
/// additive) RE-JUDGES rather than serving nothing. Never suppress a judgment on possibly-new
/// surface.
#[test]
fn not_additive_without_baseline_still_rejudges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp");
    assert!(matches!(
        classify_adjudication(&store, &p, false, None, Instant::now()),
        AdjGate::Judge
    ));
}

/// An exact-fingerprint LRU hit (JEF-390) serves the cached verdict as a plain hit (`held =
/// false`), taking precedence over the delta gate.
#[test]
fn exact_fingerprint_hit_serves_unheld() {
    let store = state::VerdictStore::new();
    store.cache_decisive("entry", "fp-seen".into(), Verdict::Refuted("cached".into()));
    let p = pending("entry", "fp-seen");
    // Even with an additive delta, the exact-state cache hit wins (identical input ⇒ identical
    // verdict).
    match classify_adjudication(&store, &p, true, None, Instant::now()) {
        AdjGate::Resolved { verdict, held } => {
            assert!(!held, "an exact LRU hit is not a subtractive hold");
            assert_eq!(verdict, Verdict::Refuted("cached".into()));
        }
        other => panic!("expected an LRU hit, got {other:?}"),
    }
}
