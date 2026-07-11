//! Tests for the bounded per-entry LRU verdict cache (JEF-390) and its env knob. Extracted to a
//! sibling file to keep `verdict_store.rs` well under the 1,000-line cap (CLAUDE.md).
//!
//! The LRU widens the old single verdict slot so a workload whose evidence oscillates between
//! recently-judged states (A→B→A) HITS on the return instead of re-judging every flip, WITHOUT
//! regressing the JEF-234 invariant that only decisive verdicts are cached and an `Uncertain`
//! still arms exponential backoff.

use std::time::Instant;

use super::*;

/// A DECISIVE verdict tagged so distinct states are distinguishable in assertions.
fn decisive(tag: &str) -> Verdict {
    Verdict::Refuted(tag.to_string())
}

/// An INCONCLUSIVE verdict tagged so distinct outages are distinguishable in assertions.
fn uncertain(tag: &str) -> Verdict {
    Verdict::Uncertain(tag.to_string())
}

/// JEF-371: the display carry-forward now lives entirely in `VerdictStore::resolve_display`.
/// This exercises the four cases the old split logic (engine publish phase + `set_display`)
/// produced, asserting each yields the EXACT same displayed verdict — behaviour-neutrality is
/// the hard requirement for this most-debugged, blank-dashboard-incident surface (JEF-157).
#[test]
fn resolve_display_owns_the_full_carry_forward_precedence() {
    let store = VerdictStore::with_cache_slots(32);

    // (a) A decisive verdict this pass is shown as-is and becomes the displayed verdict.
    let a = decisive("live-A");
    assert_eq!(store.resolve_display("e", &a), a);
    assert_eq!(store.display_verdict("e"), Some(a.clone()));

    // (b) An Uncertain this pass with a prior decisive verdict CARRIES the decisive one FORWARD —
    // the dashboard keeps showing the last real call rather than blanking to "uncertain".
    let returned = store.resolve_display("e", &uncertain("model unavailable"));
    assert_eq!(returned, a, "the prior decisive verdict is carried forward");
    assert_eq!(
        store.display_verdict("e"),
        Some(a),
        "the carry-forward does not regress the displayed posture"
    );

    // A later decisive verdict supersedes the carried-forward one (normal progression).
    let b = decisive("live-B");
    assert_eq!(store.resolve_display("e", &b), b);
    assert_eq!(store.display_verdict("e"), Some(b));

    // (b′) An Uncertain this pass with NO prior decisive display shows the Uncertain itself —
    // there is nothing to carry forward on a fresh entry.
    let unc = uncertain("cold-start timeout");
    assert_eq!(store.resolve_display("fresh", &unc), unc);
    assert_eq!(store.display_verdict("fresh"), Some(unc));

    // (c) A journal-restored entry shows the restored summary until a LIVE verdict supersedes it.
    let restored_at = Instant::now();
    store.seed_restored(
        "boot",
        "restored: refuted last run".to_string(),
        restored_at,
    );
    assert_eq!(
        store.display_summary("boot").as_deref(),
        Some("restored: refuted last run"),
        "the restored summary shows on boot before any live verdict"
    );
    // An Uncertain first pass on a RESTORED entry does NOT carry the restored summary — there is
    // no prior *live decisive* display, so the Uncertain lands and supersedes the restored summary
    // (identical to the pre-JEF-371 `set_display` clearing `restored` on any live write).
    let boot_unc = uncertain("first live pass timed out");
    assert_eq!(store.resolve_display("boot", &boot_unc), boot_unc);
    assert_eq!(store.display_verdict("boot"), Some(boot_unc.clone()));
    assert_eq!(
        store.display_summary("boot"),
        Some(boot_unc.summary()),
        "a live verdict supersedes the restored summary"
    );

    // (c′) A decisive live verdict on a freshly-restored entry likewise supersedes the summary.
    store.seed_restored("boot2", "restored: exploitable".to_string(), restored_at);
    let live = decisive("live decisive after restore");
    assert_eq!(store.resolve_display("boot2", &live), live);
    assert_eq!(
        store.display_summary("boot2"),
        Some(live.summary()),
        "the live decisive verdict supersedes the restored summary"
    );

    // (d) JEF-234 backoff / Uncertain-never-cached is unchanged: resolving an Uncertain for
    // display neither caches it nor establishes a baseline (the cache path is orthogonal).
    assert!(
        store.cached_for("fresh", "any-fp").is_none(),
        "resolving an Uncertain for display never caches a verdict"
    );
    assert!(
        store.baseline_for("fresh").is_none(),
        "resolving display never establishes a re-judge baseline"
    );
}

/// Model ONE judging pass for `entry` at fingerprint `fp`, mirroring the engine loop
/// (`engine/src/engine/mod.rs`): serve the cache on a hit; on a miss, honour JEF-234 backoff,
/// then "judge" — caching only a DECISIVE verdict and arming backoff on an `Uncertain`. Returns
/// `true` iff a fresh (would-be model) call actually happened, so tests can count re-judges.
fn judge_pass(
    store: &VerdictStore,
    entry: &str,
    fp: &str,
    would_return: &Verdict,
    now: Instant,
) -> bool {
    if store.cached_for(entry, fp).is_some() {
        return false; // cache hit — no model call
    }
    if store.entry_backing_off(entry, now) {
        return false; // JEF-234: in backoff after a recent inconclusive — skip the model
    }
    match would_return {
        Verdict::Uncertain(_) => store.record_inconclusive(entry, now),
        d => {
            store.cache_decisive(entry, fp.to_string(), d.clone());
            store.record_decisive(entry);
        }
    }
    true
}

#[test]
fn a_b_a_returns_a_from_cache_with_two_judgements_not_three() {
    let store = VerdictStore::with_cache_slots(32);
    let now = Instant::now();
    let (va, vb) = (decisive("A"), decisive("B"));

    let mut judgements = 0;
    if judge_pass(&store, "entry", "fpA", &va, now) {
        judgements += 1;
    }
    if judge_pass(&store, "entry", "fpB", &vb, now) {
        judgements += 1;
    }
    // The return to state A must be served from the LRU — under the old single slot, judging B
    // had overwritten A and this would re-judge (a third call).
    let re_judged = judge_pass(&store, "entry", "fpA", &va, now);

    assert!(
        !re_judged,
        "return to a recently-judged state A must HIT the cache"
    );
    assert_eq!(
        judgements, 2,
        "only A and B were judged; the return to A is a hit"
    );
    assert_eq!(
        store.cached_for("entry", "fpA"),
        Some(va),
        "the served verdict is exactly A's decisive verdict"
    );
}

#[test]
fn beyond_the_cap_lru_evicts_least_recently_used_and_re_judges_it() {
    // Two slots: the smallest cache that still retains one prior state across a flip.
    let store = VerdictStore::with_cache_slots(2);
    let now = Instant::now();
    let (va, vb, vc) = (decisive("A"), decisive("B"), decisive("C"));

    assert!(judge_pass(&store, "entry", "fpA", &va, now)); // [A]
    assert!(judge_pass(&store, "entry", "fpB", &vb, now)); // [B, A]

    // Revisit A: a HIT that promotes A to most-recently-used, so B is now the LRU victim.
    assert!(!judge_pass(&store, "entry", "fpA", &va, now)); // [A, B]

    // A third state evicts the LRU (B), NOT the just-used A — proving it's an LRU, not a FIFO.
    assert!(judge_pass(&store, "entry", "fpC", &vc, now)); // [C, A]

    assert!(
        store.cached_for("entry", "fpA").is_some(),
        "the recently-used A survives eviction"
    );
    assert!(
        store.cached_for("entry", "fpB").is_none(),
        "the least-recently-used B was evicted past the cap"
    );
    // Returning to the evicted state is a genuine miss → a fresh re-judge.
    assert!(
        judge_pass(&store, "entry", "fpB", &vb, now),
        "the evicted state re-judges on its return"
    );
}

/// ADR-0023 (JEF-391): the delta-aware baseline round-trips — absent until set, then stored and
/// replaced by the most recent decisive verdict's surface.
#[test]
fn baseline_is_absent_then_set_and_replaced() {
    use crate::engine::reason::adjudicate::JudgedSurface;
    let store = VerdictStore::with_cache_slots(32);

    assert!(
        store.baseline_for("entry").is_none(),
        "no baseline until the entry is judged decisively"
    );

    store.set_baseline("entry", JudgedSurface::default(), decisive("first"));
    assert_eq!(
        store.baseline_for("entry").map(|b| b.verdict),
        Some(decisive("first")),
        "the baseline holds the decisive verdict it was set with"
    );

    // A later decisive verdict replaces the baseline (the accumulation window resets).
    store.set_baseline("entry", JudgedSurface::default(), decisive("second"));
    assert_eq!(
        store.baseline_for("entry").map(|b| b.verdict),
        Some(decisive("second")),
        "the most recent decisive verdict is the baseline"
    );
}

#[test]
fn uncertain_is_never_cached_and_the_entry_backs_off() {
    let store = VerdictStore::with_cache_slots(32);
    let now = Instant::now();
    let unc = Verdict::Uncertain("model unavailable".to_string());

    // A first pass makes a fresh call that comes back inconclusive.
    assert!(judge_pass(&store, "entry", "fpU", &unc, now));

    // JEF-234: the Uncertain is NOT added to the LRU...
    assert!(
        store.cached_for("entry", "fpU").is_none(),
        "an Uncertain verdict is never cached"
    );
    // ...and the entry is now in exponential backoff, so the next pass skips the (struggling)
    // model rather than re-judging the same failing fingerprint immediately.
    assert!(
        store.entry_backing_off("entry", now),
        "the inconclusive armed the backoff"
    );
    assert!(
        !judge_pass(&store, "entry", "fpU", &unc, now),
        "the backoff gate skips the model on the very next pass"
    );

    // A later decisive verdict resets the backoff and DOES populate the LRU.
    let later = now + std::time::Duration::from_secs(3600);
    let v = decisive("clear");
    assert!(judge_pass(&store, "entry", "fpU", &v, later));
    assert_eq!(store.cached_for("entry", "fpU"), Some(v));
    assert!(
        !store.entry_backing_off("entry", later),
        "a decisive verdict clears the backoff"
    );
}

#[test]
fn env_slots_parse_defaults_on_invalid_or_zero_and_floors_small_values() {
    // Unset / unparseable / zero all fall back to the default.
    assert_eq!(parse_verdict_cache_slots(None), DEFAULT_VERDICT_CACHE_SLOTS);
    assert_eq!(
        parse_verdict_cache_slots(Some("")),
        DEFAULT_VERDICT_CACHE_SLOTS
    );
    assert_eq!(
        parse_verdict_cache_slots(Some("nope")),
        DEFAULT_VERDICT_CACHE_SLOTS
    );
    assert_eq!(
        parse_verdict_cache_slots(Some("0")),
        DEFAULT_VERDICT_CACHE_SLOTS
    );
    assert_eq!(
        parse_verdict_cache_slots(Some("-4")),
        DEFAULT_VERDICT_CACHE_SLOTS
    );

    // A positive value is honoured (and trimmed)...
    assert_eq!(parse_verdict_cache_slots(Some("8")), 8);
    assert_eq!(parse_verdict_cache_slots(Some("  16 ")), 16);
    // ...but a too-small value is floored so the cache can always retain one prior state.
    assert_eq!(
        parse_verdict_cache_slots(Some("1")),
        MIN_VERDICT_CACHE_SLOTS
    );
}
