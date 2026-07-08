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
