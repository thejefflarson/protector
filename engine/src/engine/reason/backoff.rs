//! Exponential backoff + a global circuit-breaker for inconclusive adjudication
//! (JEF-234).
//!
//! The judging loop caches a DECISIVE verdict so it is not re-judged while its evidence
//! fingerprint is unchanged. An `Uncertain` verdict — what a model timeout / Ollama-down
//! / OOM returns ("model unavailable") — is deliberately NOT cached, so without a gate it
//! is re-judged on EVERY pass. A pass fires on every cluster change plus the poll tick,
//! so a degraded Ollama gets re-judged for every failed entry every pass: a feedback loop
//! that hammers the struggling (OOM-prone) model and prevents recovery.
//!
//! This module is the gate. It is intentionally pure and clock-injected — every decision
//! takes the caller's `now: Instant`, so tests drive the schedule deterministically with
//! no real sleeps. There is no `Instant::now()` reached for in here.
//!
//! Two layers:
//! - PER-ENTRY backoff ([`EntryBackoff`]): each `Uncertain` grows that entry's retry delay
//!   exponentially (capped); a decisive verdict resets it.
//! - GLOBAL breaker ([`CircuitBreaker`]): when the model appears fully down (a run of
//!   consecutive `Uncertain` calls across all entries), back off the WHOLE judging pass for
//!   a cooldown window, so a fully-down Ollama's total calls-per-window is bounded
//!   regardless of how many entries exist. The first decisive success closes it.

use std::time::{Duration, Instant};

/// Base delay after the first inconclusive verdict — the first retry waits ~this long.
pub const BASE: Duration = Duration::from_secs(30);

/// Ceiling on the per-entry retry delay; the exponential growth is clamped here so a
/// long-degraded entry still gets retried roughly every `CAP`, not exponentially never.
pub const CAP: Duration = Duration::from_secs(600);

/// How many consecutive across-all-entries `Uncertain` calls trip the global breaker.
/// Below this, per-entry backoff alone governs; at/above it the model looks fully down
/// and the whole pass is gated for [`BREAKER_COOLDOWN`].
pub const BREAKER_TRIP: u32 = 3;

/// How long the global breaker stays open (no model calls at all) once tripped. While
/// open, the entire pass's `judge()` calls are skipped, so a fully-down Ollama is hit at
/// most ~once per cooldown (the one probe call that re-trips or closes it).
pub const BREAKER_COOLDOWN: Duration = Duration::from_secs(120);

/// The exponential backoff delay for an entry with `failures` consecutive inconclusive
/// verdicts (`failures >= 1`): `min(base * 2^(failures-1), cap)`, then a small
/// deterministic jitter so a fleet of entries that failed on the same pass don't all
/// retry on the exact same later pass (thundering herd).
///
/// Pure and deterministic: the jitter is derived from `(seed, failures)` via a cheap
/// hash, NOT a RNG, so the schedule is fully reproducible in tests. `seed` is the entry
/// key in production (so different entries spread out); tests pass a fixed seed to assert
/// the exact delay.
pub fn delay(failures: u32, base: Duration, cap: Duration, seed: u64) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // Exponential growth, saturating: shift past 63 (or any overflow) clamps to `cap`.
    let shift = failures.saturating_sub(1);
    let factor: u64 = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let grown = base
        .checked_mul(factor.min(u32::MAX as u64) as u32)
        .unwrap_or(cap)
        .min(cap);
    // Deterministic jitter in [0, 12.5%) of the (capped) delay, so identical-schedule
    // entries de-sync without a RNG. 1/8 keeps it cheap (a shift) and bounded.
    let jitter_span = grown / 8;
    let jitter = if jitter_span.is_zero() {
        Duration::ZERO
    } else {
        let h = mix(seed ^ ((failures as u64) << 32));
        Duration::from_nanos(h % (jitter_span.as_nanos() as u64).max(1))
    };
    (grown + jitter).min(cap + jitter_span)
}

/// A tiny integer hash (splitmix64 finalizer) — used only to derive deterministic jitter.
/// Not cryptographic; just a cheap, well-distributed scramble with no external dependency.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Per-entry inconclusive-adjudication backoff state — lives on the verdict store's entry
/// record. Default is "never failed": no backoff, retry immediately.
#[derive(Debug, Clone, Default)]
pub struct EntryBackoff {
    /// Consecutive `Uncertain` verdicts for this entry since its last decisive verdict.
    pub failures: u32,
    /// The earliest `Instant` this entry may be re-judged. `None` means no active backoff
    /// (retry now). Set on each `Uncertain`, cleared on a decisive verdict.
    pub next_retry_at: Option<Instant>,
}

impl EntryBackoff {
    /// Whether this entry is currently in backoff at `now` — i.e. the model call should be
    /// SKIPPED this pass (keep displaying the prior verdict, don't re-judge).
    pub fn is_backing_off(&self, now: Instant) -> bool {
        match self.next_retry_at {
            Some(at) => now < at,
            None => false,
        }
    }

    /// Record one inconclusive verdict at `now`: grow the failure count and arm the next
    /// retry per the exponential schedule. `seed` spreads entries' jitter apart.
    pub fn record_failure(&mut self, now: Instant, seed: u64) {
        self.failures = self.failures.saturating_add(1);
        self.next_retry_at = Some(now + delay(self.failures, BASE, CAP, seed));
    }

    /// Record a decisive verdict: clear all backoff so the entry is judged normally again.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.next_retry_at = None;
    }
}

/// Global circuit-breaker over ALL entries' adjudications (JEF-234). It bounds total model
/// calls when Ollama is fully down: per-entry backoff alone still lets N entries each fire
/// one call on the first degraded pass (N calls); this caps the whole fleet to ~one probe
/// per cooldown until the model recovers.
///
/// Clock-injected like the rest of the module — `now` is always supplied by the caller.
#[derive(Debug, Clone, Default)]
pub struct CircuitBreaker {
    /// Consecutive `Uncertain` model calls observed across ALL entries since the last
    /// decisive success. Reset to 0 by any decisive verdict.
    consecutive_failures: u32,
    /// When set and `now < open_until`, the breaker is OPEN: skip the entire pass's model
    /// calls. Cleared (closed) by the first decisive success.
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    /// Whether the breaker is open at `now` — the whole judging pass should skip its model
    /// calls (no `judge()` at all this pass), so a fully-down model is probed at most once
    /// per cooldown.
    pub fn is_open(&self, now: Instant) -> bool {
        match self.open_until {
            Some(until) => now < until,
            None => false,
        }
    }

    /// Record one inconclusive model call at `now`. When the consecutive-failure run
    /// reaches [`BREAKER_TRIP`], (re)open the breaker for [`BREAKER_COOLDOWN`].
    pub fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= BREAKER_TRIP {
            self.open_until = Some(now + BREAKER_COOLDOWN);
        }
    }

    /// Record a decisive model call: the model answered, so close the breaker and clear the
    /// failure run. The first success after an outage immediately restores normal judging.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed seed makes the (deterministic) jitter reproducible so we can assert the
    // delay falls in the exact [base*2^(n-1), +12.5%) band per failure count.
    const SEED: u64 = 0;

    fn assert_band(failures: u32, lo: Duration, hi: Duration) {
        let d = delay(failures, BASE, CAP, SEED);
        assert!(
            d >= lo && d < hi,
            "failures={failures}: delay {d:?} not in [{lo:?}, {hi:?})"
        );
    }

    #[test]
    fn delay_is_zero_with_no_failures() {
        assert_eq!(delay(0, BASE, CAP, SEED), Duration::ZERO);
    }

    #[test]
    fn delay_grows_exponentially_then_caps() {
        // 1 -> 30s, 2 -> 60s, 3 -> 120s, 4 -> 240s, 5 -> 480s, then clamps at 600s.
        assert_band(1, Duration::from_secs(30), Duration::from_millis(33_750));
        assert_band(2, Duration::from_secs(60), Duration::from_millis(67_500));
        assert_band(3, Duration::from_secs(120), Duration::from_millis(135_000));
        assert_band(4, Duration::from_secs(240), Duration::from_millis(270_000));
        assert_band(5, Duration::from_secs(480), Duration::from_millis(540_000));
        // At/after the cap, the delay never exceeds CAP + the jitter span (CAP/8).
        for n in 6..40 {
            let d = delay(n, BASE, CAP, SEED);
            assert!(
                d >= CAP && d <= CAP + CAP / 8,
                "failures={n}: delay {d:?} should be clamped near CAP"
            );
        }
    }

    #[test]
    fn delay_never_panics_on_extreme_failure_counts() {
        // Saturating math: huge counts clamp, they don't overflow/panic.
        let _ = delay(u32::MAX, BASE, CAP, 12345);
    }

    #[test]
    fn entry_backoff_gates_then_reopens_after_the_delay() {
        let now = Instant::now();
        let mut b = EntryBackoff::default();
        assert!(!b.is_backing_off(now), "fresh entry is not backing off");

        b.record_failure(now, SEED);
        assert_eq!(b.failures, 1);
        // Immediately after a failure the entry is gated (next pass would skip).
        assert!(b.is_backing_off(now));
        // Still gated just before the first-retry delay elapses...
        assert!(b.is_backing_off(now + BASE - Duration::from_millis(1)));
        // ...and open again once the (capped) delay has fully elapsed.
        assert!(!b.is_backing_off(now + CAP + CAP / 8 + Duration::from_secs(1)));
    }

    #[test]
    fn entry_backoff_resets_on_decisive_success() {
        let now = Instant::now();
        let mut b = EntryBackoff::default();
        b.record_failure(now, SEED);
        b.record_failure(now, SEED);
        assert_eq!(b.failures, 2);
        b.record_success();
        assert_eq!(b.failures, 0);
        assert!(!b.is_backing_off(now), "a decisive verdict clears backoff");
    }

    #[test]
    fn breaker_trips_after_n_consecutive_failures_and_closes_on_success() {
        let now = Instant::now();
        let mut cb = CircuitBreaker::default();
        assert!(!cb.is_open(now));
        // Below the trip threshold the breaker stays closed.
        for _ in 0..(BREAKER_TRIP - 1) {
            cb.record_failure(now);
            assert!(
                !cb.is_open(now),
                "must not trip before {BREAKER_TRIP} failures"
            );
        }
        // The trip'th consecutive failure opens it for the cooldown window.
        cb.record_failure(now);
        assert!(cb.is_open(now));
        assert!(cb.is_open(now + BREAKER_COOLDOWN - Duration::from_millis(1)));
        assert!(!cb.is_open(now + BREAKER_COOLDOWN), "closes after cooldown");

        // A decisive success closes it immediately, even mid-cooldown.
        cb.record_failure(now);
        cb.record_failure(now);
        cb.record_failure(now);
        assert!(cb.is_open(now));
        cb.record_success();
        assert!(
            !cb.is_open(now),
            "first decisive success closes the breaker"
        );
    }
}
