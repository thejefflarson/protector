//! The **coverage-stall** edge (JEF-421): the cross-pass tracker that turns the per-pass
//! [`RuntimeCoverage`] into a loud, server-derived **stalled** signal when protector's OWN runtime
//! sensors go dark — a fleet that WAS corroborating (at least one expected node healthy) and has now
//! gone FULLY blind, held across a debounce window so a normal DaemonSet roll never strobes.
//!
//! Honesty (ADR-0016/0025): the STALL is derived HERE, on the server, from live coverage — the
//! client only selects copy. The threshold (`STALL_HOLD_PASSES`), the "was covering" memory, and the
//! last-healthy timestamp all live server-side so the wire carries the decided answer, never the
//! inputs to re-derive it. **Stalled is DISTINCT from absent** (never-enabled coverage): a fleet that
//! was never corroborating is honestly *absent* (muted), not *stalled* (loud). A partial fleet is
//! *degraded*, not stalled. Only was-covering → now-silent trips the loud edge.

use std::time::SystemTime;

use super::RuntimeCoverage;

/// How many CONSECUTIVE fully-blind passes a was-covering fleet must stay dark before the stall edge
/// fires. The debounce (hysteresis): a routine DaemonSet roll blinds a node (or briefly the fleet)
/// for a pass or two while pods reschedule — holding the edge for this many passes keeps that from
/// strobing the loud "stalled" banner. The FLEET-WIDE dark condition (every expected node blind) is
/// already itself far past a single-node blip; the hold guards the last-pod-rescheduling window.
pub const STALL_HOLD_PASSES: u32 = 3;

/// The coarse, server-derived coverage register the STRIP chip renders (JEF-421). Distinct rungs so
/// the loud `Stalled` (was-covering → now-silent) never collapses into the muted, honest `Absent`
/// (coverage was never enabled) nor the partial `Degraded`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CoverageState {
    /// Coverage was never enabled (no expected nodes), OR a never-covering fleet is dark — an
    /// honest known-absence, muted. NOT a stall. The default until the first pass observes coverage.
    #[default]
    Absent,
    /// Every expected node reporting, probes loaded — corroboration is live.
    Covered,
    /// Some expected nodes blind or partially probing, others healthy — partial coverage.
    Degraded,
    /// A fleet that WAS corroborating has gone fully blind and stayed dark past the debounce —
    /// the loud edge. Carries the alert payload the strip renders as a banner.
    Stalled(CoverageAlert),
}

/// The strip-level **coverage-alert** payload (JEF-421), present ONLY when a covering feed stalled.
/// Additive on the wire; the client renders it verbatim (no honesty derivation) and never
/// synthesizes it. Every string is UNTRUSTED at render (escaped by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageAlert {
    /// The stalled feed's human label (`Runtime`).
    pub feed_label: String,
    /// A human "N ago" for the last pass the fleet was still corroborating — when the sensors were
    /// last observed live. `None` if we never captured a healthy observation (shouldn't happen for a
    /// stall, which requires a prior covering pass, but honest if the clock is unavailable).
    pub last_observation: Option<String>,
    /// The honest one-line message: how many of how many nodes went dark.
    pub message: String,
}

/// The cross-pass **stall tracker** (JEF-421): remembers whether the fleet was ever corroborating,
/// stamps the last-healthy wall-clock time, and counts consecutive fully-blind passes so the loud
/// stall edge only fires after the debounce. One instance per engine, updated each pass in
/// `Findings::stamp_runtime_coverage`. Pure over its `(coverage, now)` input given its held state.
#[derive(Debug, Default)]
pub struct CoverageStallTracker {
    /// The fleet has been corroborating at least once (≥1 expected node healthy) since boot — the
    /// "was covering" memory that distinguishes a STALL (was covering → now dark) from a never-
    /// enabled ABSENCE. Latches true; a stall doesn't clear it (a recovered fleet can stall again).
    was_covering: bool,
    /// The last wall-clock time the fleet had a healthy expected node — the "last observed live"
    /// timestamp the alert surfaces. `None` until the first healthy pass.
    last_healthy_at: Option<SystemTime>,
    /// Consecutive passes the was-covering fleet has been FULLY blind. Reset the moment any expected
    /// node reports healthy again. The stall edge fires once this reaches [`STALL_HOLD_PASSES`].
    blind_passes: u32,
}

impl CoverageStallTracker {
    /// Observe this pass's coverage and derive the coarse [`CoverageState`] for the strip chip,
    /// firing the loud `Stalled` edge only when a WAS-COVERING fleet has been fully blind for
    /// [`STALL_HOLD_PASSES`] consecutive passes. `now` is the pass's wall clock (injected so the
    /// tests are deterministic). Updates the held state as a side effect.
    pub fn observe(&mut self, coverage: &RuntimeCoverage, now: SystemTime) -> CoverageState {
        let expected = coverage.expected_count();

        // No expected nodes: coverage isn't enabled in scope this pass — honestly absent, never a
        // stall. Don't advance the blind counter (a fleet that isn't scheduled can't "go dark").
        if expected == 0 {
            return CoverageState::Absent;
        }

        let healthy = coverage.healthy_count();
        let fully_blind = coverage.blind_nodes().len() == expected;

        if healthy > 0 {
            // At least one node is corroborating — the fleet is live. Latch "was covering", stamp the
            // last-healthy time, and clear the blind streak. Covered iff EVERY expected node is
            // healthy; otherwise partial → degraded.
            self.was_covering = true;
            self.last_healthy_at = Some(now);
            self.blind_passes = 0;
            return if coverage.all_healthy() {
                CoverageState::Covered
            } else {
                CoverageState::Degraded
            };
        }

        // No healthy node this pass. If the fleet is only PARTIALLY blind (some nodes are degraded-
        // probes, none healthy) it's still degraded, not a stall — and not a clean blind streak.
        if !fully_blind {
            self.blind_passes = 0;
            return CoverageState::Degraded;
        }

        // Fully blind. A fleet that was NEVER corroborating is honestly absent (never-enabled), not
        // stalled — don't manufacture a stall out of a cold start that never came up.
        if !self.was_covering {
            return CoverageState::Absent;
        }

        // Was covering, now fully dark: advance the debounce. Until it clears the hold window this
        // reads as degraded (loud-but-not-yet-stalled), so a DaemonSet roll doesn't strobe.
        self.blind_passes = self.blind_passes.saturating_add(1);
        if self.blind_passes < STALL_HOLD_PASSES {
            return CoverageState::Degraded;
        }

        CoverageState::Stalled(self.alert(expected, now))
    }

    /// Build the stall alert payload — the stalled feed label, the "N ago" last-observed time, and
    /// the honest "N of M nodes went dark" message.
    fn alert(&self, expected: usize, now: SystemTime) -> CoverageAlert {
        CoverageAlert {
            feed_label: "Runtime".to_string(),
            last_observation: self.last_healthy_at.map(|at| last_observed_age(at, now)),
            message: format!(
                "runtime corroboration stalled — all {expected} sensor node{} went dark (was reporting); paths on these nodes are no longer being watched",
                if expected == 1 { "" } else { "s" }
            ),
        }
    }
}

/// A coarse "N ago" for the last-observed-live line — whole units only (the alert is an at-a-glance
/// hint, not a precise clock). Clamps a non-monotonic clock read to 0.
fn last_observed_age(at: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(at).map(|d| d.as_secs()).unwrap_or(0);
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    let unit = if secs >= DAY {
        format!("{}d", secs / DAY)
    } else if secs >= HOUR {
        format!("{}h", secs / HOUR)
    } else if secs >= MIN {
        format!("{}m", secs / MIN)
    } else {
        format!("{secs}s")
    };
    format!("{unit} ago")
}

#[cfg(test)]
#[path = "stall_tests.rs"]
mod tests;
