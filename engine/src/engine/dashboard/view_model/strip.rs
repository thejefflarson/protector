//! Map the engine's [`Readiness`] coverage snapshot + the per-pass freshness into the
//! persistent [`StatusStripProps`] (the three honesty axes — decided/judging/covered). This is
//! the load-bearing honesty surface: `model_judging`/`warming_up` flow straight through so the
//! components can refuse to render a calm/green all-clear when it would be dishonest (invariant
//! #1).

use std::time::SystemTime;

use crate::engine::state::Readiness;

use super::posture::human_age;
use super::props::{CoverageChip, StatusStripProps};

/// The enrichment feeds shown as coverage chips in the strip, in a stable order. Arm-state and
/// journal are reported elsewhere (the mode pill / Readiness tab), not as coverage chips.
const COVERAGE_FEEDS: [(&str, &str); 3] = [
    ("kev", "KEV"),
    ("epss", "EPSS"),
    // ONE agent-sourced runtime-corroboration chip (JEF-308). It goes degraded the moment any
    // expected node is blind (the collapsed readiness row's Degraded state), and reads as a gap
    // (not present) when corroboration is wholly blind.
    ("runtime-corroboration", "Runtime"),
];

/// Build the coverage chips from the readiness rows. A `Present` row is covered; a `Degraded`
/// one is degraded (configured but not answering — distinct from absent); `Absent` is a gap.
fn coverage_chips(readiness: &Readiness) -> Vec<CoverageChip> {
    use crate::engine::state::InputState;
    COVERAGE_FEEDS
        .iter()
        .filter_map(|(id, label)| {
            let row = readiness.inputs.iter().find(|r| r.id == *id)?;
            Some(CoverageChip {
                label: label.to_string(),
                present: row.state == InputState::Present,
                degraded: row.state == InputState::Degraded,
                // Expected-but-wholly-dark this pass (cold start / crash-loop): loud, forbids green,
                // DISTINCT from absent (never enabled). The per-pass companion to `stalled`.
                blind: row.state == InputState::Blind,
                // The stall register is a CROSS-PASS edge the readiness row can't see (it's derived
                // per-pass); it's overlaid later via `StatusStripProps::with_coverage_stall`.
                stalled: false,
            })
        })
        .collect()
}

/// Whether the engine is armed (enforcing), read from the readiness `arm-state` row's detail.
fn armed_from(readiness: &Readiness) -> bool {
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "arm-state")
        .map(|r| r.detail.starts_with("enforcing"))
        .unwrap_or(false)
}

/// Build the status-strip props. `cluster` is the cluster label; `last_pass` the engine's
/// last-pass time (for the freshness line); the headline counts come from the mapped findings
/// (filled by the caller — see [`super::build_status_strip`]). Pure given its inputs.
#[allow(clippy::too_many_arguments)]
pub(super) fn status_strip(
    cluster: String,
    readiness: &Readiness,
    last_pass: Option<SystemTime>,
    breach_count: usize,
    awaiting_count: usize,
    uncertain_count: usize,
    cleared_count: usize,
    escalated_count: usize,
) -> StatusStripProps {
    StatusStripProps {
        cluster,
        armed: armed_from(readiness),
        model_judging: readiness.model_judging,
        warming_up: readiness.warming_up,
        model_attached: readiness.model_attached(),
        coverage: coverage_chips(readiness),
        // Overlaid later by the caller with the cross-pass stall register (JEF-421).
        coverage_alert: None,
        last_pass: last_pass.map(last_pass_age),
        breach_count,
        awaiting_count,
        uncertain_count,
        cleared_count,
        escalated_count,
        // Signing-regression counts (JEF-264) are wired in by the caller that holds the
        // admission-decision log (`DashboardState::with_signing_regressions`); the findings-derived
        // strip carries none of its own.
        signing_regression_breach: 0,
        signing_regression_uncertain: 0,
    }
}

/// Render the "last pass NNs ago" age from a wall-clock instant, clamped at 0.
fn last_pass_age(at: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(at)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{} ago", human_age(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::coverage_stall_alert;
    use crate::engine::state::{
        BlindReason, CoverageAlert, CoverageState, ModelHealth, NodeCoverage, NodeState,
        ReadinessConfig, RuntimeCoverage, derive_readiness,
    };

    fn covered() -> ReadinessConfig {
        ReadinessConfig {
            model_attached: true,
            kev_count: 5,
            epss_count: 5,
            journal_durable: true,
            armed: false,
            tuf_cache_age_secs: Some(60),
            unverifiable_spike: false,
            checking_images: 0,
        }
    }

    /// A coverage snapshot from `(node, state)` pairs.
    fn coverage(nodes: &[(&str, NodeState)]) -> RuntimeCoverage {
        RuntimeCoverage {
            nodes: nodes
                .iter()
                .map(|(n, s)| NodeCoverage {
                    node: (*n).to_string(),
                    state: *s,
                })
                .collect(),
        }
    }

    #[test]
    fn judging_model_strip_is_honest_calm() {
        // One healthy agent node → the Runtime chip is present.
        let cov = coverage(&[("node-a", NodeState::Healthy { signals: 2 })]);
        let r = derive_readiness(&covered(), ModelHealth::Ok, Some(SystemTime::now()), &cov);
        // Judging + covered + nothing breach/awaiting/uncertain (3 cleared) ⇒ honest all-clear.
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0);
        assert!(strip.model_is_up());
        assert!(strip.all_clear());
        assert!(!strip.watching());
        assert!(!strip.armed);
        // Runtime corroboration is ONE agent-sourced Runtime chip (JEF-308).
        assert!(strip.coverage.iter().all(|c| c.label != "eBPF"));
        let runtime = strip
            .coverage
            .iter()
            .find(|c| c.label == "Runtime")
            .unwrap();
        assert!(runtime.present);
        assert!(!runtime.degraded);
    }

    /// JEF-308: the Runtime chip goes degraded the moment any expected node is blind.
    #[test]
    fn a_blind_node_degrades_the_runtime_chip() {
        let cov = coverage(&[
            ("node-a", NodeState::Healthy { signals: 1 }),
            (
                "node-b",
                NodeState::Blind {
                    reason: BlindReason::NotReporting,
                },
            ),
        ]);
        let r = derive_readiness(&covered(), ModelHealth::Ok, Some(SystemTime::now()), &cov);
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0);
        let runtime = strip
            .coverage
            .iter()
            .find(|c| c.label == "Runtime")
            .unwrap();
        assert!(
            runtime.degraded,
            "a blind node degrades the corroboration chip"
        );
        assert!(
            !strip.all_clear(),
            "a degraded feed forbids the green all-clear"
        );
    }

    /// JEF-421: a covering Runtime feed that STALLED (server-derived `CoverageState::Stalled`)
    /// marks the chip stalled, forbids the green all-clear, ships the strip-level coverage-alert —
    /// and leaves the JUDGING axis independent (the model is still judging; a coverage stall must
    /// NOT downgrade "model judging" to blind).
    #[test]
    fn a_stalled_runtime_feed_is_loud_but_leaves_judging_independent() {
        let cov = coverage(&[("node-a", NodeState::Healthy { signals: 1 })]);
        let stalled = CoverageState::Stalled(CoverageAlert {
            feed_label: "Runtime".into(),
            last_observation: Some("2m ago".into()),
            message: "runtime corroboration stalled — all 1 sensor node went dark".into(),
        });
        // The readiness overlay escalates the runtime row; the strip overlay marks the chip + banner.
        let r = derive_readiness(&covered(), ModelHealth::Ok, Some(SystemTime::now()), &cov)
            .with_coverage_stall(&stalled);
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0)
            .with_coverage_stall(coverage_stall_alert(&stalled));

        let runtime = strip
            .coverage
            .iter()
            .find(|c| c.label == "Runtime")
            .unwrap();
        assert!(runtime.stalled, "the covering feed reads stalled");
        assert!(!runtime.present && !runtime.degraded);
        assert!(
            !strip.all_clear(),
            "a stalled feed forbids the green all-clear"
        );
        assert!(strip.coverage_alert.is_some(), "the banner ships");
        // The JUDGING axis is independent: the model is still up/judging (not blind/no-model).
        assert!(
            strip.model_is_up(),
            "a coverage stall does not downgrade model judging"
        );
        assert_ne!(strip.judging_state(), "blind");
        assert_ne!(strip.judging_state(), "no-model");
    }

    /// JEF-421: an ABSENT (never-enabled) coverage feed stays muted/honest — no stall banner, and
    /// its known-absence does NOT by itself forbid the green all-clear.
    #[test]
    fn absent_coverage_is_muted_not_stalled() {
        // A never-covering fleet ⇒ CoverageState::Absent ⇒ no alert overlay.
        let absent = CoverageState::Absent;
        assert!(coverage_stall_alert(&absent).is_none());
        // With an all-healthy fleet + Absent state overlay, the strip stays all-clear (absent state
        // makes no change — the honest known-absence never manufactures a stall).
        let cov = coverage(&[("node-a", NodeState::Healthy { signals: 1 })]);
        let r = derive_readiness(&covered(), ModelHealth::Ok, Some(SystemTime::now()), &cov)
            .with_coverage_stall(&absent);
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0)
            .with_coverage_stall(coverage_stall_alert(&absent));
        assert!(strip.coverage_alert.is_none());
        assert!(strip.all_clear());
    }

    #[test]
    fn timed_out_model_strip_is_not_calm() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Timeout,
            Some(SystemTime::now()),
            &RuntimeCoverage::default(),
        );
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 0, 0);
        assert!(!strip.model_is_up());
        assert!(!strip.all_clear());
        assert!(!strip.watching()); // model down ⇒ neither all-clear nor watching
        assert!(strip.model_attached); // configured, just not answering
    }

    #[test]
    fn warming_strip_is_not_calm() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Unknown,
            None,
            &RuntimeCoverage::default(),
        );
        let strip = status_strip("prod".into(), &r, None, 0, 0, 0, 0, 0);
        assert!(!strip.model_is_up());
        assert!(!strip.all_clear());
        assert!(strip.warming_up);
        assert!(strip.last_pass.is_none());
    }

    /// JEF-264: an ESTABLISHED-baseline signing regression counts toward breach — it forbids the
    /// green all-clear AND the calm "watching" reading (it is louder than watching).
    #[test]
    fn established_signing_regression_forbids_green_and_watching() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Ok,
            Some(SystemTime::now()),
            &RuntimeCoverage::default(),
        );
        // Everything else is clear (would be all-clear) — but one established regression stands.
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0)
            .with_signing_regressions(1, 0);
        assert!(strip.has_signing_regression());
        assert!(
            !strip.all_clear(),
            "a standing regression can never read as green"
        );
        assert!(
            !strip.watching(),
            "an established regression is louder than the calm watching register"
        );
    }

    /// JEF-264: a COLD-baseline signing regression maps to uncertain — it forbids green, but reads
    /// as the calmer, non-green "watching" register (a weak lead, not a breach).
    #[test]
    fn cold_signing_regression_is_watching_not_green() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Ok,
            Some(SystemTime::now()),
            &RuntimeCoverage::default(),
        );
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0)
            .with_signing_regressions(0, 1);
        assert!(!strip.all_clear(), "a cold regression still forbids green");
        assert!(
            strip.watching(),
            "a cold regression reads as the calm watching register"
        );
    }

    /// Judging + covered but an entry is still awaiting/uncertain ⇒ NOT all-clear; the elevated
    /// "watching" state (the model hasn't finished — quiet is not clearance). Refinement A.
    #[test]
    fn judging_with_pending_entries_is_watching_not_all_clear() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Ok,
            Some(SystemTime::now()),
            &RuntimeCoverage::default(),
        );
        // One entry still awaiting, one still uncertain — model hasn't cleared everything.
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 1, 1, 4, 0);
        assert!(strip.model_is_up());
        assert!(
            !strip.all_clear(),
            "pending entries forbid the green all-clear"
        );
        assert!(
            strip.watching(),
            "it is the elevated watching state instead"
        );
    }
}
