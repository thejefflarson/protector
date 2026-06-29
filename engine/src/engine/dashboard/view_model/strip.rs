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
const COVERAGE_FEEDS: [(&str, &str); 4] = [
    ("kev", "KEV"),
    ("epss", "EPSS"),
    ("falco", "Falco"),
    ("ebpf-agent", "eBPF"),
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
        last_pass: last_pass.map(last_pass_age),
        breach_count,
        awaiting_count,
        uncertain_count,
        cleared_count,
        escalated_count,
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
    use crate::engine::state::{BakeStats, ModelHealth, ReadinessConfig, derive_readiness};

    fn covered() -> ReadinessConfig {
        ReadinessConfig {
            model_attached: true,
            kev_count: 5,
            epss_count: 5,
            journal_durable: true,
            armed: false,
        }
    }

    #[test]
    fn judging_model_strip_is_honest_calm() {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("alert".into(), 1);
        let r = derive_readiness(&covered(), ModelHealth::Ok, &bake, Some(SystemTime::now()));
        // Judging + covered + nothing breach/awaiting/uncertain (3 cleared) ⇒ honest all-clear.
        let strip = status_strip("prod".into(), &r, Some(SystemTime::now()), 0, 0, 0, 3, 0);
        assert!(strip.model_is_up());
        assert!(strip.all_clear());
        assert!(!strip.watching());
        assert!(!strip.armed);
        // KEV/EPSS present; Falco present (alert signal); eBPF absent.
        let falco = strip.coverage.iter().find(|c| c.label == "Falco").unwrap();
        assert!(falco.present);
        let ebpf = strip.coverage.iter().find(|c| c.label == "eBPF").unwrap();
        assert!(!ebpf.present);
    }

    #[test]
    fn timed_out_model_strip_is_not_calm() {
        let r = derive_readiness(
            &covered(),
            ModelHealth::Timeout,
            &BakeStats::default(),
            Some(SystemTime::now()),
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
            &BakeStats::default(),
            None,
        );
        let strip = status_strip("prod".into(), &r, None, 0, 0, 0, 0, 0);
        assert!(!strip.model_is_up());
        assert!(!strip.all_clear());
        assert!(strip.warming_up);
        assert!(strip.last_pass.is_none());
    }

    /// Judging + covered but an entry is still awaiting/uncertain ⇒ NOT all-clear; the elevated
    /// "watching" state (the model hasn't finished — quiet is not clearance). Refinement A.
    #[test]
    fn judging_with_pending_entries_is_watching_not_all_clear() {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("alert".into(), 1);
        let r = derive_readiness(&covered(), ModelHealth::Ok, &bake, Some(SystemTime::now()));
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
