//! The ENGINE-INTERNALS view-model (JEF-255): the demoted diagnostics behind the page's one
//! collapsed `<details>` — coverage detail (the readiness rows), recent reversions (lifted
//! cuts), and the behavioral-bake counts. Never competes with the answer; it is the
//! "am I covered / what's the engine doing" detail an operator opens on demand.
//!
//! Pure data shaping over the readiness snapshot, the reversion log, and the bake stats; the
//! renderer takes only these props (ADR-0019).

use crate::engine::dashboard::model::{BakeStats, ReversionRecord, relative_time};
use crate::engine::dashboard::view_model::readiness_data::Readiness;
use std::time::{Duration, UNIX_EPOCH};

/// One coverage row in the internals disclosure — a decision input, its live state word, the
/// "why it matters", the enabling env/mount, and a live detail. Whether its absence weakens
/// the model's decision drives the visual emphasis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRow {
    pub label: &'static str,
    pub state: &'static str,
    pub why: &'static str,
    pub enable: &'static str,
    pub detail: String,
    pub weakens: bool,
}

/// One lifted-cut row — the cut signature, why it was lifted, and how long ago.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversionRow {
    pub cut: String,
    pub reason: String,
    pub ago: String,
}

/// One behavioral-bake count line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BakeRow {
    pub label: &'static str,
    pub value: String,
}

/// The whole internals disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalsProps {
    pub coverage: Vec<CoverageRow>,
    /// True if any decision-weakening input is unmet — the page opens the disclosure so a
    /// blind cluster is not silently calm.
    pub coverage_unmet: bool,
    pub reversions: Vec<ReversionRow>,
    pub bake: Vec<BakeRow>,
}

/// Build the internals props from the live readiness, the reversion log, and the bake stats.
pub fn internals_props(
    readiness: &Readiness,
    reversions: &[ReversionRecord],
    bake: &BakeStats,
) -> InternalsProps {
    InternalsProps {
        coverage: readiness
            .inputs
            .iter()
            .map(|r| CoverageRow {
                label: r.label,
                state: r.state.word(),
                why: r.why,
                enable: r.enable,
                detail: r.detail.clone(),
                weakens: r.weakens_decisions,
            })
            .collect(),
        coverage_unmet: readiness.has_unmet(),
        reversions: reversions.iter().map(reversion_row).collect(),
        bake: bake_rows(bake),
    }
}

fn reversion_row(r: &ReversionRecord) -> ReversionRow {
    let at = UNIX_EPOCH + Duration::from_millis(r.at_ms);
    ReversionRow {
        cut: r.cut.clone(),
        reason: r.reason.clone(),
        ago: relative_time(Some(at)),
    }
}

fn bake_rows(bake: &BakeStats) -> Vec<BakeRow> {
    vec![
        BakeRow {
            label: "signals this pass",
            value: bake.total_signals().to_string(),
        },
        BakeRow {
            label: "attributed (resolved)",
            value: bake.resolved.to_string(),
        },
        BakeRow {
            label: "unattributed (unresolved)",
            value: bake.unresolved.to_string(),
        },
        BakeRow {
            label: "runtime working set",
            value: bake.runtime_store.to_string(),
        },
        BakeRow {
            label: "corroborations this pass",
            value: bake.corroborations.to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{ModelHealth, ReadinessConfig};
    use crate::engine::dashboard::view_model::readiness_data::derive_readiness;
    use std::time::SystemTime;

    fn readiness() -> Readiness {
        derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        )
    }

    #[test]
    fn coverage_rows_mirror_readiness_and_flag_unmet() {
        let p = internals_props(&readiness(), &[], &BakeStats::default());
        assert!(!p.coverage.is_empty());
        assert!(p.coverage_unmet, "default config is all-absent → unmet");
        // The model row weakens decisions and reads absent here.
        let model = p
            .coverage
            .iter()
            .find(|r| r.label == "Model adjudicator")
            .unwrap();
        assert_eq!(model.state, "absent");
        assert!(model.weakens);
    }

    #[test]
    fn bake_rows_carry_the_counts() {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("exec".into(), 4);
        bake.corroborations = 2;
        let p = internals_props(&readiness(), &[], &bake);
        let signals = p
            .bake
            .iter()
            .find(|r| r.label == "signals this pass")
            .unwrap();
        assert_eq!(signals.value, "4");
        let corr = p
            .bake
            .iter()
            .find(|r| r.label == "corroborations this pass")
            .unwrap();
        assert_eq!(corr.value, "2");
    }

    #[test]
    fn reversion_rows_render_cut_reason_and_age() {
        let rev = ReversionRecord {
            cut: "a -[reaches]-> b".into(),
            reason: "breach condition cleared".into(),
            at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };
        let p = internals_props(&readiness(), &[rev], &BakeStats::default());
        assert_eq!(p.reversions.len(), 1);
        assert_eq!(p.reversions[0].cut, "a -[reaches]-> b");
        assert_eq!(p.reversions[0].reason, "breach condition cleared");
    }
}
