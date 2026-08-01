//! The cut-divergence log: a bounded, newest-last ring of recent
//! [`crate::engine::cut_divergence::DivergenceRecord`]s, analogous to [`super::ReversionLog`] —
//! shared between the engine (writer) and the dashboard's read-only view (reader). Audit only;
//! pure data. Feeds the shadow-bake arm-readiness exit criterion (see
//! `docs/adr/0037-shadow-bake-arm-readiness.md`): a human reads
//! this log (and the durable journal's `CutDivergence` lines it mirrors) to decide whether the
//! model-vs-deterministic bake has cleared the bar for the `enforce` flip — this log itself
//! decides nothing and mutates nothing else (ADR-0016, presentation is a view, never a gate).

use std::sync::Mutex;

use serde::Serialize;

use crate::engine::cut_divergence::{DivergenceClass, DivergenceRecord};

/// One entry's divergence classification, durable-log shape (JSON-serializable for the
/// read-only view).
#[derive(Clone, Serialize)]
pub struct DivergenceRow {
    /// The internet-facing entry this classification was computed for.
    pub entry: String,
    /// How the model's chosen cut-set compared to the deterministic fallback set.
    pub class: DivergenceClass,
    /// Node keys the model named this pass (sorted, deduped) — empty for a decisive `NoAttack`.
    pub model_cuts: Vec<String>,
    /// Node keys `containment_for` + the quarantine-target resolvers would propose for the
    /// same chains, independent of the model's call (sorted, deduped).
    pub deterministic_cuts: Vec<String>,
    /// When this pass computed the classification, Unix epoch milliseconds (so the row is
    /// self-contained and a reader can render "NNs ago").
    pub at_ms: u64,
}

impl DivergenceRow {
    /// Stamp a [`DivergenceRecord`] with the current wall-clock time.
    pub fn now(record: DivergenceRecord) -> Self {
        let at_ms = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            entry: record.entry,
            class: record.class,
            model_cuts: record.model_cuts,
            deterministic_cuts: record.deterministic_cuts,
            at_ms,
        }
    }
}

/// A bounded, newest-last ring of recent [`DivergenceRow`]s. Audit only — the engine appends,
/// the dashboard's read-only view snapshots; neither ever mutates a mitigation or the ledger
/// from here (view-never-mutates, ADR-0016).
#[derive(Default)]
pub struct DivergenceLog {
    rows: Mutex<std::collections::VecDeque<DivergenceRow>>,
}

impl DivergenceLog {
    pub(crate) const CAP: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Append a classification, evicting the oldest once at capacity.
    pub fn record(&self, row: DivergenceRow) {
        let mut rows = self.rows.lock().expect("divergence log mutex poisoned");
        if rows.len() >= Self::CAP {
            rows.pop_front();
        }
        rows.push_back(row);
    }

    /// Snapshot newest-first for the read-only view.
    pub fn snapshot(&self) -> Vec<DivergenceRow> {
        self.rows
            .lock()
            .expect("divergence log mutex poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Counts by [`DivergenceClass`] over the current ring — the summary the arm-readiness
    /// exit criterion reads (see `docs/adr/0037-shadow-bake-arm-readiness.md`): a nonzero
    /// `model_over_cut` count against a
    /// clean/no-evidence workload, or any standing `mixed` divergence, is a bake-bar failure.
    pub fn class_counts(&self) -> DivergenceCounts {
        let rows = self.rows.lock().expect("divergence log mutex poisoned");
        let mut counts = DivergenceCounts::default();
        for row in rows.iter() {
            match row.class {
                DivergenceClass::Agree => counts.agree += 1,
                DivergenceClass::ModelOverCut => counts.model_over_cut += 1,
                DivergenceClass::ModelUnderCut => counts.model_under_cut += 1,
                DivergenceClass::Mixed => counts.mixed += 1,
            }
        }
        counts
    }
}

/// A tally of the current ring's [`DivergenceClass`]es — the compact summary the arm-readiness
/// review reads without walking every row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DivergenceCounts {
    pub agree: usize,
    pub model_over_cut: usize,
    pub model_under_cut: usize,
    pub mixed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(entry: &str, class: DivergenceClass) -> DivergenceRow {
        DivergenceRow {
            entry: entry.to_string(),
            class,
            model_cuts: Vec::new(),
            deterministic_cuts: Vec::new(),
            at_ms: 0,
        }
    }

    #[test]
    fn ring_evicts_oldest_past_capacity() {
        let log = DivergenceLog::new();
        for i in 0..DivergenceLog::CAP + 10 {
            log.record(row(&format!("entry-{i}"), DivergenceClass::Agree));
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), DivergenceLog::CAP);
        // Newest-first: the last-recorded row is first.
        assert_eq!(
            snapshot[0].entry,
            format!("entry-{}", DivergenceLog::CAP + 9)
        );
        // The oldest CAP+10 - CAP = 10 rows were evicted.
        assert_eq!(snapshot.last().unwrap().entry, "entry-10");
    }

    #[test]
    fn class_counts_tally_the_current_ring() {
        let log = DivergenceLog::new();
        log.record(row("a", DivergenceClass::Agree));
        log.record(row("b", DivergenceClass::ModelOverCut));
        log.record(row("c", DivergenceClass::ModelUnderCut));
        log.record(row("d", DivergenceClass::Mixed));
        log.record(row("e", DivergenceClass::Agree));

        let counts = log.class_counts();
        assert_eq!(
            counts,
            DivergenceCounts {
                agree: 2,
                model_over_cut: 1,
                model_under_cut: 1,
                mixed: 1,
            }
        );
    }
}
