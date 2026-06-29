//! The reversion log: one [`ReversionRecord`] (a lifted cut and why) and the bounded
//! [`ReversionLog`] ring the engine writes and the metrics mirror reads, seeded from the
//! journal on boot so lifted cuts survive a restart. Audit only; pure data.

use std::sync::Mutex;

use serde::Serialize;

/// One lifted cut for the reversion log (JEF-141): the self-revert is the core safety story
/// (ADR-0016 — a cut persists only while the breach condition holds, then self-reverts), made
/// durable and visible here so a lifted cut is not invisible.
#[derive(Clone, Serialize)]
pub struct ReversionRecord {
    /// The cut signature that was lifted (`from -[relation]-> to`).
    pub cut: String,
    /// Why it was lifted — health divergence, or the breach condition cleared.
    pub reason: String,
    /// When it was lifted, Unix epoch milliseconds (so the record is self-contained and a
    /// consumer can render "NNs ago").
    pub at_ms: u64,
}

/// A bounded, newest-last ring of recent [`ReversionRecord`]s, analogous to
/// [`super::JudgementLog`] — shared between the engine (writer) and any reader, and seeded
/// from the journal on boot so lifted cuts survive a restart. Audit only.
#[derive(Default)]
pub struct ReversionLog {
    rows: Mutex<std::collections::VecDeque<ReversionRecord>>,
}

impl ReversionLog {
    pub(crate) const CAP: usize = 64;

    pub fn new() -> Self {
        Self::default()
    }

    /// Append a reversion, evicting the oldest once at capacity.
    pub fn record(&self, reversion: ReversionRecord) {
        let mut rows = self.rows.lock().expect("reversion log mutex poisoned");
        if rows.len() >= Self::CAP {
            rows.pop_front();
        }
        rows.push_back(reversion);
    }

    /// Snapshot newest-first for inspection.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<ReversionRecord> {
        self.rows
            .lock()
            .expect("reversion log mutex poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}
