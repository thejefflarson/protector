//! The model-judgement record: one [`Judgement`] (the prompt the model saw, its raw reply, and
//! the final verdict after the guards) and the bounded [`JudgementLog`] ring the adjudicator
//! writes and the metrics mirror reads. Diagnostic only; pure data.

use std::sync::Mutex;

use serde::Serialize;

/// A single model judgement captured for diagnosis: the full prompt the model saw,
/// its raw reply, and the final verdict after the deterministic guards. Diagnostic
/// only — kept so the prompt behind an `exploitable` verdict can be inspected directly
/// instead of reconstructed from multi-line logs.
#[derive(Clone, Serialize)]
pub struct Judgement {
    /// The internet-facing entry that was judged.
    pub entry: String,
    /// How many objectives the entry reaches (the breadth the model weighed).
    pub objectives: usize,
    /// The final verdict (Debug form: variant + reason), after both guards.
    pub verdict: String,
    /// The full prompt sent to the model. `None` when the deterministic pre-call
    /// filter (JEF-112) refuted the entry without asking the model.
    pub prompt: Option<String>,
    /// The model's raw reply, before parsing/guards. `None` when the model was
    /// unavailable (timeout).
    pub reply: Option<String>,
}

/// A bounded, newest-last ring of recent [`Judgement`]s, shared between the
/// adjudicator (writer) and any reader. Diagnostic only: a handful of entries are judged
/// per pass and only on cache misses, so the cap comfortably holds several restarts'
/// worth of judgements without growing unbounded.
#[derive(Default)]
pub struct JudgementLog {
    rows: Mutex<std::collections::VecDeque<Judgement>>,
}

impl JudgementLog {
    pub(crate) const CAP: usize = 64;

    pub fn new() -> Self {
        Self::default()
    }

    /// Append a judgement, evicting the oldest once at capacity.
    pub fn record(&self, judgement: Judgement) {
        let mut rows = self.rows.lock().expect("judgement log mutex poisoned");
        if rows.len() >= Self::CAP {
            rows.pop_front();
        }
        rows.push_back(judgement);
    }

    /// Snapshot newest-first for inspection.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<Judgement> {
        self.rows
            .lock()
            .expect("judgement log mutex poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}
