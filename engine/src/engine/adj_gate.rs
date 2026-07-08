//! The per-entry adjudication RE-JUDGE gate — the pure, cheap decision (no model call) of what
//! to do with one breach-relevant entry this pass. Extracted from the orchestrator to keep it
//! under the file-size cap (CLAUDE.md) and to hold the layered gate in one readable place.
//!
//! The gate layers, in order (first match wins):
//! 1. **Exact-fingerprint LRU hit (JEF-390)** — the model's input is byte-identical to a
//!    recently-judged state; serve that decisive verdict, no model call.
//! 2. **Purely-subtractive delta hold (ADR-0023, JEF-391)** — a fingerprint miss but nothing was
//!    ADDED to the entry's surface since its last DECISIVE verdict (something was only removed —
//!    a pod vanished, a peer aged out). The prior decisive verdict still holds (its surface only
//!    shrank; removal can only reduce breach risk), so serve it without a fresh call. This is
//!    what stops the ephemeral-churn ping-pong at its root. Fails toward re-judging: a
//!    non-additive delta always has a baseline (a missing baseline is additive → first judgment),
//!    so a stray absent baseline re-judges rather than skips.
//! 3. **Breaker / backoff skip (JEF-234)** — the model looks down (global breaker) or this entry
//!    is in inconclusive-adjudication backoff; synthesize an Uncertain and send nothing.
//! 4. Otherwise **re-judge** — a genuine cache miss with new (additive) surface.

use super::graph;
use super::state;
use super::{Engine, PendingEntry, reason};

/// The classification outcome for one entry this pass — decided WITHOUT calling the model.
#[cfg_attr(test, derive(Debug))]
pub(super) enum AdjGate {
    /// Serve a decisive verdict with no model call: an exact-fingerprint LRU hit (JEF-390) or a
    /// purely-subtractive delta hold (JEF-391). `held` is true only for the delta hold, so the
    /// pass log can show how much churn the delta gate absorbed.
    Resolved {
        verdict: reason::adjudicate::Verdict,
        held: bool,
    },
    /// Skip the model this pass and carry the prior display forward (JEF-234 breaker / backoff).
    Skipped(reason::adjudicate::Verdict),
    /// Queue for a fresh model call — a genuine re-judge.
    Judge,
}

impl Engine {
    /// Build one breach-relevant entry's [`PendingEntry`] for this pass: read its delta-aware
    /// baseline (ADR-0023), build the model's complete prompt WITH the "Changes since…" delta
    /// section, derive the verdict-cache key from that prompt (JEF-350) and the churn fingerprints
    /// (JEF-387), and project this pass's surface (snapshotted as the next baseline on a decisive
    /// verdict). Returns the pending record, whether the delta since the baseline is ADDITIVE
    /// (re-judge) vs subtractive (the prior verdict holds), and the baseline itself (the gate
    /// serves its verdict on a subtractive hold). Built before the cache lookup so the cached-on
    /// and sent prompt bytes can never drift.
    pub(super) fn prepare_pending(
        &self,
        entry_key: &str,
        entry: graph::NodeKey,
        objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)>,
        idxs: &[usize],
        graph: &graph::SecurityGraph,
        asn: &crate::engine::observe::asn::AsnDb,
    ) -> (PendingEntry, bool, Option<state::VerdictBaseline>) {
        let baseline = self.verdicts.baseline_for(entry_key);
        let delta = reason::adjudicate::build_delta_prompt_asn(
            &entry,
            &objectives,
            graph,
            asn,
            baseline.as_ref().map(|b| &b.surface),
        );
        // The verdict-cache key is the FULL-STATE hash (excludes the "Changes since…" section) so
        // an identical full state always keys identically regardless of the delta — see
        // `build_delta_prompt_asn` for why (ADR-0023's fingerprint↔delta-gate resolution).
        let fingerprint = delta.cache_key;
        let chain = reason::adjudicate::chain_shape_hash(&objectives);
        let pending = PendingEntry {
            entry_key: entry_key.to_string(),
            entry,
            objectives,
            prompt: delta.prompt,
            fingerprint,
            sections: delta.sections,
            chain,
            surface: delta.surface,
            idxs: idxs.to_vec(),
        };
        (pending, delta.additive, baseline)
    }
}

/// Classify one breach-relevant entry's re-judge decision (see the module docs for the layered
/// gate). Reads only the verdict store (no other engine state), so it is a free function over
/// [`state::VerdictStore`] — directly unit-testable without a full engine. `additive` and
/// `baseline` come from the delta build (ADR-0023): `additive` is false only when a decisive
/// baseline exists AND nothing was added since it. `now` is the pass's single injected clock
/// (shared with the JEF-234 backoff). The subtractive-hold path warms the LRU under the current
/// fingerprint so the settled steady state HITS next pass.
pub(super) fn classify_adjudication(
    verdicts: &state::VerdictStore,
    pending: &PendingEntry,
    additive: bool,
    baseline: Option<&state::VerdictBaseline>,
    now: std::time::Instant,
) -> AdjGate {
    use reason::adjudicate::Verdict;
    // 1. Exact-fingerprint LRU hit (JEF-390): byte-identical input, serve the cached verdict.
    if let Some(verdict) = verdicts.cached_for(&pending.entry_key, &pending.fingerprint) {
        return AdjGate::Resolved {
            verdict,
            held: false,
        };
    }
    // 2. Purely-subtractive / unchanged delta since a decisive baseline (JEF-391): the prior
    //    verdict holds. `!additive` implies a baseline exists; a defensive absent baseline falls
    //    through to a re-judge (never suppress a judgment on possibly-new surface).
    if !additive && let Some(b) = baseline {
        verdicts.cache_decisive(
            &pending.entry_key,
            pending.fingerprint.clone(),
            b.verdict.clone(),
        );
        return AdjGate::Resolved {
            verdict: b.verdict.clone(),
            held: true,
        };
    }
    // 3. JEF-234 breaker / backoff: the model looks down — skip and carry the display forward.
    if verdicts.breaker_open(now) {
        return AdjGate::Skipped(Verdict::Uncertain(
            "model unavailable (breaker open)".into(),
        ));
    }
    if verdicts.entry_backing_off(&pending.entry_key, now) {
        return AdjGate::Skipped(Verdict::Uncertain("model unavailable (backing off)".into()));
    }
    // 4. A genuine cache miss with new (additive) surface — re-judge.
    AdjGate::Judge
}

#[cfg(test)]
#[path = "adj_gate_tests.rs"]
mod tests;
