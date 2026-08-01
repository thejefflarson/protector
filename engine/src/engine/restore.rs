//! Boot-time journal replay — [`Engine::replay_journal`], extracted whole from the
//! orchestrator to keep it under the file-size cap (CLAUDE.md) and to hold the one
//! restore concern in a single readable place.
//!
//! This is a behavior-neutral code move: it restores exactly the in-memory views the
//! inline block did — the last-known verdict per entry (display + cache), the reversion
//! and divergence rings, the staged cut-choice decisions (ADR-0034 D8's replay-lock), and
//! the last-pass freshness stamp — from the durable decision journal on boot. Idempotent
//! and bounded by the journal's own rotation window.

use super::{Engine, RestoredDecision, journal, state};

impl Engine {
    /// Replay the journal's durable decisions onto the in-memory views: the last-known
    /// verdict per entry (so findings show a judgement without re-judging), the recent
    /// reversions ring, and the last-pass freshness stamp. Idempotent and bounded by the
    /// journal's own rotation window.
    pub(super) fn replay_journal(&mut self, journal: &journal::DecisionJournal) {
        let entries = journal.replay();
        if entries.is_empty() {
            return;
        }
        let mut latest_at = std::time::SystemTime::UNIX_EPOCH;
        let mut restored_verdicts = 0usize;
        let mut restored_reversions = 0usize;
        let mut restored_decisions = 0usize;
        let mut restored_divergence = 0usize;
        // The boot instant the recency tracker stamps as a restored entry's synthetic
        // `first_seen` — a past instant relative to any later pass, so a restored
        // entry is never mislabeled NEW. (Restored ages are suppressed regardless.)
        let restored_at = std::time::Instant::now();
        for entry in &entries {
            latest_at = latest_at.max(entry.at());
            match &entry.decision {
                journal::Decision::Breach {
                    entry: key,
                    verdict,
                    fingerprint,
                    verdict_typed,
                    ..
                } => {
                    // Carry the model's prior words forward verbatim as a display memory,
                    // so the breach path shows its last judgement IMMEDIATELY while a fresh
                    // one is computed. Replayed in chronological order, so the final write
                    // per entry wins. Display-only: the action logic still uses the live
                    // verdict, never this restored string.
                    //
                    // a restored entry existed BEFORE this run, so it must never read
                    // as NEW in the Δ column. `restored_at` (boot `Instant`) seeds its
                    // `first_seen` in the past and flags it `restored`; the recency cell shows
                    // `Restored`, not NEW, until a live pass re-judges it.
                    self.verdicts
                        .seed_restored(key, verdict.clone(), restored_at);
                    // re-seed the verdict CACHE so an UNCHANGED entry skips a fresh
                    // (slow, OOM-prone) model call across a restart — the big request-volume cut.
                    // Restores the EXACT prior decision (a persisted `Exploitable` stays one);
                    // `cached_for` serves it only while the fingerprint matches, so changed
                    // evidence re-judges — never a stale verdict. Older lines are display-only.
                    if let (Some(fp), Some(typed)) = (fingerprint, verdict_typed) {
                        self.verdicts.cache_decisive(key, fp.clone(), typed.clone());
                    }
                    restored_verdicts += 1;
                }
                journal::Decision::Revert { cut, reason } => {
                    self.reversions.record(state::ReversionRecord {
                        cut: cut.clone(),
                        reason: reason.clone(),
                        at_ms: entry.at_ms,
                    });
                    restored_reversions += 1;
                }
                // ADR-0034 D8: stage this entry's cut-choice decision for the double
                // replay-lock — held in `restored_decisions`, NEVER written straight into the
                // live `decisions` map here (there is no current menu/fingerprint to check it
                // against yet; that only exists once a real pass runs). Chronological replay
                // means the LAST line for an entry wins, matching every other last-write-wins
                // restore in this loop.
                journal::Decision::Incident {
                    entry: key,
                    assessment,
                    reason,
                    cuts,
                    fingerprint,
                    ..
                } => {
                    self.restored_decisions.insert(
                        key.clone(),
                        RestoredDecision {
                            fingerprint: fingerprint.clone(),
                            assessment: *assessment,
                            reason: reason.clone(),
                            cuts: cuts.clone(),
                        },
                    );
                    restored_decisions += 1;
                }
                // Shadow-bake divergence lines (the model-vs-deterministic cut comparator)
                // restore into the divergence ring exactly like a reversion restores into the
                // reversion ring above, so the bake history survives a restart instead of
                // resetting the arm-readiness window.
                journal::Decision::CutDivergence {
                    entry: key,
                    class,
                    model_cuts,
                    deterministic_cuts,
                } => {
                    self.divergence.record(state::DivergenceRow {
                        entry: key.clone(),
                        class: *class,
                        model_cuts: model_cuts.clone(),
                        deterministic_cuts: deterministic_cuts.clone(),
                        at_ms: entry.at_ms,
                    });
                    restored_divergence += 1;
                }
                // Applies are durable for the audit trail but don't seed output state directly
                // (the live ledger re-derives the active set from current proof each pass).
                journal::Decision::Apply { .. } => {}
                // Admission decisions restore into the webhook's admission-decision
                // log, not the engine's findings or reversion state — `run_watch` does that
                // restore from the same journal, since it (not the engine) holds the shared
                // decision ring.
                journal::Decision::Admission { .. } => {}
                // Per-repo signing baselines restore into the dedicated
                // `SigningBaselineStore`, not the engine's findings/reversion state —
                // `run_watch` does that restore from the same journal, since it (not the engine
                // core) owns the baseline store the sweep feeds each pass.
                journal::Decision::SigningBaseline { .. } => {}
            }
        }
        if latest_at > std::time::SystemTime::UNIX_EPOCH {
            self.findings.mark_pass(latest_at);
        }
        tracing::info!(
            decisions = entries.len(),
            restored_verdicts,
            restored_reversions,
            restored_decisions,
            restored_divergence,
            "replayed decision journal on boot (output state populated from durable history)"
        );
    }
}
