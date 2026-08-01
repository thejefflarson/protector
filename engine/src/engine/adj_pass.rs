//! The four-phase adjudication pass — the model-as-judge stage of [`Engine::process`],
//! extracted whole to keep the orchestrator under the file-size cap (CLAUDE.md) and to hold
//! the pass in one readable, independently-testable place (JEF-370).
//!
//! Given this pass's proven chains (already published for display), it judges every
//! breach-relevant path exactly as the analyst would (ADR-0013):
//!
//! - **Phase 1 — classify** each breach-relevant ENTRY without calling the model: group the
//!   chains by their internet-facing front door, build each entry's delta-aware prompt +
//!   cache key ([`Engine::prepare_pending`]), then run the layered re-judge gate
//!   ([`super::adj_gate`], JEF-390 LRU / JEF-391 delta hold / JEF-234 breaker+backoff). A
//!   cache/hold/skip resolves with no model call; a genuine miss queues for dispatch.
//! - **Phase 2 — dispatch** the fresh model calls CONCURRENTLY (JEF-337), bounded by
//!   `model_concurrency`; each transport error resolves to an Uncertain for that entry alone.
//! - **Phase 3 — fold** each fresh verdict back into the per-entry store: cache a decisive one
//!   + baseline it + close the breaker; arm backoff on an Uncertain; record latency/outcome.
//! - **Phase 4 — publish** display / journal / notify / per-chain stamps for EVERY entry, in a
//!   STABLE (sorted-by-entry) order so the durable journal is deterministic regardless of the
//!   order the concurrent calls completed in.
//!
//! This is a behavior-neutral code move: it mutates exactly the state the inline block did
//! (`verdicts`, `journal`, `notifier`, `findings`, `metrics`) and stamps verdicts onto the
//! passed-in `chains` in place. The caller re-publishes the enriched chains afterward.
//!
//! **ADR-0034 (JEF-570):** each entry's model call now returns an
//! [`incident::IncidentDecision`] (a 3-value assessment + the engine-resolved cuts it chose
//! from the entry's deterministic menu, built in Phase 1), not the bare legacy
//! [`reason::adjudicate::Verdict`]. The pass folds it two ways: `to_verdict()` derives the
//! `Verdict` every existing rail here — the cache, the re-judge gate, the journal `Breach`
//! line, the notifier, the display — keeps consuming unchanged (ADR-0023 stays intact), while
//! the decision itself is collected and returned so the caller can hand it to
//! [`super::respond::MitigationLedger::reconcile`] (D6/D7): the ledger's desired set is now the
//! model-chosen cuts, not a deterministic insertion.

use futures::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::{
    Engine, PendingEntry, RestoredDecision, adj_gate, churn_diag, graph, journal, model, notify,
    observe, reason, state,
};
use reason::adjudicate::incident;

impl Engine {
    /// Run the four-phase adjudication pass over this pass's breach-relevant chains (see the
    /// module docs). Stamps each entry's verdict onto `chains` in place (for the timer path's
    /// `chain.emit()` log and the `from_chain` fallback) and writes the resolved verdict to the
    /// shared store the instant it's decided, so the findings snapshot resolves it immediately.
    /// `pass_now` is the pass's single injected clock, shared with every backoff/breaker decision.
    /// Returns this pass's per-entry cut-choice decision (ADR-0034), keyed by entry key, for the
    /// ledger reconcile.
    pub(super) async fn run_adjudication_pass(
        &mut self,
        chains: &mut [reason::proof::ProvenChain],
        graph: &graph::SecurityGraph,
        health: &observe::health::HealthReport,
        pass_now: std::time::Instant,
    ) -> BTreeMap<String, incident::IncidentDecision> {
        // Adjudicate (ADR-0013): the model is the JUDGE of every breach-relevant PATH,
        // always. The deterministic proof winnows to the paths an internet-facing
        // workload can actually reach (internet → entry → objective); the model then
        // makes the analyst's call on EACH one — is this reachability a real breach
        // risk, or legitimate? A path is risky two independent ways: an ACTIVE EXPLOIT
        // (a critical/KEV CVE or a live runtime signal), OR a STRUCTURAL EXPOSURE (the
        // objective is reachable from the internet when it shouldn't be — a
        // misconfiguration). So absence of a CVE is NOT safety: an internet-reachable
        // path to something sensitive is a finding on its own. Defense in depth —
        // every path is evaluated, every time the facts behind it change.
        //
        // Judged ONCE PER ENTRY — one model call per internet-facing front door, made
        // holistically over EVERY objective it reaches (NOT per path, and NOT one call for
        // the whole graph). Cached across passes: keyed by the entry and invalidated by
        // its evidence fingerprint (the entry's CVEs/runtime + its reachable-objective
        // set), so it's re-judged when a scan lands a new CVE or a misconfig newly exposes
        // an objective. A local CPU model is slow, so this caching is what keeps steady
        // state quiet; the findings were already published above, so a slow or unavailable
        // model never blocks the findings state.
        //
        // Two consequences follow from the verdict:
        // - Corroborated chain (live runtime signal): a non-confirming verdict
        //   downgrades the eligible auto-action to a human proposal (the veto direction).
        // - Uncorroborated path: an affirmative `exploitable` verdict PROMOTES it to
        //   auto-eligible — but only when the `judgement` class is armed, since
        //   promoting on the model's say-so is the opt-in speculative lane.
        // Group the breach-relevant chains by their internet-facing ENTRY, then judge
        // each entry ONCE over everything it can reach — not once per path. A
        // broadly-privileged entry reaches dozens of objectives; per-path that's dozens
        // of slow CPU-model calls (which queue and time out, so verdicts never land).
        // Per-entry it's ~one call per internet front door.
        let mut by_entry: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (i, c) in chains.iter().enumerate() {
            if c.is_breach_relevant() {
                by_entry.entry(c.entry.0.clone()).or_default().push(i);
            }
        }
        let current_entries: HashSet<String> = by_entry.keys().cloned().collect();
        let mut verdict_counts: HashMap<&'static str, u64> = HashMap::new();
        // JEF-234: cache misses we DECLINE to send to the model this pass because the entry
        // (or the whole fleet, via the global breaker) is in inconclusive-adjudication backoff.
        // A sustained nonzero rate means the model is down and we are correctly NOT hammering it.
        let mut cached = 0u64;
        let mut skipped = 0u64;
        // ADR-0023 (JEF-391): fingerprint misses HELD on a purely-subtractive delta (the prior
        // decisive verdict served, no model call). Folded into `cached` for the OTLP counter;
        // tracked separately only so the pass log shows how much churn the delta gate absorbed.
        let mut held = 0u64;

        // Phase 1 — classify each breach-relevant entry WITHOUT calling the model (pure/cheap,
        // so it stays sequential). A cache hit (fingerprint unchanged) reuses the stored
        // verdict; an open global breaker or a per-entry backoff synthesizes an Uncertain (so
        // the display carries the prior decisive verdict forward, exactly as a real timeout
        // would) and sends nothing; everything else is a cache miss queued for the concurrent
        // model dispatch below.
        let mut resolved: Vec<(PendingEntry, reason::adjudicate::Verdict)> = Vec::new();
        let mut to_judge: Vec<PendingEntry> = Vec::new();
        // One immutable ASN snapshot for the whole pass (JEF-380): a hot-reload that lands
        // mid-pass swaps the next pass's snapshot, never this one — so every entry judged this
        // pass sees a consistent provider table (mirrors the KEV/EPSS per-pass snapshot).
        let asn = self.asn.snapshot();
        for (entry_key, idxs) in &by_entry {
            let entry = chains[idxs[0]].entry.clone();
            // The (objective, technique) set this entry reaches — what the model judges.
            let mut objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)> = idxs
                .iter()
                .map(|&i| (chains[i].objective.clone(), chains[i].attack))
                .collect();
            objectives.sort_by(|a, b| a.0.0.cmp(&b.0.0));
            objectives.dedup_by(|a, b| a.0 == b.0);

            // JEF-565: the deduped, sorted workload set on this entry's PROVEN paths, excluding
            // the entry itself — every workload the model's prompt now renders its own evidence
            // block for (see `downstream_workloads`).
            let downstream = downstream_workloads(&entry, idxs, chains);

            // ADR-0034 D4 (JEF-570): the deterministic cut-choice menu for this entry, unioned
            // across every one of its objective-chains (see `entry_menu`) — the SAME menu the
            // prompt's containment-options section renders and the model's `contain` reply
            // resolves against.
            let menu = entry_menu(idxs, chains, graph, health);

            // Build the entry's delta-aware pending record (prompt + fingerprint + projected
            // surface) and read its baseline — see [`Engine::prepare_pending`] (ADR-0023 / JEF-350
            // / JEF-387). `additive` says whether the delta since the baseline is additive.
            let (pending, additive, baseline) = self.prepare_pending(
                entry_key, entry, objectives, downstream, idxs, graph, &asn, menu,
            );
            // ADR-0034 D8 (JEF-639): attempt the double replay-lock BEFORE the re-judge gate —
            // a no-op once this run already has a LIVE decision for the entry, or when nothing
            // was journal-restored for it. See `try_rearm_decision`/`rearm_restored_decision`.
            self.try_rearm_decision(&pending);
            // The layered re-judge gate (JEF-390 LRU / JEF-391 delta hold / JEF-234 breaker +
            // backoff / re-judge), decided WITHOUT a model call — see [`adj_gate`].
            match adj_gate::classify_adjudication(
                &self.verdicts,
                &pending,
                additive,
                baseline.as_ref(),
                pass_now,
            ) {
                adj_gate::AdjGate::Resolved { verdict, held: h } => {
                    cached += 1;
                    held += u64::from(h);
                    resolved.push((pending, verdict));
                }
                adj_gate::AdjGate::Skipped(verdict) => {
                    skipped += 1;
                    resolved.push((pending, verdict));
                }
                adj_gate::AdjGate::Judge => {
                    // ADJ-MISS-DIAG (JEF-387): one compact churn-attribution line per re-judge.
                    churn_diag::log_rejudge(&pending);
                    to_judge.push(pending);
                }
            }
        }
        // Model calls this pass (cache misses actually sent). A persistently high value means
        // the fingerprint is churning (re-judging unchanged entries) — watch it for model load.
        let judged = to_judge.len() as u64;

        // Phase 2 — dispatch the fresh model calls CONCURRENTLY (JEF-337). protector no longer
        // serializes model calls behind a process-wide 1-permit gate; ollama owns concurrency
        // (`OLLAMA_NUM_PARALLEL` + its queue) and is sized for the node it runs on.
        // `buffer_unordered` keeps at most `model_concurrency` calls in flight — a
        // connection/timeout fan-out safety bound (each call can hold the full model timeout),
        // NOT a throttle. Isolation is structural: `Adjudicator::judge` resolves every
        // transport/500/timeout error to an Uncertain for THAT entry (see the model call), and
        // `buffer_unordered` never short-circuits — so one entry's model failure resolves to
        // that entry being inconclusive (retried next pass) and can never abort or poison the
        // other entries' adjudication in the same pass.
        let judged_results: Vec<(
            PendingEntry,
            incident::IncidentDecision,
            std::time::Duration,
        )> = {
            let adjudicator = &self.adjudicator;
            let graph_ref = graph;
            futures::stream::iter(to_judge.into_iter().map(|pending| async move {
                let started = std::time::Instant::now();
                let decision = adjudicator
                    .judge(
                        &pending.entry,
                        &pending.objectives,
                        graph_ref,
                        &pending.prompt,
                        &pending.downstream,
                        &pending.menu,
                    )
                    .await;
                (pending, decision, started.elapsed())
            }))
            .buffer_unordered(model::model_concurrency())
            .collect()
            .await
        };

        // Phase 3 — fold each fresh decision back into the per-entry store (sequential; each
        // step mutates the engine). Cache a decisive verdict (derived from the decision,
        // ADR-0034) + clear its backoff/close the breaker; arm backoff on an Uncertain; record
        // the model-call latency + outcome. This is the SAME bookkeeping the old sequential loop
        // did per fresh call — only the dispatch shape (concurrent, above) changed.
        for (pending, decision, elapsed) in judged_results {
            // Time the (slow, CPU-bound) model call so its latency tail is observable in
            // shadow (JEF-100). Recorded for every fresh call; `result` labels the outcome.
            self.metrics
                .model_latency_ms
                .record(elapsed.as_secs_f64() * 1000.0, &[]);
            // The legacy 4-value Verdict every rail below still consumes unchanged (ADR-0023's
            // cache/gate/journal/notify/display — see `IncidentDecision::to_verdict`).
            let verdict = decision.to_verdict();
            // An Uncertain is usually a transient model outage — re-judge later rather than
            // pin the failure into the cache. Logged at info: on a slow CPU model nearly every
            // verdict lands here, and a silent inconclusive is indistinguishable from "the
            // model never ran" — surface why.
            let result = match &verdict {
                reason::adjudicate::Verdict::Uncertain(why) => {
                    tracing::info!(entry = %pending.entry.0, objectives = pending.objectives.len(), %why, "adjudication inconclusive (will retry)");
                    // JEF-234: arm this entry's exponential backoff and advance the global
                    // breaker's failure run, so the next pass does NOT re-judge it immediately.
                    self.verdicts
                        .record_inconclusive(&pending.entry_key, pass_now);
                    // ADR-0034 D7: a fresh Uncertain retires nothing and cuts nothing — leave
                    // whatever decision (if any) is already recorded for this entry standing,
                    // rather than clearing it. Inert both ways.
                    "unavailable"
                }
                decisive => {
                    tracing::info!(entry = %pending.entry.0, objectives = pending.objectives.len(), verdict = ?decisive, "adjudicated entry");
                    // ADR-0034 D8 (JEF-639): durably record THIS pass's decisive cut-choice
                    // decision — the double replay-lock's source material on a future restart
                    // (see `rearm_restored_decision`). Only when it actually CHANGED from the
                    // decision already standing for this entry: `Exploitable`/`Attack` is
                    // re-verified every pass (JEF-445), so an unchanged standing incident would
                    // otherwise write an identical line every pass — the exact per-pass spam the
                    // journal's rotation-window design (several restarts' worth of history)
                    // depends on NOT happening. A no-op when the journal is disabled.
                    if self.decisions.get(&pending.entry_key) != Some(&decision) {
                        self.journal.record(journal::Decision::Incident {
                            entry: pending.entry_key.clone(),
                            objectives: pending.objectives.len(),
                            assessment: decision.assessment,
                            reason: decision.reason.clone(),
                            cuts: decision
                                .cuts
                                .iter()
                                .map(|c| journal::JournaledCut {
                                    node: c.node.0.clone(),
                                    cut_signature: c.cut_signature.clone(),
                                })
                                .collect(),
                            fingerprint: pending.fingerprint.clone(),
                        });
                    }
                    // ADR-0034 D6/D7: record THIS pass's decisive cut-choice decision — the
                    // ledger reconcile reads it back below. Overwrites any prior decision for
                    // this entry, so a fresh decisive decision that DROPS a cut is exactly what
                    // retires it (the ledger's own active-vs-desired diff does the rest).
                    self.decisions
                        .insert(pending.entry_key.clone(), decision.clone());
                    self.verdicts.cache_decisive(
                        &pending.entry_key,
                        pending.fingerprint.clone(),
                        verdict.clone(),
                    );
                    // ADR-0023 (JEF-391): snapshot THIS pass's judged surface + verdict as the
                    // entry's new baseline, so the next pass measures additions against what this
                    // call saw. Only decisive verdicts baseline (the `Uncertain` arm never does),
                    // so a failed call can't suppress a later re-judge.
                    self.verdicts.set_baseline(
                        &pending.entry_key,
                        pending.surface.clone(),
                        verdict.clone(),
                    );
                    // JEF-234: a decisive answer means the model is alive — clear this entry's
                    // backoff and close the global breaker so judging resumes for the fleet.
                    // Also stamps the actuation-trust clock (`decisive_at`) `pass_now` reads.
                    self.verdicts.record_decisive(&pending.entry_key, pass_now);
                    "ok"
                }
            };
            // Piggyback the readiness aggregation's LIVE model health (JEF-160) on this call's
            // outcome — cheap, no extra call: decisive ⇒ answered, Uncertain ⇒ timed out /
            // endpoint down. The readiness aggregation reads this back.
            self.findings.set_model_health(match result {
                "ok" => state::ModelHealth::Ok,
                _ => state::ModelHealth::Timeout,
            });
            self.metrics
                .model_calls
                .add(1, &[opentelemetry::KeyValue::new("result", result)]);
            resolved.push((pending, verdict));
        }

        // Phase 4 — display / journal / notify / per-chain stamps for EVERY entry, in a STABLE
        // (sorted-by-entry) order so the durable journal is deterministic regardless of the
        // order the concurrent model calls above completed in. Each entry's this-pass verdict
        // is now known (cached, skipped, or freshly judged).
        let outcomes: std::collections::BTreeMap<
            String,
            (PendingEntry, reason::adjudicate::Verdict),
        > = resolved
            .into_iter()
            .map(|(pending, verdict)| (pending.entry_key.clone(), (pending, verdict)))
            .collect();
        for (entry_key, (pending, verdict)) in &outcomes {
            let objectives = &pending.objectives;
            let entry = &pending.entry;
            // Resolve AND record what to DISPLAY for this entry in one place (JEF-371): the store
            // owns the full carry-forward precedence — a decisive verdict shows as-is; an
            // inconclusive pass (a transient model timeout) carries the prior decisive verdict
            // forward rather than regressing the posture to "uncertain"; a live verdict supersedes
            // any journal-restored summary. It writes the chosen verdict to the single source of
            // truth (JEF-157) the MOMENT it's decided, so the findings snapshot resolves it with no
            // end-of-pass re-publish. The action logic below still uses this pass's real `verdict`.
            let display = self.verdicts.resolve_display(entry_key, verdict);
            // Record this pass's display POSTURE for the Δ / recency column (JEF-201): the
            // store sets `first_seen` on first sight and diffs against the previous pass to
            // derive the Δ glyph. Shares `pass_now` with the JEF-234 backoff (one injected
            // clock). Pure presentation metadata — it gates nothing (ADR-0016: recency is a view).
            self.verdicts.record_recency(
                entry_key,
                state::StoredPosture::of_verdict(Some(&display)),
                pass_now,
            );
            // Append the breach decision to the durable journal (JEF-141) — only a DECISIVE
            // verdict, and only when it changed from the last line for this entry, so a
            // steady-state cluster doesn't append an identical line every pass. Uncertain is
            // skipped (mirrors the cache discipline). A no-op when the journal is disabled.
            let summary = display.summary();
            if !matches!(display, reason::adjudicate::Verdict::Uncertain(_))
                && self.verdicts.journaled(entry_key).as_ref() != Some(&summary)
            {
                // Re-derive the structured enrichment-coverage (JEF-145) from the SAME evidence
                // the model was given, so the would-have-acted report classifies a coverage gap
                // from fact instead of grepping the verdict prose for a `CVE-` token. Cheap+pure.
                let coverage = reason::adjudicate::entry_coverage(graph, entry);
                // JEF-301: persist fingerprint + TYPED verdict so a restart re-seeds the cache.
                // Pair them ONLY when THIS pass judged decisively for THIS fingerprint; a
                // carried-forward prior (this pass Uncertain) doesn't belong to the current
                // fingerprint, so persist `None` rather than seed a stale pair (re-judge on boot).
                let decisive_now = !matches!(verdict, reason::adjudicate::Verdict::Uncertain(_));
                self.journal.record(journal::Decision::Breach {
                    entry: entry_key.clone(),
                    objectives: objectives.len(),
                    verdict: summary.clone(),
                    coverage: Some(journal::EnrichmentCoverage {
                        cves: coverage.cves,
                        behavioral: coverage.behavioral,
                    }),
                    fingerprint: decisive_now.then(|| pending.fingerprint.clone()),
                    verdict_typed: decisive_now.then(|| verdict.clone()),
                });
                self.verdicts.set_journaled(entry_key, summary.clone());
                // The ONE sanctioned outbound notification (JEF-144, ADR-0018), fired on the
                // SAME decision identity as the journal write above — a decisive verdict whose
                // summary changed for this entry — so dedupe and durability share one key and
                // a steady-state cluster notifies once, never per pass. The payload is redacted
                // (decision summary only: no secret names, no peer graph, no CVE list) and the
                // shadow-vs-armed posture is explicit. A no-op (zero outbound calls) when no
                // notify URL is configured. Best-effort: it never affects the verdict, the
                // journal, or actuation.
                self.notifier
                    .notify(&notify::BreachNotice {
                        entry: entry_key,
                        verdict: &display,
                        objectives,
                        enforcement: notify::Enforcement::from_armed(!self.active.is_empty()),
                    })
                    .await;
            }
            // The entry's verdict applies to every chain from it. The findings snapshot
            // derives the verdict from the shared store (JEF-157); this per-chain stamp is
            // kept for the timer path's `chain.emit()` log and as the `from_chain` fallback.
            for &i in &pending.idxs {
                *verdict_counts.entry(verdict.label()).or_insert(0) += 1;
                chains[i].verdict = Some(display.summary());
                if chains[i].corroborated {
                    if !verdict.is_confirmed() {
                        chains[i].adjudicated = false;
                    }
                } else if verdict.promotes() && self.active.judgement_enabled() {
                    chains[i].promoted = true;
                }
            }
        }
        // Drop verdicts for entries that no longer exist (ephemeral workloads, removed
        // exposure), so the store tracks the live cluster rather than growing forever.
        self.verdicts.retain_present(&current_entries);
        // Current verdict distribution over breach paths (per-label gauge).
        for (verdict, count) in &verdict_counts {
            self.metrics
                .verdicts
                .record(*count, &[opentelemetry::KeyValue::new("verdict", *verdict)]);
        }
        // How much judging this pass did, as proper cumulative counters (JEF-100, replacing
        // the prior `verdicts{verdict="judged_this_pass"}` gauge hack): `judged` = fresh
        // model calls (cache misses), `cached` = reused verdicts. Steady state should be
        // judged≈0; a sustained nonzero rate means fingerprint churn — the thing to watch
        // for model load. Counters (not a gauge) so the rate is computable in the collector.
        if judged > 0 {
            self.metrics.judged.add(judged, &[]);
        }
        if cached > 0 {
            self.metrics.cached.add(cached, &[]);
        }
        if skipped > 0 {
            self.metrics.skipped.add(skipped, &[]);
        }
        // Mirror the shadow would-have-acted report headline (JEF-143) to OTLP, like the
        // bake counts: the gates-exiting-shadow figures (JEF-50) over the default window,
        // read back from the durable journal we just appended this pass's breach decision
        // to. Cheap no-op when the journal is disabled (replay is empty). Read-only.
        let report = state::default_window_report(&self.journal);
        self.metrics
            .report_would_act
            .record(report.would_act_count() as u64, &[]);
        self.metrics
            .report_left_alone
            .record(report.left_alone_count() as u64, &[]);
        self.metrics
            .report_short_lived
            .record(report.short_lived_count() as u64, &[]);
        self.metrics
            .report_coverage_gap
            .record(report.coverage_gap_count() as u64, &[]);
        if !by_entry.is_empty() {
            tracing::info!(
                entries = by_entry.len(),
                judged,
                cached,
                held,
                skipped,
                "adjudication pass (model calls = judged)"
            );
        }
        // ADR-0034 D6/D7 (JEF-570): drop decisions for entries that no longer exist this pass
        // (mirrors `self.verdicts.retain_present` above) — a stale decision must never outlive
        // the entry it was judged for. Every entry STILL present keeps its last DECISIVE
        // decision even on a cache-hit/held/backoff pass this cycle (no fresh call ran), which
        // is exactly D7's retirement asymmetry: only a fresh decisive decision (Phase 3 above)
        // or the entry disappearing here changes what the ledger sees; a this-pass Uncertain
        // (skipped/backoff) never clears it.
        self.decisions
            .retain(|k, _| current_entries.contains(k.as_str()));
        // ADR-0034 D8 (JEF-639): a journal-restored decision that never got the chance to be
        // checked this run (its entry wasn't breach-relevant this pass, or vanished before
        // `try_rearm_decision` ran) can't outlive the entry either — same prune as above.
        self.restored_decisions
            .retain(|k, _| current_entries.contains(k.as_str()));
        self.decisions.clone()
    }

    /// ADR-0034 D8 (JEF-639): attempt to re-arm a journal-restored decision for this entry
    /// against THIS pass's freshly-rebuilt fingerprint + menu — the double replay-lock (see
    /// [`rearm_restored_decision`]). A no-op once a LIVE decision already governs the entry
    /// this run (a fresh Phase 3 judgment always wins over a restored one) or when nothing
    /// was journal-restored for it. Consumes the restored entry either way — armed into
    /// [`Engine::decisions`] on a lock hold, discarded on a miss — so it is never re-checked
    /// or retried blind on a later pass.
    fn try_rearm_decision(&mut self, pending: &PendingEntry) {
        if self.decisions.contains_key(&pending.entry_key) {
            return; // a live decision (this run) already governs this entry
        }
        let Some(restored) = self.restored_decisions.remove(&pending.entry_key) else {
            return; // nothing was journal-restored for this entry
        };
        match rearm_restored_decision(&restored, &pending.fingerprint, &pending.menu) {
            Some(decision) => {
                tracing::info!(
                    entry = %pending.entry_key,
                    cuts = decision.cuts.len(),
                    "re-armed a journal-restored decision (double replay-lock held, ADR-0034 D8)"
                );
                self.decisions.insert(pending.entry_key.clone(), decision);
            }
            None => {
                tracing::info!(
                    entry = %pending.entry_key,
                    "journal-restored decision failed the replay-lock — cold re-judging for cuts (ADR-0034 D8)"
                );
            }
        }
    }
}

/// The ADR-0034 D8 double replay-lock, pure: re-arm `restored` ONLY when BOTH (1) its
/// fingerprint matches `current_fingerprint` byte-identically, and (2) EVERY one of its cuts
/// re-resolves, byte-identically, to the SAME `cut_signature` against `current_menu` — the
/// exact menu this pass would show the model if it re-judged now. Either lock failing returns
/// `None` — re-arm NOTHING for this entry (a cold re-judge), never a partial or best-guess
/// repoint.
///
/// SECURITY-SENSITIVE: this is the replay/re-arm path for a possibly-armed cut. A mis-keyed or
/// over-eager re-arm here would auto-apply a cut the current state doesn't justify, so both
/// locks fail closed — lock 1 catches evidence/menu drift (the fingerprint covers the full
/// prompt, including the rendered menu, ADR-0034 D4/D9); lock 2 additionally catches a
/// mechanism-RESOLVER version drift that an unchanged fingerprint alone can't (the prompt hash
/// covers the rendered menu TEXT, not the resolver code that produced it).
pub(super) fn rearm_restored_decision(
    restored: &RestoredDecision,
    current_fingerprint: &str,
    current_menu: &incident::Menu,
) -> Option<incident::IncidentDecision> {
    if restored.fingerprint != current_fingerprint {
        return None;
    }
    let mut cuts = Vec::with_capacity(restored.cuts.len());
    for cut in &restored.cuts {
        let resolved = current_menu.resolve(&graph::NodeKey(cut.node.clone()))?;
        if resolved.cut_signature != cut.cut_signature {
            return None;
        }
        cuts.push(resolved);
    }
    Some(incident::IncidentDecision {
        assessment: restored.assessment,
        reason: restored.reason.clone(),
        cuts,
    })
}

/// The deduped, sorted workload [`graph::NodeKey`]s on this entry's PROVEN paths (JEF-565),
/// EXCLUDING the entry itself (its own evidence is the entry's dedicated prompt fields). Scope
/// is deliberately EVERY workload node across ALL of `idxs`' chains' `ProvenChain::paths` — not
/// just `quarantine_targets`, which is narrower (only nodes that already carry their OWN
/// exploitation evidence) and so can't render the "checked, found nothing" clean marker for an
/// intermediate hop the model should still be told was looked at. Deterministic: sorted + deduped
/// so the same proven paths always yield the same downstream set, in the same order.
fn downstream_workloads(
    entry: &graph::NodeKey,
    idxs: &[usize],
    chains: &[reason::proof::ProvenChain],
) -> Vec<graph::NodeKey> {
    let mut nodes: Vec<graph::NodeKey> = idxs
        .iter()
        .flat_map(|&i| chains[i].paths.iter())
        .flat_map(|path| path.iter())
        .flat_map(|link| [link.from.clone(), link.to.clone()])
        .filter(|k| k != entry && k.kind() == "workload")
        .collect();
    nodes.sort();
    nodes.dedup();
    nodes
}

/// The deterministic cut-choice menu for one entry (ADR-0034 D4, JEF-570), unioned across
/// EVERY one of its objective-chains — [`incident::build_menu`] itself takes just one
/// [`reason::proof::ProvenChain`] (an (entry, objective) pair), but the model is judged once
/// PER ENTRY over every objective it reaches, so the menu it's shown must be the union of what
/// each of those chains would offer. Pure data merge (no decision logic duplicated): re-sorts +
/// dedups exactly as `build_menu` does internally, so a node covered by more than one chain
/// (e.g. two objectives sharing a downstream pivot) still appears exactly once.
fn entry_menu(
    idxs: &[usize],
    chains: &[reason::proof::ProvenChain],
    graph: &graph::SecurityGraph,
    health: &observe::health::HealthReport,
) -> incident::Menu {
    let mut selectable = Vec::new();
    let mut uncontainable = Vec::new();
    for &i in idxs {
        let m = incident::build_menu(&chains[i], graph, health);
        selectable.extend(m.selectable);
        uncontainable.extend(m.uncontainable);
    }
    incident::normalize_menu(&mut selectable, &mut uncontainable);
    incident::Menu {
        selectable,
        uncontainable,
    }
}

#[cfg(test)]
#[path = "adj_pass_tests.rs"]
mod tests;
