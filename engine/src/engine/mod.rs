//! The asynchronous mitigation engine.
//!
//! Distinct from the admission webhook (see the crate root): the webhook is the
//! synchronous *floor*; the engine is the out-of-band loop that watches observed
//! cluster state, proves which changes open real attack chains, and — in hard
//! mode — cuts them. See `docs/adr/0001`–`0004` for the decisions behind it.
//!
//! [`Engine::process`] runs the five-question pipeline against one observed
//! snapshot: build the [`graph`], diff it (Q1, [`graph::delta`]), assess health (Q3,
//! [`observe::health`]), prove ATT&CK-tagged chains and cuts (Q2, [`reason::proof`]) —
//! the deterministic enumerator is exhaustive at this cluster's scale, so it is the sole
//! chain source (ADR-0001, narrowed: no model-backed propose stage) — and
//! [`reason::adjudicate`] each breach-relevant chain — the model judges exploitability,
//! vetoing a live chain or promoting an exposed one (ADR-0013) — reconcile proposed
//! mitigations as self-retiring debt (Q4/Q5, [`respond`]), and gate + (closed-loop)
//! actuate them ([`respond::actuator`]). [`run_watch`] drives it event-driven (the
//! default); [`run`] is the poll fallback.
//!
//! **Default posture is shadow mode**: with no action classes enabled and the
//! dry-run actuator, every decision is propose/forbid and nothing reaches the
//! cluster. What's left is integration behind ports that already exist and are
//! tested — the cluster/model I/O glue (watch streams, kube apply/delete, the
//! behavioral-ingest receiver, the model call).

// Modules are grouped by domain (see each group's mod.rs):
//   graph/   — the stable vocabulary + its diff (ADR-0003/0004)
//   observe/ — observed state + capability ports/adapters (ADR-0002/0003)
//   reason/  — prove / judge (ADR-0001/0005/0013)
//   respond/ — proven chains → self-retiring controls, then apply (ADR-0002/0009)
// `model` is a cross-cutting single file; `state` is the engine's output-state domain layer;
// this mod.rs is the orchestrator.
// The server-rendered operator dashboard (ADR-0019): the read-only presentation platform for
// the engine's output state (zero-egress, light theme). view_model → components → page → routes;
// wired into the watch loop behind PROTECTOR_DASHBOARD_ADDR.
pub mod dashboard;
pub mod graph;
pub mod journal;
pub mod model;
pub mod notify;
pub mod observe;
// JEF-226: the bounded admission-decision ring (written by the webhook engine, read by
// the admission decision log). Standalone module to stay clear of the JEF-218
// file-split refactor of this orchestrator.
pub mod policy_log;
pub mod reason;
pub mod respond;
// The engine's output-state domain layer: the proven-chain findings, the per-entry
// verdict store, the judgement/reversion logs, the behavioral-bake snapshot, and the
// would-have-acted / readiness aggregations the per-pass OTLP mirror reads.
pub mod state;

// OTLP instruments (extracted for the file-size cap, CLAUDE.md).
mod metrics;
use metrics::EngineMetrics;

use futures::StreamExt;
use graph::delta::GraphSnapshot;
use observe::Snapshot;
use observe::adapter::Adapter;
use observe::health::{Health, HealthProvider, PodStatusHealth};
use respond::MitigationLedger;
use respond::actuator::{
    ActionLog, ActuationScope, Actuator, Decision, EnabledActions, decide, predict_blast_radius,
};
use std::collections::{HashMap, HashSet};

/// One breach-relevant ENTRY queued for adjudication this pass: its identity, the
/// (objective, technique) set the model judges it over, the DETERMINISTIC prompt the model
/// will see, the verdict-cache key (a hash of that prompt, JEF-350), and the chain indices
/// its verdict stamps. Built once in the classification phase so the concurrent model
/// dispatch (JEF-337) reuses the exact prompt bytes the cache key was derived from — the
/// cached-on input and the sent input can never drift.
struct PendingEntry {
    entry_key: String,
    entry: graph::NodeKey,
    objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)>,
    /// The model's complete, deterministic input (built by `build_judgment_prompt`).
    prompt: String,
    /// The verdict-cache key: `prompt_cache_key(&prompt)` — the freshness key persisted in
    /// the journal (JEF-301) and matched by `cached_for`. Named `fingerprint` because the
    /// cache/journal seam is generic over "the freshness key string"; its value is now the
    /// prompt hash, not the old predicted-input fingerprint.
    fingerprint: String,
    idxs: Vec<usize>,
}

/// The engine's stateful processing core. It owns everything that persists across
/// observations — the prior graph state, the mitigation ledger, and the applied-
/// action log — and exposes one operation, [`Engine::process`], run once per
/// observed snapshot. Both the poll loop ([`run`]) and the event-driven observer
/// ([`run_watch`]) drive the same `process`, so the analysis is identical; only the
/// *trigger* differs.
pub struct Engine {
    adapters: Vec<Box<dyn Adapter>>,
    active: EnabledActions,
    /// Where a cut may be auto-applied (the namespace allowlist). Separate from
    /// [`EnabledActions`] (what classes are armed): one says "is this class enabled",
    /// the other "is this cut in scope" (JEF-104 follow-up).
    scope: ActuationScope,
    actuator: Box<dyn Actuator>,
    adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    findings: std::sync::Arc<state::Findings>,
    /// The reversion log (JEF-141): recent lifted cuts + why. Seeded from the journal on boot
    /// so a self-revert survives a restart.
    reversions: std::sync::Arc<state::ReversionLog>,
    /// The durable decision journal (JEF-141): each pass's breach decisions and ledger
    /// apply/revert deltas are appended here so a restart replays them. Disabled (a
    /// no-op) when no `PROTECTOR_ENGINE_JOURNAL_PATH` volume is configured — the engine
    /// then runs exactly as it did before, in-memory only. Replayed read-only by the
    /// would-have-acted report aggregation (JEF-143) the per-pass OTLP mirror reads.
    journal: std::sync::Arc<journal::DecisionJournal>,
    /// The breach notifier (JEF-144, ADR-0018): the one sanctioned outbound path. POSTs a
    /// redacted breach-decision summary to an operator-configured sink, fired on the SAME
    /// decision identity as the journal write below — so one new decision is one
    /// notification, never per-pass spam. Disabled (a no-op, zero outbound calls) when no
    /// `PROTECTOR_ENGINE_NOTIFY_URL` is configured: the engine then behaves exactly as it
    /// did before, byte-identical.
    notifier: notify::BreachNotifier,
    previous: GraphSnapshot,
    ledger: MitigationLedger,
    actions: ActionLog,
    /// The SINGLE per-entry verdict store (JEF-157), shared (`Arc`) with the
    /// [`state::Findings`] handle. One record per internet-facing ENTRY collapses what used
    /// to be four parallel maps:
    /// - the cross-pass verdict CACHE (evidence fingerprint → decisive verdict): the
    ///   model judges each breach-relevant entry holistically (ADR-0013), but a CPU-only
    ///   local model is too slow to re-run every watch event, so an entry is re-judged
    ///   only when its fingerprint changes (its CVEs/runtime OR its reachable-objective
    ///   set — a misconfig that newly exposes something re-triggers it);
    /// - the DISPLAY memory (the last verdict shown, decisive or inconclusive): carried
    ///   forward so the resolved posture never blanks while the slow model re-judges;
    /// - the journal-RESTORED summary (JEF-141): the model's prior words shown on boot
    ///   until a live verdict supersedes them;
    /// - the JOURNALED-summary dedup key: a decisive verdict is journaled + notified only
    ///   when it changed for the entry.
    ///
    /// Because the findings snapshot (via [`state::Findings::snapshot`]) and the judgement
    /// record both derive an entry's verdict from this one store, they cannot disagree, and a
    /// verdict is resolved the instant the judging loop writes it here — there is no
    /// end-of-pass re-publish lag. Pruned to present entries each pass (ephemeral workloads,
    /// removed exposure).
    verdicts: std::sync::Arc<state::VerdictStore>,
    /// Per-node agent-liveness (JEF-308), shared with the ingest; classified each pass into the
    /// runtime-corroboration coverage the readiness row reads. `None` when no ingest is wired.
    agent_liveness: Option<std::sync::Arc<state::AgentLivenessStore>>,
    /// OTLP instruments (no-op when no collector is configured).
    metrics: EngineMetrics,
}

impl Engine {
    /// Build an engine with an explicit actuator and adjudicator. The binary passes
    /// a [`DryRunActuator`] when nothing is enabled and a live actuator otherwise,
    /// and a model-backed adjudicator when a model is configured. Chain discovery is
    /// the deterministic enumerator ([`reason::proof::prove`]) alone — there is no
    /// model-backed propose stage (ADR-0001, narrowed).
    pub fn new(
        active: EnabledActions,
        scope: ActuationScope,
        actuator: Box<dyn Actuator>,
        adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    ) -> Self {
        if active.is_empty() {
            tracing::info!("engine: no action classes enabled (easy mode — proposals only)");
        } else {
            tracing::warn!("engine: action classes enabled — auto-application is on for them");
        }
        let findings = std::sync::Arc::new(state::Findings::new());
        // The arm state is reported via `ReadinessConfig.armed` (set in run_loop) in the
        // readiness aggregation's coverage row.
        // The verdict store (JEF-157) is OWNED by the findings handle and SHARED with the
        // engine: both write/read the same `Arc`, so a verdict the judging loop writes is
        // resolved into the findings snapshot immediately.
        let verdicts = findings.verdicts();
        Self {
            adapters: observe::adapter::default_adapters(),
            active,
            scope,
            actuator,
            adjudicator,
            findings,
            reversions: std::sync::Arc::new(state::ReversionLog::new()),
            // Disabled by default — durability is opt-in via a mounted volume. The watch
            // path enables it from the env (see [`with_journal`]); tests run in-memory.
            journal: std::sync::Arc::new(journal::DecisionJournal::disabled()),
            // Off by default (ADR-0018): no outbound path unless the watch loop enables it
            // from the env (see [`with_notifier`]). Tests run with it disabled.
            notifier: notify::BreachNotifier::disabled(),
            previous: GraphSnapshot::default(),
            ledger: MitigationLedger::new(),
            actions: ActionLog::new(),
            verdicts,
            agent_liveness: None,
            metrics: EngineMetrics::new(),
        }
    }

    /// Attach the per-node agent-liveness store (JEF-308), read each pass to stamp coverage.
    pub fn with_agent_liveness(mut self, l: std::sync::Arc<state::AgentLivenessStore>) -> Self {
        self.agent_liveness = Some(l);
        self
    }

    /// Attach a durable decision journal (JEF-141) and replay it onto the in-memory
    /// state, so the findings snapshot, the resolved verdicts, and the reversion log populate
    /// IMMEDIATELY after a restart — before a fresh (slow CPU) model pass lands. A disabled
    /// journal
    /// (no volume configured) replays nothing, leaving today's cold-start behaviour.
    /// Builder-style; called once on boot.
    pub fn with_journal(mut self, journal: journal::DecisionJournal) -> Self {
        self.replay_journal(&journal);
        self.journal = std::sync::Arc::new(journal);
        self
    }

    /// A handle to the durable decision journal (JEF-143), for the would-have-acted report
    /// aggregation to replay read-only. Shares the same `Arc` the engine writes through, so the
    /// aggregation reflects every decision the live engine has journaled this run plus the
    /// pre-restart history on disk.
    pub fn journal(&self) -> std::sync::Arc<journal::DecisionJournal> {
        self.journal.clone()
    }

    /// Attach the operator-configured breach notifier (JEF-144, ADR-0018). The one
    /// sanctioned outbound path: a redacted breach-decision summary POSTed to an in-cluster
    /// sink, deduped on the journal's decision identity. A disabled notifier (no
    /// `PROTECTOR_ENGINE_NOTIFY_URL`) makes zero outbound calls — today's behaviour exactly.
    /// Builder-style; called once on boot.
    pub fn with_notifier(mut self, notifier: notify::BreachNotifier) -> Self {
        self.notifier = notifier;
        self
    }

    /// Replay the journal's durable decisions onto the in-memory views: the last-known
    /// verdict per entry (so findings show a judgement without re-judging), the recent
    /// reversions ring, and the last-pass freshness stamp. Idempotent and bounded by the
    /// journal's own rotation window.
    fn replay_journal(&mut self, journal: &journal::DecisionJournal) {
        let entries = journal.replay();
        if entries.is_empty() {
            return;
        }
        let mut latest_at = std::time::SystemTime::UNIX_EPOCH;
        let mut restored_verdicts = 0usize;
        let mut restored_reversions = 0usize;
        // The boot instant the recency tracker stamps as a restored entry's synthetic
        // `first_seen` (JEF-201) — a past instant relative to any later pass, so a restored
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
                    // JEF-201: a restored entry existed BEFORE this run, so it must never read
                    // as NEW in the Δ column. `restored_at` (boot `Instant`) seeds its
                    // `first_seen` in the past and flags it `restored`; the recency cell shows
                    // `Restored`, not NEW, until a live pass re-judges it.
                    self.verdicts
                        .seed_restored(key, verdict.clone(), restored_at);
                    // JEF-301: re-seed the verdict CACHE so an UNCHANGED entry skips a fresh
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
                // Applies are durable for the audit trail but don't seed output state directly
                // (the live ledger re-derives the active set from current proof each pass).
                journal::Decision::Apply { .. } => {}
                // Admission decisions (JEF-237) restore into the webhook's admission-decision
                // log, not the engine's findings or reversion state — `run_watch` does that
                // restore from the same journal, since it (not the engine) holds the shared
                // decision ring.
                journal::Decision::Admission { .. } => {}
                // Per-repo signing baselines (JEF-263) restore into the dedicated
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
            "replayed decision journal on boot (output state populated from durable history)"
        );
    }

    /// A handle to the current findings snapshot (proven chains + verdicts), for a reader.
    pub fn findings(&self) -> std::sync::Arc<state::Findings> {
        self.findings.clone()
    }

    /// A handle to the reversion log (JEF-141): the recent lifted-cuts ring.
    pub fn reversions(&self) -> std::sync::Arc<state::ReversionLog> {
        self.reversions.clone()
    }

    /// Run the five-question pipeline against one observed snapshot.
    ///
    /// Proof, ledger reconciliation, and the action decision run **every pass** —
    /// not only on a structural delta — because corroboration, vulnerability, and
    /// health facts can change a chain's status without changing the graph's shape
    /// (a runtime alert is the motivating case: it flips a chain to fully
    /// corroborated without adding a node or edge). The structural delta only gates
    /// the *verbose reporting* (the Q1 threat-delta and per-chain logs), to keep a
    /// quiet cluster quiet.
    #[tracing::instrument(name = "engine.process", skip_all)]
    pub async fn process(&mut self, snapshot: &Snapshot) {
        self.metrics.passes.add(1, &[]);
        // Behavioral-port instrumentation (JEF-100, pure observe): count what the
        // behavioral port saw this pass, by variant and attribution outcome, plus the
        // live store cardinality. Labels are low-cardinality (variant names, resolved/
        // unresolved) — never per-pod. `runtime_events` is the TTL'd store's snapshot
        // (`RuntimeEvents::current()`), so its length is the store cardinality.
        self.metrics
            .runtime_store
            .record(snapshot.runtime_events.len() as u64, &[]);
        // Accumulate this pass's bake snapshot (JEF-48) alongside the OTLP counters: the
        // same figures, surfaced in the output state so the shadow-bake exit criteria are
        // readable without an OTLP collector. Filled out (corroborations) after the chains
        // are proven below, then published to the findings handle.
        let mut bake = state::BakeStats {
            runtime_store: snapshot.runtime_events.len() as u64,
            ..Default::default()
        };
        // The live pod UIDs, built once so the per-event ByPodUid attribution check below
        // is an O(1) set lookup rather than an O(pods) scan per runtime event.
        let pod_uids: HashSet<&str> = snapshot
            .pods
            .iter()
            .filter_map(|p| p.metadata.uid.as_deref())
            .collect();
        for event in &snapshot.runtime_events {
            self.metrics.signals.add(
                1,
                &[opentelemetry::KeyValue::new(
                    "behavior",
                    event.behavior.variant_label(),
                )],
            );
            *bake
                .signals_by_variant
                .entry(event.behavior.variant_label().to_string())
                .or_insert(0) += 1;
            // The resolution rule lives on `Attribution` (shared with the RuntimeAdapter,
            // so the two can't drift): a namespace/name attribution always resolves; a
            // cgroup-UID one resolves iff a pod with that UID is in the snapshot (the
            // adapter drops the rest as unknown UIDs).
            let outcome = if event.attribution.resolves_in(|uid| pod_uids.contains(uid)) {
                bake.resolved += 1;
                "resolved"
            } else {
                bake.unresolved += 1;
                "unresolved"
            };
            self.metrics
                .attribution
                .add(1, &[opentelemetry::KeyValue::new("outcome", outcome)]);
        }
        let graph = observe::adapter::build_graph(snapshot, &self.adapters);
        let current = GraphSnapshot::of(&graph);
        let health = PodStatusHealth.assess(snapshot);

        let delta = graph::delta::diff(&self.previous, &current);
        let structurally_changed = !delta.is_empty();
        if structurally_changed {
            delta.emit();
            let (alive, degraded, halted) = health.counts();
            tracing::info!(alive, degraded, halted, "cluster health");
        }

        // Prove (Question 2) every pass. The deterministic enumerator finds every
        // structurally-proven chain by exhaustive walk — at this cluster's scale that
        // is exhaustive, so it is the sole chain source (ADR-0001, narrowed: no
        // model-backed propose stage). Only proof moves privilege.
        let mut chains = reason::proof::prove(&graph);

        // Publish the proven chains NOW, before the (CPU-bound, possibly slow or
        // unreachable) adjudication. The findings snapshot must always reflect the current
        // graph even while the model is judging or down — model latency must never blank the
        // findings state. JEF-157: the rows carry NO per-chain verdict; each finding's
        // verdict is resolved from the shared verdict store at snapshot time (the last-
        // known live verdict, or a journal-restored one). So this single publish already
        // shows the carried-forward verdict, and when the judging loop below writes a
        // fresh verdict into the store it is resolved IMMEDIATELY — no end-of-pass
        // re-publish is needed to surface it. `publish_chains` also stamps each finding's entry
        // node (JEF-308) so a latent finding on a blind node can carry its "no live sensor" caveat.
        self.findings.publish_chains(&chains, &graph, snapshot);

        // Snapshot gauges for this pass.
        self.metrics.chains.record(chains.len() as u64, &[]);
        // One pass over the chains for both breach-relevant counts: the breach-path gauge
        // and the corroborations metric (JEF-100) — the latter the subset also marked
        // `corroborated` (a live runtime signal completing the action bar, ADR-0009). In
        // shadow this counts "would this have promoted?" without changing any behavior —
        // promotion still stays gated behind `judgement_enabled()` below.
        let (breach_paths, corroborations) = chains
            .iter()
            .filter(|c| c.is_breach_relevant())
            .fold((0u64, 0u64), |(breach, corr), c| {
                (breach + 1, corr + u64::from(c.corroborated))
            });
        self.metrics.breach_paths.record(breach_paths, &[]);
        if corroborations > 0 {
            self.metrics.corroborations.add(corroborations, &[]);
        }
        // Publish this pass's behavioral-bake snapshot into the output state (JEF-48). Done
        // here, before the slow adjudication loop, for the same reason the findings are:
        // the bake snapshot must reflect the current pass even while the model is judging.
        bake.corroborations = corroborations;
        self.findings.set_bake(bake);

        // Runtime-corroboration coverage per node (JEF-308) for the readiness row.
        if let Some(liveness) = &self.agent_liveness {
            self.findings
                .stamp_runtime_coverage(liveness, &snapshot.pods);
        }

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
        // One `now` for the whole pass so every backoff/breaker decision shares a single clock
        // read — the timing seam the JEF-234 tests drive deterministically (store methods all
        // take `now`, never reach for `Instant::now()`).
        let pass_now = std::time::Instant::now();

        // Phase 1 — classify each breach-relevant entry WITHOUT calling the model (pure/cheap,
        // so it stays sequential). A cache hit (fingerprint unchanged) reuses the stored
        // verdict; an open global breaker or a per-entry backoff synthesizes an Uncertain (so
        // the display carries the prior decisive verdict forward, exactly as a real timeout
        // would) and sends nothing; everything else is a cache miss queued for the concurrent
        // model dispatch below.
        let mut resolved: Vec<(PendingEntry, reason::adjudicate::Verdict)> = Vec::new();
        let mut to_judge: Vec<PendingEntry> = Vec::new();
        for (entry_key, idxs) in &by_entry {
            let entry = chains[idxs[0]].entry.clone();
            // The (objective, technique) set this entry reaches — what the model judges.
            let mut objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)> = idxs
                .iter()
                .map(|&i| (chains[i].objective.clone(), chains[i].attack))
                .collect();
            objectives.sort_by(|a, b| a.0.0.cmp(&b.0.0));
            objectives.dedup_by(|a, b| a.0 == b.0);

            // Build the model's complete, deterministic prompt BEFORE the cache lookup, then
            // key the cache on its hash (JEF-350): the prompt is exactly what the model sees,
            // so the cache invalidates iff the model's input changes. On a hit we serve the
            // stored decisive verdict with no model call; on a miss we hand this same prompt to
            // `judge` (no rebuild), so the cached-on and sent inputs can't drift.
            let prompt = reason::adjudicate::build_judgment_prompt(&entry, &objectives, &graph);
            let fingerprint = reason::adjudicate::prompt_cache_key(&prompt);
            let pending = PendingEntry {
                entry_key: entry_key.clone(),
                entry,
                objectives,
                prompt,
                fingerprint,
                idxs: idxs.clone(),
            };
            match self.verdicts.cached_for(entry_key, &pending.fingerprint) {
                Some(v) => {
                    cached += 1;
                    resolved.push((pending, v));
                }
                // JEF-234: the GLOBAL breaker is open — the model looks fully down, so skip
                // EVERY entry's model call this pass (a fully-down Ollama is probed at most
                // ~once per cooldown).
                None if self.verdicts.breaker_open(pass_now) => {
                    skipped += 1;
                    resolved.push((
                        pending,
                        reason::adjudicate::Verdict::Uncertain(
                            "model unavailable (breaker open)".into(),
                        ),
                    ));
                }
                // JEF-234: THIS entry is in exponential backoff after a recent inconclusive
                // verdict — don't re-judge it until its backoff elapses.
                None if self.verdicts.entry_backing_off(entry_key, pass_now) => {
                    skipped += 1;
                    resolved.push((
                        pending,
                        reason::adjudicate::Verdict::Uncertain(
                            "model unavailable (backing off)".into(),
                        ),
                    ));
                }
                None => to_judge.push(pending),
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
            reason::adjudicate::Verdict,
            std::time::Duration,
        )> = {
            let adjudicator = &self.adjudicator;
            let graph_ref = &graph;
            futures::stream::iter(to_judge.into_iter().map(|pending| async move {
                let started = std::time::Instant::now();
                let verdict = adjudicator
                    .judge(
                        &pending.entry,
                        &pending.objectives,
                        graph_ref,
                        &pending.prompt,
                    )
                    .await;
                (pending, verdict, started.elapsed())
            }))
            .buffer_unordered(model::model_concurrency())
            .collect()
            .await
        };

        // Phase 3 — fold each fresh verdict back into the per-entry store (sequential; each
        // step mutates the engine). Cache a decisive verdict + clear its backoff/close the
        // breaker; arm backoff on an Uncertain; record the model-call latency + outcome. This
        // is the SAME bookkeeping the old sequential loop did per fresh call — only the
        // dispatch shape (concurrent, above) changed.
        for (pending, verdict, elapsed) in judged_results {
            // Time the (slow, CPU-bound) model call so its latency tail is observable in
            // shadow (JEF-100). Recorded for every fresh call; `result` labels the outcome.
            self.metrics
                .model_latency_ms
                .record(elapsed.as_secs_f64() * 1000.0, &[]);
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
                    "unavailable"
                }
                decisive => {
                    tracing::info!(entry = %pending.entry.0, objectives = pending.objectives.len(), verdict = ?decisive, "adjudicated entry");
                    self.verdicts.cache_decisive(
                        &pending.entry_key,
                        pending.fingerprint.clone(),
                        verdict.clone(),
                    );
                    // JEF-234: a decisive answer means the model is alive — clear this entry's
                    // backoff and close the global breaker so judging resumes for the fleet.
                    self.verdicts.record_decisive(&pending.entry_key);
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
            // Choose what to DISPLAY: if this pass came back inconclusive (a transient model
            // timeout — "model unavailable") but we have a prior decisive verdict, keep showing
            // the decisive one rather than regressing the resolved posture to "uncertain". The
            // action logic below still uses this pass's real `verdict`.
            let display = match (verdict, self.verdicts.display_verdict(entry_key)) {
                (reason::adjudicate::Verdict::Uncertain(_), Some(prior))
                    if !matches!(prior, reason::adjudicate::Verdict::Uncertain(_)) =>
                {
                    prior
                }
                _ => verdict.clone(),
            };
            // Write the displayed verdict to the single source of truth (JEF-157) the MOMENT
            // it's decided, so the findings snapshot resolves it immediately (no end-of-pass
            // re-publish). A live verdict supersedes any journal-restored one (in `set_display`).
            self.verdicts.set_display(entry_key, display.clone());
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
                let coverage = reason::adjudicate::entry_coverage(&graph, entry);
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
                skipped,
                "adjudication pass (model calls = judged)"
            );
        }
        // Re-publish the enriched chains — promotions move into remediations, vetoes flip
        // `adjudicated`, so the disposition is current. JEF-157: the VERDICT is no longer
        // what this re-publish is for (it was already written to the shared store the
        // instant each entry was judged, and the findings snapshot resolves it from there) —
        // this only refreshes the structural enrichment of the rows (+ re-stamps entry nodes).
        self.findings.publish_chains(&chains, &graph, snapshot);

        if structurally_changed && !chains.is_empty() {
            tracing::info!(count = chains.len(), "proven chains");
            for chain in &chains {
                chain.emit();
                if chain.foothold.is_some() && health.of(&chain.entry) == Health::Alive {
                    tracing::warn!(
                        entry = %chain.entry.0,
                        objective = %chain.objective.0,
                        technique = chain.attack.technique_id,
                        "live foothold: exploitable entry is currently serving"
                    );
                }
            }
        }

        // Reconcile proposed mitigations against the current chains (Q4 and Q5).
        let ledger_delta = self.ledger.reconcile(&chains);
        if !ledger_delta.is_empty() {
            ledger_delta.emit();
        }
        let newly_proposed: HashSet<String> = ledger_delta
            .proposed
            .iter()
            .map(|m| m.cut_signature())
            .collect();

        // Decide over *all* active mitigations (Q4 hard mode), not just the
        // newly-proposed ones — so a corroboration flip on an existing proposal is
        // acted on. AutoApply is deduped by the action log; propose/forbid is logged
        // only for newly-proposed cuts to avoid per-pass spam.
        let active_mitigations: Vec<_> = self.ledger.active().cloned().collect();
        self.metrics
            .active_mitigations
            .record(active_mitigations.len() as u64, &[]);
        for mitigation in &active_mitigations {
            let blast = predict_blast_radius(mitigation, &graph, &health);
            match decide(mitigation, &self.active, &self.scope, &blast) {
                Decision::AutoApply => {
                    if !self.actions.is_active(mitigation) {
                        self.actuator.apply(mitigation).await;
                        self.actions
                            .record(mitigation.clone(), health.alive_workloads());
                        self.metrics
                            .mitigations
                            .add(1, &[opentelemetry::KeyValue::new("action", "applied")]);
                        // Durable record of the cut going live (JEF-141) — one line, only
                        // when newly applied (the `is_active` guard), so re-applies don't
                        // re-log. No-op when the journal is disabled.
                        self.journal.record(journal::Decision::Apply {
                            cut: mitigation.cut_signature(),
                        });
                    }
                }
                Decision::Propose(reason) => {
                    if newly_proposed.contains(&mitigation.cut_signature()) {
                        tracing::info!(%reason, "mitigation needs human approval");
                    }
                }
                Decision::Forbidden(reason) => {
                    if newly_proposed.contains(&mitigation.cut_signature()) {
                        tracing::info!(%reason, "mitigation not auto-enabled");
                    }
                }
            }
        }

        // Self-reverting closed loop, every pass: revert any applied action whose
        // protected workload went down (health divergence) or whose justifying
        // chain is no longer proven (posture improved).
        let justified: HashSet<String> = self.ledger.active().map(|m| m.cut_signature()).collect();
        for reversion in self.actions.reconcile(&health, &justified) {
            tracing::info!(reason = %reversion.reason, "reverting applied mitigation");
            self.actuator.revert(&reversion.mitigation).await;
            self.metrics
                .mitigations
                .add(1, &[opentelemetry::KeyValue::new("action", "reverted")]);
            // Make the lifted cut VISIBLE and DURABLE (JEF-141): the self-revert is the
            // core safety story (ADR-0016), but it was previously invisible. Push it onto
            // the in-memory reversion log and append it to the journal so it survives a
            // restart.
            let cut = reversion.mitigation.cut_signature();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            self.reversions.record(state::ReversionRecord {
                cut: cut.clone(),
                reason: reversion.reason.clone(),
                at_ms: now_ms,
            });
            self.journal.record(journal::Decision::Revert {
                cut,
                reason: reversion.reason.clone(),
            });
        }

        // Mark the pass complete for the output state's "last pass NNs ago" freshness line
        // (JEF-141), so a quiet/loading reader sees fresh state rather than a broken one.
        self.findings.mark_pass(std::time::SystemTime::now());

        self.previous = current;
    }
}

// The engine's driver (`run_watch`) and its env-driven builders live in a sibling
// module, split out to keep this file under the 1,000-line cap (repo CLAUDE.md). The
// public surface (`run_watch`) is re-exported here so external paths
// (`protector::engine::run_watch`) resolve unchanged.
mod run_loop;
pub use run_loop::run_watch;

// The per-pass signing-posture sweep (ADR-0020 Stage 1, JEF-261): observes the
// already-running pods' images and records their posture into the shared admission-decision
// log, complementing the webhook's admit-time observation.
pub mod signing_sweep;

// The pure signing-drift classifier (ADR-0020 §3, JEF-264): classifies a fresh posture against
// the repo's learned baseline into continuous / regression / identity-change / new-repo, so the
// sweep can surface an audit-only signing-regression finding on drift from the baseline.
pub mod signing_drift;

// The build-provenance drift classifier + sweep (ADR-0020 §5, JEF-275): the provenance twin of
// signing_drift/signing_sweep — observes each image's SLSA provenance posture, learns the per-repo
// provenance identity (TOFU), and surfaces an audit-only provenance-change finding when an
// established repo is built by an unexpected builder/source. OFF by default — zero extra egress.
pub mod provenance_drift;
pub mod provenance_sweep;

// TUF trust-root freshness + fleet-wide unverifiable-spike signals (ADR-0020 §5, JEF-280): a stale
// or starved trust root turns genuine signatures into `UnverifiableHere` and can mass-blind signing
// detection, so its cache age + a fleet-wide unverifiable spike are surfaced (non-green) in
// readiness. Pure/deterministic signals; never a gate.
pub mod signing_trust;

// The per-repo signing-baseline strength row (ADR-0020 §4, JEF-266): surfaces whether a repo's
// baseline is log-corroborated (Rekor vouches for it) or local-only (weaker TOFU) in the inventory.
pub mod signing_baseline_strength;

// The opt-in Rekor transparency-log lane (ADR-0020 §4, JEF-266): after the sweep observes each
// image, corroborates the repo baseline against the public signing history (marking it stronger
// than local-only TOFU) and surfaces registry↔log divergence as a finding. OFF by default —
// zero egress preserved unless the operator enables it.
pub mod signing_rekor;

#[cfg(test)]
mod tests;
