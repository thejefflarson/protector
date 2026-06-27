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
//! a model may propose candidates ([`reason::hypothesis`]) the proof gate confirms, and
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
//! Falco receiver, the model call).

// Modules are grouped by domain (see each group's mod.rs):
//   graph/   — the stable vocabulary + its diff (ADR-0003/0004)
//   observe/ — observed state + capability ports/adapters (ADR-0002/0003)
//   reason/  — propose / prove / judge (ADR-0001/0005/0013)
//   respond/ — proven chains → self-retiring controls, then apply (ADR-0002/0009)
// model + dashboard are cross-cutting single files; this mod.rs is the orchestrator.
pub mod dashboard;
pub mod graph;
pub mod journal;
pub mod model;
pub mod notify;
pub mod observe;
// JEF-226: the bounded admission-decision ring (written by the webhook engine, read by
// the dashboard's `/policy` view). Standalone module to stay clear of the JEF-218
// file-split refactor of this orchestrator.
pub mod policy_log;
pub mod reason;
pub mod respond;

use graph::delta::GraphSnapshot;
use observe::Snapshot;
use observe::adapter::Adapter;
use observe::health::{Health, HealthProvider, PodStatusHealth};
use respond::MitigationLedger;
use respond::actuator::{
    ActionLog, ActuationScope, Actuator, Decision, EnabledActions, decide, predict_blast_radius,
};
use std::collections::{HashMap, HashSet};

/// OTLP instruments for the engine, recorded against the global meter (see
/// [`crate::telemetry`]). When no OTLP endpoint is configured the global meter is a
/// no-op, so these calls cost nothing — the engine is instrumented unconditionally.
/// Counters are cumulative; gauges hold the last pass's snapshot.
struct EngineMetrics {
    /// Process passes (one per observed change).
    passes: opentelemetry::metrics::Counter<u64>,
    /// Adjudicator model invocations, by `result` (`ok`/`unavailable`).
    model_calls: opentelemetry::metrics::Counter<u64>,
    /// Mitigations actuated, by `action` (`applied`/`reverted`).
    mitigations: opentelemetry::metrics::Counter<u64>,
    /// Proven chains in the last pass.
    chains: opentelemetry::metrics::Gauge<u64>,
    /// Breach-relevant findings (internet-facing) in the last pass.
    breach_paths: opentelemetry::metrics::Gauge<u64>,
    /// Active mitigations currently in the ledger.
    active_mitigations: opentelemetry::metrics::Gauge<u64>,
    /// Breach-path count by model `verdict` (the current judgement distribution).
    verdicts: opentelemetry::metrics::Gauge<u64>,
    /// Behavioral signals ingested this pass, by `behavior` variant (alert/connection/
    /// secret-read/library-load/file-read/priv-change/exec) — the shadow-bake (JEF-48)
    /// view of *what* the behavioral port is seeing, labeled low-cardinality (variant
    /// names only, never per-pod).
    signals: opentelemetry::metrics::Counter<u64>,
    /// Signal attribution outcome, by `outcome` (`resolved`/`unresolved`): how many
    /// ingested signals the runtime adapter could attribute to a live workload vs drop as
    /// an unknown cgroup UID. A sustained `unresolved` means the agent's UIDs aren't
    /// matching pod metadata.
    attribution: opentelemetry::metrics::Counter<u64>,
    /// `RuntimeEvents` store cardinality (distinct live observations) as of this pass —
    /// a gauge so the TTL'd store's working-set size is observable.
    runtime_store: opentelemetry::metrics::Gauge<u64>,
    /// Corroborations fired this pass: proven breach-relevant chains whose `corroborated`
    /// predicate is set (ADR-0009). In shadow this is the countable answer to "would this
    /// have promoted?" without any behavior change.
    corroborations: opentelemetry::metrics::Counter<u64>,
    /// Per-pass adjudications that issued a fresh model call (verdict-cache miss). A
    /// proper cumulative counter (replaces the prior `verdicts{verdict="judged_this_pass"}`
    /// gauge hack) so model-call frequency is rate-able.
    judged: opentelemetry::metrics::Counter<u64>,
    /// Per-pass adjudications served from the verdict cache (cache hit). Cumulative
    /// counter, the companion to [`Self::judged`].
    cached: opentelemetry::metrics::Counter<u64>,
    /// Adjudicator model-call latency in milliseconds (histogram), recorded around each
    /// fresh `judge` call so the slow CPU model's tail is visible.
    model_latency_ms: opentelemetry::metrics::Histogram<f64>,
    /// Shadow would-have-acted report headline (JEF-143): distinct workloads the engine
    /// WOULD have isolated over the default rolling window, as of this pass — the gates-
    /// exiting-shadow figure (JEF-50), mirrored to OTLP like the bake counts. A gauge:
    /// the current window snapshot, the in-process mirror of the `/report` panel.
    report_would_act: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: distinct proven-but-cleared paths the model left alone
    /// over the window (the trust half of the diff).
    report_left_alone: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: would-acts whose projected cut was short-lived (likely
    /// false positives) — the subset to discount when judging the shadow bake.
    report_short_lived: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: would-acts made during an enrichment-coverage gap (no CVE
    /// backing) — the ones to scrutinize first.
    report_coverage_gap: opentelemetry::metrics::Gauge<u64>,
}

impl EngineMetrics {
    fn new() -> Self {
        let m = opentelemetry::global::meter("protector.engine");
        Self {
            passes: m
                .u64_counter("protector.engine.passes")
                .with_description("Engine process passes (one per observed change).")
                .build(),
            model_calls: m
                .u64_counter("protector.engine.model_calls")
                .with_description("Adjudicator model invocations by result.")
                .build(),
            mitigations: m
                .u64_counter("protector.engine.mitigations")
                .with_description("Mitigations actuated by action.")
                .build(),
            chains: m
                .u64_gauge("protector.engine.chains")
                .with_description("Proven chains in the last pass.")
                .build(),
            breach_paths: m
                .u64_gauge("protector.engine.breach_paths")
                .with_description("Breach-relevant (internet-facing) findings in the last pass.")
                .build(),
            active_mitigations: m
                .u64_gauge("protector.engine.active_mitigations")
                .with_description("Active mitigations in the ledger.")
                .build(),
            verdicts: m
                .u64_gauge("protector.engine.verdicts")
                .with_description("Breach paths by model verdict (current distribution).")
                .build(),
            signals: m
                .u64_counter("protector.engine.signals")
                .with_description("Behavioral signals ingested by variant.")
                .build(),
            attribution: m
                .u64_counter("protector.engine.attribution")
                .with_description("Signal attribution outcome (resolved/unresolved).")
                .build(),
            runtime_store: m
                .u64_gauge("protector.engine.runtime_store")
                .with_description("RuntimeEvents store cardinality (live observations).")
                .build(),
            corroborations: m
                .u64_counter("protector.engine.corroborations")
                .with_description("Corroborations fired (corroborated breach chains) per pass.")
                .build(),
            judged: m
                .u64_counter("protector.engine.judged")
                .with_description("Adjudications that issued a fresh model call (cache miss).")
                .build(),
            cached: m
                .u64_counter("protector.engine.cached")
                .with_description("Adjudications served from the verdict cache (cache hit).")
                .build(),
            model_latency_ms: m
                .f64_histogram("protector.engine.model_latency_ms")
                .with_description("Adjudicator model-call latency in milliseconds.")
                .build(),
            report_would_act: m
                .u64_gauge("protector.engine.report_would_act")
                .with_description(
                    "Shadow report: workloads that would have been isolated (window).",
                )
                .build(),
            report_left_alone: m
                .u64_gauge("protector.engine.report_left_alone")
                .with_description("Shadow report: proven-but-cleared paths left alone (window).")
                .build(),
            report_short_lived: m
                .u64_gauge("protector.engine.report_short_lived")
                .with_description("Shadow report: short-lived would-acts (likely false positives).")
                .build(),
            report_coverage_gap: m
                .u64_gauge("protector.engine.report_coverage_gap")
                .with_description("Shadow report: would-acts during an enrichment-coverage gap.")
                .build(),
        }
    }
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
    hypothesizer: Box<dyn reason::hypothesis::HypothesisSource>,
    adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    findings: std::sync::Arc<dashboard::Findings>,
    /// Recent lifted cuts + why (JEF-141), shared with the dashboard's `/reversions`.
    /// Seeded from the journal on boot so a self-revert survives a restart.
    reversions: std::sync::Arc<dashboard::ReversionLog>,
    /// The durable decision journal (JEF-141): each pass's breach decisions and ledger
    /// apply/revert deltas are appended here so a restart replays them. Disabled (a
    /// no-op) when no `PROTECTOR_ENGINE_JOURNAL_PATH` volume is configured — the engine
    /// then runs exactly as it did before, in-memory only. Shared (`Arc`) with the
    /// dashboard's `/report` view (JEF-143), which replays it read-only to aggregate the
    /// shadow "would-have-acted" diff.
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
    /// The SINGLE per-entry verdict store (JEF-157), shared (`Arc`) with the dashboard's
    /// [`dashboard::Findings`]. One record per internet-facing ENTRY collapses what used
    /// to be four parallel maps:
    /// - the cross-pass verdict CACHE (evidence fingerprint → decisive verdict): the
    ///   model judges each breach-relevant entry holistically (ADR-0013), but a CPU-only
    ///   local model is too slow to re-run every watch event, so an entry is re-judged
    ///   only when its fingerprint changes (its CVEs/runtime OR its reachable-objective
    ///   set — a misconfig that newly exposes something re-triggers it);
    /// - the DISPLAY memory (the last verdict shown, decisive or inconclusive): carried
    ///   forward so the dashboard never blanks while the slow model re-judges;
    /// - the journal-RESTORED summary (JEF-141): the model's prior words shown on boot
    ///   until a live verdict supersedes them;
    /// - the JOURNALED-summary dedup key: a decisive verdict is journaled + notified only
    ///   when it changed for the entry.
    ///
    /// Because both `/findings` (via [`dashboard::Findings::snapshot`]) and `/judgements`
    /// derive an entry's verdict from this one store, they cannot disagree, and a verdict
    /// is visible on the dashboard the instant the judging loop writes it here — there is
    /// no end-of-pass re-publish lag. Pruned to present entries each pass (ephemeral
    /// workloads, removed exposure).
    verdicts: std::sync::Arc<dashboard::VerdictStore>,
    /// OTLP instruments (no-op when no collector is configured).
    metrics: EngineMetrics,
}

impl Engine {
    /// Build an engine with an explicit actuator, hypothesis source, and
    /// adjudicator. The binary passes a [`DryRunActuator`] when nothing is enabled
    /// and a live actuator otherwise, and model-backed source/adjudicator when a
    /// model is configured.
    pub fn new(
        active: EnabledActions,
        scope: ActuationScope,
        actuator: Box<dyn Actuator>,
        hypothesizer: Box<dyn reason::hypothesis::HypothesisSource>,
        adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    ) -> Self {
        if active.is_empty() {
            tracing::info!("engine: no action classes enabled (easy mode — proposals only)");
        } else {
            tracing::warn!("engine: action classes enabled — auto-application is on for them");
        }
        let findings = std::sync::Arc::new(dashboard::Findings::new());
        findings.set_armed(!active.is_empty());
        // The verdict store (JEF-157) is OWNED by the findings handle and SHARED with the
        // engine: both write/read the same `Arc`, so a verdict the judging loop writes is
        // visible on `/findings` immediately.
        let verdicts = findings.verdicts();
        Self {
            adapters: observe::adapter::default_adapters(),
            active,
            scope,
            actuator,
            hypothesizer,
            adjudicator,
            findings,
            reversions: std::sync::Arc::new(dashboard::ReversionLog::new()),
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
            metrics: EngineMetrics::new(),
        }
    }

    /// Attach a durable decision journal (JEF-141) and replay it onto the in-memory
    /// state, so `/findings`, `/judgements`, and the reversions view populate IMMEDIATELY
    /// after a restart — before a fresh (slow CPU) model pass lands. A disabled journal
    /// (no volume configured) replays nothing, leaving today's cold-start behaviour.
    /// Builder-style; called once on boot.
    pub fn with_journal(mut self, journal: journal::DecisionJournal) -> Self {
        self.replay_journal(&journal);
        self.journal = std::sync::Arc::new(journal);
        self
    }

    /// A handle to the durable decision journal (JEF-143), for the dashboard's `/report`
    /// view to replay read-only. Shares the same `Arc` the engine writes through, so the
    /// report reflects every decision the live engine has journaled this run plus the
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
        for entry in &entries {
            latest_at = latest_at.max(entry.at());
            match &entry.decision {
                journal::Decision::Breach {
                    entry: key,
                    verdict,
                    ..
                } => {
                    // Carry the model's prior words forward verbatim as a display memory,
                    // so the breach path shows its last judgement IMMEDIATELY while a fresh
                    // one is computed. Replayed in chronological order, so the final write
                    // per entry wins. Display-only: the action logic still uses the live
                    // verdict, never this restored string.
                    self.verdicts.seed_restored(key, verdict.clone());
                    restored_verdicts += 1;
                }
                journal::Decision::Revert { cut, reason } => {
                    self.reversions.record(dashboard::ReversionRecord {
                        cut: cut.clone(),
                        reason: reason.clone(),
                        at_ms: entry.at_ms,
                    });
                    restored_reversions += 1;
                }
                // Applies are durable for the audit trail but don't seed a view directly
                // (the live ledger re-derives the active set from current proof each pass).
                journal::Decision::Apply { .. } => {}
            }
        }
        if latest_at > std::time::SystemTime::UNIX_EPOCH {
            self.findings.mark_pass(latest_at);
        }
        tracing::info!(
            decisions = entries.len(),
            restored_verdicts,
            restored_reversions,
            "replayed decision journal on boot (dashboard populated from durable history)"
        );
    }

    /// A handle to the current findings, for the dashboard server to read.
    pub fn findings(&self) -> std::sync::Arc<dashboard::Findings> {
        self.findings.clone()
    }

    /// A handle to the recent-reversions ring (JEF-141), for the dashboard's
    /// `/reversions` view.
    pub fn reversions(&self) -> std::sync::Arc<dashboard::ReversionLog> {
        self.reversions.clone()
    }

    /// Run the five-question pipeline against one observed snapshot.
    ///
    /// Proof, ledger reconciliation, and the action decision run **every pass** —
    /// not only on a structural delta — because corroboration, vulnerability, and
    /// health facts can change a chain's status without changing the graph's shape
    /// (a Falco event is the motivating case: it flips a chain to fully
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
        // same figures, surfaced on the dashboard so the shadow-bake exit criteria are
        // readable without an OTLP collector. Filled out (corroborations) after the chains
        // are proven below, then published to the findings handle.
        let mut bake = dashboard::BakeStats {
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

        // Prove (Question 2) every pass. The deterministic enumerator finds the
        // structural chains; a model hypothesis source may *additionally* propose
        // candidates, which the confirmation gate accepts only if every link is a
        // real proof-grade edge ("a model may propose; only proof moves
        // privilege"). Confirmed model chains are merged, deduped by endpoints.
        let mut chains = reason::proof::prove(&graph);
        let proposed = self.hypothesizer.propose(&graph).await;
        for confirmed in reason::hypothesis::confirm_all(&graph, &proposed) {
            if !chains
                .iter()
                .any(|c| c.entry == confirmed.entry && c.objective == confirmed.objective)
            {
                chains.push(confirmed);
            }
        }

        // Publish the proven chains NOW, before the (CPU-bound, possibly slow or
        // unreachable) adjudication. The dashboard must always reflect the current graph
        // even while the model is judging or down — model latency must never blank the
        // findings view. JEF-157: the rows carry NO per-chain verdict; each finding's
        // verdict is resolved from the shared verdict store at snapshot time (the last-
        // known live verdict, or a journal-restored one). So this single publish already
        // shows the carried-forward verdict, and when the judging loop below writes a
        // fresh verdict into the store it is visible IMMEDIATELY — no end-of-pass
        // re-publish is needed to surface it.
        self.findings.replace(
            chains
                .iter()
                .map(|c| dashboard::Finding::from_chain(c, &graph))
                .collect(),
        );

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
        // Publish this pass's behavioral-bake snapshot for the dashboard (JEF-48). Done
        // here, before the slow adjudication loop, for the same reason the findings are:
        // the bake view must reflect the current pass even while the model is judging.
        bake.corroborations = corroborations;
        self.findings.set_bake(bake);

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
        // model never blocks the dashboard.
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
        // How often we actually call the (slow, CPU-bound) model this pass vs reuse a
        // cached verdict. A persistently high `judged` means the verdict-cache fingerprint
        // is churning (re-judging unchanged entries) — the thing to watch for model load.
        let (mut judged, mut cached) = (0u64, 0u64);
        for (entry_key, idxs) in &by_entry {
            let entry = chains[idxs[0]].entry.clone();
            // The (objective, technique) set this entry reaches — what the model judges.
            let mut objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)> = idxs
                .iter()
                .map(|&i| (chains[i].objective.clone(), chains[i].attack))
                .collect();
            objectives.sort_by(|a, b| a.0.0.cmp(&b.0.0));
            objectives.dedup_by(|a, b| a.0 == b.0);

            let fingerprint = reason::adjudicate::entry_fingerprint(&graph, &entry, &objectives);
            let verdict = match self.verdicts.cached_for(entry_key, &fingerprint) {
                Some(v) => {
                    cached += 1;
                    v
                }
                None => {
                    judged += 1;
                    // Time the (slow, CPU-bound) model call so its latency tail is
                    // observable in shadow (JEF-100). Recorded for every fresh call,
                    // success or timeout — the `result` label below distinguishes them.
                    let started = std::time::Instant::now();
                    let v = self.adjudicator.judge(&entry, &objectives, &graph).await;
                    self.metrics
                        .model_latency_ms
                        .record(started.elapsed().as_secs_f64() * 1000.0, &[]);
                    // An Uncertain is usually a transient model outage (e.g. a CPU-model
                    // timeout) — re-judge next pass rather than pin the failure into the
                    // cache. Logged at info (not debug): on a slow CPU model nearly every
                    // verdict lands here, and a silent inconclusive looks indistinguishable
                    // from "the model never ran" — surface why (timeout vs unparseable).
                    let result = match &v {
                        reason::adjudicate::Verdict::Uncertain(why) => {
                            tracing::info!(entry = %entry.0, objectives = objectives.len(), %why, "adjudication inconclusive (will retry)");
                            "unavailable"
                        }
                        decisive => {
                            tracing::info!(entry = %entry.0, objectives = objectives.len(), verdict = ?decisive, "adjudicated entry");
                            self.verdicts
                                .cache_decisive(entry_key, fingerprint, v.clone());
                            "ok"
                        }
                    };
                    // Piggyback the readiness panel's LIVE model health (JEF-160) on this
                    // call's outcome — cheap, no extra model call. A decisive verdict means
                    // the model answered; an Uncertain ("model unavailable") means it timed
                    // out / the endpoint is down. The coverage panel reads this back.
                    self.findings.set_model_health(match result {
                        "ok" => dashboard::ModelHealth::Ok,
                        _ => dashboard::ModelHealth::Timeout,
                    });
                    self.metrics
                        .model_calls
                        .add(1, &[opentelemetry::KeyValue::new("result", result)]);
                    v
                }
            };
            // Choose what to DISPLAY: if this pass came back inconclusive (a transient
            // model timeout — "model unavailable") but we have a prior decisive verdict,
            // keep showing the decisive one rather than regressing the dashboard to
            // "uncertain". The action logic below still uses this pass's real `verdict`.
            let display = match (&verdict, self.verdicts.display_verdict(entry_key)) {
                (reason::adjudicate::Verdict::Uncertain(_), Some(prior))
                    if !matches!(prior, reason::adjudicate::Verdict::Uncertain(_)) =>
                {
                    prior
                }
                _ => verdict.clone(),
            };
            // Write the displayed verdict to the single source of truth (JEF-157) the
            // MOMENT it's decided — so `/findings` shows it immediately, not only after
            // an end-of-pass re-publish. A live verdict supersedes any journal-restored
            // one for this entry (handled inside `set_display`).
            self.verdicts.set_display(entry_key, display.clone());
            // Append the breach decision to the durable journal (JEF-141) — but only a
            // DECISIVE verdict, and only when it changed from the last line we wrote for
            // this entry, so a steady-state cluster doesn't append an identical line every
            // pass. Uncertain (transient timeout) is skipped, mirroring the verdict-cache
            // discipline. A no-op when the journal is disabled (no volume).
            let summary = display.summary();
            if !matches!(display, reason::adjudicate::Verdict::Uncertain(_))
                && self.verdicts.journaled(entry_key).as_ref() != Some(&summary)
            {
                // Re-derive the structured enrichment-coverage (JEF-145) from the SAME
                // evidence the model was given (`entry_evidence`, via `entry_coverage`),
                // so `/report` classifies an enrichment-coverage gap from fact instead of
                // grepping this verdict's prose for a `CVE-` token. Cheap and pure.
                let coverage = reason::adjudicate::entry_coverage(&graph, &entry);
                self.journal.record(journal::Decision::Breach {
                    entry: entry_key.clone(),
                    objectives: objectives.len(),
                    verdict: summary.clone(),
                    coverage: Some(journal::EnrichmentCoverage {
                        cves: coverage.cves,
                        behavioral: coverage.behavioral,
                    }),
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
                        objectives: &objectives,
                        enforcement: notify::Enforcement::from_armed(!self.active.is_empty()),
                    })
                    .await;
            }
            // The entry's verdict applies to every chain from it. The dashboard derives
            // the verdict from the shared store (JEF-157); this per-chain stamp is kept
            // for the timer path's `chain.emit()` log and as the `from_chain` fallback.
            for &i in idxs {
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
        // Mirror the shadow would-have-acted report headline (JEF-143) to OTLP, like the
        // bake counts: the gates-exiting-shadow figures (JEF-50) over the default window,
        // read back from the durable journal we just appended this pass's breach decision
        // to. Cheap no-op when the journal is disabled (replay is empty). Read-only.
        let report = dashboard::default_window_report(&self.journal);
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
                "adjudication pass (model calls = judged)"
            );
        }
        // Re-publish the enriched chains — promotions move into remediations, vetoes flip
        // `adjudicated`, so the disposition is current. JEF-157: the VERDICT is no longer
        // what this re-publish is for (it was already written to the shared store the
        // instant each entry was judged, and `/findings` reads it from there) — this only
        // refreshes the structural enrichment of the rows.
        self.findings.replace(
            chains
                .iter()
                .map(|c| dashboard::Finding::from_chain(c, &graph))
                .collect(),
        );

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
            // the in-memory reversions ring (for `/reversions`) and append it to the
            // journal so it survives a restart.
            let cut = reversion.mitigation.cut_signature();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            self.reversions.record(dashboard::ReversionRecord {
                cut: cut.clone(),
                reason: reversion.reason.clone(),
                at_ms: now_ms,
            });
            self.journal.record(journal::Decision::Revert {
                cut,
                reason: reversion.reason.clone(),
            });
        }

        // Mark the pass complete for the dashboard's "last pass NNs ago" freshness line
        // (JEF-141), so a quiet/loading view reads as fresh rather than broken.
        self.findings.mark_pass(std::time::SystemTime::now());

        self.previous = current;
    }
}

// The engine's drivers (run_watch/run) and their env-driven builders live in a sibling
// module, split out to keep this file under the 1,000-line cap (repo CLAUDE.md). The
// public surface (`run`, `run_watch`) is re-exported here so external paths
// (`protector::engine::run_watch`) resolve unchanged.
mod run_loop;
pub use run_loop::{run, run_watch};

#[cfg(test)]
mod tests;
