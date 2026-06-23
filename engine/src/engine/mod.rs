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

use std::time::Duration;

// Modules are grouped by domain (see each group's mod.rs):
//   graph/   — the stable vocabulary + its diff (ADR-0003/0004)
//   observe/ — observed state + capability ports/adapters (ADR-0002/0003)
//   reason/  — propose / prove / judge (ADR-0001/0005/0013)
//   respond/ — proven chains → self-retiring controls, then apply (ADR-0002/0009)
// model + dashboard are cross-cutting single files; this mod.rs is the orchestrator.
pub mod dashboard;
pub mod graph;
pub mod model;
pub mod observe;
pub mod reason;
pub mod respond;

use graph::delta::GraphSnapshot;
use observe::Snapshot;
use observe::adapter::Adapter;
use observe::health::{Health, HealthProvider, PodStatusHealth};
use respond::MitigationLedger;
use respond::actuator::{
    ActionLog, Actuator, Decision, DryRunActuator, EnabledActions, decide, predict_blast_radius,
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
        }
    }
}

/// Whether an ingested signal's [`Attribution`] resolves to a live workload, mirroring
/// the [`observe::adapter::RuntimeAdapter`]'s resolution rule (JEF-100, for the
/// attribution-outcome metric — pure, no graph mutation). A namespace/name attribution
/// (Falco) is always resolvable; a cgroup-UID attribution (the eBPF agent) resolves only
/// if a pod with that UID is in the snapshot, exactly as the adapter's `by_uid` lookup
/// does — an unknown UID (pod gone / not yet observed) is dropped as `unresolved`.
fn attribution_resolves(attribution: &observe::Attribution, pod_uids: &HashSet<&str>) -> bool {
    match attribution {
        observe::Attribution::ByNamespacedName { .. } => true,
        observe::Attribution::ByPodUid { pod_uid } => pod_uids.contains(pod_uid.as_str()),
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
    actuator: Box<dyn Actuator>,
    hypothesizer: Box<dyn reason::hypothesis::HypothesisSource>,
    adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    findings: std::sync::Arc<dashboard::Findings>,
    previous: GraphSnapshot,
    ledger: MitigationLedger,
    actions: ActionLog,
    /// Cross-pass verdict cache, keyed by internet-facing ENTRY → (evidence
    /// fingerprint, the model's verdict). The model judges each breach-relevant entry
    /// holistically over everything it reaches (ADR-0013), but a CPU-only local model
    /// is far too slow to re-run on every watch event; an entry is re-judged only when
    /// its fingerprint changes (its CVEs/runtime OR its reachable-objective set — so a
    /// misconfig that newly exposes something re-triggers it). Pruned to present
    /// entries each pass (ephemeral workloads, removed exposure).
    verdict_cache: HashMap<String, (String, reason::adjudicate::Verdict)>,
    /// The most recent verdict per internet-facing ENTRY, of *any* kind (decisive or
    /// inconclusive) — distinct from [`verdict_cache`], which holds only decisive
    /// verdicts and governs re-judging. This is the **display** memory: each pass
    /// republishes findings with `verdict: None` *before* the (slow) judging loop runs,
    /// so without carrying the last-known verdict forward the dashboard blanks every
    /// pass. Seeded onto fresh chains at publish time so a judgement — even "uncertain
    /// — model unavailable" — stays visible while the model re-judges. Pruned to present
    /// entries each pass.
    last_verdict: HashMap<String, reason::adjudicate::Verdict>,
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
        Self {
            adapters: observe::adapter::default_adapters(),
            active,
            actuator,
            hypothesizer,
            adjudicator,
            findings,
            previous: GraphSnapshot::default(),
            ledger: MitigationLedger::new(),
            actions: ActionLog::new(),
            verdict_cache: HashMap::new(),
            last_verdict: HashMap::new(),
            metrics: EngineMetrics::new(),
        }
    }

    /// A handle to the current findings, for the dashboard server to read.
    pub fn findings(&self) -> std::sync::Arc<dashboard::Findings> {
        self.findings.clone()
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
            // Mirror the RuntimeAdapter's resolution rule: a namespace/name attribution is
            // always resolvable; a cgroup-UID one resolves iff a pod with that UID is in
            // the snapshot (the adapter drops the rest as unknown UIDs).
            let outcome = if attribution_resolves(&event.attribution, &pod_uids) {
                "resolved"
            } else {
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

        // Carry the last-known verdict forward onto each breach-relevant chain so the
        // dashboard shows the most recent judgement IMMEDIATELY — the judging loop below
        // is slow on a CPU model, and publishing with verdict=None first would blank the
        // UI every pass. Both decisive and inconclusive verdicts are carried (seeing
        // "uncertain — model unavailable" is the point — it shows the model was asked).
        for c in chains.iter_mut() {
            if c.is_breach_relevant()
                && let Some(v) = self.last_verdict.get(&c.entry.0)
            {
                c.verdict = Some(v.summary());
            }
        }

        // Publish the proven chains NOW, before the (CPU-bound, possibly slow or
        // unreachable) adjudication. The dashboard must always reflect the current
        // graph even while the model is judging or down — model latency must never
        // blank the findings view. The judging loop below enriches verdicts and
        // re-publishes; until it does, paths show the carried-forward verdict above.
        self.findings
            .replace(chains.iter().map(dashboard::Finding::from_chain).collect());

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
            let verdict = match self.verdict_cache.get(entry_key) {
                Some((fp, v)) if *fp == fingerprint => {
                    cached += 1;
                    v.clone()
                }
                _ => {
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
                            self.verdict_cache
                                .insert(entry_key.clone(), (fingerprint, v.clone()));
                            "ok"
                        }
                    };
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
            let display = match (&verdict, self.last_verdict.get(entry_key)) {
                (reason::adjudicate::Verdict::Uncertain(_), Some(prior))
                    if !matches!(prior, reason::adjudicate::Verdict::Uncertain(_)) =>
                {
                    prior.clone()
                }
                _ => verdict.clone(),
            };
            // Remember the displayed verdict for the carry-forward seed above, so the
            // next pass shows it instead of blanking.
            self.last_verdict.insert(entry_key.clone(), display.clone());
            // The entry's verdict applies to every chain from it. Keep the model's call
            // — positive *and* negative — on each so the dashboard shows why it acted.
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
        // exposure), so the cache tracks the live cluster rather than growing forever.
        self.verdict_cache
            .retain(|entry, _| current_entries.contains(entry));
        self.last_verdict
            .retain(|entry, _| current_entries.contains(entry));
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
        if !by_entry.is_empty() {
            tracing::info!(
                entries = by_entry.len(),
                judged,
                cached,
                "adjudication pass (model calls = judged)"
            );
        }
        // Re-publish with the model's verdicts now attached — the enriched view
        // (promotions move into remediations; judged paths show the model's words).
        self.findings
            .replace(chains.iter().map(dashboard::Finding::from_chain).collect());

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
            match decide(mitigation, &self.active, &blast) {
                Decision::AutoApply => {
                    if !self.actions.is_active(mitigation) {
                        self.actuator.apply(mitigation).await;
                        self.actions
                            .record(mitigation.clone(), health.alive_workloads());
                        self.metrics
                            .mitigations
                            .add(1, &[opentelemetry::KeyValue::new("action", "applied")]);
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
        }

        self.previous = current;
    }
}

/// Poll loop: re-list the whole cluster every `interval`, assemble a snapshot, and
/// process it. The simple fallback for environments where a watch isn't available;
/// [`run_watch`] is the default. A stable cluster does no useful work here between
/// changes — it just re-lists — which is exactly why the watch path is preferred.
pub async fn run(
    client: kube::Client,
    interval: Duration,
    active: EnabledActions,
    kev: observe::exploit_intel::KevCatalog,
) {
    let mut engine = Engine::new(
        active.clone(),
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(),
    );
    loop {
        match Snapshot::observe(client.clone()).await {
            Ok(mut snapshot) => {
                kev.mark_exploited(&mut snapshot.image_vulns);
                engine.process(&snapshot).await;
            }
            Err(error) => tracing::warn!(%error, "observe failed; retaining previous state"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Choose the actuator. Dry-run when nothing is enabled (the engine can never touch
/// the cluster). Otherwise `PROTECTOR_ENGINE_ACTUATOR` selects the mechanism:
/// `networkpolicy` isolates the compromised workload with a default-deny
/// NetworkPolicy — works on flannel/kube-router (ADR-0010); `adminnetworkpolicy`
/// does a surgical ANP edge-cut on Cilium/Calico (ADR-0007); `dryrun` logs only.
///
/// Unknown/empty values **fail safe to dry-run** (with a warning), not to a live
/// actuator: a typo'd selector must never silently turn a shadow deployment into
/// one that mutates the cluster.
fn build_actuator(active: &EnabledActions, client: &kube::Client) -> Box<dyn Actuator> {
    if active.is_empty() {
        return Box::new(DryRunActuator);
    }
    match std::env::var("PROTECTOR_ENGINE_ACTUATOR")
        .unwrap_or_default()
        .trim()
    {
        "networkpolicy" | "net" => {
            Box::new(respond::actuator::IsolationActuator::new(client.clone()))
        }
        "adminnetworkpolicy" | "anp" => {
            Box::new(respond::actuator::KubeActuator::new(client.clone()))
        }
        "dryrun" => Box::new(DryRunActuator),
        other => {
            tracing::warn!(
                actuator = %other,
                "unknown PROTECTOR_ENGINE_ACTUATOR with an action class enabled; \
                 failing safe to dry-run (no cluster writes). \
                 Set 'networkpolicy', 'adminnetworkpolicy', or 'dryrun'."
            );
            Box::new(DryRunActuator)
        }
    }
}

/// The model endpoint + name, read once from `PROTECTOR_ENGINE_MODEL` /
/// `PROTECTOR_ENGINE_MODEL_NAME`. `None` when no endpoint is set (deterministic-only
/// — null hypothesizer and adjudicator). Shared by both model-backed builders so the
/// endpoint and the default model name have a single source of truth.
fn model_config() -> Option<(String, String)> {
    let endpoint = std::env::var("PROTECTOR_ENGINE_MODEL")
        .ok()
        .filter(|e| !e.is_empty())?;
    let name =
        std::env::var("PROTECTOR_ENGINE_MODEL_NAME").unwrap_or_else(|_| "qwen2.5:3b".to_string());
    Some((endpoint, name))
}

/// Choose the hypothesis source: a model-backed one when a model is configured AND
/// `PROTECTOR_ENGINE_HYPOTHESIS=model` opts it in, else the null source. Local-first:
/// point it at an in-cluster model so the graph never leaves.
fn build_hypothesizer() -> Box<dyn reason::hypothesis::HypothesisSource> {
    // The model hypothesis source is OFF by default. The deterministic enumerator
    // already finds every structural chain at this cluster's scale (so model
    // proposals are redundant), and the hypothesis prompt sends the *whole graph* —
    // thousands of tokens, minutes of CPU inference on a Pi-class node — which would
    // block the engine loop every pass for no gain. Opt in with
    // `PROTECTOR_ENGINE_HYPOTHESIS=model` only where the model is fast enough; the
    // model's real job is adjudication (ADR-0013), wired separately below.
    let opt_in = std::env::var("PROTECTOR_ENGINE_HYPOTHESIS").as_deref() == Ok("model");
    match model_config() {
        Some((endpoint, model)) if opt_in => {
            tracing::info!(%endpoint, %model, "hypothesis source: model-backed (local tier)");
            Box::new(reason::hypothesis::ModelHypothesizer::new(
                endpoint,
                model,
                reason::hypothesis::Tier::Local,
            ))
        }
        _ => Box::new(reason::hypothesis::NullHypothesizer),
    }
}

/// Keep the configured model warm so the first judging pass after an engine restart
/// isn't glacial (the "dashboard blank ~20 min after restart" pain, JEF-63). A CPU-only
/// local model takes minutes to load its weights; once Ollama unloads an idle model
/// (default 5 min) the next adjudication eats that cold-load before any verdict lands.
///
/// This spawns a lightweight background task that warms the model once at startup and
/// then pings it on an interval shorter than Ollama's unload timeout, keeping the model
/// resident between judging passes. It is strictly **best-effort and shadow-safe**: the
/// ping is a one-token no-op chat (see [`model::keep_warm`]) that touches no verdict,
/// enable, or actuation path, and a down or slow endpoint is logged at debug and
/// retried next tick — it never blocks the engine loop or the dashboard.
///
/// A **no-op when no model is configured** (`PROTECTOR_ENGINE_MODEL` empty → no task is
/// spawned) and when keep-warm is disabled (`PROTECTOR_ENGINE_KEEPWARM_SECS=0`).
/// Returns the spawned task's handle (so the caller can abort it on shutdown), or `None`
/// when nothing was spawned.
fn spawn_keep_warm() -> Option<tokio::task::JoinHandle<()>> {
    let (endpoint, model, interval) = keep_warm_plan(model_config(), model::keepwarm_interval())?;
    tracing::info!(
        %model,
        interval_secs = interval.as_secs(),
        "keep-warm: pinging the model to stay resident between judging passes"
    );
    Some(tokio::spawn(async move {
        let client = model::client();
        let mut ticker = tokio::time::interval(interval);
        // Skip missed ticks rather than bursting catch-up pings if a tick is delayed
        // (e.g. the runtime was busy) — one ping per interval is all keep-warm needs.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // The first tick fires immediately, giving the startup warm-up; subsequent
            // ticks are the periodic keep-alive.
            ticker.tick().await;
            if model::keep_warm(&client, &endpoint, &model).await {
                tracing::debug!(%model, "keep-warm ping ok (model resident)");
            } else {
                tracing::debug!(%model, "keep-warm ping failed (model down?); retrying next tick");
            }
        }
    }))
}

/// The pure keep-warm gating decision, split out of [`spawn_keep_warm`] so it's testable
/// without spawning a task or reading process env. Returns `Some((endpoint, model,
/// interval))` only when BOTH a model is configured (`config`) AND keep-warm is enabled
/// (`interval`); `None` otherwise — i.e. a no-op when `PROTECTOR_ENGINE_MODEL` is empty
/// or `PROTECTOR_ENGINE_KEEPWARM_SECS=0`.
fn keep_warm_plan(
    config: Option<(String, String)>,
    interval: Option<Duration>,
) -> Option<(String, String, Duration)> {
    let (endpoint, model) = config?;
    let interval = interval?;
    Some((endpoint, model, interval))
}

/// Choose the adjudicator (ADR-0013): a model-backed judge when a model endpoint is
/// configured, else the null adjudicator (confirm everything — the deterministic bar
/// governs). The model judges exploitability bidirectionally — vetoing a live chain
/// the deterministic bar would act on, or promoting an exposed one it wouldn't.
fn build_adjudicator() -> Box<dyn reason::adjudicate::Adjudicator> {
    match model_config() {
        Some((endpoint, model)) => {
            tracing::info!(%model, "adjudicator: model-backed (judges exploitability — promote/veto)");
            Box::new(reason::adjudicate::ModelAdjudicator::new(endpoint, model))
        }
        None => Box::new(reason::adjudicate::NullAdjudicator),
    }
}

/// Event-driven observer: the default. Reflectors keep an in-memory store of each
/// watched resource current via `list`-then-`watch` (the periodic relist is the
/// resync floor ADR-0004 calls for). The engine reacts to *events* — it sits quiet
/// on a stable cluster and processes only when something actually changes, which
/// also means it catches **ephemeral** workloads (e.g. short-lived CI runners) a
/// poll between ticks would miss entirely.
///
/// The graph-building, proof, and response logic is identical to [`run`]; only the
/// trigger differs (event stream vs. timer). This path is exercised against a real
/// cluster, not unit tests — the analysis it drives is what the tests cover.
pub async fn run_watch(
    client: kube::Client,
    active: EnabledActions,
    runtime_addr: Option<std::net::SocketAddr>,
    dashboard_addr: Option<std::net::SocketAddr>,
    kev: observe::exploit_intel::KevCatalog,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use k8s_openapi::api::core::v1::{Pod, Secret, Service};
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
    use kube::Api;
    use kube::runtime::{WatchStreamExt, reflector, watcher};

    let mut engine = Engine::new(
        active.clone(),
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(),
    );

    // Findings dashboard (read-only): surfaces the proven chains, especially the
    // latent-foothold proposals a human acts on.
    if let Some(addr) = dashboard_addr {
        let findings = engine.findings();
        tokio::spawn(async move {
            if let Err(error) = dashboard::serve_dashboard(addr, findings).await {
                tracing::error!(%error, "dashboard stopped");
            }
        });
    }

    // Keep-warm (JEF-107): warm the model at startup and ping it periodically so it
    // stays resident between judging passes — the first post-restart pass isn't glacial.
    // Best-effort and shadow-safe; a no-op when no model is configured. Aborted on loop
    // exit so it can't outlive the engine.
    let keep_warm = spawn_keep_warm();

    // Runtime evidence (Falco alerts + the eBPF agent's behaviors) is a stream, not a
    // an HTTP endpoint falcosidekick POSTs to, are held in a TTL'd store, and wake
    // the loop so a "happening now" signal is acted on immediately (it flips a
    // chain's corroboration without changing the graph's shape). Signals expire, so
    // corroboration stays live.
    let runtime_events = std::sync::Arc::new(observe::runtime::RuntimeEvents::new(
        std::time::Duration::from_secs(300),
    ));
    let (runtime_tx, mut runtime_rx) = tokio::sync::mpsc::channel::<()>(64);
    if let Some(addr) = runtime_addr {
        let events = runtime_events.clone();
        tokio::spawn(async move {
            if let Err(error) = observe::runtime::serve_runtime(addr, events, runtime_tx).await {
                tracing::error!(%error, "runtime-evidence ingest stopped");
            }
        });
    }

    // A reflector per watched type: it owns a Store kept current as its stream is
    // polled, and yields a tick on every change. Merging the tick streams gives a
    // single "something changed" signal.
    let (pods, pods_w) = reflector::store::<Pod>();
    let (netpols, netpols_w) = reflector::store::<NetworkPolicy>();
    let (services, services_w) = reflector::store::<Service>();
    let (secrets, secrets_w) = reflector::store::<Secret>();
    let (roles, roles_w) = reflector::store::<Role>();
    let (rolebindings, rolebindings_w) = reflector::store::<RoleBinding>();
    let (clusterroles, clusterroles_w) = reflector::store::<ClusterRole>();
    let (clusterrolebindings, clusterrolebindings_w) = reflector::store::<ClusterRoleBinding>();

    let cfg = watcher::Config::default();
    // CRITICAL: each reflector runs in its OWN task so its Store stays current no
    // matter how long `process()` takes. Driving the watches inline in the loop (the
    // old design) meant a slow pass — e.g. a 30s model call — stopped reading the
    // apiserver watch streams; unread for that long they reset before the initial
    // LIST completed, so the stores never populated and the graph stayed empty. The
    // tasks ping `change_tx` on every touched object; the loop wakes on that.
    let (change_tx, mut change_rx) = tokio::sync::mpsc::channel::<()>(64);
    macro_rules! spawn_reflector {
        ($writer:expr, $typ:ty) => {{
            let tx = change_tx.clone();
            let api = Api::<$typ>::all(client.clone());
            let cfg = cfg.clone();
            tokio::spawn(
                reflector($writer, watcher(api, cfg))
                    .touched_objects()
                    .for_each(move |res| {
                        let tx = tx.clone();
                        async move {
                            if let Err(error) = res {
                                tracing::warn!(%error, kind = stringify!($typ), "watch error");
                            }
                            let _ = tx.try_send(());
                        }
                    }),
            );
        }};
    }
    spawn_reflector!(pods_w, Pod);
    spawn_reflector!(netpols_w, NetworkPolicy);
    spawn_reflector!(services_w, Service);
    spawn_reflector!(secrets_w, Secret);
    spawn_reflector!(roles_w, Role);
    spawn_reflector!(rolebindings_w, RoleBinding);
    spawn_reflector!(clusterroles_w, ClusterRole);
    spawn_reflector!(clusterrolebindings_w, ClusterRoleBinding);

    tracing::info!("engine: watching cluster (event-driven)");
    loop {
        // Wake on either a cluster change or a behavioral report. The behavioral channel
        // only fires when the ingest actually changed the evidence store (a new
        // observation, not a repeat) — see `ingest_behavior`. So a report that tells us
        // nothing new never reaches here, and we don't burn a graph rebuild + CRD lists
        // for it; mundane churn (the same connections, again) is dropped at ingest.
        tokio::select! {
            next = change_rx.recv() => if next.is_none() { break },
            _ = runtime_rx.recv() => {},
        }
        // Coalesce an already-queued burst (a Deployment rollout, or several material
        // reports) into one pass.
        while change_rx.try_recv().is_ok() {}
        while runtime_rx.try_recv().is_ok() {}

        let (linkerd_servers_now, linkerd_policies_now, linkerd_mtls_now) =
            observe::list_linkerd_authz(&client).await;
        let snapshot = Snapshot {
            pods: pods.state().iter().map(|p| (**p).clone()).collect(),
            network_policies: netpols.state().iter().map(|n| (**n).clone()).collect(),
            services: services.state().iter().map(|s| (**s).clone()).collect(),
            secrets: secrets
                .state()
                .iter()
                .filter_map(|s| {
                    Some(observe::SecretMeta {
                        namespace: s.metadata.namespace.clone()?,
                        name: s.metadata.name.clone()?,
                    })
                })
                .collect(),
            roles: roles.state().iter().map(|r| (**r).clone()).collect(),
            role_bindings: rolebindings.state().iter().map(|r| (**r).clone()).collect(),
            cluster_roles: clusterroles.state().iter().map(|r| (**r).clone()).collect(),
            cluster_role_bindings: clusterrolebindings
                .state()
                .iter()
                .map(|r| (**r).clone())
                .collect(),
            // Vulnerabilities are listed best-effort on each pass (cheap, only when
            // something changed), then enriched with KEV exploit intel. Runtime
            // events are the live, TTL'd Falco signals.
            image_vulns: {
                let mut v = observe::list_image_vulns(&client).await;
                kev.mark_exploited(&mut v);
                v
            },
            runtime_events: runtime_events.current(),
            // Linkerd authz CRDs, listed best-effort each pass (the mesh-native
            // reachability source — see LinkerdReachabilityAdapter).
            linkerd_servers: linkerd_servers_now,
            linkerd_authz_policies: linkerd_policies_now,
            linkerd_mtls_auths: linkerd_mtls_now,
        };
        engine.process(&snapshot).await;
    }

    // The change stream closed (all reflectors gone) — tear down the keep-warm task so
    // it doesn't outlive the engine loop.
    if let Some(task) = keep_warm {
        task.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::attack::AttackRef;
    use crate::engine::graph::{NodeKey, SecurityGraph};
    use crate::engine::observe::{SecretMeta, Snapshot};
    use crate::engine::reason::adjudicate::Verdict;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An adjudicator that counts how many times it's consulted (and confirms).
    struct CountingAdjudicator(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl reason::adjudicate::Adjudicator for CountingAdjudicator {
        async fn judge(
            &self,
            _entry: &NodeKey,
            _objectives: &[(NodeKey, AttackRef)],
            _graph: &SecurityGraph,
        ) -> Verdict {
            self.0.fetch_add(1, Ordering::SeqCst);
            Verdict::Refuted("counted".into())
        }
    }

    /// An internet-exposed (LoadBalancer) web pod that mounts a secret, optionally
    /// carrying a critical CVE on its image (which makes it a proven foothold).
    fn exposed_snapshot(with_cve: bool) -> Snapshot {
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::ImageVulnerabilities;
        use std::time::SystemTime;

        let web = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]}
        }))
        .unwrap();
        let lb = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: if with_cve {
                vec![ImageVulnerabilities {
                    image: "web:1".into(),
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2026-0001".into(),
                        severity: Severity::Critical,
                        exploited_in_wild: true,
                        epss: None,
                        sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                        ..Default::default()
                    }],
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    fn engine_with(counter: Arc<AtomicUsize>) -> Engine {
        Engine::new(
            EnabledActions::from_names(std::iter::empty::<&str>()),
            Box::new(DryRunActuator),
            Box::new(reason::hypothesis::NullHypothesizer),
            Box::new(CountingAdjudicator(counter)),
        )
    }

    /// The model judges EVERY breach-relevant path, with or without a CVE — an
    /// internet-reachable path to a secret is a finding on its own (structural
    /// exposure), so absence of a CVE is not a reason to skip it (ADR-0013, defense in
    /// depth). The verdict is cached per path, so re-processing the same facts doesn't
    /// re-call the model.
    #[tokio::test]
    async fn judges_every_breach_relevant_path_even_without_a_cve() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut engine = engine_with(calls.clone());

        // Exposed, reaches a secret, NO CVE and NO runtime → still judged (structural).
        engine.process(&exposed_snapshot(false)).await;
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "an internet-reachable path must be judged even with no CVE"
        );
        // The model's verdict is attached to the published finding.
        let findings = engine.findings().snapshot();
        assert!(
            findings
                .iter()
                .any(|f| f.breach_relevant && f.verdict.is_some()),
            "the judged breach path carries the model's verdict"
        );

        // Re-processing identical facts reuses the cached verdict — no new model call.
        let before = calls.load(Ordering::SeqCst);
        engine.process(&exposed_snapshot(false)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "an unchanged path must not be re-judged (cache hit)"
        );
    }

    /// Findings are published even when adjudication can't run, so model latency or an
    /// outage never blanks the dashboard. With evidence present but the (counting)
    /// model refuting, the breach finding is still there.
    #[tokio::test]
    async fn publishes_findings_independent_of_the_model() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut engine = engine_with(calls.clone());
        engine.process(&exposed_snapshot(true)).await;
        let findings = engine.findings().snapshot();
        assert!(
            findings.iter().any(|f| f.breach_relevant),
            "the breach-relevant finding is published regardless of the verdict"
        );
    }

    /// The attribution-outcome metric (JEF-100) must mirror the RuntimeAdapter's
    /// resolution rule: a namespace/name attribution always resolves; a cgroup-UID one
    /// resolves only when a pod with that UID is in the snapshot (an unknown UID is
    /// `unresolved`).
    #[test]
    fn attribution_resolves_mirrors_the_adapter_rule() {
        use crate::engine::observe::Attribution;

        // A pod whose metadata.uid is "uid-1".
        let pod: k8s_openapi::api::core::v1::Pod = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "uid": "uid-1"}
        }))
        .unwrap();
        let snapshot = Snapshot {
            pods: vec![pod],
            ..Default::default()
        };
        // The live pod-UID set the metric loop builds once per pass.
        let uids = |snap: &Snapshot| -> HashSet<String> {
            snap.pods
                .iter()
                .filter_map(|p| p.metadata.uid.clone())
                .collect()
        };
        let present = uids(&snapshot);
        let present: HashSet<&str> = present.iter().map(String::as_str).collect();
        let empty: HashSet<&str> = HashSet::new();

        // namespace/name (Falco) always resolves, even against an empty snapshot.
        assert!(attribution_resolves(
            &Attribution::by_namespaced_name("app", "web"),
            &present
        ));
        assert!(attribution_resolves(
            &Attribution::by_namespaced_name("ghost", "nobody"),
            &empty
        ));
        // A cgroup UID resolves iff a pod with that UID is present.
        assert!(attribution_resolves(
            &Attribution::by_pod_uid("uid-1"),
            &present
        ));
        assert!(!attribution_resolves(
            &Attribution::by_pod_uid("uid-unknown"),
            &present
        ));
    }

    /// Keep-warm (JEF-107) is gated on BOTH a configured model and a non-zero interval.
    /// With no model configured it must be a no-op regardless of the interval — that's
    /// the `PROTECTOR_ENGINE_MODEL` empty case the issue requires.
    #[test]
    fn keep_warm_is_a_noop_with_no_model() {
        assert!(
            keep_warm_plan(None, Some(Duration::from_secs(240))).is_none(),
            "no model configured must mean no keep-warm, even with a valid interval"
        );
    }

    /// With keep-warm disabled (`PROTECTOR_ENGINE_KEEPWARM_SECS=0` → `None` interval) it
    /// must be a no-op even when a model IS configured.
    #[test]
    fn keep_warm_is_a_noop_when_disabled() {
        assert!(
            keep_warm_plan(Some(("http://ollama/v1".into(), "qwen2.5:3b".into())), None).is_none(),
            "a zero interval must disable keep-warm even with a model configured"
        );
    }

    /// With both a model and an interval, keep-warm carries the endpoint/model/interval
    /// through unchanged for the spawned task to use.
    #[test]
    fn keep_warm_plans_when_model_and_interval_present() {
        let plan = keep_warm_plan(
            Some(("http://ollama/v1".into(), "qwen2.5:3b".into())),
            Some(Duration::from_secs(120)),
        );
        assert_eq!(
            plan,
            Some((
                "http://ollama/v1".to_string(),
                "qwen2.5:3b".to_string(),
                Duration::from_secs(120)
            ))
        );
    }

    /// A live alert on a breach-relevant entry sets `corroborated` — the source the
    /// corroborations-fired counter reads (JEF-100). Pure instrumentation: this asserts
    /// the predicate the metric counts, and that recording it doesn't disturb processing.
    #[tokio::test]
    async fn corroboration_predicate_fires_on_a_live_alert() {
        use crate::engine::observe::{Attribution, RuntimeObservation};
        use protector_behavior::Behavior;

        let calls = Arc::new(AtomicUsize::new(0));
        let mut engine = engine_with(calls.clone());

        // The exposed foothold snapshot plus a live critical alert on the entry pod.
        let mut snapshot = exposed_snapshot(true);
        snapshot.runtime_events = vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("falco".into()),
            observed_at_ms: None,
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        }];
        engine.process(&snapshot).await;

        let findings = engine.findings().snapshot();
        assert!(
            findings.iter().any(|f| f.breach_relevant && f.corroborated),
            "a live alert on the entry must corroborate a breach-relevant chain"
        );
    }
}
