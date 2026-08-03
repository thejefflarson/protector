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
// The GitOps-independent disarm kill switch (ADR-0021's enforcement gate, fast path): a
// mounted flag file, polled every pass, that narrows the running posture to dry-run and
// drives standing cuts to revert with no restart. See the module doc for why a file over a
// local admin endpoint.
pub mod break_glass;
pub mod graph;
pub mod journal;
pub mod model;
pub mod notify;
pub mod observe;
// the bounded admission-decision ring (written by the webhook engine, read by
// the admission decision log). Standalone module to stay clear of the
// file-split refactor of this orchestrator.
pub mod policy_log;
pub mod reason;
// Shared redaction primitives (ADR-0031): the egress-safety scrubbers lifted out of the
// breach notifier (`notify`, ADR-0018) so the notifier and the read-only MCP server share
// ONE implementation of "what is safe to emit off-cluster."
pub mod redact;
// The read-only, token-claim-bound tiered-redaction MCP server (ADR-0031): a second
// sanctioned egress carve-out, served on its own bind (`PROTECTOR_MCP_ADDR`) behind the SAME
// OIDC verifier as the dashboard, exposing exactly four READ-ONLY tools. No actuation tool
// exists by construction.
pub mod mcp;
pub mod respond;
// The engine's output-state domain layer: the proven-chain findings, the per-entry
// verdict store, the judgement/reversion logs, the behavioral-bake snapshot, and the
// would-have-acted / readiness aggregations the per-pass OTLP mirror reads.
pub mod state;

// OTLP instruments (extracted for the file-size cap, CLAUDE.md).
mod metrics;
use metrics::EngineMetrics;

// The shadow-bake divergence comparator (ADR-0035's "bake a model-vs-deterministic cut
// comparator in shadow" step): compares each entry's model-chosen cut-set against the
// deterministic fallback `respond::containment_for`/`quarantine_workload_link` would have
// proposed for the same chains. View only — see the module docs. `pub` so `state::divergence`
// and the dashboard's read-only view can share its record/class types.
pub mod cut_divergence;

// The ADJ-MISS-DIAG re-judge diagnostic, extracted to keep this orchestrator under
// the file-size cap (CLAUDE.md). Emits the compact, per-section-fingerprinted line the churn
// harness ingests.
mod churn_diag;

// The layered per-entry adjudication re-judge gate, extracted to
// keep this orchestrator under the file-size cap.
mod adj_gate;

// The four-phase adjudication pass (classify → dispatch → fold → publish), extracted from
// `Engine::process` to keep this orchestrator under the file-size cap and make the
// pass independently testable. Behavior-neutral code move.
mod adj_pass;

// Boot-time journal replay (durable decisions → in-memory views), extracted from
//  to keep this orchestrator under the file-size cap. Behavior-neutral
// code move.
mod restore;
use graph::delta::GraphSnapshot;
use observe::Snapshot;
use observe::adapter::Adapter;
use observe::health::{Health, PodStatusHealth};
use respond::Mitigation;
use respond::MitigationLedger;
use respond::ProposedAction;
use respond::actuator::{
    ActionLog, ActuationScope, Actuator, Decision, EnabledActions, decide, predict_blast_radius,
};
use std::collections::HashSet;

/// How long a mitigation's justifying entry may trust its last DECISIVE model verdict for a
/// **brand-new** auto-actuation, once the global judge breaker is closed again (see
/// [`Engine::gate_on_judge_freshness`]). Chosen well inside the documented model cold-start
/// window (tens of minutes on a cold local CPU model) so a judge that never comes back up is
/// caught well before an operator would notice on their own, while comfortably above the
/// breaker cooldown and the per-entry backoff ceiling (`reason::backoff::CAP`, 10 minutes) so
/// ordinary retry cadence never trips it. A code default, not an operator toggle — CLAUDE.md's
/// "detection on by default" rule reads across to actuation trust: there is nothing to turn
/// off, only a bound tuned once here.
const JUDGE_FRESHNESS_BOUND: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// One breach-relevant ENTRY queued for adjudication this pass: its identity, the
/// (objective, technique) set the model judges it over, the DETERMINISTIC prompt the model
/// will see, the verdict-cache key (a hash of that prompt), and the chain indices
/// its verdict stamps. Built once in the classification phase so the concurrent model
/// dispatch reuses the exact prompt bytes the cache key was derived from — the
/// cached-on input and the sent input can never drift.
struct PendingEntry {
    entry_key: String,
    entry: graph::NodeKey,
    objectives: Vec<(graph::NodeKey, graph::attack::AttackRef)>,
    /// The deduped, sorted workload [`graph::NodeKey`]s on this entry's PROVEN paths
    /// (`ProvenChain::paths`), EXCLUDING the entry itself — every workload the model's
    /// prompt renders its own evidence block for, threaded through to `Adjudicator::judge` so an
    /// implementation's own backstops can weigh downstream evidence exactly as the prompt does.
    downstream: Vec<graph::NodeKey>,
    /// The model's complete, deterministic input (built by `build_judgment_prompt`).
    prompt: String,
    /// The verdict-cache key: `prompt_cache_key(&prompt)` — the freshness key persisted in
    /// the journal and matched by `cached_for`. Named `fingerprint` because the
    /// cache/journal seam is generic over "the freshness key string"; its value is now the
    /// prompt hash, not the old predicted-input fingerprint.
    fingerprint: String,
    /// The per-section fingerprints of `prompt`: a hash of each labeled section
    /// (runtime / cves / secrets / posture / objectives / entry), logged in the compact
    /// `ADJ-MISS-DIAG` line so the churn harness attributes each re-judge to the EXACT section.
    sections: reason::adjudicate::PromptSections,
    /// A stable hash of this entry's objective/technique SET — the "chain shape".
    /// Entries with the same shape share this value so the harness can group them.
    chain: String,
    /// This pass's delta-aware surface (ADR-0023): snapshotted as the entry's next
    /// baseline when this pass judges it decisively, so the next pass measures additions against it.
    surface: reason::adjudicate::JudgedSurface,
    idxs: Vec<usize>,
    /// The deterministic cut-choice menu (ADR-0034 D4) `prompt`'s containment-options
    /// section rendered — carried alongside the prompt so [`reason::adjudicate::Adjudicator::judge`]
    /// parses/resolves the model's `contain` reply against the EXACT menu the entry's prompt
    /// showed (never rebuilt, so the two can never drift).
    menu: reason::adjudicate::incident::Menu,
}

/// A journal-restored per-entry cut-choice decision (ADR-0034 D8), held until the
/// DOUBLE replay-lock verifies it against THIS RUN's own freshly-rebuilt state (see
/// [`adj_pass::rearm_restored_decision`]). Deliberately NOT an
/// [`incident::IncidentDecision`](reason::adjudicate::incident::IncidentDecision) — its cuts
/// carry only the two facts the journal persisted (node key + resolved cut signature); the
/// mechanism/edge are re-derived from the CURRENT menu on a lock hold, never trusted from
/// disk (see [`journal::JournaledCut`]).
struct RestoredDecision {
    /// The full-prompt fingerprint this decision was judged against — the first lock.
    fingerprint: String,
    assessment: reason::adjudicate::incident::Assessment,
    reason: String,
    /// The cuts the model chose, as recorded — re-resolved against the current menu before
    /// ever being trusted (the second lock).
    cuts: Vec<journal::JournaledCut>,
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
    /// the other "is this cut in scope" (follow-up).
    scope: ActuationScope,
    actuator: Box<dyn Actuator>,
    adjudicator: Box<dyn reason::adjudicate::Adjudicator>,
    findings: std::sync::Arc<state::Findings>,
    /// The reversion log: recent lifted cuts + why. Seeded from the journal on boot
    /// so a self-revert survives a restart.
    reversions: std::sync::Arc<state::ReversionLog>,
    /// The shadow-bake divergence log (ADR-0035's bake step): the bounded ring of recent
    /// model-vs-deterministic [`cut_divergence::DivergenceRecord`]s, read-only input to the
    /// human arm-readiness review (see `docs/adr/0037-shadow-bake-arm-readiness.md`). Written every pass alongside the durable
    /// journal's own `CutDivergence` lines; never read back by the engine itself (a view, never
    /// a gate, ADR-0016).
    divergence: std::sync::Arc<state::DivergenceLog>,
    /// The durable decision journal: each pass's breach decisions and ledger
    /// apply/revert deltas are appended here so a restart replays them. Disabled (a
    /// no-op) when no `PROTECTOR_ENGINE_JOURNAL_PATH` volume is configured — the engine
    /// then runs exactly as it did before, in-memory only. Replayed read-only by the
    /// would-have-acted report aggregation the per-pass OTLP mirror reads.
    journal: std::sync::Arc<journal::DecisionJournal>,
    /// The breach notifier (ADR-0018): the one sanctioned outbound path. POSTs a
    /// redacted breach-decision summary to an operator-configured sink, fired on the SAME
    /// decision identity as the journal write below — so one new decision is one
    /// notification, never per-pass spam. Disabled (a no-op, zero outbound calls) when no
    /// `PROTECTOR_ENGINE_NOTIFY_URL` is configured: the engine then behaves exactly as it
    /// did before, byte-identical.
    notifier: notify::BreachNotifier,
    previous: GraphSnapshot,
    ledger: MitigationLedger,
    actions: ActionLog,
    /// The SINGLE per-entry verdict store, shared (`Arc`) with the
    /// [`state::Findings`] handle. One record per internet-facing ENTRY collapses what used
    /// to be four parallel maps:
    /// - the cross-pass verdict CACHE (evidence fingerprint → decisive verdict): the
    ///   model judges each breach-relevant entry holistically (ADR-0013), but a CPU-only
    ///   local model is too slow to re-run every watch event, so an entry is re-judged
    ///   only when its fingerprint changes (its CVEs/runtime OR its reachable-objective
    ///   set — a misconfig that newly exposes something re-triggers it);
    /// - the DISPLAY memory (the last verdict shown, decisive or inconclusive): carried
    ///   forward so the resolved posture never blanks while the slow model re-judges;
    /// - the journal-RESTORED summary: the model's prior words shown on boot
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
    /// This pass's per-entry cut-choice decision (ADR-0034): the model's last
    /// DECISIVE [`reason::adjudicate::incident::IncidentDecision`], keyed by entry key. Engine-
    /// local (no `Arc`, no reader shares it — only [`respond::MitigationLedger::reconcile`]
    /// consumes it, via [`adj_pass::run_adjudication_pass`]'s return value). Retained across a
    /// cache-hit/backoff pass exactly like [`Self::verdicts`]'s cache (D7's retirement
    /// asymmetry: a this-pass `Uncertain` never clears it); pruned to present entries each pass.
    /// Seeded ACROSS a restart from the durable journal (ADR-0034 D8) — see
    /// [`Self::restored_decisions`] and [`adj_pass::rearm_restored_decision`] — so a standing
    /// model-chosen cut survives the model's cold-start window rather than dropping to the
    /// `containment_for` human-proposal fallback until re-judged.
    decisions: std::collections::BTreeMap<String, reason::adjudicate::incident::IncidentDecision>,
    /// Journal-restored decisions (ADR-0034 D8), pending the double replay-lock
    /// verification against THIS RUN's own freshly-rebuilt state — see
    /// [`adj_pass::rearm_restored_decision`]. Seeded once at boot from the journal's `Incident`
    /// lines ([`Self::replay_journal`], chronological replay ⇒ last-write-wins per entry);
    /// each entry is consumed (removed) the first pass it's checked, whether the lock holds or
    /// not — a hold arms it into [`Self::decisions`], a miss discards it (cold re-judge, never
    /// repointed or retried blind on a later pass). Nothing else ever reads this map directly.
    restored_decisions: std::collections::BTreeMap<String, RestoredDecision>,
    /// Per-node agent-liveness, shared with the ingest; classified each pass into the
    /// runtime-corroboration coverage the readiness row reads. `None` when no ingest is wired.
    agent_liveness: Option<std::sync::Arc<state::AgentLivenessStore>>,
    /// The offline IP→ASN dataset, hot-reloadable like KEV/EPSS. Read each pass when
    /// building an entry's adjudication prompt so INTERNET egress renders grouped by provider
    /// (`GitHub [AS36459]`) — the salient provider signal AND the CDN-rotation churn fix.
    /// Defaults to an empty dataset (every internet peer falls back to its raw `IP:port`,
    /// exactly today's behavior) until the watch loop attaches the file-backed feed.
    asn: observe::feed_reload::ReloadableFeed<observe::asn::AsnDb>,
    /// The GitOps-independent kill switch (ADR-0021's enforcement gate, fast path):
    /// checked every pass. Its presence clamps this pass's armed classes to none, for
    /// both the auto-apply decision and the self-revert check, so a standing cut starts
    /// reverting the very next pass with no restart. Defaults to
    /// [`break_glass::BreakGlass::disabled`] (never engaged), so every engine built
    /// without [`Self::with_break_glass`] — every existing test, and any embedding that
    /// doesn't opt in — is unaffected by this module's existence.
    break_glass: break_glass::BreakGlass,
    /// Whether break-glass was engaged as of the previous pass, so the engage/clear
    /// transition is logged and metered exactly ONCE (an edge), not every pass —
    /// mirroring the collapse/recovery edge-detection already used above for runtime-
    /// coverage.
    break_glass_was_engaged: bool,
    /// OTLP instruments (no-op when no collector is configured).
    metrics: EngineMetrics,
    /// This pass's standing-cut snapshot (ADR-0021, ADR-0016) — every active mitigation
    /// paired with the blast radius already computed for it below, for the dashboard's
    /// read-only pre-arm scope-simulation preview to classify against a candidate
    /// `enforceScope` on demand. Written at the SAME point the live blast gate computes
    /// each blast, never a second, independently-derived pass over the graph/health.
    scope_preview: std::sync::Arc<state::ScopePreviewStore>,
    /// The live cluster-facing revert half of the ADR-0040 node-containment actuator
    /// (cordon lift + co-resident-deny lift), reached through the narrow
    /// [`respond::actuator::node_containment::NodeContainmentRevert`] seam so the
    /// self-revert loop below can hold either the real cluster actuator or a test double —
    /// mirroring [`Self::actuator`] above. `None` (the [`Self::new`] default) leaves a
    /// standing `ContainNode` mitigation un-reverted rather than driving it through the
    /// wrong-shaped generic `actuator` (see [`Self::revert_contain_node`]); wiring a real
    /// one in is a follow-up once a node-observation adapter exists
    /// ([`respond::actuator::node_containment`]'s own doc).
    node_containment_actuator:
        Option<Box<dyn respond::actuator::node_containment::NodeContainmentRevert>>,
    /// Observed [`respond::actuator::node_containment::NodeFact`]s for the `ContainNode`
    /// revert ownership self-gate (ADR-0040 §5), keyed by node name. Empty (the
    /// [`Self::new`] default) until seeded via [`Self::with_node_fact`] — a real
    /// node-observation adapter refreshing this fleet every pass is a follow-up
    /// (`respond::actuator::node_containment`'s own doc). A `ContainNode` mitigation whose
    /// host has no entry here is left un-reverted rather than fabricating "no data ⇒ pass"
    /// for the ownership check — the same discipline that module already applies to the
    /// cordon rails.
    node_facts: std::collections::BTreeMap<String, respond::actuator::node_containment::NodeFact>,
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
        // The verdict store is OWNED by the findings handle and SHARED with the
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
            divergence: std::sync::Arc::new(state::DivergenceLog::new()),
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
            decisions: std::collections::BTreeMap::new(),
            restored_decisions: std::collections::BTreeMap::new(),
            agent_liveness: None,
            // Empty until the watch loop attaches the file-backed feed: internet
            // peers then render as raw `IP:port`, exactly today's pre-feed behavior.
            asn: observe::feed_reload::ReloadableFeed::from_store(observe::asn::AsnDb::empty()),
            break_glass: break_glass::BreakGlass::disabled(),
            break_glass_was_engaged: false,
            metrics: EngineMetrics::new(),
            scope_preview: std::sync::Arc::new(state::ScopePreviewStore::new()),
            node_containment_actuator: None,
            node_facts: std::collections::BTreeMap::new(),
        }
    }

    /// Attach the per-node agent-liveness store, read each pass to stamp coverage.
    pub fn with_agent_liveness(mut self, l: std::sync::Arc<state::AgentLivenessStore>) -> Self {
        self.agent_liveness = Some(l);
        self
    }

    /// Attach the offline IP→ASN dataset, read each pass to group INTERNET egress
    /// peers by provider in the adjudication prompt. Shares the same `ArcSwap` cell as the
    /// handle the watch loop spawns the reloader on, so a daily CronJob refresh is visible to
    /// the engine without a restart. Builder-style; called once on boot.
    pub fn with_asn(
        mut self,
        asn: observe::feed_reload::ReloadableFeed<observe::asn::AsnDb>,
    ) -> Self {
        self.asn = asn;
        self
    }

    /// Attach a durable decision journal and replay it onto the in-memory
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

    /// A handle to the durable decision journal, for the would-have-acted report
    /// aggregation to replay read-only. Shares the same `Arc` the engine writes through, so the
    /// aggregation reflects every decision the live engine has journaled this run plus the
    /// pre-restart history on disk.
    pub fn journal(&self) -> std::sync::Arc<journal::DecisionJournal> {
        self.journal.clone()
    }

    /// Attach the operator-configured breach notifier (ADR-0018). The one
    /// sanctioned outbound path: a redacted breach-decision summary POSTed to an in-cluster
    /// sink, deduped on the journal's decision identity. A disabled notifier (no
    /// `PROTECTOR_ENGINE_NOTIFY_URL`) makes zero outbound calls — today's behaviour exactly.
    /// Builder-style; called once on boot.
    pub fn with_notifier(mut self, notifier: notify::BreachNotifier) -> Self {
        self.notifier = notifier;
        self
    }

    /// Attach the break-glass kill switch (ADR-0021's enforcement gate, fast path):
    /// watched every pass thereafter. Builder-style; called once on boot by
    /// [`run_watch`]. Tests that don't call this get [`break_glass::BreakGlass::disabled`]
    /// (never engaged) from [`Self::new`] — behavior is unaffected.
    pub fn with_break_glass(mut self, break_glass: break_glass::BreakGlass) -> Self {
        self.break_glass = break_glass;
        self
    }

    /// A handle to the current findings snapshot (proven chains + verdicts), for a reader.
    pub fn findings(&self) -> std::sync::Arc<state::Findings> {
        self.findings.clone()
    }

    /// A handle to the reversion log: the recent lifted-cuts ring.
    pub fn reversions(&self) -> std::sync::Arc<state::ReversionLog> {
        self.reversions.clone()
    }

    /// A handle to the shadow-bake divergence log, for the dashboard's read-only view (and any
    /// future arm-readiness aggregation) to snapshot. Shares the same `Arc` the engine writes
    /// through each pass.
    pub fn divergence(&self) -> std::sync::Arc<state::DivergenceLog> {
        self.divergence.clone()
    }

    /// A handle to this pass's standing-cut snapshot (ADR-0021, ADR-0016), for the
    /// dashboard's read-only pre-arm scope-simulation preview.
    pub fn scope_preview(&self) -> std::sync::Arc<state::ScopePreviewStore> {
        self.scope_preview.clone()
    }

    /// This pass's effective armed classes (ADR-0021's enforcement gate, fast disarm path):
    /// a single local file-existence check, fresh every pass. Break-glass engaged narrows
    /// `self.active` (the mode/enforceScope the process booted with, never mutated) down to
    /// `EnabledActions::none()` for this pass alone — feeding both the auto-apply decision and
    /// the self-revert check, so a standing cut starts reverting the very next pass with no
    /// restart. Logs and meters ONLY the engage/clear EDGE, not every pass.
    fn poll_break_glass(&mut self) -> EnabledActions {
        let engaged = self.break_glass.engaged();
        if engaged != self.break_glass_was_engaged {
            self.break_glass_was_engaged = engaged;
            if engaged {
                tracing::warn!(
                    "BREAK-GLASS ENGAGED: actuation clamped to dry-run; standing cuts begin \
                     reverting this pass"
                );
            } else {
                tracing::info!(
                    "break-glass CLEARED: posture restored to the configured mode/enforceScope"
                );
            }
            self.metrics.record_break_glass_transition(engaged);
        }
        self.metrics.record_break_glass(engaged);
        if engaged {
            EnabledActions::none()
        } else {
            self.active.clone()
        }
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
        // Behavioral-port instrumentation (pure observe): count what the
        // behavioral port saw this pass, by variant and attribution outcome, plus the
        // live store cardinality. Labels are low-cardinality (variant names, resolved/
        // unresolved) — never per-pod. `runtime_events` is the TTL'd store's snapshot
        // (`RuntimeEvents::current()`), so its length is the store cardinality.
        self.metrics
            .runtime_store
            .record(snapshot.runtime_events.len() as u64, &[]);
        // Accumulate this pass's bake snapshot alongside the OTLP counters: the
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
        // findings state. the rows carry NO per-chain verdict; each finding's
        // verdict is resolved from the shared verdict store at snapshot time (the last-
        // known live verdict, or a journal-restored one). So this single publish already
        // shows the carried-forward verdict, and when the judging loop below writes a
        // fresh verdict into the store it is resolved IMMEDIATELY — no end-of-pass
        // re-publish is needed to surface it. `publish_chains` also stamps each finding's entry
        // node so a latent finding on a blind node can carry its "no live sensor" caveat.
        // `self.decisions` here is the CARRIED-FORWARD prior pass's cut-choice map —
        // this pass's adjudication hasn't run yet, so the finding detail shows the last-known
        // cut-set immediately, refreshed by the re-publish below once fresh decisions land.
        self.findings
            .publish_chains(&chains, &graph, snapshot, &self.decisions, &health);

        // Snapshot gauges for this pass.
        self.metrics.chains.record(chains.len() as u64, &[]);
        // One pass over the chains for both breach-relevant counts: the breach-path gauge
        // and the corroborations metric — the latter the subset also marked
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
        // Publish this pass's behavioral-bake snapshot into the output state. Done
        // here, before the slow adjudication loop, for the same reason the findings are:
        // the bake snapshot must reflect the current pass even while the model is judging.
        bake.corroborations = corroborations;
        self.findings.set_bake(bake);

        // Runtime-corroboration coverage per node for the readiness row, and its
        // OTLP mirror. Reading the coverage back after stamping means the gauges are
        // sourced from the SAME `derive_runtime_coverage` the dashboard reads — they can never
        // disagree. Counts only, no per-node label dimension: node names are attacker-
        // influenceable, so a per-node series would be a cardinality/DoS vector.
        if let Some(liveness) = &self.agent_liveness {
            let edge = self
                .findings
                .stamp_runtime_coverage(liveness, &snapshot.pods);
            self.metrics
                .record_coverage(&self.findings.runtime_coverage());
            // push the operator ONCE on a coverage collapse/recovery EDGE — the gap the
            // breach notifier can't cover (a blind engine makes no breach decisions, so it stays
            // silent exactly when its own sensors have gone dark). Edge-triggered (not per pass),
            // reusing 's stall hysteresis; best-effort, bounded, redacted counts-only; a
            // no-op when the notifier is disabled (zero outbound calls).
            if let Some(edge) = edge {
                self.notifier.notify_coverage(&edge.into()).await;
            }
        }

        // One `now` for the whole pass so every backoff/breaker decision shares a single clock
        // read — the timing seam the tests drive deterministically (store methods all
        // take `now`, never reach for `Instant::now()`).
        let pass_now = std::time::Instant::now();

        // Adjudicate (ADR-0013): the model is the JUDGE of every breach-relevant path — group
        // the breach-relevant chains by their internet-facing entry, judge each entry once, and
        // fold the verdicts back into the store / journal / notifier, stamping each chain in
        // place. Extracted whole; see [`adj_pass`] for the four-phase detail. Returns
        // this pass's per-entry cut-choice decisions (ADR-0034), consumed by the ledger
        // reconcile below.
        let decisions = self
            .run_adjudication_pass(&mut chains, &graph, &health, pass_now)
            .await;
        // Re-publish the enriched chains — promotions move into remediations, vetoes flip
        // `adjudicated`, so the disposition is current. the VERDICT is no longer
        // what this re-publish is for (it was already written to the shared store the
        // instant each entry was judged, and the findings snapshot resolves it from there) —
        // this only refreshes the structural enrichment of the rows (+ re-stamps entry nodes) —
        // and, with THIS pass's fresh `decisions`, the finding detail's cut-set list.
        self.findings
            .publish_chains(&chains, &graph, snapshot, &decisions, &health);

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

        // Shadow-bake divergence comparator (ADR-0035's bake step): for every entry with a
        // decisive cut-choice decision this pass, compare the model's chosen cut-set against the
        // deterministic fallback `containment_for`/`quarantine_workload_link` would have proposed
        // for the SAME chains. VIEW ONLY — reads `chains`/`decisions`, never feeds back into the
        // reconcile below or anything else that arms/mutates state; it is the read-only signal the
        // human arm-readiness review reads (`docs/adr/0037-shadow-bake-arm-readiness.md`), never an auto-arm.
        for record in cut_divergence::compute(&chains, &decisions) {
            let row = state::DivergenceRow::now(record);
            self.journal.record(journal::Decision::CutDivergence {
                entry: row.entry.clone(),
                class: row.class,
                model_cuts: row.model_cuts.clone(),
                deterministic_cuts: row.deterministic_cuts.clone(),
            });
            self.divergence.record(row);
        }

        // Reconcile proposed mitigations against the current chains AND this pass's model
        // decisions (Q4 and Q5, ADR-0034 D6/D7).
        let ledger_delta = self.ledger.reconcile(&chains, &decisions);
        if !ledger_delta.is_empty() {
            ledger_delta.emit();
        }
        let newly_proposed: HashSet<String> = ledger_delta
            .proposed
            .iter()
            .map(|m| m.cut_signature())
            .collect();
        // ADR-0040 actuation metrics: a newly-proposed `ContainNode` mitigation is real,
        // genuine data today (the `boundary_break` trigger + menu resolver already run
        // unconditionally, ADR-0040 §1-3) — unlike the deterministic rails
        // (`respond::actuator::node_containment::cordon_decision`/`revert_decision`), which
        // need an observed `NodeFact` fleet the engine does not watch yet (that module's own
        // doc), so evaluating them here would mean gating against fabricated "no data" and
        // silently reading as always-pass. `applied`/`reverted`/`rail_refused` wire in once
        // that observation lands.
        for mitigation in &ledger_delta.proposed {
            if mitigation.action == ProposedAction::ContainNode {
                self.metrics.record_contain_node("proposed", None);
            }
        }

        // The break-glass kill switch (ADR-0021's enforcement gate, fast path): checked fresh
        // every pass, narrowing `self.active` down for THIS pass alone when engaged. See
        // `poll_break_glass`.
        let effective_active = self.poll_break_glass();

        // Decide over *all* active mitigations (Q4 hard mode), not just the
        // newly-proposed ones — so a corroboration flip on an existing proposal is
        // acted on. AutoApply is deduped by the action log; propose/forbid is logged
        // only for newly-proposed cuts to avoid per-pass spam.
        let active_mitigations: Vec<_> = self.ledger.active().cloned().collect();
        self.metrics
            .active_mitigations
            .record(active_mitigations.len() as u64, &[]);
        // The actuation-trust signal for this pass (JUDGE FRESHNESS): mirror the global
        // breaker's CURRENT state so an operator watching only `/metrics` sees a degraded
        // judge at a glance, independent of whether anything was actually held this pass.
        self.metrics
            .judge_degraded
            .record(u64::from(self.verdicts.breaker_open(pass_now)), &[]);
        // This pass's blast radii, in step with `active_mitigations`, so the read-only
        // pre-arm scope-simulation preview (ADR-0021, ADR-0016) can be built below from the
        // SAME numbers the live blast gate just computed, without a second `Mitigation`
        // clone or a recomputation that could drift from what the gate acted on.
        let mut blasts = Vec::with_capacity(active_mitigations.len());
        for mitigation in &active_mitigations {
            let blast = predict_blast_radius(mitigation, &graph, &health);
            // Break-glass narrows the armed classes for THIS pass (`effective_active`, #307),
            // then judge-freshness downgrades an AutoApply to a degraded Propose when the model
            // can't currently verify (#306). Both gates only ever REFUSE to arm a new cut.
            let decision = decide(mitigation, &effective_active, &self.scope, &blast);
            let decision = self.gate_on_judge_freshness(mitigation, decision, pass_now);
            match decision {
                Decision::AutoApply => {
                    if !self.actions.is_active(mitigation) {
                        self.actuator.apply(mitigation).await;
                        self.actions
                            .record(mitigation.clone(), health.alive_workloads());
                        self.metrics
                            .mitigations
                            .add(1, &[opentelemetry::KeyValue::new("action", "applied")]);
                        // Durable record of the cut going live — one line, only
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
            blasts.push(blast);
        }
        self.scope_preview
            .set(active_mitigations.into_iter().zip(blasts).collect());

        // Self-reverting closed loop, every pass: revert any applied action whose
        // protected workload went down (health divergence), whose justifying chain is
        // no longer proven (posture improved), or whose action class is no longer
        // armed — a mode/enforceScope narrow to audit, or break-glass engaging, must
        // drive every standing cut to revert exactly like any other retirement.
        let justified: HashSet<String> = self.ledger.active().map(|m| m.cut_signature()).collect();
        for reversion in self
            .actions
            .reconcile(&health, &justified, &effective_active)
        {
            tracing::info!(reason = %reversion.reason, "reverting applied mitigation");
            // ADR-0040 §5: a `ContainNode` reversion is a cordon lift + co-resident-deny
            // lift, not the generic network actuator's `AdminNetworkPolicy`/`NetworkPolicy`
            // delete — routing it through `self.actuator` would silently no-op (wrong object
            // name, wrong kind) and leave the node cordoned. See `revert_contain_node`.
            if reversion.mitigation.action == ProposedAction::ContainNode {
                self.revert_contain_node(&reversion.mitigation, &graph)
                    .await;
            } else {
                self.actuator.revert(&reversion.mitigation).await;
            }
            self.metrics
                .mitigations
                .add(1, &[opentelemetry::KeyValue::new("action", "reverted")]);
            // Make the lifted cut VISIBLE and DURABLE: the self-revert is the
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
        // so a quiet/loading reader sees fresh state rather than a broken one.
        self.findings.mark_pass(std::time::SystemTime::now());

        self.previous = current;
    }

    /// Gate a `decide()` verdict on JUDGE FRESHNESS before it can newly actuate: an
    /// `AutoApply` is downgraded to a degraded-judge `Propose` unless at least one entry
    /// granting this mitigation's live-corroboration
    /// ([`Mitigation::live_corroborating_entries`]) has a decisive verdict from the model
    /// within [`JUDGE_FRESHNESS_BOUND`], with the global breaker currently CLOSED
    /// ([`state::VerdictStore::verdict_fresh`]).
    ///
    /// This closes the one gap `decide()`'s own checks (`is_live_corroborated`) don't: the
    /// verdict-cache hit and the subtractive-delta hold both resolve BEFORE
    /// the breaker check (`adj_gate`), by design — an unchanged evidence fingerprint is
    /// exactly as valid to DISPLAY as when it was judged (ADR-0023) — so a fingerprint that
    /// happens to replay while the judge is CURRENTLY down can otherwise still read as
    /// decisively confirmed or promoted for actuation purposes too. Gating once, here, at the
    /// single actuation choke point leaves that display/cache correctness untouched; it only
    /// refuses to let a not-currently-verifiable judge arm a NEW cut.
    ///
    /// `Propose`/`Forbidden` pass through unchanged. An `AutoApply` for a mitigation that is
    /// ALREADY applied costs nothing extra either way — the `AutoApply` arm only acts on a
    /// mitigation that isn't active yet — and a REVERT runs on the wholly separate
    /// `ActionLog::reconcile` path below, which this gate never touches: a degraded judge
    /// still LIFTS a cut whose health or justification no longer holds. The fail-safe
    /// asymmetry stays toward lifting, never toward cutting.
    fn gate_on_judge_freshness(
        &self,
        mitigation: &Mitigation,
        decision: Decision,
        now: std::time::Instant,
    ) -> Decision {
        if decision != Decision::AutoApply {
            return decision;
        }
        let fresh = mitigation.live_corroborating_entries().any(|entry| {
            self.verdicts
                .verdict_fresh(entry, now, JUDGE_FRESHNESS_BOUND)
        });
        if fresh {
            return decision;
        }
        self.metrics.mitigations.add(
            1,
            &[opentelemetry::KeyValue::new("action", "held_degraded")],
        );
        tracing::info!(
            cut = %mitigation.cut_signature(),
            "auto-actuation held: judge is degraded (breaker open or no fresh decisive verdict)"
        );
        Decision::Propose(
            "judge is degraded (breaker open, or no fresh decisive verdict within the trust \
             window); held as a proposal until the model verifiably answers again"
                .to_string(),
        )
    }
}

// The ADR-0040 `ContainNode` revert seam (the builders attaching a live actuator/observed
// `NodeFact`s, and the self-revert loop's `revert_contain_node` call above), extracted to
// keep this orchestrator under the file-size cap (repo CLAUDE.md).
mod node_containment_revert;

// The engine's driver (`run_watch`) and its env-driven builders live in a sibling
// module, split out to keep this file under the 1,000-line cap (repo CLAUDE.md). The
// public surface (`run_watch`) is re-exported here so external paths
// (`protector::engine::run_watch`) resolve unchanged.
mod run_loop;
pub use run_loop::run_watch;

// The supply-chain trust sweeps (ADR-0020): the per-pass signature / Rekor / provenance /
// trust-root observation the engine runs over the already-running fleet, gathered into one module
// behind the `run_sweeps` facade `run_watch` drives. The submodules
// (`signing_sweep`, `signing_drift`, `signing_rekor`, `signing_trust`, `signing_baseline_strength`,
// `provenance_sweep`, `provenance_drift`) keep their public surface, so external paths resolve as
// `engine::supply_chain::<module>`.
pub mod supply_chain;

#[cfg(test)]
mod tests;

// the journal / notifier / persistence tests, split out of `tests.rs` to keep every
// file under the 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod journal_tests;

// The judge-freshness actuation gate's tests, split out of `tests.rs` to keep every file under
// the 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod judge_freshness_tests;

// The break-glass disarm tests (enforce→audit self-revert + the fast, GitOps-independent kill
// switch), split out of `tests.rs` to keep every file under the 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod break_glass_tests;

// The ADR-0040 `ContainNode` revert-wiring tests (break-glass + the standard ledger
// self-revert must actually uncordon a node, not just drop its co-resident
// NetworkPolicies), split out of `break_glass_tests.rs` to keep every file under the
// 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod break_glass_node_tests;

// The pre-arm scope-simulation preview's engine-level mutation-free proof (ADR-0021,
// ADR-0016), split out of `tests.rs` to keep every file under the 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod scope_preview_tests;
