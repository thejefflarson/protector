//! The proven-chain output rows: the [`Finding`] (one ENTRY-rooted attack path, its evidence,
//! and the model's typed verdict) and its [`PathStep`] hops, the deterministic [`classify`]
//! disposition, and the [`Findings`] handle the engine writes each pass and the metrics mirror
//! reads.
//!
//! Pure data: no rendering. Each finding's verdict + recency are resolved from the shared
//! [`VerdictStore`] at snapshot time, so a verdict the engine just wrote is visible immediately.

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use crate::engine::graph::SecurityGraph;
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::reason::proof::ProvenChain;

use super::evidence::EntryEvidence;
use super::recency::RecencyInfo;
use super::verdict_store::{BakeStats, ModelHealth, ReadinessConfig, VerdictStore};

/// One ENTRY-rooted proven attack path, its evidence, and the model's typed verdict — the
/// unit the engine publishes per pass (JEF-255). It carries the proven facts (topology, cut),
/// the model's inputs (evidence), and its TYPED [`Verdict`] — the single source of truth for
/// posture, so no verdict prose is ever re-parsed downstream (the JEF-255 typed-verdict SSOT).
#[derive(Debug, Clone)]
pub struct Finding {
    pub entry: String,
    pub objective: String,
    /// Whether the entry is an internet-facing FRONT DOOR — drives the breach-relevance
    /// discriminator.
    pub foothold: bool,
    /// A live runtime signal backed this chain up (ADR-0009) — the corroboration flag.
    pub corroborated: bool,
    /// The chain's **mechanical** disposition — what its minimal cut can do
    /// (auto-eligible / latent foothold / structural / durable-fix PR / forbidden /
    /// no-cut), independent of the model's exploitability call. The human-facing "is this
    /// exploitable" judgement is [`verdict`](Self::verdict), the model's own typed call
    /// (the LLM is the judge — ADR-0013).
    pub disposition: String,
    /// The single-edge cut that severs it, if one exists.
    pub cut: Option<String>,
    /// Whether the entry is internet-facing — the discriminator between a real breach
    /// path and an assume-breach access path. Only breach-relevant chains are surfaced;
    /// see [`ProvenChain::is_breach_relevant`].
    pub breach_relevant: bool,
    /// The model's TYPED adjudication, if it judged this entry (JEF-255) — the single source
    /// of truth for posture and the verbatim "why". `None` if no model was consulted. Resolved
    /// from the shared [`VerdictStore`] at [`Findings::snapshot`] time, so posture is never
    /// re-parsed from verdict prose.
    pub verdict: Option<Verdict>,
    /// The proven attack path, hop by hop (entry → … → objective).
    pub path: Vec<PathStep>,
    /// The evidence the adjudicator weighed for this path's entry (JEF-133) — the CVEs
    /// on the entry's image and the runtime signals observed on it. Pulled from the same
    /// [`SecurityGraph::entry_evidence`] the model reads, so the evidence is the model's own
    /// inputs. ADR-0016 frames the two as divergent: CVEs are a SEVERITY/reachability input,
    /// runtime alerts the LIVE corroboration signal.
    pub evidence: EntryEvidence,
    /// The per-entry recency / Δ facts (JEF-201) — what changed for this entry since the last
    /// pass (NEW / escalated / de-escalated / unchanged-age / restored). Resolved from the
    /// shared verdict store at [`Findings::snapshot`] time, like [`verdict`](Self::verdict),
    /// so the Δ tracks the stored first-seen / posture history rather than the render clock.
    /// `None` on a row published before any recency update. Pure presentation metadata
    /// (ADR-0016).
    pub recency: Option<RecencyInfo>,
}

/// One hop of a proven chain: `from -[relation]-> to`, with the **full** node keys
/// (so a consumer can derive both a short label and the node kind/shape).
#[derive(Debug, Clone)]
pub struct PathStep {
    pub from: String,
    pub relation: String,
    pub to: String,
}

impl Finding {
    /// Build a finding from a proven chain and the graph it was proven over. The graph is
    /// needed for the per-entry evidence blocks (JEF-133): the chain alone carries the
    /// topology, but the CVEs and runtime signals live on the entry's graph node — the same
    /// place the adjudicator reads them.
    pub fn from_chain(chain: &ProvenChain, graph: &SecurityGraph) -> Self {
        let action = chain
            .single_edge_cuts
            .first()
            .map(crate::engine::respond::ProposedAction::for_cut);
        Finding {
            evidence: EntryEvidence::for_entry(graph, &chain.entry),
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            disposition: classify(chain, action),
            cut: chain
                .single_edge_cuts
                .first()
                .map(crate::engine::respond::cut_signature),
            breach_relevant: chain.is_breach_relevant(),
            // The verdict is the model's per-ENTRY call (JEF-157), held in the shared verdict
            // store and resolved by [`Findings::snapshot`] at read time. The published row
            // carries none of its own.
            verdict: None,
            path: chain
                .links
                .iter()
                .map(|l| PathStep {
                    from: l.from.0.clone(),
                    relation: l.relation.clone(),
                    to: l.to.0.clone(),
                })
                .collect(),
            recency: None,
        }
    }
}

/// The one disposition that routes to the remediations set: a reversible network
/// cut that meets the action bar (so it auto-applies armed, or is proposed in shadow).
pub(crate) const AUTO_ELIGIBLE: &str = "auto-eligible";

/// The chain's mechanical disposition — what its minimal cut can do, by cut type. This
/// is *not* the exploitability judgement (that's the model's [`ProvenChain::verdict`],
/// shown to humans); it's the deterministic "can we cut this, and does it meet the
/// bar" annotation. It mirrors [`super::super::respond::actuator::decide`] minus the
/// runtime-only gates (enabled class, blast radius): only a network cut (`DenyNetworkPath`)
/// auto-applies; subtractive cuts are durable GitOps fixes, an escape primitive is
/// irreversible, no single edge is no-cut.
pub(crate) fn classify(
    chain: &ProvenChain,
    action: Option<crate::engine::respond::ProposedAction>,
) -> String {
    use crate::engine::respond::ProposedAction as A;
    match action {
        None => "no-cut",
        Some(A::RemoveEscapePrimitive) => "forbidden",
        Some(A::RevokeRbacGrant | A::RemoveSecretMount | A::RebindIdentity) => "durable-fix PR",
        Some(A::Unclassified) => "unclassified",
        Some(A::DenyNetworkPath) => {
            if !chain.meets_action_bar() {
                if chain.is_latent_foothold() {
                    "latent foothold — propose"
                } else {
                    "structural — propose"
                }
            } else if !chain.adjudicated {
                "vetoed — propose"
            } else {
                AUTO_ELIGIBLE
            }
        }
    }
    .to_string()
}

/// The current findings snapshot, shared between the engine (writer) and the metrics
/// mirror (reader).
#[derive(Default)]
pub struct Findings {
    rows: Mutex<Vec<Finding>>,
    /// The single per-entry verdict store (JEF-157): each finding's verdict is derived
    /// from this at [`snapshot`](Self::snapshot) time, so the snapshot reflects a verdict
    /// the instant the engine writes it — never only at end-of-pass.
    verdicts: Arc<VerdictStore>,
    /// The most recent behavioral-bake snapshot (JEF-48), replaced each pass alongside
    /// the findings rows.
    bake: Mutex<BakeStats>,
    /// When the engine last completed a pass (JEF-141), surfaced as "last pass NNs ago"
    /// so a quiet/loading consumer reads as *fresh*, not broken. `None` until the first
    /// pass completes (or is seeded from the journal on boot).
    last_pass: Mutex<Option<SystemTime>>,
    /// The engine's config summary for the readiness aggregation (JEF-160) — presence/absence
    /// of each decision input, captured once at boot. Defaults to all-absent until set, so the
    /// snapshot reads as "unconfigured" rather than falsely "ready".
    readiness: Mutex<ReadinessConfig>,
    /// The LIVE model health (JEF-160), stamped by the judging loop from the LAST
    /// adjudication outcome — `0`/`1`/`2` per [`ModelHealth::as_u8`]. Cheap: no extra model
    /// call, just the result of the call the engine already makes.
    model_health: std::sync::atomic::AtomicU8,
}

impl Findings {
    pub fn new() -> Self {
        Self::default()
    }

    /// The single per-entry verdict store (JEF-157), shared with the engine. The engine
    /// writes verdicts here the instant they land; [`snapshot`](Self::snapshot) reads
    /// them, so a reader never lags behind a judgement.
    pub fn verdicts(&self) -> Arc<VerdictStore> {
        self.verdicts.clone()
    }

    /// Replace the snapshot with this pass's findings.
    pub fn replace(&self, findings: Vec<Finding>) {
        *self.rows.lock().expect("findings mutex poisoned") = findings;
    }

    /// The current findings, each with its verdict resolved from the shared verdict
    /// store (JEF-157) at read time. The published rows carry no verdict of their own;
    /// the verdict is looked up per entry here, so a verdict the engine just wrote is
    /// visible immediately — there is no end-of-pass re-publish needed to surface it.
    pub fn snapshot(&self) -> Vec<Finding> {
        self.snapshot_at(Instant::now())
    }

    /// The findings snapshot resolved against an injected `now` (JEF-201) — the seam the
    /// recency tests drive deterministically (no real sleeps). The live [`snapshot`] passes
    /// `Instant::now()`. Only the human AGE in the recency cell uses `now`; the Δ GLYPH was
    /// already computed (and stored) at pass time with the pass's clock, so it is stable
    /// across repeated reads regardless of the render-time `now`.
    ///
    /// [`snapshot`]: Self::snapshot
    pub(crate) fn snapshot_at(&self, now: Instant) -> Vec<Finding> {
        let mut rows = self.rows.lock().expect("findings mutex poisoned").clone();
        for f in &mut rows {
            // A breach-relevant finding's verdict is the model's per-entry call, the one
            // source of truth. Non-breach-relevant rows are never judged, so they keep
            // their (absent) verdict. Resolving here means publishing the rows once is
            // enough — the verdict tracks the store, not the last `replace`.
            if f.breach_relevant {
                // The TYPED verdict (JEF-255) is the single source of truth for posture — a
                // consumer derives posture from it once, never re-parsing the summary prose.
                f.verdict = self.verdicts.display_verdict(&f.entry);
                // The Δ / recency facts track the same per-entry store (JEF-201): the glyph is
                // the one computed at pass time, only the age is freshened at `now`.
                f.recency = self.verdicts.recency_for(&f.entry, now);
            }
        }
        rows
    }

    /// Replace the behavioral-bake snapshot (JEF-48) with this pass's figures.
    pub fn set_bake(&self, bake: BakeStats) {
        *self.bake.lock().expect("bake mutex poisoned") = bake;
    }

    /// The most recent behavioral-bake snapshot.
    pub fn bake(&self) -> BakeStats {
        self.bake.lock().expect("bake mutex poisoned").clone()
    }

    /// Mark a pass as just completed (JEF-141) — drives the "last pass NNs ago"
    /// freshness line. Also used to seed freshness from the journal on boot.
    pub fn mark_pass(&self, at: SystemTime) {
        *self.last_pass.lock().expect("last_pass mutex poisoned") = Some(at);
    }

    /// When the last pass completed, if any. `None` until the first pass (or journal
    /// seed).
    pub fn last_pass(&self) -> Option<SystemTime> {
        *self.last_pass.lock().expect("last_pass mutex poisoned")
    }

    /// Record the engine's config summary for the readiness aggregation (JEF-160) — set once
    /// at boot from the env/handles the engine already reads. Presence/absence only; no secret
    /// names, no values.
    pub fn set_readiness_config(&self, config: ReadinessConfig) {
        *self.readiness.lock().expect("readiness mutex poisoned") = config;
    }

    /// The engine's config summary for the readiness aggregation. Defaults to all-absent until
    /// [`set_readiness_config`](Self::set_readiness_config) is called.
    #[allow(dead_code)]
    pub fn readiness_config(&self) -> ReadinessConfig {
        *self.readiness.lock().expect("readiness mutex poisoned")
    }

    /// Stamp the LIVE model health from the LAST adjudication outcome (JEF-160). Called by
    /// the judging loop on every fresh model call (cache miss) — cheap, no extra call.
    pub fn set_model_health(&self, health: ModelHealth) {
        self.model_health
            .store(health.as_u8(), std::sync::atomic::Ordering::Relaxed);
    }

    /// The LIVE model health — the last adjudication outcome, or [`ModelHealth::Unknown`]
    /// until the model has been called this run (cold start / no model configured).
    #[allow(dead_code)]
    pub fn model_health(&self) -> ModelHealth {
        ModelHealth::from_u8(self.model_health.load(std::sync::atomic::Ordering::Relaxed))
    }
}
