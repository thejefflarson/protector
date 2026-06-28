//! The dashboard's domain DATA layer (ADR-0019): the shared types the engine writes and the
//! dashboard reads — the [`Finding`] row and its evidence, the per-entry [`VerdictStore`],
//! the [`Findings`] / [`JudgementLog`] / [`ReversionLog`] handles, the [`BakeStats`] /
//! [`ModelHealth`] / [`ReadinessConfig`] coverage shapes, and the small data helpers
//! ([`classify`], [`killchain`], [`relative_time`]).
//!
//! This is data, not markup: it holds NO rendering. The presentation reads it through the
//! `view_model` (which shapes it into `Props`) and the `components` (which render those
//! props); `mod.rs` owns the engine-facing handles. maud auto-escapes every value at render,
//! so these strings are carried verbatim here and escaped where they are spliced into HTML.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use serde::Serialize;

use crate::engine::dashboard::recency::{Delta, RecencyInfo, StoredPosture};
use crate::engine::graph::{Behavior, SecurityGraph, Vulnerability};
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::reason::backoff::{CircuitBreaker, EntryBackoff};
use crate::engine::reason::proof::ProvenChain;

/// One row: a proven chain, its ATT&CK label and evidence, and what the engine
/// does with it.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub entry: String,
    pub objective: String,
    pub tactic: String,
    /// The ATT&CK tactic name (e.g. "Credential Access") — for the attack-vector summary.
    pub tactic_name: String,
    pub technique: String,
    /// The ATT&CK technique name (e.g. "Unsecured Credentials").
    pub technique_name: String,
    pub foothold: bool,
    pub corroborated: bool,
    pub adjudicated: bool,
    /// The model promoted this chain to auto-eligible (ADR-0011), as opposed to live
    /// runtime corroboration.
    pub promoted: bool,
    /// The chain's **mechanical** disposition — what its minimal cut can do
    /// (auto-eligible / latent foothold / structural / durable-fix PR / forbidden /
    /// no-cut), independent of the model's exploitability call. This is metadata for
    /// the JSON view and drives only the dashboard's remediation-vs-attack-path
    /// routing; the human-facing "is this exploitable" judgement is [`verdict`], the
    /// model's own words (the LLM is the judge — ADR-0013).
    pub disposition: String,
    /// The single-edge cut that severs it, if one exists.
    pub cut: Option<String>,
    /// Whether the entry is internet-facing — the discriminator between a real breach
    /// path and an assume-breach access path. Only breach-relevant chains are shown;
    /// see [`ProvenChain::is_breach_relevant`].
    pub breach_relevant: bool,
    /// The ATT&CK kill chain this path realizes, in plain terms — the Initial Access
    /// foothold (if any) through the objective's technique.
    pub killchain: String,
    /// The model's adjudication, if it judged this chain — both positive ("exploitable
    /// — …") and negative ("not exploitable — …") calls, with the model's reasoning.
    /// `None` if no model was consulted.
    pub verdict: Option<String>,
    /// The proven attack path, hop by hop (entry → … → objective).
    pub path: Vec<PathStep>,
    /// The evidence the adjudicator weighed for this path's entry (JEF-133) — the CVEs
    /// on the entry's image and the runtime signals observed on it. Pulled from the same
    /// [`SecurityGraph::entry_evidence`] the model reads, so the dashboard answers "what
    /// is the evidence for this path?" with the model's own inputs. ADR-0016 frames the
    /// two as divergent: CVEs are a SEVERITY/reachability input, runtime alerts the LIVE
    /// corroboration signal — the view presents them as two distinct labeled blocks.
    pub evidence: EntryEvidence,
    /// The per-entry recency / Δ facts (JEF-201) — what changed for this entry since the last
    /// pass (NEW / escalated / de-escalated / unchanged-age / restored). Resolved from the
    /// shared verdict store at [`Findings::snapshot`] time, like [`verdict`](Self::verdict),
    /// so the Δ tracks the stored first-seen / posture history rather than the render clock.
    /// `None` on a row published before any recency update (the published rows carry no
    /// recency of their own). Pure presentation metadata: gates nothing (ADR-0016).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recency: Option<RecencyInfo>,
}

/// One hop of a proven chain: `from -[relation]-> to`, with the **full** node keys
/// (so the renderer can derive both a short label and the node kind/shape).
#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub from: String,
    pub relation: String,
    pub to: String,
}

/// A single CVE on the entry's image, the dashboard-/JSON-facing projection of a
/// [`graph::Vulnerability`] (JEF-133). The same fields `cve_evidence` surfaces to the
/// model: id, severity, reachability, fix availability, and CWE/advisory when the
/// mounted snapshot enriched it. ADR-0016: this is a SEVERITY/reachability input — "how
/// bad IF exploited" — never on its own the breach call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CveEvidence {
    pub id: String,
    /// `low` / `medium` / `high` / `critical` (from [`graph::Severity::label`]).
    pub severity: String,
    /// Whether the CVE is listed in a known-exploited catalogue (CISA KEV) — the
    /// stronger-than-severity exploitation signal.
    pub kev: bool,
    /// `unknown` / `loaded-at-runtime` / `not-observed` (from [`graph::Reachability`]).
    pub reachability: String,
    /// A human fix-availability phrase: `no fix available`, `fix available: <ver>`, or
    /// `fix available: <installed> to <fixed>` — the same shape the prompt uses.
    pub fix: String,
    /// The advisory title (trivy's `title`), if reported. Untrusted free-text — HTML-
    /// escaped at render time like every other model-adjacent string.
    pub title: Option<String>,
    /// CWE id(s) from a mounted advisory snapshot (ADR-0015), if matched. Empty otherwise.
    pub cwe: Vec<String>,
}

impl CveEvidence {
    /// Project a graph [`Vulnerability`] into the view shape. Keeps the fix-availability
    /// phrasing identical to the adjudicator's `cve_evidence` so the operator reads the
    /// same fact the model did.
    pub(crate) fn from_vuln(v: &Vulnerability) -> Self {
        let fix = match (v.fixed_version.as_deref(), v.installed_version.as_deref()) {
            (Some(fixed), Some(installed)) => format!("fix available: {installed} to {fixed}"),
            (Some(fixed), None) => format!("fix available: {fixed}"),
            (None, _) => "no fix available".to_string(),
        };
        CveEvidence {
            id: v.id.clone(),
            severity: v.severity.label().to_string(),
            kev: v.exploited_in_wild,
            reachability: v.reachability.label().to_string(),
            fix,
            title: v.title.clone(),
            cwe: v
                .advisory
                .as_ref()
                .map(|a| a.cwe.clone())
                .unwrap_or_default(),
        }
    }
}

/// The two evidence blocks ADR-0016 keeps distinct, attached to a finding's entry
/// (JEF-133):
///
/// - `cves` — the entry image's foothold-relevant CVEs (KEV or critical), the
///   SEVERITY/reachability input.
/// - `runtime` — the runtime [`Behavior`]s observed on the entry, the LIVE-corroboration
///   signal. The subset that actually *corroborates* (Falco-style `Alert`s) is what flips
///   `corroborated`; non-corroborating agent behaviors (exec/connect/secret-read/library-
///   load/privilege-change) ride along as context, exactly as the model sees them.
///
/// Both empty is the honest "no evidence" state (render shows "none" / "unknown", never
/// an implied-absent blank — JEF-161 coverage-gap idiom).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EntryEvidence {
    pub cves: Vec<CveEvidence>,
    pub runtime: Vec<Behavior>,
}

impl EntryEvidence {
    /// Pull the entry's evidence from the graph — the SAME selection the adjudicator
    /// reads ([`SecurityGraph::entry_evidence`]: KEV-or-critical CVEs + the entry's
    /// runtime behaviors), projected into the view shape.
    pub(crate) fn for_entry(graph: &SecurityGraph, entry: &crate::engine::graph::NodeKey) -> Self {
        let (vulns, runtime) = graph.entry_evidence(entry);
        EntryEvidence {
            cves: vulns.iter().map(CveEvidence::from_vuln).collect(),
            runtime,
        }
    }

    /// The runtime behaviors that actually corroborate the chain (Falco-style alerts) —
    /// what flips `ProvenChain::corroborated` (ADR-0009). Separated from context behaviors
    /// in the live-corroboration block.
    pub(crate) fn corroborating(&self) -> impl Iterator<Item = &Behavior> {
        self.runtime.iter().filter(|b| b.is_alert())
    }

    /// The non-corroborating agent behaviors — context for the chain, not a corroboration
    /// (exec/connect/secret-read/library-load/privilege-change). Shown for context.
    pub(crate) fn context_behaviors(&self) -> impl Iterator<Item = &Behavior> {
        self.runtime.iter().filter(|b| !b.is_alert())
    }
}

impl Finding {
    /// Build a finding from a proven chain and the graph it was proven over. The graph is
    /// needed for the per-entry evidence blocks (JEF-133): the chain alone carries the
    /// topology and verdict, but the CVEs and runtime signals live on the entry's graph
    /// node — the same place the adjudicator reads them.
    pub fn from_chain(chain: &ProvenChain, graph: &SecurityGraph) -> Self {
        let action = chain
            .single_edge_cuts
            .first()
            .map(crate::engine::respond::ProposedAction::for_cut);
        Finding {
            evidence: EntryEvidence::for_entry(graph, &chain.entry),
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            tactic: chain.attack.tactic.id().to_string(),
            tactic_name: chain.attack.tactic.name().to_string(),
            technique: chain.attack.technique_id.to_string(),
            technique_name: chain.attack.technique.to_string(),
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            adjudicated: chain.adjudicated,
            promoted: chain.promoted,
            disposition: classify(chain, action),
            cut: chain
                .single_edge_cuts
                .first()
                .map(crate::engine::respond::cut_signature),
            breach_relevant: chain.is_breach_relevant(),
            killchain: killchain(chain),
            // The verdict is NOT stamped per-chain any more (JEF-157): it is the
            // model's per-ENTRY call, held in the shared verdict store and resolved by
            // [`Findings::snapshot`] at read time. `chain.verdict` is carried along only
            // as a fallback for the timer path (no dashboard) / direct callers.
            verdict: chain.verdict.clone(),
            path: chain
                .links
                .iter()
                .map(|l| PathStep {
                    from: l.from.0.clone(),
                    relation: l.relation.clone(),
                    to: l.to.0.clone(),
                })
                .collect(),
            // Resolved per-entry from the verdict store at `Findings::snapshot` time
            // (JEF-201), like `verdict`; the published row carries none of its own.
            recency: None,
        }
    }
}

/// The attack steps in plain terms: the front-door foothold (T1190), when the entry is
/// an exploitable front door, through the target's own technique. Plain-language leading,
/// MITRE code in parentheses — this is the JSON-facing text form; the card renders the
/// same steps with the code tucked into an `<abbr>` tooltip (the maud
/// `view_model::findings` killchain props).
pub(crate) fn killchain(chain: &ProvenChain) -> String {
    let goal = format!("{} ({})", chain.attack.technique, chain.attack.technique_id);
    if chain.foothold.is_some() {
        format!("break in through an internet-facing service (T1190) → {goal}")
    } else {
        goal
    }
}

/// The one disposition that routes to the remediations section: a reversible network
/// cut that meets the action bar (so it auto-applies armed, or is proposed in shadow).
pub(crate) const AUTO_ELIGIBLE: &str = "auto-eligible";

/// The chain's mechanical disposition — what its minimal cut can do, by cut type. This
/// is *not* the exploitability judgement (that's the model's [`ProvenChain::verdict`],
/// shown to humans); it's the deterministic "can we cut this, and does it meet the
/// bar" annotation that routes the dashboard and rides along in the JSON. It mirrors
/// [`super::actuator::decide`] minus the runtime-only gates (enabled class, blast
/// radius): only a network cut (`DenyNetworkPath`) auto-applies; subtractive cuts are
/// durable GitOps fixes, an escape primitive is irreversible, no single edge is no-cut.
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

/// The behavioral-bake snapshot (JEF-48): what the behavioral port saw in the most
/// recent pass, surfaced on the dashboard so the shadow bake's exit criteria are
/// readable WITHOUT an OTLP collector. The same per-pass figures also feed the OTLP
/// counters (JEF-100) — this is the at-a-glance, in-process mirror. Purely observational:
/// it carries no per-pod payload, only counts and low-cardinality variant labels.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BakeStats {
    /// Signals ingested this pass by [`crate::engine::graph::Behavior::variant_label`]
    /// (connection / secret-read / library-load / exec / priv-change / file-read /
    /// alert), ordered by variant for a stable table.
    pub signals_by_variant: BTreeMap<String, u64>,
    /// Signals this pass the runtime adapter could attribute to a live workload
    /// (a namespace/name attribution, or a cgroup UID matching a pod in the snapshot).
    pub resolved: u64,
    /// Signals this pass whose attribution did NOT resolve (unknown cgroup UID — pod
    /// gone or not yet observed). A sustained nonzero share is the JEF-48 attribution
    /// exit-criterion to watch.
    pub unresolved: u64,
    /// The live (TTL'd) runtime-store cardinality as of this pass — the working set.
    pub runtime_store: u64,
    /// Corroborations that fired this pass: breach-relevant chains a live runtime signal
    /// completed (ADR-0009). In shadow this is the countable "would this have promoted?"
    pub corroborations: u64,
}

impl BakeStats {
    /// Total signals ingested this pass (the sum across variants), the volume figure
    /// for the JEF-48 "signal volume per node is sane" criterion.
    pub fn total_signals(&self) -> u64 {
        self.signals_by_variant.values().copied().sum()
    }

    /// The fraction of attributed signals that did NOT resolve to a live workload, in
    /// `[0, 1]`; `0.0` when nothing was attributed this pass (no signals → no misses).
    /// This is the engine-side resolution rate JEF-48 reads attribution quality from.
    pub fn unresolved_fraction(&self) -> f64 {
        let total = self.resolved + self.unresolved;
        if total == 0 {
            0.0
        } else {
            self.unresolved as f64 / total as f64
        }
    }
}

/// The LIVE health of the model adjudicator, derived cheaply by piggybacking the LAST
/// adjudication outcome (JEF-160) — NOT a fresh model call. The judging loop stamps this
/// on every fresh call (cache misses): a decisive verdict is [`Ok`](Self::Ok); an
/// inconclusive one ("model unavailable" — a CPU-model timeout / down endpoint) is
/// [`Timeout`](Self::Timeout). [`Unknown`](Self::Unknown) until the model has actually
/// been called this run (cold start, or no model configured — see [`ReadinessConfig`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelHealth {
    /// No fresh model call has landed yet this run (cold start), or no model is
    /// configured at all (the absence is reported via [`ReadinessConfig::model_attached`]).
    #[default]
    Unknown,
    /// The most recent fresh adjudication returned a decisive verdict — the model answered.
    Ok,
    /// The most recent fresh adjudication came back inconclusive ("model unavailable") —
    /// the CPU model timed out or the endpoint is down. The decision still falls through
    /// to the skeptic default, but the model is not currently answering.
    Timeout,
}

impl ModelHealth {
    /// The `u8` wire form for the atomic store on [`Findings`] (no extra deps for an enum
    /// atomic). Round-trips through [`from_u8`](Self::from_u8).
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            ModelHealth::Unknown => 0,
            ModelHealth::Ok => 1,
            ModelHealth::Timeout => 2,
        }
    }

    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => ModelHealth::Ok,
            2 => ModelHealth::Timeout,
            _ => ModelHealth::Unknown,
        }
    }
}

/// The engine's **config summary** for the readiness panel (JEF-160): presence/absence of
/// each decision input, NOT a config echo. This carries no secret names, no endpoints, no
/// values — only whether an input is wired and (for the file-backed stores) how many
/// entries loaded, which is a non-sensitive coverage figure. Captured once at dashboard
/// boot from the same env/handles the engine already reads, and threaded into
/// [`render_html`] so the panel reports LIVE presence rather than guessing.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadinessConfig {
    /// A model adjudicator is configured (`PROTECTOR_ENGINE_MODEL` set). When false, NO
    /// exploitability calls are made — every breach-relevant chain falls through to the
    /// deterministic skeptic default, the single most load-bearing coverage gap (ADR-0016).
    pub model_attached: bool,
    /// How many KEV/advisory CVE ids loaded from the mounted catalogue. `0` ⇒ the store is
    /// absent or empty, so no known-exploited enrichment reaches the model.
    pub kev_count: usize,
    /// How many advisory records loaded from the mounted snapshot. `0` ⇒ no CVE summary /
    /// fix-version enrichment is available.
    pub advisory_count: usize,
    /// The decision journal is durable (a writable `PROTECTOR_ENGINE_JOURNAL_PATH` volume
    /// is mounted). `false` ⇒ in-memory only: verdicts and the would-have-acted report
    /// don't survive a restart.
    pub journal_durable: bool,
    /// Any action class is armed (`engine.enable` non-empty) — enforcing vs shadow. This
    /// is posture, not a gap: shadow is the safe default, reported so the operator can SEE
    /// it rather than infer it.
    pub armed: bool,
}

/// One internet-facing entry's verdict state — the SINGLE source of truth for the
/// model's call on that entry (JEF-157). Collapses what used to be four separate
/// per-entry maps in the engine (`last_verdict` / `verdict_cache` / `restored_verdicts`
/// / `journaled_verdicts`) into one record, so `/findings` and `/judgements` can never
/// disagree on an entry's verdict and the dashboard reflects a verdict the instant it
/// lands — not only at end-of-pass.
#[derive(Debug, Clone, Default)]
pub struct VerdictEntry {
    /// The current DISPLAY verdict, typed — the carry-forward + Uncertain-fallback
    /// memory (formerly `last_verdict`). `None` until a live verdict has been displayed
    /// this run; a journal-restored entry carries [`restored`](Self::restored) instead.
    pub display: Option<Verdict>,
    /// A verdict restored from the durable journal on boot (JEF-141), its summary string
    /// — shown until a live verdict supersedes it (formerly `restored_verdicts`). Cleared
    /// once `display` lands a live verdict for the entry.
    pub restored: Option<String>,
    /// The cached DECISIVE verdict and the evidence fingerprint it was judged against —
    /// the re-judge gate (formerly `verdict_cache`). Present only for a decisive verdict;
    /// an unchanged fingerprint serves this without calling the (slow CPU) model again.
    pub cached: Option<(String, Verdict)>,
    /// The last verdict summary journaled + notified for this entry — the dedup key
    /// (formerly `journaled_verdicts`), so a steady-state cluster writes/notifies once
    /// per change, not per pass.
    pub journaled: Option<String>,
    /// Exponential-backoff state for INCONCLUSIVE adjudication (JEF-234). An `Uncertain`
    /// verdict (a model timeout / Ollama-down / OOM) is never cached, so without this gate
    /// the entry is re-judged every pass and hammers a struggling model. Each `Uncertain`
    /// grows the retry delay; a decisive verdict resets it. The verdict cache above still
    /// serves decisive verdicts — this only gates the re-judge of failed ones.
    pub backoff: EntryBackoff,
    /// When this entry's key FIRST appeared (JEF-201) — set the first pass the key is seen,
    /// never overwritten after. The Δ column's age is measured from here, NOT from render
    /// time, so it survives the `/fragment` poll. A journal-restored entry seeds this with a
    /// synthetic PAST instant (so it never reads as "this pass") via [`restored_recency`].
    ///
    /// [`restored_recency`]: Self::restored_recency
    pub first_seen: Option<Instant>,
    /// The DISPLAY posture this entry carried on the PREVIOUS pass (JEF-201), updated each
    /// pass by diffing the new posture against it. `None` until the first recency update; the
    /// diff against it yields the Δ glyph (escalated / de-escalated / unchanged).
    pub prev_posture: Option<StoredPosture>,
    /// The Δ verdict computed on the LAST recency update (JEF-201) — what changed at the most
    /// recent pass. Held here (not recomputed at render) so a `/fragment` re-render with no
    /// new pass shows the same Δ rather than flickering to NEW each poll. `None` until the
    /// first recency update has run for the entry.
    pub last_delta: Option<Delta>,
    /// Whether this entry was RESTORED from the durable journal on boot (JEF-201, JEF-141) —
    /// it existed before this run, so its first live recency update must read [`Delta::New`]'s
    /// quieter sibling [`Delta::Restored`], never NEW. Cleared once a live pass re-judges it.
    pub restored_recency: bool,
}

impl VerdictEntry {
    /// The summary string to DISPLAY for this entry: the live display verdict if one
    /// has landed this run, else the journal-restored summary, else nothing. This is
    /// exactly the carry-forward precedence the engine used to apply at publish time —
    /// a live verdict supersedes a restored one — now in one place.
    pub(crate) fn display_summary(&self) -> Option<String> {
        self.display
            .as_ref()
            .map(Verdict::summary)
            .or_else(|| self.restored.clone())
    }

    /// The entry's resolved recency facts at `now` (JEF-201): the stored Δ verdict and the
    /// age since `first_seen`. The Δ is the one computed at the LAST recency update (held in
    /// `last_delta`), so this is stable across `/fragment` polls — `now` only freshens the
    /// human age, never the glyph. A restored entry reports no meaningful age (its first_seen
    /// is synthetic). `None` Δ (no recency update yet) reads as `Unchanged` with no age.
    pub(crate) fn recency_info(&self, now: Instant) -> RecencyInfo {
        let delta = self.last_delta.unwrap_or(Delta::Unchanged);
        // A restored entry's first_seen is synthetic — its age is not a real "seen N ago".
        let age_secs = if self.restored_recency {
            None
        } else {
            self.first_seen
                .map(|fs| now.saturating_duration_since(fs).as_secs())
        };
        RecencyInfo { delta, age_secs }
    }
}

/// The single per-entry verdict store (JEF-157): the one source of truth for the
/// model's verdict per internet-facing entry, shared (`Arc`) between the engine (the
/// writer) and the dashboard (the reader). Both `/findings` (via [`Findings::snapshot`])
/// and the per-pass display derive each finding's verdict by looking its entry up here
/// at render time, so a verdict is visible the moment it is written — there is no
/// end-of-pass re-publish lag (the bug JEF-157 fixes: `/judgements` showing a verdict
/// `/findings` didn't yet have). Keyed by the entry's node key.
#[derive(Default)]
pub struct VerdictStore {
    entries: Mutex<BTreeMap<String, VerdictEntry>>,
    /// The GLOBAL inconclusive-adjudication circuit-breaker (JEF-234): when the model
    /// looks fully down (a run of consecutive `Uncertain` calls across all entries), the
    /// whole judging pass skips its model calls for a cooldown, so a fully-down Ollama's
    /// total calls-per-window is bounded regardless of entry count. A decisive success
    /// closes it. Separate lock from `entries` — it is touched once per call, not per entry.
    breaker: Mutex<CircuitBreaker>,
}

/// A stable per-entry seed for the backoff jitter (JEF-234), derived from the entry key
/// so two entries that fail on the same pass spread their retries apart rather than
/// thundering back together. A plain `DefaultHasher` of the key — deterministic per key,
/// no external dependency.
fn jitter_seed(entry: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    entry.hash(&mut h);
    h.finish()
}

impl VerdictStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The display summary for an entry, if any — what `/findings` shows for a chain
    /// from that entry (a live verdict, or a journal-restored one). `None` when the
    /// entry has no verdict yet (the model hasn't reached it).
    pub fn display_summary(&self, entry: &str) -> Option<String> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(VerdictEntry::display_summary)
    }

    /// Apply a mutation to an entry's record (inserting a default first), under one lock.
    /// The engine's writes go through this so each is atomic and visible immediately.
    pub(crate) fn update(&self, entry: &str, f: impl FnOnce(&mut VerdictEntry)) {
        let mut entries = self.entries.lock().expect("verdict store mutex poisoned");
        f(entries.entry(entry.to_string()).or_default());
    }

    /// Seed a journal-restored verdict summary for an entry (JEF-141) — shown until a
    /// live verdict supersedes it. Does not touch the cache or the journaled-dedup key.
    ///
    /// JEF-201: a restored entry existed BEFORE this run, so it must never read as NEW in the
    /// Δ column. This marks it `restored_recency` and seeds its `first_seen` with a synthetic
    /// PAST instant (`restored_at`, the journal's last-pass time) so the recency tracker treats
    /// it as pre-existing. The first live pass that re-judges it clears the restored flag.
    pub fn seed_restored(&self, entry: &str, summary: String, restored_at: Instant) {
        self.update(entry, |e| {
            e.restored = Some(summary);
            e.restored_recency = true;
            e.first_seen.get_or_insert(restored_at);
            // A restored entry already has a posture to diff future passes against; until a
            // live pass lands, its Δ reads `Restored` (not `New`).
            e.last_delta.get_or_insert(Delta::Restored);
            e.prev_posture.get_or_insert(StoredPosture::Awaiting);
        });
    }

    /// Record this pass's display POSTURE for an entry and compute its Δ (JEF-201): set
    /// `first_seen` on first sight, diff the new posture against the stored `prev_posture`,
    /// store the resulting [`Delta`], and roll `prev_posture` forward. `now` is injected (the
    /// pass's single `Instant`) so the recency tracking is deterministic in tests and shares
    /// the same clock as the JEF-234 backoff. Pure presentation metadata — never gates a
    /// decision (ADR-0016). A previously-restored entry's first live posture clears the
    /// restored flag and reads as `Restored` for one pass (it existed before this run), then
    /// diffs normally.
    pub fn record_recency(&self, entry: &str, posture: StoredPosture, now: Instant) {
        self.update(entry, |e| {
            let first = e.first_seen.is_none() && !e.restored_recency;
            e.first_seen.get_or_insert(now);
            let delta = if first {
                // Brand-new key this run — NEW regardless of which posture it lands on.
                Delta::New
            } else if e.restored_recency {
                // It was restored from history; its first live pass reads `Restored`, not NEW.
                e.restored_recency = false;
                Delta::Restored
            } else {
                match e.prev_posture {
                    Some(prev) => StoredPosture::delta_from(prev, posture),
                    // No previous posture but already seen (e.g. restored seeded Awaiting and
                    // then cleared): treat as unchanged rather than fabricating an arrow.
                    None => Delta::Unchanged,
                }
            };
            e.last_delta = Some(delta);
            e.prev_posture = Some(posture);
        });
    }

    /// The entry's resolved recency facts at `now` (JEF-201) — the Δ verdict + age the Δ
    /// column renders. `None` when the entry has no record yet (never seen). `now` is injected
    /// for deterministic tests.
    pub fn recency_for(&self, entry: &str, now: Instant) -> Option<RecencyInfo> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .map(|e| e.recency_info(now))
    }

    /// The cached decisive verdict for an entry whose fingerprint matches — the re-judge
    /// gate. `Some(verdict)` serves the cache (no model call); `None` means re-judge.
    pub fn cached_for(&self, entry: &str, fingerprint: &str) -> Option<Verdict> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| match &e.cached {
                Some((fp, v)) if fp == fingerprint => Some(v.clone()),
                _ => None,
            })
    }

    /// Cache a fresh DECISIVE verdict + its fingerprint for the re-judge gate.
    pub fn cache_decisive(&self, entry: &str, fingerprint: String, verdict: Verdict) {
        self.update(entry, |e| e.cached = Some((fingerprint, verdict)));
    }

    /// JEF-234 — whether the judging loop should SKIP the model call for `entry` this pass
    /// because it is in inconclusive-adjudication backoff at `now`. On a cache MISS the loop
    /// checks this BEFORE calling `judge()`: if backing off it keeps the prior display
    /// verdict and does not touch the (struggling) model. `now` is injected for testability.
    pub fn entry_backing_off(&self, entry: &str, now: Instant) -> bool {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .is_some_and(|e| e.backoff.is_backing_off(now))
    }

    /// JEF-234 — record an INCONCLUSIVE (`Uncertain`) adjudication for `entry` at `now`:
    /// grow the entry's exponential backoff AND advance the global breaker's failure run.
    /// The jitter seed is derived from the entry key so distinct entries de-sync their
    /// retries. Does NOT cache the verdict (Uncertain is never decisive) — the backoff is
    /// the gate.
    pub fn record_inconclusive(&self, entry: &str, now: Instant) {
        let seed = jitter_seed(entry);
        self.update(entry, |e| e.backoff.record_failure(now, seed));
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .record_failure(now);
    }

    /// JEF-234 — record a DECISIVE adjudication for `entry`: clear the entry's backoff and
    /// close the global breaker (the model answered). Pairs with [`cache_decisive`], which
    /// the loop still calls to cache the verdict itself.
    ///
    /// [`cache_decisive`]: Self::cache_decisive
    pub fn record_decisive(&self, entry: &str) {
        self.update(entry, |e| e.backoff.record_success());
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .record_success();
    }

    /// JEF-234 — whether the GLOBAL breaker is open at `now`: the whole judging pass should
    /// skip its model calls (the model looks fully down). `now` is injected for testability.
    pub fn breaker_open(&self, now: Instant) -> bool {
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .is_open(now)
    }

    /// The entry's current typed DISPLAY verdict (the carry-forward + Uncertain-fallback
    /// memory), if a live one has landed this run.
    pub fn display_verdict(&self, entry: &str) -> Option<Verdict> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| e.display.clone())
    }

    /// Record the entry's DISPLAY verdict the instant it is decided — making it visible
    /// on `/findings` immediately (the JEF-157 no-lag fix). A live verdict supersedes any
    /// journal-restored one for the entry.
    pub fn set_display(&self, entry: &str, verdict: Verdict) {
        self.update(entry, |e| {
            e.display = Some(verdict);
            e.restored = None;
        });
    }

    /// The last verdict summary journaled/notified for an entry — the dedup key.
    pub fn journaled(&self, entry: &str) -> Option<String> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| e.journaled.clone())
    }

    /// Record the verdict summary just journaled/notified for an entry (the dedup key).
    pub fn set_journaled(&self, entry: &str, summary: String) {
        self.update(entry, |e| e.journaled = Some(summary));
    }

    /// Drop entries that are no longer present in the live cluster (ephemeral workloads,
    /// removed exposure), so the store tracks the live cluster rather than growing
    /// forever — the prune the engine ran across all four maps each pass.
    pub fn retain_present(&self, present: &std::collections::HashSet<String>) {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .retain(|entry, _| present.contains(entry));
    }
}

/// The current findings snapshot, shared between the engine (writer) and the HTTP
/// server (reader).
#[derive(Default)]
pub struct Findings {
    rows: Mutex<Vec<Finding>>,
    /// The single per-entry verdict store (JEF-157): each finding's verdict is derived
    /// from this at [`snapshot`](Self::snapshot) time, so `/findings` reflects a verdict
    /// the instant the engine writes it — never only at end-of-pass.
    verdicts: Arc<VerdictStore>,
    /// Whether any action class is armed (`engine.enable` non-empty). Drives the
    /// remediations section title: "Active" when armed, "Proposed" in shadow.
    armed: std::sync::atomic::AtomicBool,
    /// The most recent behavioral-bake snapshot (JEF-48), replaced each pass alongside
    /// the findings rows.
    bake: Mutex<BakeStats>,
    /// When the engine last completed a pass (JEF-141), surfaced as "last pass NNs ago"
    /// so a quiet/loading dashboard reads as *fresh*, not broken. `None` until the first
    /// pass completes (or is seeded from the journal on boot).
    last_pass: Mutex<Option<SystemTime>>,
    /// The engine's config summary for the readiness panel (JEF-160) — presence/absence of
    /// each decision input, captured once at dashboard boot. Defaults to all-absent until
    /// set, so the panel reads as "unconfigured" rather than falsely "ready".
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

    /// Record whether an action class is armed (set once from `EnabledActions`).
    pub fn set_armed(&self, armed: bool) {
        self.armed
            .store(armed, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The single per-entry verdict store (JEF-157), shared with the engine. The engine
    /// writes verdicts here the instant they land; [`snapshot`](Self::snapshot) reads
    /// them, so the dashboard never lags behind a judgement.
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
    /// across `/fragment` polls regardless of the render-time `now`.
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
                f.verdict = self.verdicts.display_summary(&f.entry);
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

    /// The most recent behavioral-bake snapshot, for the dashboard / `/findings` view.
    pub fn bake(&self) -> BakeStats {
        self.bake.lock().expect("bake mutex poisoned").clone()
    }

    /// Mark a pass as just completed (JEF-141) — drives the "last pass NNs ago"
    /// freshness line. Also used to seed freshness from the journal on boot.
    pub fn mark_pass(&self, at: SystemTime) {
        *self.last_pass.lock().expect("last_pass mutex poisoned") = Some(at);
    }

    /// When the last pass completed, if any. `None` until the first pass (or journal
    /// seed). The dashboard renders this as a relative "NNs ago".
    pub fn last_pass(&self) -> Option<SystemTime> {
        *self.last_pass.lock().expect("last_pass mutex poisoned")
    }

    /// Record the engine's config summary for the readiness panel (JEF-160) — set once at
    /// dashboard boot from the env/handles the engine already reads. Presence/absence only;
    /// no secret names, no values.
    pub fn set_readiness_config(&self, config: ReadinessConfig) {
        *self.readiness.lock().expect("readiness mutex poisoned") = config;
    }

    /// The engine's config summary for the readiness panel. Defaults to all-absent until
    /// [`set_readiness_config`](Self::set_readiness_config) is called.
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
    pub fn model_health(&self) -> ModelHealth {
        ModelHealth::from_u8(self.model_health.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Render a `SystemTime` as a short relative "NN<unit> ago" (JEF-141), so the dashboard's
/// freshness line reads as a human duration. `None` (no pass yet) renders as a muted
/// "waiting for first pass". A future timestamp (clock skew) clamps to "just now".
pub(crate) fn relative_time(at: Option<SystemTime>) -> String {
    let Some(at) = at else {
        return "waiting for first pass".to_string();
    };
    let secs = SystemTime::now()
        .duration_since(at)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if secs < 1 {
        "just now".to_string()
    } else if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// A single model judgement captured for diagnosis: the full prompt the model saw,
/// its raw reply, and the final verdict after the deterministic guards. Diagnostic
/// only — exposed read-only at `/judgements` so the prompt behind an `exploitable`
/// verdict can be inspected directly instead of reconstructed from multi-line logs.
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
/// adjudicator (writer) and the HTTP server (reader). Diagnostic only: a handful of
/// entries are judged per pass and only on cache misses, so the cap comfortably holds
/// several restarts' worth of judgements without growing unbounded.
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

    /// Snapshot newest-first for display.
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

/// One lifted cut for the recent-reversions view (JEF-141): the self-revert is the core
/// safety story (ADR-0016 — a cut persists only while the breach condition holds, then
/// self-reverts), but it was previously invisible — nothing showed a cut was lifted and
/// why. This makes it durable and visible.
#[derive(Clone, Serialize)]
pub struct ReversionRecord {
    /// The cut signature that was lifted (`from -[relation]-> to`).
    pub cut: String,
    /// Why it was lifted — health divergence, or the breach condition cleared.
    pub reason: String,
    /// When it was lifted, Unix epoch milliseconds (so the JSON view is self-contained
    /// and the HTML can render "NNs ago").
    pub at_ms: u64,
}

/// A bounded, newest-last ring of recent [`ReversionRecord`]s, analogous to
/// [`JudgementLog`] — shared between the engine (writer) and the HTTP server (reader),
/// and seeded from the journal on boot so lifted cuts survive a restart. Diagnostic /
/// audit only.
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

    /// Snapshot newest-first for display.
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
