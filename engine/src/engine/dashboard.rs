//! The findings dashboard: a read-only view of the engine's current proven chains
//! and their disposition — built mainly to surface the **latent-foothold** case
//! (ADR-0009), the exposable front doors that are propose-only and want a human.
//!
//! The engine replaces the [`Findings`] snapshot each pass; a small HTTP server
//! renders it as a flat table (`/`) and as JSON (`/findings`). The classification
//! ([`Finding::from_chain`]) is pure and tested; the server is glue.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::graph::{Behavior, SecurityGraph, Vulnerability};
use super::journal::{Decision, DecisionJournal, EnrichmentCoverage, JournalEntry};
use super::reason::adjudicate::Verdict;
use super::reason::proof::ProvenChain;

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
    fn from_vuln(v: &Vulnerability) -> Self {
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
    fn for_entry(graph: &SecurityGraph, entry: &super::graph::NodeKey) -> Self {
        let (vulns, runtime) = graph.entry_evidence(entry);
        EntryEvidence {
            cves: vulns.iter().map(CveEvidence::from_vuln).collect(),
            runtime,
        }
    }

    /// The runtime behaviors that actually corroborate the chain (Falco-style alerts) —
    /// what flips `ProvenChain::corroborated` (ADR-0009). Separated from context behaviors
    /// in the live-corroboration block.
    fn corroborating(&self) -> impl Iterator<Item = &Behavior> {
        self.runtime.iter().filter(|b| b.is_alert())
    }

    /// The non-corroborating agent behaviors — context for the chain, not a corroboration
    /// (exec/connect/secret-read/library-load/privilege-change). Shown for context.
    fn context_behaviors(&self) -> impl Iterator<Item = &Behavior> {
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
            .map(super::respond::ProposedAction::for_cut);
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
                .map(super::respond::cut_signature),
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
        }
    }
}

/// The attack steps in plain terms: the front-door foothold (T1190), when the entry is
/// an exploitable front door, through the target's own technique. Plain-language leading,
/// MITRE code in parentheses — this is the JSON-facing text form; the card renders the
/// same steps with the code tucked into an `<abbr>` tooltip (see [`killchain_html`]).
fn killchain(chain: &ProvenChain) -> String {
    let goal = format!("{} ({})", chain.attack.technique, chain.attack.technique_id);
    if chain.foothold.is_some() {
        format!("break in through an internet-facing service (T1190) → {goal}")
    } else {
        goal
    }
}

/// The attack steps for the finding card: leads with the plain technique name and tucks
/// the MITRE code into an `<abbr>` tooltip so it is available without crowding the line
/// (JEF-176 AC #3). Mirrors [`killchain`]'s steps. All values come from a closed ATT&CK
/// catalogue (technique ids/names), so they are not untrusted free-text; escaped anyway
/// for defence in depth.
fn killchain_html(f: &Finding) -> String {
    let goal = format!(
        "<abbr title=\"{} {}\">{}</abbr>",
        escape(&f.technique),
        escape(&f.technique_name),
        escape(&f.technique_name),
    );
    if f.foothold {
        format!(
            "<abbr title=\"T1190 Exploit Public-Facing Application\">break in through an \
             internet-facing service</abbr> → {goal}"
        )
    } else {
        goal
    }
}

/// The one disposition that routes to the remediations section: a reversible network
/// cut that meets the action bar (so it auto-applies armed, or is proposed in shadow).
const AUTO_ELIGIBLE: &str = "auto-eligible";

/// The chain's mechanical disposition — what its minimal cut can do, by cut type. This
/// is *not* the exploitability judgement (that's the model's [`ProvenChain::verdict`],
/// shown to humans); it's the deterministic "can we cut this, and does it meet the
/// bar" annotation that routes the dashboard and rides along in the JSON. It mirrors
/// [`super::actuator::decide`] minus the runtime-only gates (enabled class, blast
/// radius): only a network cut (`DenyNetworkPath`) auto-applies; subtractive cuts are
/// durable GitOps fixes, an escape primitive is irreversible, no single edge is no-cut.
fn classify(chain: &ProvenChain, action: Option<super::respond::ProposedAction>) -> String {
    use super::respond::ProposedAction as A;
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
    /// Signals ingested this pass by [`super::graph::Behavior::variant_label`]
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
    fn as_u8(self) -> u8 {
        match self {
            ModelHealth::Unknown => 0,
            ModelHealth::Ok => 1,
            ModelHealth::Timeout => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
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
}

impl VerdictEntry {
    /// The summary string to DISPLAY for this entry: the live display verdict if one
    /// has landed this run, else the journal-restored summary, else nothing. This is
    /// exactly the carry-forward precedence the engine used to apply at publish time —
    /// a live verdict supersedes a restored one — now in one place.
    fn display_summary(&self) -> Option<String> {
        self.display
            .as_ref()
            .map(Verdict::summary)
            .or_else(|| self.restored.clone())
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
    fn update(&self, entry: &str, f: impl FnOnce(&mut VerdictEntry)) {
        let mut entries = self.entries.lock().expect("verdict store mutex poisoned");
        f(entries.entry(entry.to_string()).or_default());
    }

    /// Seed a journal-restored verdict summary for an entry (JEF-141) — shown until a
    /// live verdict supersedes it. Does not touch the cache or the journaled-dedup key.
    pub fn seed_restored(&self, entry: &str, summary: String) {
        self.update(entry, |e| e.restored = Some(summary));
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

    fn is_armed(&self) -> bool {
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
        let mut rows = self.rows.lock().expect("findings mutex poisoned").clone();
        for f in &mut rows {
            // A breach-relevant finding's verdict is the model's per-entry call, the one
            // source of truth. Non-breach-relevant rows are never judged, so they keep
            // their (absent) verdict. Resolving here means publishing the rows once is
            // enough — the verdict tracks the store, not the last `replace`.
            if f.breach_relevant {
                f.verdict = self.verdicts.display_summary(&f.entry);
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
fn relative_time(at: Option<SystemTime>) -> String {
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
    const CAP: usize = 64;

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
    const CAP: usize = 64;

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

/// Minimal HTML escape for the few values that could contain markup-special chars.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A short, human label for a node key — drop the kind prefix (`workload/`, …).
/// Delegates to [`NodeKey::short_of`] so the parsing lives in one place.
fn short(key: &str) -> String {
    crate::engine::graph::NodeKey::short_of(key).to_string()
}

/// The node kind — the key's first path segment (`secret`, `capability`, …).
/// Delegates to [`NodeKey::kind_of`]; a keyless string has no kind prefix, so it
/// falls back to `"node"` (matching the prior behaviour).
fn kind(key: &str) -> &str {
    match key.split_once('/') {
        Some(_) => crate::engine::graph::NodeKey::kind_of(key),
        None => "node",
    }
}

/// Sanitize an untrusted label for the Mermaid source. Strips the characters that
/// break a Mermaid quoted label (`"` backtick CR LF) AND the HTML metacharacters
/// `< > &` — the source is interpolated into a `<pre>` and then re-parsed by the
/// client renderer into `innerHTML`'d SVG, so a label like `</pre><img onerror=…>`
/// would otherwise be stored XSS. Node keys/relations are RFC-1123-ish and never
/// legitimately contain these, so stripping is lossless for real data.
fn mm(s: &str) -> String {
    s.replace(['"', '`', '\n', '\r', '<', '>', '&'], " ")
}

/// Mermaid node-shape delimiters by node kind (from the key prefix): secret =
/// cylinder, capability = hexagon, host = parallelogram, identity = stadium, else
/// rectangle (workload / image / endpoint).
fn shape(key: &str) -> (&'static str, &'static str) {
    match kind(key) {
        "secret" => ("[(", ")]"),
        "capability" => ("{{", "}}"),
        "host" => ("[/", "/]"),
        "identity" => ("([", "])"),
        _ => ("[", "]"),
    }
}

/// Accumulates a Mermaid `flowchart LR`: every distinct node key gets a stable
/// synthetic id (Mermaid ids must be identifier-safe), labeled with its short name
/// and shaped by kind.
#[derive(Default)]
struct Mermaid {
    ids: BTreeMap<String, String>,
    nodes: String,
    edges: String,
}

impl Mermaid {
    fn node(&mut self, key: &str) -> String {
        let label = short(key);
        self.node_labeled(key, &label)
    }

    /// Like [`node`](Self::node) but with an explicit label (the key still drives the
    /// shape + dedup identity). Used for aggregate fan-out nodes like "47 secrets".
    fn node_labeled(&mut self, key: &str, label: &str) -> String {
        if let Some(id) = self.ids.get(key) {
            return id.clone();
        }
        let id = format!("n{}", self.ids.len());
        let (open, close) = shape(key);
        self.nodes
            .push_str(&format!("  {id}{open}\"{}\"{close}\n", mm(label)));
        self.ids.insert(key.to_string(), id.clone());
        id
    }

    /// An edge to a node carrying an explicit label (for aggregate targets).
    fn edge_to_labeled(&mut self, from: &str, to_key: &str, to_label: &str, label: &str) {
        let a = self.node(from);
        let b = self.node_labeled(to_key, to_label);
        self.edges
            .push_str(&format!("  {a} -->|\"{}\"| {b}\n", mm(label)));
    }

    /// The fixed Internet source node (a circle), linked into `entry` with a bold
    /// arrow — the attacker's origin.
    fn add_internet(&mut self, entry: &str) {
        let net = self.ids.get("__internet__").cloned().unwrap_or_else(|| {
            let id = format!("n{}", self.ids.len());
            self.nodes.push_str(&format!("  {id}((\"Internet\"))\n"));
            self.ids.insert("__internet__".into(), id.clone());
            id
        });
        let to = self.node(entry);
        self.edges.push_str(&format!("  {net} ==> {to}\n"));
    }

    /// A labeled edge; `cut` draws it dashed (the severing action).
    fn edge(&mut self, from: &str, to: &str, label: &str, cut: bool) {
        let a = self.node(from);
        let b = self.node(to);
        let arrow = if cut { "-.->" } else { "-->" };
        self.edges
            .push_str(&format!("  {a} {arrow}|\"{}\"| {b}\n", mm(label)));
    }

    fn finish(self) -> String {
        format!("flowchart LR\n{}{}", self.nodes, self.edges)
    }
}

/// One remediation card: the kill chain caption and a graph of the path with the
/// severing edge dashed.
fn remediation_card(f: &Finding, armed: bool) -> String {
    let mut m = Mermaid::default();
    m.add_internet(&f.entry);
    for step in &f.path {
        let sig = format!("{} -[{}]-> {}", step.from, step.relation, step.to);
        let is_cut = f.cut.as_deref() == Some(sig.as_str());
        let label = if is_cut {
            "✂ NetworkPolicy cut".to_string()
        } else {
            humanize_relation(&step.relation)
        };
        m.edge(&step.from, &step.to, &label, is_cut);
    }
    let status = if armed {
        "<span class=\"applied\">applied</span>"
    } else {
        "<span class=\"proposed\">would apply (shadow)</span>"
    };
    // JEF-161 verdict-first card: posture chip + the model's words VERBATIM above
    // everything, then the "what's proven" certainty rail, then the (cut-marked) graph,
    // then the disposition-derived "what to do". The remediation card is one chain, so
    // the rail/aria are built over that single finding.
    let one = std::slice::from_ref(&f);
    let verdict_line = verdict_line(f.verdict.as_deref());
    let facts: String = proven_facts(&f.entry, one)
        .iter()
        .map(|b| format!("<li>{b}</li>"))
        .collect();
    let rail = format!(
        "<div class=\"rail\"><div class=\"rail-cap\">what's proven \
         <span class=\"muted\">— deterministic facts; the model's call is above</span></div>\
         <ul>{facts}</ul></div>"
    );
    // The per-path evidence (JEF-133): the entry's CVEs (severity input) and runtime
    // alerts (live corroboration), the two ADR-0016 blocks — placed right after the
    // certainty rail so "what's proven" → "what's the evidence" reads top to bottom.
    let evidence = evidence_blocks(&f.evidence);
    let todo_line = format!(
        "<div class=\"todo\"><b>what to do:</b> {}</div>",
        what_to_do(&f.disposition)
    );
    let aria = escape(&path_aria_label(&f.entry, one));
    format!(
        "<div class=\"card\">{verdict_line}{rail}{evidence}\
         <div class=\"kc2\">the picture of those facts — attack steps: {}  {status}</div>\
         <pre class=\"mermaid\" data-aria=\"{aria}\">{}</pre>{todo_line}</div>",
        killchain_html(f),
        m.finish(),
    )
}

/// Pluralize an objective kind for an aggregate label ("47 secrets").
fn plural(kind: &str, n: usize) -> String {
    if n == 1 {
        return kind.to_string();
    }
    match kind {
        "capability" => "capabilities".to_string(),
        "identity" => "identities".to_string(),
        k => format!("{k}s"),
    }
}

/// One endpoint card: every breach path from this internet-facing entry in a single
/// graph, captioned with the **model's judgement** of the entry — the LLM is the
/// judge (ADR-0013), so the disposition is its own words ("not exploitable — …"),
/// never a rule-based category. The verdict is per-entry, so one judgement covers the
/// whole card. A broadly-privileged entry (argocd, protector) fans out to hundreds of
/// objectives, so terminal objectives sharing a (hop, kind) are **collapsed into one
/// aggregate node** ("47 secrets") — the graph stays readable. Intermediate hops are
/// deduped.
/// A human edge label for a graph relation, so an operator can tell *how* a hop works
/// — most importantly the two ways to reach a secret: a **mounted** secret it already
/// holds (`can-read`, direct, just that one secret) vs an **RBAC** grant its identity
/// can exercise against the API (`can-do/get/secrets`, often any secret in scope).
fn humanize_relation(rel: &str) -> String {
    if rel == "can-read" {
        return "mounts (direct read)".to_string();
    }
    if let Some(rest) = rel.strip_prefix("can-do/") {
        // can-do/get/secrets → "RBAC get secrets (API)"
        return format!("RBAC {} (API)", rest.replace('/', " "));
    }
    if let Some(via) = rel.strip_prefix("escapes-to/") {
        return format!("escapes via {via}");
    }
    if rel.starts_with("can-egress") {
        return "internet egress (exfil)".to_string();
    }
    if rel.starts_with("reaches") {
        return "network reach".to_string();
    }
    if rel == "runs-as" {
        return "runs as".to_string();
    }
    rel.to_string()
}

/// The three posture states a verdict can be in, for the verdict-first card and the
/// `/judgements` view (JEF-161). The breach call is the model's (ADR-0013/0016), so
/// this maps only the model's *own* affirmation to `[BREACH]` — a "not exploitable"
/// verdict is `[SAFE]`, and no verdict yet is the muted `[awaiting judgement]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Posture {
    /// The model affirmed a real breach (its words begin with "exploitable").
    Breach,
    /// The model judged this NOT a breach (a "not exploitable — …" call).
    Safe,
    /// The model hasn't reached this entry yet (slow CPU model) — not "clear".
    Awaiting,
}

impl Posture {
    /// The posture for a verdict summary string (the model's own words), or `None` if
    /// the model hasn't judged the entry yet. Mirrors [`flagged`] for the breach test.
    fn of(verdict: Option<&str>) -> Self {
        match verdict {
            None => Posture::Awaiting,
            Some(v) if flagged(Some(v)) => Posture::Breach,
            Some(_) => Posture::Safe,
        }
    }

    /// The chip TEXT — meaning carried in words, never color/glyph alone (accessibility,
    /// JEF-161 AC #4). The brackets read as a posture chip in a screen reader too.
    fn label(self) -> &'static str {
        match self {
            Posture::Breach => "[BREACH]",
            Posture::Safe => "[SAFE]",
            Posture::Awaiting => "[awaiting judgement]",
        }
    }

    /// The CSS tone class for the chip — red breach / green-calm safe / muted awaiting.
    fn tone(self) -> &'static str {
        match self {
            Posture::Breach => "chip-breach",
            Posture::Safe => "chip-safe",
            Posture::Awaiting => "chip-awaiting",
        }
    }
}

/// The posture chip + the model's verdict VERBATIM (never paraphrased — the LLM is the
/// judge, ADR-0013), foregrounded above everything on a finding card (JEF-161). When the
/// model hasn't judged the entry, the chip stands alone with a muted "the model hasn't
/// reached this entry yet" — an honest awaiting state, not an implied "clear".
fn verdict_line(verdict: Option<&str>) -> String {
    let posture = Posture::of(verdict);
    let chip = format!(
        "<span class=\"chip {}\">{}</span>",
        posture.tone(),
        posture.label()
    );
    match verdict {
        Some(v) => format!(
            "<div class=\"vline\">{chip} <span class=\"vwords\">{}</span></div>",
            escape(v)
        ),
        None => format!(
            "<div class=\"vline\">{chip} <span class=\"muted\">the model hasn't reached \
             this entry yet — paths below are proven, the breach call is pending</span></div>"
        ),
    }
}

/// The "what's proven" certainty rail (JEF-161 AC #1/#2): 2–4 bullets of DETERMINISTIC
/// facts drawn only from existing `Finding` fields — the proof side of the proof-vs-
/// judgement line (ADR-0016). Missing evidence reads "unknown / not cited", never
/// implied-absent (coverage-gap honesty, AC #2). No model call. Facts:
///   1. internet-reachable (every shown finding is `breach_relevant` from an entry).
///   2. how it reaches each objective kind — by RBAC vs mount, via [`humanize_relation`].
///   3. CVE presence — surfaced ONLY from a `CVE-` id the model cited in its verdict
///      (JEF-133 builds the real per-path evidence feed; here we read existing fields).
fn proven_facts(entry: &str, fs: &[&Finding]) -> Vec<String> {
    let mut facts = Vec::new();

    // 1. Internet-reachability is the entry-level fact (only breach-relevant chains from
    // an internet-facing entry reach this card — ProvenChain::is_breach_relevant).
    facts.push(format!(
        "internet-reachable: <code>{}</code> is an internet-facing service (a front door)",
        escape(&short(entry))
    ));

    // 2. The distinct terminal relations — HOW it reaches an objective (RBAC vs mount vs
    // network), the deterministic mechanism. Deduped, stable-ordered.
    let mut relations: BTreeSet<String> = BTreeSet::new();
    for f in fs {
        if let Some(step) = f.path.iter().find(|s| s.to == f.objective) {
            relations.insert(humanize_relation(&step.relation));
        }
    }
    for rel in &relations {
        facts.push(format!("reaches a target by <b>{}</b>", escape(rel)));
    }

    // 3. CVE presence — from a `CVE-` id the model cited in its verdict (existing field
    // only; NOT JEF-133's per-path feed). Absence reads "no CVE cited", never implied.
    let cve = fs
        .iter()
        .find_map(|f| f.verdict.as_deref().and_then(cve_id).map(str::to_string));
    match cve {
        Some(id) => facts.push(format!(
            "CVE present: the model cited <code>{}</code>",
            escape(&id)
        )),
        None => facts.push(
            "CVE: <span class=\"muted\">none cited in this verdict (CVE coverage unknown)</span>"
                .to_string(),
        ),
    }

    facts
}

/// How many CVEs to list inline before the rest go behind a "show all" `<details>`
/// expander (JEF-133 AC: CVE lists can be long — summarize, detail on demand). The
/// top-N are shown by `severity_rank` so the worst surface first.
const CVE_INLINE_CAP: usize = 3;

/// The CSS tone class for a CVE severity label — reuses the chip idiom so critical/high
/// read as alarming and low/medium calm, WITHOUT relying on color alone (the label text
/// carries the meaning too, JEF-161 AC #4 accessibility).
fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "critical" => "sev-critical",
        "high" => "sev-high",
        "medium" => "sev-medium",
        _ => "sev-low",
    }
}

/// A sort key putting the worst CVEs first: critical, then high, then KEV-flagged, then
/// the rest. Used for both the inline top-N and the severity summary.
fn severity_rank(c: &CveEvidence) -> u8 {
    match c.severity.as_str() {
        "critical" => 0,
        "high" => 1,
        _ if c.kev => 2,
        "medium" => 3,
        _ => 4,
    }
}

/// One CVE as a list item: id, a severity chip, KEV/reachability/fix, and CWE/title when
/// present. All free-text (title) is HTML-escaped — it is untrusted third-party data.
fn cve_li(c: &CveEvidence) -> String {
    let kev = if c.kev {
        " <span class=\"kev\" title=\"CISA Known-Exploited\">KEV</span>"
    } else {
        ""
    };
    let cwe = if c.cwe.is_empty() {
        String::new()
    } else {
        format!(
            " <span class=\"muted\">[{}]</span>",
            escape(&c.cwe.join(", "))
        )
    };
    let title = match c.title.as_deref() {
        Some(t) if !t.is_empty() => format!(" — {}", escape(t)),
        _ => String::new(),
    };
    format!(
        "<li><code>{}</code> <span class=\"chip {}\">{}</span>{kev} \
         <span class=\"muted\">reachability: {} · {}</span>{cwe}{title}</li>",
        escape(&c.id),
        severity_tone(&c.severity),
        escape(&c.severity),
        escape(&c.reachability),
        escape(&c.fix),
    )
}

/// The CVE evidence block (JEF-133) — the SEVERITY/reachability input half of ADR-0016.
/// A one-line summary (count + the worst severities) with the full list behind a
/// `<details>` expander when it runs long. Empty CVEs render an honest muted "none on the
/// entry's image" — never an implied-absent blank box (JEF-161 coverage-gap idiom).
fn cve_block(ev: &EntryEvidence) -> String {
    if ev.cves.is_empty() {
        return "<div class=\"ev ev-cve\"><div class=\"ev-cap\">CVEs \
                <span class=\"muted\">— how bad it would be if exploited</span>\
                </div><div class=\"muted\">none on this service's image \
                <span class=\"muted\">(KEV or critical; lower-severity CVEs not shown)</span>\
                </div></div>"
            .to_string();
    }

    let mut sorted: Vec<&CveEvidence> = ev.cves.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(a)
            .cmp(&severity_rank(b))
            .then(a.id.cmp(&b.id))
    });

    // Summary: count + a per-severity tally (critical/high/medium/low), worst first.
    let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &sorted {
        *by_sev.entry(c.severity.as_str()).or_default() += 1;
    }
    let order = ["critical", "high", "medium", "low"];
    let tally: Vec<String> = order
        .iter()
        .filter_map(|s| by_sev.get(*s).map(|n| format!("{n} {s}")))
        .collect();
    let n = sorted.len();
    let summary = format!(
        "<b>{n}</b> CVE{} <span class=\"muted\">({})</span>",
        if n == 1 { "" } else { "s" },
        tally.join(", ")
    );

    let inline: String = sorted
        .iter()
        .take(CVE_INLINE_CAP)
        .map(|c| cve_li(c))
        .collect();
    let rest: String = sorted
        .iter()
        .skip(CVE_INLINE_CAP)
        .map(|c| cve_li(c))
        .collect();
    let more = if rest.is_empty() {
        String::new()
    } else {
        format!("<details><summary>show all {n} CVEs</summary><ul>{rest}</ul></details>",)
    };

    format!(
        "<div class=\"ev ev-cve\"><div class=\"ev-cap\">CVEs \
         <span class=\"muted\">— how bad it would be if exploited</span></div>\
         <div class=\"ev-sum\">{summary}</div><ul>{inline}</ul>{more}</div>"
    )
}

/// The runtime-alert block (JEF-133) — the LIVE-corroboration half of ADR-0016. Lists the
/// corroborating signals first (Falco-style `Alert`s, what flips `corroborated`), then the
/// non-corroborating agent behaviors as context. Empty renders an honest muted "no runtime
/// signal observed" — never implied-absent.
fn runtime_block(ev: &EntryEvidence) -> String {
    let corroborating: Vec<&Behavior> = ev.corroborating().collect();
    let context: Vec<&Behavior> = ev.context_behaviors().collect();

    let body = if corroborating.is_empty() && context.is_empty() {
        "<div class=\"muted\">no live activity seen on this service \
         <span class=\"muted\">(no Falco alert, no agent behavior attributed)</span></div>"
            .to_string()
    } else {
        let mut out = String::new();
        if corroborating.is_empty() {
            out.push_str(
                "<div class=\"muted\">nothing seen happening live \
                 (no live activity backs this up as being exploited now)</div>",
            );
        } else {
            let items: String = corroborating
                .iter()
                .map(|b| {
                    format!(
                        "<li><span class=\"chip chip-breach\">SEEN LIVE</span> {}</li>",
                        escape(&b.summary())
                    )
                })
                .collect();
            out.push_str(&format!("<ul>{items}</ul>"));
        }
        if !context.is_empty() {
            let items: String = context
                .iter()
                .map(|b| {
                    format!(
                        "<li><span class=\"muted\">[{}]</span> {}</li>",
                        escape(b.variant_label()),
                        escape(&b.summary())
                    )
                })
                .collect();
            out.push_str(&format!(
                "<details><summary>{} agent behavior{} (background, not seen exploited)</summary>\
                 <ul>{items}</ul></details>",
                context.len(),
                if context.len() == 1 { "" } else { "s" },
            ));
        }
        out
    };

    format!(
        "<div class=\"ev ev-runtime\"><div class=\"ev-cap\">live activity \
         <span class=\"muted\">— is it being exploited right now</span></div>{body}</div>"
    )
}

/// The two ADR-0016 evidence blocks for a finding's entry (JEF-133), wrapped so they read
/// as one "evidence for this path" section beneath the certainty rail. CVEs (severity
/// input) then runtime alerts (live corroboration) — always both blocks, each with its own
/// honest empty state, so the operator can tell "no CVE" from "CVE block missing".
fn evidence_blocks(ev: &EntryEvidence) -> String {
    format!(
        "<div class=\"evidence\"><div class=\"ev-head\">evidence for this path</div>{}{}</div>",
        cve_block(ev),
        runtime_block(ev),
    )
}

/// The first `CVE-NNNN-NNNN` id in a string (case-insensitive prefix), if any — the
/// only CVE signal available from existing fields (the model cites it in its verdict).
/// Used by the certainty rail; the full per-path CVE evidence is JEF-133's job.
fn cve_id(s: &str) -> Option<&str> {
    let upper = s.to_ascii_uppercase();
    let start = upper.find("CVE-")?;
    let bytes = s.as_bytes();
    let mut end = start + 4;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'-') {
        end += 1;
    }
    // Trim a trailing '-' (e.g. cited at the end of a sentence "… CVE-2021-44228.").
    while end > start + 4 && bytes[end - 1] == b'-' {
        end -= 1;
    }
    (end > start + 4).then(|| &s[start..end])
}

/// The "what to do" line, derived ONLY from the finding's mechanical `disposition`
/// (JEF-161 AC #1) — no new model call, no new action. The disposition already encodes
/// the cut type (see [`classify`]); this translates it to the operator's next step.
fn what_to_do(disposition: &str) -> &'static str {
    match disposition {
        AUTO_ELIGIBLE
        | "latent foothold — propose"
        | "structural — propose"
        | "vetoed — propose" => "would cut in shadow; arm `network` to act",
        "durable-fix PR" => "revoke the grant / remove the mount (durable fix)",
        "forbidden" => "manual — the only cut is an irreversible escape primitive",
        "no-cut" => "manual — no single-edge cut severs this path",
        // "unclassified" and any future disposition: the safe, conservative default.
        _ => "manual — no automatic cut classified for this path",
    }
}

/// The Mermaid graph's `aria-label` (JEF-161 AC #4): the proven path summarized IN WORDS
/// so a screen reader conveys the picture the SVG draws. Applied to the rendered graph by
/// the inline script (the SVG is client-rendered) via a `data-aria` attribute on the
/// `<pre>`. Plain text only (it is an attribute value); escaped at the call site.
fn path_aria_label(entry: &str, fs: &[&Finding]) -> String {
    let objectives = fs
        .iter()
        .flat_map(|f| f.path.iter())
        .filter(|s| fs.iter().any(|f| s.to == f.objective))
        .map(|s| s.to.clone())
        .collect::<BTreeSet<_>>()
        .len();
    format!(
        "Attack-path graph: the internet reaches {entry}, which reaches {objectives} \
         target{} it can get to.",
        if objectives == 1 { "" } else { "s" },
        entry = short(entry),
    )
}

fn endpoint_card(entry: &str, fs: &[&Finding], tier: Tier) -> String {
    let mut m = Mermaid::default();
    m.add_internet(entry);
    let mut seen_intermediate: BTreeSet<String> = BTreeSet::new();
    // Terminal fan-out grouped by (from-node, relation, objective-kind) → the
    // objective keys in that group. One group → one node (or aggregate).
    let mut groups: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    let mut objectives = 0usize;

    for f in fs {
        for step in &f.path {
            if step.to == f.objective {
                objectives += 1;
                let kind = kind(&step.to).to_string();
                groups
                    .entry((step.from.clone(), step.relation.clone(), kind))
                    .or_default()
                    .push(step.to.clone());
            } else if seen_intermediate
                .insert(format!("{}|{}|{}", step.from, step.to, step.relation))
            {
                m.edge(
                    &step.from,
                    &step.to,
                    &humanize_relation(&step.relation),
                    false,
                );
            }
        }
    }

    for ((from, relation, kind), objs) in &groups {
        let label = humanize_relation(relation);
        if objs.len() == 1 {
            m.edge(from, &objs[0], &label, false);
        } else {
            // Collapse the fan-out into one aggregate node.
            let agg_key = format!("{kind}/__agg/{from}/{relation}");
            let agg_label = format!("{} {}", objs.len(), plural(kind, objs.len()));
            m.edge_to_labeled(from, &agg_key, &agg_label, &label);
        }
    }

    // ONE model judgement for the whole endpoint — the model judges per internet-facing
    // entry, over everything it reaches, in a single call (ADR-0013); it is NOT a
    // per-edge or per-objective verdict. So show the entry's one verdict (the model's
    // own words), not a count that would imply many judgements. `None` = the model
    // hasn't reached this entry yet (slow CPU model); the paths still render.
    //
    // JEF-161 verdict-first card: the posture chip + the model's words VERBATIM are
    // foregrounded ABOVE everything, then the "what's proven" certainty rail draws the
    // proof-vs-judgement line, then the graph, then a disposition-derived "what to do".
    let verdict = fs.iter().find_map(|f| f.verdict.as_deref());
    let posture = Posture::of(verdict);
    let verdict_line = verdict_line(verdict);

    // The certainty rail — deterministic facts, captioned so the model's call (above) is
    // clearly the judgement and these are the proof (ADR-0016 proof-vs-judgement line).
    let facts: String = proven_facts(entry, fs)
        .iter()
        .map(|b| format!("<li>{b}</li>"))
        .collect();
    let rail = format!(
        "<div class=\"rail\"><div class=\"rail-cap\">what's proven \
         <span class=\"muted\">— deterministic facts; the model's call is above</span></div>\
         <ul>{facts}</ul></div>"
    );

    // The per-path evidence (JEF-133): the entry's CVEs + runtime alerts, the two ADR-0016
    // blocks. The model judges per ENTRY over everything it reaches, so the whole card
    // shares ONE entry's evidence — take it from the first finding (all `fs` are this
    // entry's paths). Behaviors are attributed by pod UID, so this is the entry's own
    // low-cardinality signal set, no per-objective sprawl.
    let evidence = fs
        .first()
        .map(|f| evidence_blocks(&f.evidence))
        .unwrap_or_default();

    // Severity ≠ breach (ADR-0016): a broad, calm [SAFE] entry with a huge graph is the
    // INTENDED picture — breadth is severity, not urgency. Call it out so the wide graph
    // doesn't read as alarming. Only when the model judged it safe AND the reach is broad.
    let breadth = if posture == Posture::Safe && objectives >= 20 {
        "<div class=\"breadth muted\">wide reach, but not a break-in — wide access isn't a \
         break-in.</div>"
            .to_string()
    } else {
        String::new()
    };

    // What to do — derived from the disposition class only (no model call). The endpoint
    // card groups many findings; they share the entry's posture, so take the disposition
    // of the first as the representative next step for this entry's paths.
    let todo = fs
        .first()
        .map(|f| what_to_do(&f.disposition))
        .unwrap_or("manual — no automatic cut classified for this path");
    let todo_line = format!("<div class=\"todo\"><b>what to do:</b> {todo}</div>");

    let aria = escape(&path_aria_label(entry, fs));

    // Expand the coalesced fan-out: a collapsed aggregate node ("47 secrets") hides
    // the names, so list each aggregated group's members under a native <details>
    // the operator can open. Singletons are already named in the graph, so skip them.
    let expand: String = groups
        .iter()
        .filter(|(_, objs)| objs.len() > 1)
        .map(|((_, relation, kind), objs)| {
            let mut names: Vec<String> = objs.iter().map(|o| short(o)).collect();
            names.sort();
            let items: String = names
                .iter()
                .map(|n| format!("<li>{}</li>", escape(n)))
                .collect();
            format!(
                "<details><summary>{} {} <span class=\"muted\">via {}</span></summary><ul>{}</ul></details>",
                objs.len(),
                plural(kind, objs.len()),
                escape(relation),
                items
            )
        })
        .collect();

    // The attention tier (JEF-163): a small chip — reusing the card chip idiom — that
    // says WHY this card is where it is in the "look at this first" order. View-only; it
    // labels the already-decided card and gates nothing (ADR-0016).
    let tier_chip = format!(
        "<span class=\"chip {}\" title=\"attention tier\">{}</span>",
        tier.chip_class(),
        tier.label()
    );

    // The card inner — identical regardless of tier; only the wrapper differs so the
    // lowest (context) tier is de-emphasized AND collapsible (AC #3).
    let inner = format!(
        "{tier_chip}{verdict_line}{rail}{evidence}{breadth}\
         <div class=\"kc2\">the picture of those facts — \
         <span class=\"muted\">{} ({} target{} reachable)</span></div>\
         <pre class=\"mermaid\" data-aria=\"{aria}\">{}</pre>{todo_line}{}",
        escape(&short(entry)),
        objectives,
        if objectives == 1 { "" } else { "s" },
        m.finish(),
        if expand.is_empty() {
            String::new()
        } else {
            format!("<div class=\"expand\">{expand}</div>")
        },
    );

    // Context-tier cards collapse behind a <details> so the operator's eye lands on the
    // flagged/watch cards first; flagged/watch render expanded as before.
    if tier == Tier::Context {
        format!(
            "<details class=\"card card-context\"><summary>{tier_chip}\
             <span class=\"muted\">{} — background, not flagged ({} target{} reachable)</span>\
             </summary>{inner}</details>",
            escape(&short(entry)),
            objectives,
            if objectives == 1 { "" } else { "s" },
        )
    } else {
        format!("<div class=\"card\">{inner}</div>")
    }
}

/// A model verdict counts as a flag only when the model affirmed exploitability —
/// its own words begin with "exploitable" (a "not exploitable — …" verdict does not).
fn flagged(verdict: Option<&str>) -> bool {
    verdict.is_some_and(|v| {
        v.trim_start()
            .to_ascii_lowercase()
            .starts_with("exploitable")
    })
}

/// The operator-attention TIER a finding falls in (JEF-163) — the **view** label that
/// says *why a card is where it is*, NOT a decision (ADR-0016: ordering is a view, never
/// a gate). It does not feed the model, gate any action, or touch a verdict/disposition;
/// it is computed read-only from existing [`Finding`] fields at render time and only
/// reorders + labels the already-decided cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The model judged this a real breach (its verdict affirms `exploitable`). Always
    /// at the top — a flagged endpoint sorts above a larger-but-unflagged one (AC #2).
    Flagged,
    /// Warrants a look but the model hasn't flagged a breach: either a coverage-gap /
    /// latent foothold carrying a cited CVE, or a runtime-corroborated chain.
    Watch,
    /// Everything else — proven-reachable but neither flagged, CVE-bearing-latent, nor
    /// runtime-corroborated. De-emphasized / collapsible in the view.
    Context,
}

impl Tier {
    /// The short label shown on the card so the operator sees its tier at a glance.
    fn label(self) -> &'static str {
        match self {
            Tier::Flagged => "flagged",
            Tier::Watch => "watch",
            Tier::Context => "context",
        }
    }

    /// The chip tone class (reusing the existing card chip idiom): red for flagged,
    /// amber for watch, grey for the de-emphasized context tier.
    fn chip_class(self) -> &'static str {
        match self {
            Tier::Flagged => "tier-flagged",
            Tier::Watch => "tier-watch",
            Tier::Context => "tier-context",
        }
    }
}

/// The OPERATOR-PRIORITY rank of a single finding (JEF-163) — a TESTED PURE FUNCTION over
/// existing [`Finding`] fields (AC #4). Lower number = more attention. This is the
/// presentation-only "look at this first" key (ADR-0016: severity is a view, breach is the
/// model's; a sort key never gates, decides, or feeds the model). The four levels, in the
/// ticket's order:
///
///   1. model-flagged exploitable — the model judged a real breach ([`flagged`]).
///   2. coverage-gap / latent foothold WITH a CVE present — `disposition` is the latent
///      case AND the verdict cites a `CVE-…` ([`cve_id`], the only per-finding CVE signal
///      that exists today; see the note below).
///   3. runtime-corroborated — a live signal completed the chain (`corroborated`).
///   4. everything else.
///
/// NOTE on "KEV / critical CVE": `Finding` has no per-finding KEV flag or CVE severity
/// field — the sole CVE signal present is the id the model cited in its verdict text
/// (`cve_id`). We therefore treat *any* cited CVE on a latent foothold as level 2 rather
/// than fabricating a severity/KEV field. This is the conservative reading: it cannot
/// over-promote (a cited CVE is, at worst, slightly broader than "KEV/critical only"), and
/// it invents nothing. If a KEV/severity field is later added to `Finding`, tighten this.
fn attention_priority(f: &Finding) -> u8 {
    if flagged(f.verdict.as_deref()) {
        0
    } else if f.disposition.contains("latent foothold")
        && f.verdict.as_deref().and_then(cve_id).is_some()
    {
        1
    } else if f.corroborated {
        2
    } else {
        3
    }
}

/// The [`Tier`] a priority level maps to for display (AC #3): level 1 is `Flagged`,
/// levels 2–3 are `Watch`, level 4 is the de-emphasized `Context` tier.
fn tier_of_priority(priority: u8) -> Tier {
    match priority {
        0 => Tier::Flagged,
        1 | 2 => Tier::Watch,
        _ => Tier::Context,
    }
}

/// The attention rank of one finding: its priority level and the display tier. The pure,
/// unit-testable key for the per-card sort (AC #4) — view-only, no mutation, no model input.
fn attention_rank(f: &Finding) -> (u8, Tier) {
    let priority = attention_priority(f);
    (priority, tier_of_priority(priority))
}

/// The attention rank of an ENDPOINT card — a card coalesces every finding from one
/// internet-facing entry, so the card takes its group's WORST-CASE (lowest-number)
/// priority: a single flagged path makes the whole card flagged. Returns the card's
/// priority level and its display tier. Pure over the group; the BLAST RADIUS (group
/// size) is NOT folded in here — it is applied only as the final tiebreak at the sort
/// site, so it can never lift a card above a higher tier (AC #1, AC #2).
fn endpoint_attention_rank(fs: &[&Finding]) -> (u8, Tier) {
    // The card's priority is the most-attention-worthy of its findings (lowest number),
    // via the per-finding `attention_rank` so card and finding rankings can never drift.
    let priority = fs.iter().map(|f| attention_rank(f).0).min().unwrap_or(3);
    (priority, tier_of_priority(priority))
}

/// The attack-vector summary: the ATT&CK outcomes an external attacker can actually
/// reach, aggregated across the breach-relevant findings. Each row is one
/// tactic→technique pair with how many distinct objectives are reachable and how many
/// the model has affirmed exploitable. This is the "what can hit us, by ATT&CK
/// technique" overview that sits above the per-endpoint graphs — proof winnows the
/// reachable set, the model decides which are genuinely exploitable (ADR-0013).
fn attack_vectors(findings: &[Finding]) -> String {
    // (tactic, technique_id, technique_name) → (objectives reachable, objectives the
    // model flagged exploitable). Distinct objectives, since several chains may reach
    // the same one. BTreeMap keeps the table stable, ordered by tactic then technique.
    type VectorKey = (String, String, String);
    type VectorCounts = (BTreeSet<String>, BTreeSet<String>);
    let mut rows: BTreeMap<VectorKey, VectorCounts> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        let entry = rows
            .entry((
                f.tactic_name.clone(),
                f.technique.clone(),
                f.technique_name.clone(),
            ))
            .or_default();
        entry.0.insert(f.objective.clone());
        if flagged(f.verdict.as_deref()) {
            entry.1.insert(f.objective.clone());
        }
    }

    if rows.is_empty() {
        return "<p class=\"muted\">no internet-facing service can reach a target</p>".to_string();
    }

    let body: String = rows
        .iter()
        .map(|((tactic, tid, tname), (reachable, flagged))| {
            let flag = if flagged.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                format!("<span class=\"flagged\">{}</span>", flagged.len())
            };
            format!(
                "<tr><td>{}</td><td><abbr title=\"{} {}\">{}</abbr></td><td>{}</td><td>{}</td></tr>",
                escape(tactic),
                escape(tid),
                escape(tname),
                escape(tname),
                reachable.len(),
                flag,
            )
        })
        .collect();

    format!(
        "<table class=\"vectors\"><thead><tr><th>Tactic</th><th>Technique</th>\
         <th>Reachable</th><th>Model-flagged</th></tr></thead><tbody>{body}</tbody></table>"
    )
}

/// The behavioral-bake panel (JEF-48): the at-a-glance view of what the behavioral
/// port saw in the most recent pass — signal volume by variant, attribution
/// resolved/unresolved, the live runtime-store size, and corroborations fired. This is
/// the dashboard mirror of the OTLP bake counters (JEF-100), so the bake's exit criteria
/// ("signal volume sane", "attribution resolves", "corroboration would fire") are
/// readable on the dashboard itself, not only through a collector. Read-only, shadow-safe.
fn bake_panel(bake: &BakeStats) -> String {
    let total = bake.total_signals();
    if total == 0 && bake.runtime_store == 0 {
        return "<p class=\"muted\">no behavioral signals observed yet \
                (no sensor reporting, or a quiet cluster)</p>"
            .to_string();
    }

    // Per-variant volume rows, ordered by the BTreeMap (stable, variant-name keyed).
    let variant_rows: String = bake
        .signals_by_variant
        .iter()
        .map(|(variant, n)| {
            format!(
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                escape(variant),
                n
            )
        })
        .collect();

    // The attribution line: resolved vs unresolved with the unresolved share, the
    // JEF-48 attribution exit-criterion. A nonzero unresolved share is highlighted.
    let pct = bake.unresolved_fraction() * 100.0;
    let attribution = if bake.unresolved == 0 {
        format!(
            "<b>{}</b> resolved · <span class=\"muted\">0 unresolved</span>",
            bake.resolved
        )
    } else {
        format!(
            "<b>{}</b> resolved · <span class=\"flagged\">{} unresolved ({:.1}%)</span>",
            bake.resolved, bake.unresolved, pct
        )
    };

    format!(
        "<div class=\"sum\">last pass: <b>{total}</b> signal{} · {attribution} · \
         live store <b>{store}</b> · corroborations <b>{corr}</b></div>\
         <table class=\"vectors\"><thead><tr><th>Signal variant</th><th>Count (last pass)</th>\
         </tr></thead><tbody>{rows}</tbody></table>",
        if total == 1 { "" } else { "s" },
        store = bake.runtime_store,
        corr = bake.corroborations,
        rows = if variant_rows.is_empty() {
            "<tr><td class=\"muted\" colspan=\"2\">no signals this pass</td></tr>".to_string()
        } else {
            variant_rows
        },
    )
}

/// The recent-reversions panel (JEF-141): lifted cuts and why — the visible record of
/// the self-revert (ADR-0016). Quiet when nothing has been lifted (a healthy default,
/// not an error). Newest first.
fn reversions_panel(reversions: &[ReversionRecord]) -> String {
    if reversions.is_empty() {
        return "<p class=\"muted\">no cuts have been lifted yet</p>".to_string();
    }
    let rows: String = reversions
        .iter()
        .map(|r| {
            let when = relative_time(Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(r.at_ms),
            ));
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td class=\"muted\">{}</td></tr>",
                escape(&r.cut),
                escape(&r.reason),
                escape(&when),
            )
        })
        .collect();
    format!(
        "<table class=\"vectors\"><thead><tr><th>Lifted cut</th><th>Reason</th>\
         <th>When</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

// ===========================================================================
// The shadow "would-have-acted" report (JEF-143)
// ===========================================================================
//
// Nothing else answers the question that gates exiting shadow (JEF-50): "over the
// last N days, how many cuts WOULD protector have made, on what, and were any
// wrong?" `/report` aggregates the durable decision journal (JEF-141) into that
// diff — read-side only, no new signals, no action.
//
// The journal records one [`Decision::Breach`] per pass per internet-facing entry,
// carrying the model's verdict in its own words ("exploitable — …" / "not
// exploitable — …"). In shadow the engine never cuts, but a breach decision whose
// verdict AFFIRMS exploitability is exactly the workload it WOULD have isolated. So
// the report walks each entry's breach decisions chronologically and folds them into
// **would-act episodes**: a run of consecutive exploitable verdicts. The projected
// would-be cut lifetime is from the episode's first exploitable verdict to when it
// cleared (the next non-exploitable verdict for that entry) — or to now, if it never
// cleared (still open). An entry whose latest verdict in the window is NOT
// exploitable is a **proven-but-cleared** path the model deliberately left alone:
// the trust half of the diff.

/// Default rolling window for `/report`, in hours (7 days). The journal's own
/// rotation bounds how far back history actually reaches; this is the default the
/// view aggregates over when `?hours=`/`?days=` isn't supplied. Configurable per
/// request, never narrower than the journal — a window wider than the on-disk
/// history simply yields everything that survived rotation.
const DEFAULT_WINDOW_HOURS: u64 = 24 * 7;

/// A would-be cut lifted within this long is **short-lived** — the likely-false-
/// positive signature (a transient breach condition that cleared in minutes, e.g. a
/// scanner blip or a pod that restarted clean). A sustained would-act (at or above
/// this) is the one worth a real cut. The ticket frames "lifted within minutes" as
/// the FP tell; five minutes is the conservative default, configurable via
/// `?short_lived_secs=`.
const DEFAULT_SHORT_LIVED_SECS: u64 = 5 * 60;

/// Query parameters for `/report` (and `/report.json`): the rolling window and the
/// short-lived threshold, all optional with sane defaults. `days` is sugar for
/// `hours`; if both are given, `hours` wins (the finer unit).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportQuery {
    /// Window length in hours. Defaults to [`DEFAULT_WINDOW_HOURS`].
    pub hours: Option<u64>,
    /// Window length in days (sugar for `hours`). Ignored when `hours` is set.
    pub days: Option<u64>,
    /// Short-lived threshold in seconds. Defaults to [`DEFAULT_SHORT_LIVED_SECS`].
    pub short_lived_secs: Option<u64>,
}

impl ReportQuery {
    /// The resolved window length, falling back through `hours` → `days` → default.
    fn window(&self) -> Duration {
        let hours = self
            .hours
            .or(self.days.map(|d| d.saturating_mul(24)))
            .unwrap_or(DEFAULT_WINDOW_HOURS);
        Duration::from_secs(hours.saturating_mul(3600))
    }

    /// The resolved short-lived threshold.
    fn short_lived(&self) -> Duration {
        Duration::from_secs(self.short_lived_secs.unwrap_or(DEFAULT_SHORT_LIVED_SECS))
    }
}

/// One workload the engine WOULD have isolated in the window: the entry, how often
/// the breach condition held, the projected would-be cut lifetime, and the FP-vs-real
/// classification. JSON-serializable so `/report.json` is self-contained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WouldActEntry {
    /// The internet-facing workload key that reached the exploitable verdict.
    pub entry: String,
    /// How many would-act episodes occurred in the window (consecutive runs of
    /// exploitable verdicts) — the frequency of the breach condition recurring.
    pub episodes: usize,
    /// How many breach decisions in the window affirmed exploitability for this entry
    /// (the raw "would-cut" frequency, ≥ `episodes`).
    pub would_act_decisions: usize,
    /// The longest projected would-be cut lifetime across this entry's episodes, in
    /// seconds — how long the cut would have stood at its most sustained.
    pub max_lifetime_secs: u64,
    /// Whether the longest episode is still OPEN (the breach condition is the entry's
    /// latest verdict in the window — the cut would still be standing now).
    pub open: bool,
    /// Short-lived (lifted within the threshold) ⇒ likely false positive. `false`
    /// when sustained. An open episode is never short-lived (it's still standing).
    pub short_lived: bool,
    /// At least one would-act episode fired during an enrichment-coverage gap — the
    /// model affirmed exploitability WITHOUT a CVE backing it (no advisory enrichment
    /// matched). These are the would-acts to scrutinize first.
    pub coverage_gap: bool,
    /// The model's verdict for the most recent would-act episode (its own words) — the
    /// human-readable "why it would have cut".
    pub last_verdict: String,
}

/// One proven path the model deliberately CLEARED in the window — the entry's latest
/// breach decision affirmed it is NOT exploitable. The trust half of the diff: a
/// reachable path protector proved out and left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeftAloneEntry {
    /// The internet-facing workload key whose latest verdict cleared it.
    pub entry: String,
    /// The model's clearing verdict (its own words — "not exploitable — …").
    pub verdict: String,
}

/// The aggregated shadow report (JEF-143): the would-have-acted diff over a rolling
/// window. JSON-serializable for `/report.json`; the HTML view renders the same data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The window length aggregated over, in seconds.
    pub window_secs: u64,
    /// The short-lived threshold applied, in seconds.
    pub short_lived_secs: u64,
    /// How many breach decisions fell within the window (the raw material).
    pub decisions_in_window: usize,
    /// Whether the journal had NO breach decisions at all (durable history is empty) —
    /// drives the honest "no decisions yet" state, distinct from "decisions, but none
    /// in this window".
    pub journal_empty: bool,
    /// Workloads the engine would have isolated, most-sustained first.
    pub would_act: Vec<WouldActEntry>,
    /// Proven paths the model cleared and left alone, the trust evidence.
    pub left_alone: Vec<LeftAloneEntry>,
}

impl Report {
    /// The headline would-act count: distinct workloads that would have been cut.
    pub fn would_act_count(&self) -> usize {
        self.would_act.len()
    }

    /// The headline left-alone count: distinct proven-but-cleared paths.
    pub fn left_alone_count(&self) -> usize {
        self.left_alone.len()
    }

    /// Would-acts flagged short-lived (the likely-FP subset).
    pub fn short_lived_count(&self) -> usize {
        self.would_act.iter().filter(|w| w.short_lived).count()
    }

    /// Would-acts that fired during an enrichment-coverage gap (scrutinize first).
    pub fn coverage_gap_count(&self) -> usize {
        self.would_act.iter().filter(|w| w.coverage_gap).count()
    }
}

/// A model verdict AFFIRMS exploitability when its own words begin with "exploitable"
/// (or "confirmed" — an already-corroborated live attack that should stand). A "not
/// exploitable — …" / "refuted" / "uncertain" verdict does not. This mirrors the
/// dashboard's [`flagged`] convention so the report and the findings table agree on
/// what counts as a would-act.
fn verdict_would_act(verdict: &str) -> bool {
    let v = verdict.trim_start().to_ascii_lowercase();
    v.starts_with("exploitable") || v.starts_with("confirmed")
}

/// A would-act decision fired during an enrichment-coverage gap when the model had NO
/// real enrichment to weigh: no CVE evidence AND no behavioral signal (JEF-145). The
/// classification reads the breach line's STRUCTURED [`EnrichmentCoverage`] — the same
/// evidence the model was given at decision time — never the verdict prose. A prose
/// mention of a CVE no longer reads as covered, and a well-enriched verdict that happens
/// not to print a CVE id no longer reads as a gap.
///
/// Back-compat (AC #3): a pre-JEF-145 line has no structured coverage (`None`). That is
/// "unknown", deliberately NOT a gap — an old record never inflates the scrutinize-first
/// count with a false positive.
fn is_coverage_gap(coverage: Option<&EnrichmentCoverage>) -> bool {
    match coverage {
        Some(c) => !c.is_backed(),
        None => false,
    }
}

/// Aggregate the journal's breach decisions into the would-have-acted diff (JEF-143).
/// Pure and total: takes the replayed entries (any order — they are sorted here by
/// time) and the wall-clock `now` (injected for testability), and folds each entry's
/// breach decisions into would-act episodes vs. left-alone clears. Read-only.
fn aggregate_report(
    entries: &[JournalEntry],
    now: SystemTime,
    window: Duration,
    short_lived: Duration,
) -> Report {
    let window_start = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
    let window_start_ms = window_start
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let now_ms = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Did the journal hold ANY breach decision at all? (Distinguishes a truly empty
    // journal from one with history but nothing in this particular window.)
    let mut any_breach = false;

    // Collect breach decisions per entry, in time order, restricted to the window.
    // BTreeMap keeps the output stable (entry-keyed) before the final sustained-first sort.
    // Each breach carries its structured enrichment-coverage (JEF-145) so the gap is
    // classified from the model's actual evidence, not the verdict prose.
    type Breach<'a> = (u64, &'a str, Option<&'a EnrichmentCoverage>); // (at_ms, verdict, coverage)
    let mut by_entry: BTreeMap<&str, Vec<Breach>> = BTreeMap::new();
    let mut sorted: Vec<&JournalEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.at_ms);
    let mut decisions_in_window = 0usize;
    for e in sorted {
        if let Decision::Breach {
            entry,
            verdict,
            coverage,
            ..
        } = &e.decision
        {
            any_breach = true;
            if e.at_ms >= window_start_ms {
                by_entry.entry(entry.as_str()).or_default().push((
                    e.at_ms,
                    verdict,
                    coverage.as_ref(),
                ));
                decisions_in_window += 1;
            }
        }
    }

    let mut would_act: Vec<WouldActEntry> = Vec::new();
    let mut left_alone: Vec<LeftAloneEntry> = Vec::new();

    for (entry, decisions) in by_entry {
        // Walk the entry's window decisions, folding consecutive exploitable verdicts
        // into episodes. An episode's lifetime runs from its first exploitable verdict
        // to the first NON-exploitable verdict that follows (the clear) — or to `now`
        // if it never cleared (still open). The closing decision's timestamp is the
        // best evidence of when the breach condition lifted in the journal.
        let mut episodes = 0usize;
        let mut would_act_decisions = 0usize;
        let mut max_lifetime_ms = 0u64;
        let mut max_open = false;
        let mut coverage_gap = false;
        let mut last_would_act_verdict: Option<&str> = None;

        let mut i = 0usize;
        while i < decisions.len() {
            let (start_ms, verdict, _) = decisions[i];
            if !verdict_would_act(verdict) {
                i += 1;
                continue;
            }
            // Start of an episode: consume the run of consecutive exploitable verdicts.
            episodes += 1;
            let mut j = i;
            let mut episode_gap = false;
            while j < decisions.len() && verdict_would_act(decisions[j].1) {
                would_act_decisions += 1;
                if is_coverage_gap(decisions[j].2) {
                    episode_gap = true;
                }
                last_would_act_verdict = Some(decisions[j].1);
                j += 1;
            }
            // The episode closes at the next (non-exploitable) decision if there is one,
            // else it's still open and projected to `now`.
            let (end_ms, open) = if j < decisions.len() {
                (decisions[j].0, false)
            } else {
                (now_ms, true)
            };
            let lifetime_ms = end_ms.saturating_sub(start_ms);
            if open {
                // An open episode is the most-sustained by definition (still standing);
                // prefer it, and never mark it short-lived.
                if !max_open || lifetime_ms > max_lifetime_ms {
                    max_lifetime_ms = lifetime_ms;
                }
                max_open = true;
            } else if !max_open && lifetime_ms > max_lifetime_ms {
                max_lifetime_ms = lifetime_ms;
            }
            coverage_gap |= episode_gap;
            i = j;
        }

        if episodes > 0 {
            let short = !max_open && max_lifetime_ms < short_lived.as_millis() as u64;
            would_act.push(WouldActEntry {
                entry: entry.to_string(),
                episodes,
                would_act_decisions,
                max_lifetime_secs: max_lifetime_ms / 1000,
                open: max_open,
                short_lived: short,
                coverage_gap,
                last_verdict: last_would_act_verdict.unwrap_or_default().to_string(),
            });
        } else {
            // No would-act episode in the window: the entry's paths were all proven and
            // CLEARED. The trust half — surface the latest (clearing) verdict.
            if let Some((_, verdict, _)) = decisions.last() {
                left_alone.push(LeftAloneEntry {
                    entry: entry.to_string(),
                    verdict: verdict.to_string(),
                });
            }
        }
    }

    // Most-sustained first: open episodes, then by lifetime descending, then by entry
    // for a stable order.
    would_act.sort_by(|a, b| {
        b.open
            .cmp(&a.open)
            .then(b.max_lifetime_secs.cmp(&a.max_lifetime_secs))
            .then(a.entry.cmp(&b.entry))
    });
    left_alone.sort_by(|a, b| a.entry.cmp(&b.entry));

    Report {
        window_secs: window.as_secs(),
        short_lived_secs: short_lived.as_secs(),
        decisions_in_window,
        journal_empty: !any_breach,
        would_act,
        left_alone,
    }
}

/// Render a `Duration`-in-seconds as a compact human span ("4m", "2h", "3d") for the
/// would-be cut lifetime column. Sub-minute spans read as seconds (the short-lived
/// tell).
fn human_span(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// The `/report` HTML body: the would-have-acted diff (JEF-143). Empty journal ⇒ an
/// honest "no decisions yet" state. Otherwise the headline diff sentence, the would-act
/// table (short-lived visually distinct, coverage-gap flagged), and the left-alone
/// trust evidence.
fn report_panel(report: &Report) -> String {
    let window = human_span(report.window_secs);
    if report.journal_empty {
        return format!(
            "<p class=\"muted\">no decisions yet — the decision journal is empty (no pass has \
             recorded a breach decision, or no durable journal volume is configured). Once the \
             engine judges an internet-facing workload, this report fills in over the last \
             {window}.</p>"
        );
    }
    if report.would_act.is_empty() && report.left_alone.is_empty() {
        return format!(
            "<p class=\"muted\">no breach decisions in the last {window} (the journal has older \
             history — widen the window with <code>?days=N</code>).</p>"
        );
    }

    // The diff headline: would-isolate N, left M proven-but-cleared paths alone.
    let head = format!(
        "<div class=\"sum\">over the last <b>{window}</b> protector would have isolated \
         <b>{act}</b> workload{act_s} and deliberately left <b>{left}</b> proven-but-cleared \
         path{left_s} alone. {short} short-lived (likely FP) · {gap} with thin evidence \
         coverage (scrutinize first).</div>",
        act = report.would_act_count(),
        act_s = if report.would_act_count() == 1 {
            ""
        } else {
            "s"
        },
        left = report.left_alone_count(),
        left_s = if report.left_alone_count() == 1 {
            ""
        } else {
            "s"
        },
        short = report.short_lived_count(),
        gap = report.coverage_gap_count(),
    );

    let would_rows: String = if report.would_act.is_empty() {
        "<tr><td class=\"muted\" colspan=\"5\">none — every proven path was cleared</td></tr>"
            .to_string()
    } else {
        report
            .would_act
            .iter()
            .map(|w| {
                // Lifetime: sustained vs short-lived is the FP tell, made visually distinct.
                let life = if w.open {
                    format!(
                        "<span class=\"sustained\">{} (open)</span>",
                        human_span(w.max_lifetime_secs)
                    )
                } else if w.short_lived {
                    format!(
                        "<span class=\"shortlived\">{} (short-lived)</span>",
                        human_span(w.max_lifetime_secs)
                    )
                } else {
                    format!(
                        "<span class=\"sustained\">{}</span>",
                        human_span(w.max_lifetime_secs)
                    )
                };
                let gap = if w.coverage_gap {
                    "<span class=\"flagged\">coverage gap</span>".to_string()
                } else {
                    "<span class=\"muted\">—</span>".to_string()
                };
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>\
                     <td class=\"verdict-cell\">{}</td></tr>",
                    escape(&short(&w.entry)),
                    w.would_act_decisions,
                    life,
                    gap,
                    escape(&w.last_verdict),
                )
            })
            .collect()
    };

    let left_rows: String = if report.left_alone.is_empty() {
        "<tr><td class=\"muted\" colspan=\"2\">none</td></tr>".to_string()
    } else {
        report
            .left_alone
            .iter()
            .map(|l| {
                format!(
                    "<tr><td><code>{}</code></td><td class=\"verdict-cell\">{}</td></tr>",
                    escape(&short(&l.entry)),
                    escape(&l.verdict),
                )
            })
            .collect()
    };

    format!(
        "{head}\
         <h3>Would have isolated <span class=\"muted\">({act})</span></h3>\
         <table class=\"vectors\"><thead><tr><th>Workload</th><th>Would-cut decisions</th>\
         <th>Projected cut lifetime</th><th>Evidence coverage</th><th>Latest verdict</th></tr></thead>\
         <tbody>{would_rows}</tbody></table>\
         <h3>Left alone <span class=\"muted\">({left}) — proven, then cleared</span></h3>\
         <table class=\"vectors\"><thead><tr><th>Workload</th><th>Clearing verdict</th></tr></thead>\
         <tbody>{left_rows}</tbody></table>",
        act = report.would_act_count(),
        left = report.left_alone_count(),
    )
}

/// The full `/report` HTML page (JEF-143): a self-contained page wrapping
/// [`report_panel`], styled in the dashboard's idiom. No graph renderer needed (no
/// Mermaid), so the page is plain HTML — the would-have-acted diff that gates exiting
/// shadow (JEF-50).
fn render_report_html(report: &Report) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>protector — would-have-acted report</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         h1{{font-size:1.2rem;font-weight:600;margin:0}}\
         h2{{font-size:1rem;font-weight:600;margin:1.6rem 0 .4rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}}\
         h3{{font-size:.9rem;font-weight:600;margin:1.2rem 0 .3rem;color:#333}}\
         .sum{{margin:.4rem 0 1rem;color:#444;font-size:.9rem}}\
         .muted{{color:#777}}\
         a{{color:#06c}}\
         code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors{{border-collapse:collapse;font-size:.82rem;margin:.2rem 0 .6rem;width:100%}}\
         table.vectors th{{text-align:left;font-weight:600;color:#444;border-bottom:1px solid #ddd;padding:.25rem .5rem}}\
         table.vectors td{{padding:.25rem .5rem;border-bottom:1px solid #f0f0f0;vertical-align:top}}\
         table.vectors code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors .flagged{{color:#b00000;font-weight:600}}\
         .sustained{{color:#b00000;font-weight:600}}\
         .shortlived{{color:#9a5b00}}\
         .verdict-cell{{color:#333;max-width:38rem}}\
         </style></head><body>\
         <h1>protector — would-have-acted report</h1>\
         <p class=\"sum\">The shadow diff that gates exiting shadow: over a rolling \
         window, the workloads protector <b>would</b> have isolated, how often the breach \
         condition held, the projected cut lifetime (short-lived = likely false positive), and \
         the proven paths the model deliberately <b>left alone</b> — the trust evidence. \
         Read-only; no action. Tune the window with <code>?days=N</code> or <code>?hours=N</code> \
         and the short-lived threshold with <code>?short_lived_secs=N</code>. \
         &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; <a href=\"/report.json\">json</a></p>\
         <h2>Shadow would-have-acted diff</h2>\
         {body}\
         </body></html>",
        body = report_panel(report),
    )
}

// ===========================================================================
// The human "why" view for /judgements (JEF-161)
// ===========================================================================
//
// `/judgements` was JSON-only — an operator hitting it got a wall of escaped prompt
// text. This adds a human HTML view (mirroring how `/report` is wired) that leads with
// the posture chip + the model's prose, surfaces the three honest meta-states, and tucks
// the raw prompt+reply behind a `<details>` expander. The prompt is the injection surface
// (JEF-106); operators read the verdict, not the prompt. The JSON moves to
// `/judgements.json` (the route is documented in [`serve_dashboard`]).

/// One `/judgements` card (JEF-161): the posture chip + the model's prose, then the
/// three meta-states surfaced honestly, with the raw prompt+reply behind an expander.
fn judgement_card(j: &Judgement) -> String {
    // The posture from the final verdict (Debug form, e.g. `Exploitable("…")`). `flagged`
    // lowercases, so the capitalized Debug variant still maps correctly.
    let posture = Posture::of(Some(&j.verdict));
    let chip = format!(
        "<span class=\"chip {}\">{}</span>",
        posture.tone(),
        posture.label()
    );

    // The three honest meta-states (JEF-161 AC #3):
    //   prompt: None  → the deterministic pre-filter decided without the model (JEF-112).
    //   reply:  None  → the model timed out; the engine fell back to a safe verdict.
    //   normal        → the model answered; show its prose verdict.
    let lead = if j.prompt.is_none() {
        "<span class=\"meta\">decided without the model (pre-filter)</span>".to_string()
    } else if j.reply.is_none() {
        "<span class=\"meta\">model timed out — safe fallback</span>".to_string()
    } else {
        format!("<span class=\"vwords\">{}</span>", escape(&j.verdict))
    };

    // The raw prompt+reply behind a power-user expander — the injection surface stays a
    // diagnostic, not something operators are asked to grade (JEF-106).
    let raw = format!(
        "<details class=\"raw\"><summary>show full prompt</summary>\
         <div class=\"raw-cap\">prompt sent to the model</div><pre>{}</pre>\
         <div class=\"raw-cap\">raw model reply</div><pre>{}</pre></details>",
        escape(j.prompt.as_deref().unwrap_or("(none — pre-filter decided)")),
        escape(j.reply.as_deref().unwrap_or("(none — model timed out)")),
    );

    format!(
        "<div class=\"card\"><div class=\"vline\">{chip} {lead}</div>\
         <div class=\"kc2\"><code>{}</code> <span class=\"muted\">· {} target{} it can reach weighed</span></div>\
         {raw}</div>",
        escape(&short(&j.entry)),
        j.objectives,
        if j.objectives == 1 { "" } else { "s" },
    )
}

/// The full `/judgements` HTML page (JEF-161): the human "why" view — one card per recent
/// judgement, led by the posture chip + the model's prose, the three meta-states surfaced,
/// the raw prompt behind an expander. Self-contained, styled in the dashboard's idiom. The
/// machine-readable form stays at `/judgements.json`.
fn render_judgements_html(judgements: &[Judgement]) -> String {
    let body = if judgements.is_empty() {
        "<p class=\"muted\">no model judgements yet (the model hasn't reached an \
         internet-facing service — a slow CPU model takes a few passes after a restart)</p>"
            .to_string()
    } else {
        judgements.iter().map(judgement_card).collect()
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>protector — judgements</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         h1{{font-size:1.2rem;font-weight:600;margin:0}}\
         h2{{font-size:1rem;font-weight:600;margin:1.6rem 0 .4rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}}\
         .sum{{margin:.4rem 0 1rem;color:#444;font-size:.9rem}}\
         .muted{{color:#777}}\
         a{{color:#06c}}\
         code{{background:#f4f4f4;padding:0 .2rem}}\
         .card{{border:1px solid #e3e3e3;border-radius:0;padding:.5rem .7rem;margin:.6rem 0}}\
         .kc2{{font-size:.75rem;color:#666;margin:.15rem 0 .3rem}}\
         .vline{{font-size:.92rem;line-height:1.4;margin:.1rem 0 .4rem}}\
         .vwords{{color:#111}}\
         .meta{{color:#555;font-style:italic}}\
         .chip{{font-family:ui-monospace,monospace;font-size:.72rem;font-weight:700;letter-spacing:.02em;padding:.05rem .35rem;border-radius:2px;border:1px solid;margin-right:.35rem;white-space:nowrap}}\
         .chip-breach{{color:#7a0000;background:#fdecec;border-color:#b00000}}\
         .chip-safe{{color:#155f29;background:#eef7f0;border-color:#1a7f37}}\
         .chip-awaiting{{color:#555;background:#f4f4f4;border-color:#ccc}}\
         .raw summary{{cursor:pointer;color:#06c;font-size:.8rem}}\
         .raw-cap{{font-size:.72rem;font-weight:600;color:#444;margin:.4rem 0 .1rem}}\
         .raw pre{{white-space:pre-wrap;word-break:break-word;background:#f7f7f7;border:1px solid #eee;padding:.4rem .5rem;font-size:.72rem;margin:0}}\
         </style></head><body>\
         <h1>protector — judgements</h1>\
         <p class=\"sum\">Why the model called each internet-facing service the way it did — \
         the posture and the model's own words first. The raw prompt+reply is behind \
         <i>show full prompt</i> (a power-user diagnostic; the prompt is the part an attacker \
         could try to poison). &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; \
         <a href=\"/judgements.json\">json</a></p>\
         <h2>Recent judgements <span class=\"muted\">({n})</span></h2>\
         {body}\
         </body></html>",
        n = judgements.len(),
    )
}

// ===========================================================================
// The readiness / coverage panel (JEF-160)
// ===========================================================================
//
// When the model, KEV/advisory file, Falco feed, eBPF agent, or journal volume is
// unconfigured or down, protector degrades SILENTLY — a cluster with no model renders the
// same "quiet" empty page as a genuinely clean one (ADR-0016: enrichment coverage is
// load-bearing). This panel lists each enrichment/decision input and its LIVE state, so
// the operator can tell "all clear" from "blind", and a new operator gets a guided start.
// Read-only, zero-egress: presence/health only — no secret names, no graph data, no values.

/// The LIVE state of one decision input — present, absent, or degraded. Distinct from a
/// config echo: an input is `Absent` only when it is genuinely unconfigured/empty, and
/// `Degraded` when configured but not currently answering (e.g. a model that timed out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputState {
    /// Wired and live — contributing to decisions this pass.
    Present,
    /// Not configured (or loaded empty). For an enrichment input this is a coverage gap
    /// that weakens the model's decision (ADR-0016); rendered visually distinct.
    Absent,
    /// Configured but not currently healthy — e.g. the model is attached but its last call
    /// timed out, or signals were expected this pass but none arrived.
    Degraded,
}

impl InputState {
    /// The status WORD shown in text (never glyph-only — accessibility). The state's
    /// meaning is carried by this word; color only reinforces it.
    fn word(self) -> &'static str {
        match self {
            InputState::Present => "present",
            InputState::Absent => "absent",
            InputState::Degraded => "degraded",
        }
    }

    /// The CSS tone class — maps to the readiness tokens in the dashboard `<style>` block:
    /// green for present (the JEF-159 `#1a7f37` token), red for an absent input that
    /// weakens decisions, amber for degraded.
    fn tone(self) -> &'static str {
        match self {
            InputState::Present => "ok",
            InputState::Absent => "absent",
            InputState::Degraded => "degraded",
        }
    }
}

/// One readiness row: a decision input, its LIVE state, a one-line "why it matters", the
/// single env var / mount that enables it, and the live detail (a count, "last call ok",
/// "shadow"). `weakens_decisions` is true when this input being absent degrades the model's
/// call (the enrichment inputs of ADR-0016) — those absent rows are visually distinct.
/// JSON-serializable so `/readiness` returns exactly the panel's data.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessRow {
    /// A stable, machine-readable id for the input (`model` / `kev` / `advisory` /
    /// `falco` / `ebpf-agent` / `journal` / `arm-state`).
    pub id: &'static str,
    /// The human label shown in the panel.
    pub label: &'static str,
    /// The LIVE state of this input.
    pub state: InputState,
    /// One-line "why it matters" — what protector loses without this input.
    pub why: &'static str,
    /// The single env var or mount to enable it (the "how to fix" the checklist links to).
    /// Empty for arm-state, which is a posture toggle, not a missing input.
    pub enable: &'static str,
    /// A short live detail: a count, "last call ok", "shadow mode", etc. — never a value
    /// or secret name.
    pub detail: String,
    /// Whether this input being absent WEAKENS the model's decision (the enrichment /
    /// adjudication inputs — ADR-0016). Drives the "absent input that weakens decisions is
    /// visually distinct" acceptance criterion.
    pub weakens_decisions: bool,
}

/// The whole readiness snapshot (JEF-160): every decision input's LIVE state plus the
/// cold-start flag. JSON-serializable for `/readiness`; the HTML panel renders the same
/// data. `warming_up` mirrors the banner's [`ClusterStatus::WarmingUp`]: no pass has
/// completed, so the first verdicts are still loading (expected on a CPU model).
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// One row per decision input, in a stable, decision-ordered sequence.
    pub inputs: Vec<ReadinessRow>,
    /// No pass has completed yet — the bake window (first verdicts can take minutes on a
    /// CPU model) is still open. Drives the cold-start note.
    pub warming_up: bool,
    /// The model is actually answering RIGHT NOW — attached AND its last call was decisive
    /// ([`ModelHealth::Ok`]). False when no model is configured, or it timed out / hasn't
    /// been exercised this run. The banner (JEF-174) keys its "the model cleared them"
    /// clearance claim on this: a calm/green `Watching`/`Quiet` is only honest while the
    /// model is live; otherwise exposed paths are unjudged, not cleared (ADR-0016).
    pub model_judging: bool,
}

impl Readiness {
    /// How many enrichment/decision inputs are absent or degraded — the count the
    /// first-run discrimination keys on. Arm-state is posture, not an input gap, so it
    /// never counts here.
    pub fn unmet_count(&self) -> usize {
        self.inputs
            .iter()
            .filter(|r| r.id != "arm-state" && r.state != InputState::Present)
            .count()
    }

    /// Whether ANY decision input is unmet (absent or degraded) — the first-run gate.
    pub fn has_unmet(&self) -> bool {
        self.unmet_count() > 0
    }
}

/// Derive the readiness snapshot (JEF-160) from the engine's config summary and LIVE
/// state. PURE and total — no model call, no I/O: the model row reads the piggybacked
/// last-adjudication outcome, the behavioral rows read this pass's [`BakeStats`], and the
/// cold-start flag reads `last_pass`. This is the tested core; the panel and `/readiness`
/// both render its output.
fn derive_readiness(
    config: &ReadinessConfig,
    model_health: ModelHealth,
    bake: &BakeStats,
    last_pass: Option<SystemTime>,
) -> Readiness {
    let warming_up = last_pass.is_none();

    // The behavioral split (JEF-48 variant labels): Falco arrives as the `alert` variant;
    // every other variant is an eBPF-agent signal. We report each feed's "signals last
    // pass" from the per-variant counts the bake already holds.
    let falco_signals: u64 = bake.signals_by_variant.get("alert").copied().unwrap_or(0);
    let ebpf_signals: u64 = bake
        .signals_by_variant
        .iter()
        .filter(|(variant, _)| variant.as_str() != "alert")
        .map(|(_, n)| n)
        .sum();

    // The model is "judging" — giving live verdicts the banner can lean on — only when it
    // is attached AND its last fresh call was decisive. A timeout, a cold start, or no model
    // at all all mean "not judging right now" (JEF-174): the decision still falls through to
    // the deterministic skeptic, but the banner must not call that a clearance (ADR-0016).
    let model_judging = config.model_attached && model_health == ModelHealth::Ok;

    // The model row: attached or not, and (if attached) its last-call health. A timeout is
    // Degraded, not Absent — the model IS configured, it just isn't answering right now.
    let (model_state, model_detail) = if !config.model_attached {
        (
            InputState::Absent,
            "no model configured — no exploitability calls are made".to_string(),
        )
    } else {
        match model_health {
            ModelHealth::Ok => (InputState::Present, "attached · last call ok".to_string()),
            ModelHealth::Timeout => (
                InputState::Degraded,
                "attached · last call timed out (CPU model warming or endpoint down)".to_string(),
            ),
            ModelHealth::Unknown => (
                // Attached but not yet exercised: cold start, not a fault. Degraded so the
                // operator sees "no verdict yet" rather than a false "present".
                InputState::Degraded,
                "attached · no call yet this run (warming up)".to_string(),
            ),
        }
    };

    // A file-backed enrichment store is Present iff it loaded >=1 entry, else Absent.
    let kev_state = present_if(config.kev_count > 0);
    let advisory_state = present_if(config.advisory_count > 0);

    // A behavioral feed is Present iff it delivered >=1 signal this pass, else Absent. (A
    // genuinely quiet cluster reads as Absent for the pass — the panel's "signals last
    // pass" detail and the cold-start note keep that honest rather than alarming.)
    let falco_state = present_if(falco_signals > 0);
    let ebpf_state = present_if(ebpf_signals > 0);

    let journal_state = present_if(config.journal_durable);

    let inputs = vec![
        ReadinessRow {
            id: "model",
            label: "Model adjudicator",
            state: model_state,
            why: "decides whether a proven chain is a real breach — without it, nothing is judged exploitable",
            enable: "PROTECTOR_ENGINE_MODEL",
            detail: model_detail,
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "kev",
            label: "KEV catalogue",
            state: kev_state,
            why: "flags known-exploited CVEs so the model weighs active threats first",
            enable: "PROTECTOR_KEV_FILE",
            detail: coverage_detail(config.kev_count, "known-exploited CVE id"),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "advisory",
            label: "Advisory store",
            state: advisory_state,
            why: "adds CVE summaries + fix versions — the evidence the model judges with",
            enable: "PROTECTOR_ADVISORY_FILE",
            detail: coverage_detail(config.advisory_count, "advisory record"),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "falco",
            label: "Falco feed",
            state: falco_state,
            why: "live rule-fired alerts confirm a path is being exploited right now",
            enable: "runtime ingest (falcosidekick -> /alert)",
            detail: signals_detail(falco_state, falco_signals),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "ebpf-agent",
            label: "eBPF agent",
            state: ebpf_state,
            why: "in-kernel behavioral signals (exec, secret reads, connections) show live activity",
            enable: "deploy the agent DaemonSet (-> /behavior)",
            detail: signals_detail(ebpf_state, ebpf_signals),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "journal",
            label: "Decision journal",
            state: journal_state,
            why: "durable verdicts survive a restart and back the would-have-acted report — without it, history resets",
            enable: "PROTECTOR_ENGINE_JOURNAL_PATH",
            detail: if config.journal_durable {
                "durable volume mounted".to_string()
            } else {
                "in-memory only — resets on restart".to_string()
            },
            weakens_decisions: false,
        },
        ReadinessRow {
            id: "arm-state",
            label: "Arm state",
            // Posture, never a gap: shadow is the safe default. Always Present (the engine
            // is always in one of the two states); the detail says which.
            state: InputState::Present,
            why: "shadow proposes cuts only; enforcing applies the reversible isolation automatically",
            enable: "",
            detail: if config.armed {
                "enforcing (acting)".to_string()
            } else {
                "shadow (proposing only)".to_string()
            },
            weakens_decisions: false,
        },
    ];

    Readiness {
        inputs,
        warming_up,
        model_judging,
    }
}

/// Present iff the condition holds, else Absent.
fn present_if(present: bool) -> InputState {
    if present {
        InputState::Present
    } else {
        InputState::Absent
    }
}

/// The live detail for a file-backed store: "N records loaded" or the honest absent line.
fn coverage_detail(count: usize, noun: &str) -> String {
    if count == 0 {
        format!("not loaded — no {noun} evidence available")
    } else {
        format!("{count} {noun}{} loaded", if count == 1 { "" } else { "s" })
    }
}

/// The live detail for a behavioral feed: "N signals last pass", or an honest "none this
/// pass" when absent (no sensor reporting, or a quiet cluster).
fn signals_detail(state: InputState, signals: u64) -> String {
    match state {
        InputState::Present => format!(
            "{signals} signal{} last pass",
            if signals == 1 { "" } else { "s" }
        ),
        _ => "no signals last pass (no sensor reporting, or a quiet cluster)".to_string(),
    }
}

/// The readiness / coverage panel (JEF-160): an ordered `<ol>` of every decision input
/// with its LIVE state IN TEXT (not glyph-only — accessibility), the one-line why, the
/// live detail, and (when unmet) the single env var / mount to enable it. An absent input
/// that weakens decisions is visually distinct (the red `absent` tone + a "weakens
/// decisions" tag). Pure over the derived [`Readiness`].
fn readiness_panel(readiness: &Readiness) -> String {
    let rows: String = readiness
        .inputs
        .iter()
        .map(|r| {
            // The enable hint shows only when the input is not Present — a met input needs
            // no instruction. Arm-state has no enable hint (it's a posture toggle).
            let enable = if r.state != InputState::Present && !r.enable.is_empty() {
                format!(
                    " <span class=\"r-enable\">enable: <code>{}</code></span>",
                    escape(r.enable)
                )
            } else {
                String::new()
            };
            // An absent input that weakens decisions is called out distinctly (text tag, not
            // color alone) so a coverage gap can't hide as a benign "off".
            let weak = if r.weakens_decisions && r.state != InputState::Present {
                " <span class=\"r-weak\">weakens decisions</span>".to_string()
            } else {
                String::new()
            };
            format!(
                "<li class=\"r-row r-{tone}\"><span class=\"r-label\">{label}</span> \
                 <span class=\"r-state r-state-{tone}\">{state}</span>{weak}<br>\
                 <span class=\"r-why\">{why}</span> \
                 <span class=\"r-detail\">— {detail}</span>{enable}</li>",
                tone = r.state.tone(),
                label = escape(r.label),
                state = r.state.word(),
                why = escape(r.why),
                detail = escape(&r.detail),
            )
        })
        .collect();

    let cold = if readiness.warming_up {
        "<p class=\"r-cold\">warming up — the first pass hasn't completed; first verdicts can \
         take a few minutes on a CPU model, so a quiet dashboard right after start is expected.</p>"
    } else {
        ""
    };

    format!("{cold}<ol class=\"readiness\">{rows}</ol>")
}

/// The instructional first-run checklist (JEF-160): when the engine has no findings AND
/// inputs are unmet, this REPLACES the empty findings body — never a bare/error-looking
/// page. Each unmet input is an actionable line linking the one env var / mount to enable
/// it (status IN TEXT, ordered list — accessibility). A met input reads as a done check.
fn first_run_checklist(readiness: &Readiness) -> String {
    let items: String = readiness
        .inputs
        .iter()
        // Arm-state is posture, not a setup step — skip it in the checklist.
        .filter(|r| r.id != "arm-state")
        .map(|r| {
            if r.state == InputState::Present {
                format!(
                    "<li class=\"r-done\"><b>done</b> — {label}: {detail}</li>",
                    label = escape(r.label),
                    detail = escape(&r.detail),
                )
            } else {
                let enable = if r.enable.is_empty() {
                    String::new()
                } else {
                    format!(" — set <code>{}</code>", escape(r.enable))
                };
                format!(
                    "<li class=\"r-todo\"><b>to&nbsp;do</b> — {label}: {why}{enable}</li>",
                    label = escape(r.label),
                    why = escape(r.why),
                )
            }
        })
        .collect();

    let cold = if readiness.warming_up {
        "<p class=\"r-cold\">warming up — first verdicts can take a few minutes on a CPU model.</p>"
    } else {
        ""
    };

    format!(
        "<div class=\"firstrun\"><p class=\"sum\">No findings yet, and some decision inputs \
         aren't configured. protector degrades quietly when an input is missing — this \
         checklist is the guided start, not a blank page. Wire each input below to give the \
         model the full picture.</p>{cold}<ol class=\"checklist\">{items}</ol></div>"
    )
}

/// The glanceable cluster verdict (JEF-159): the one-word answer the status banner
/// carries, so the operator reads "is my cluster OK right now?" without synthesizing it
/// from the engine-internal counts below. Each state is a distinct word + glyph + color
/// (never color alone — the meaning is in the text), computed as a PURE function of the
/// current snapshot ([`cluster_status`]) — no new model call. Ordered from worst to best.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterStatus {
    /// `last_pass` is `None` — no pass has completed, so there are no verdicts yet. We
    /// show progress, NOT a blank and NOT a false "OK": a warming cluster is unknown, not
    /// clear.
    WarmingUp,
    /// ≥1 breach-relevant finding the model affirmed exploitable now, AND a cut is in
    /// force for it (armed + an auto-eligible remediation, which renders as "applied").
    /// The breach is real but contained — red border on a calm fill, distinct from a
    /// live, un-cut breach.
    Isolated,
    /// ≥1 breach-relevant finding the model affirmed exploitable now, with no cut in
    /// force. The one red state: a live breach the operator must look at.
    BreachLive,
    /// Exposed breach-relevant endpoints exist and the model is NOT answering (no model
    /// configured, or its last call timed out / hasn't landed this run — JEF-174). Nothing
    /// is flagged, but that is the deterministic skeptic default, NOT a model clearance: the
    /// single most load-bearing input is absent (ADR-0016). Non-green (amber) — these paths
    /// are unjudged, not confirmed safe. Ranked worse than `Watching` (a real clearance).
    Unjudged,
    /// Exposed breach-relevant endpoints exist, the model IS answering, and it cleared them
    /// all (none exploitable). Calm green — actively watched, a live verdict, nothing live.
    Watching,
    /// No breach-relevant exposure at all. Calm green — nothing reaches an objective.
    Quiet,
}

impl ClusterStatus {
    /// The one word the banner leads with — the glanceable answer.
    fn word(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "Warming up",
            ClusterStatus::Isolated => "Isolated",
            ClusterStatus::BreachLive => "Breach — live",
            ClusterStatus::Unjudged => "Unjudged",
            ClusterStatus::Watching => "Watching",
            ClusterStatus::Quiet => "Quiet",
        }
    }

    /// A leading glyph so the state is legible without color (accessibility): the meaning
    /// is carried by word + glyph, color only reinforces it.
    fn glyph(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "◌",
            ClusterStatus::Isolated => "▣",
            ClusterStatus::BreachLive => "▲",
            ClusterStatus::Unjudged => "◍",
            ClusterStatus::Watching => "●",
            ClusterStatus::Quiet => "●",
        }
    }

    /// The CSS class for the banner's tone — maps to the tokens in the `<style>` block.
    /// `ok` is the new calm/green token (the first "healthy" color); `breach` is the
    /// reserved red; `isolated` is red-border-on-calm; `warming` is muted; `unjudged` is the
    /// amber/degraded token (JEF-174) — explicitly NOT green, because nothing was cleared.
    fn tone(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "warming",
            ClusterStatus::Isolated => "isolated",
            ClusterStatus::BreachLive => "breach",
            ClusterStatus::Unjudged => "unjudged",
            ClusterStatus::Watching | ClusterStatus::Quiet => "ok",
        }
    }
}

/// The glanceable cluster status (JEF-159) — a PURE function over the snapshot the
/// dashboard already has: the resolved findings, whether the engine is armed, and the
/// last-pass time. No model call. The verdict is read from each finding's RESOLVED
/// verdict (JEF-157: the snapshot resolves it from the unified per-entry store), and a
/// finding counts as a live breach exactly when [`flagged`] is true for it.
///
/// `cut_applied` is whether a cut is actually in force — at the render layer that is
/// "armed AND an auto-eligible breach remediation exists" (an auto-eligible breach
/// finding renders as "applied" when armed; in shadow it only "would apply").
///
/// `model_judging` (JEF-174) is whether the model is actually answering right now (attached
/// AND last call decisive — [`Readiness::model_judging`]). It gates the ONE clearance claim:
/// exposed-but-unflagged paths are `Watching` (a real, green "the model cleared them") only
/// while the model is live; otherwise they are [`Unjudged`](ClusterStatus::Unjudged) —
/// non-green, because "nothing flagged" is the deterministic skeptic default, not a verdict
/// (ADR-0016). It never relaxes a breach state, only withholds a clearance.
fn cluster_status(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    model_judging: bool,
) -> ClusterStatus {
    // No pass yet ⇒ no verdicts ⇒ never claim OK (warming, not blank, not clear).
    if last_pass.is_none() {
        return ClusterStatus::WarmingUp;
    }

    let breach = findings.iter().filter(|f| f.breach_relevant);
    let mut exposed = 0usize;
    let mut live_breach = false;
    let mut cut_applied = false;
    for f in breach {
        exposed += 1;
        if flagged(f.verdict.as_deref()) {
            live_breach = true;
            // A cut is in force for a flagged breach only when the engine is armed AND the
            // chain is auto-eligible (it would render "applied", not "would apply").
            if armed && f.disposition == AUTO_ELIGIBLE {
                cut_applied = true;
            }
        }
    }

    match (live_breach, cut_applied, exposed) {
        (true, true, _) => ClusterStatus::Isolated,
        (true, false, _) => ClusterStatus::BreachLive,
        // No exposure at all ⇒ nothing for the model to clear, so model health is moot:
        // `Quiet` makes no clearance claim ("no exposure reaches an objective") regardless.
        (false, _, 0) => ClusterStatus::Quiet,
        // Exposure exists and nothing is flagged: `Watching` (a green "the model cleared
        // them") is honest ONLY while the model is live. Otherwise the all-clear is just the
        // skeptic default with no model behind it ⇒ `Unjudged`, non-green (JEF-174).
        (false, _, _) if model_judging => ClusterStatus::Watching,
        (false, _, _) => ClusterStatus::Unjudged,
    }
}

/// The full-width status banner (JEF-159): the first child of `<body>`, above `<h1>`.
/// `role="status"` + `aria-live="polite"` so a screen reader announces a change; the
/// meaning is in the WORD + glyph + subtitle, never color alone. The subtitle is the
/// freshness + arm-state line. Pure over the same inputs as [`cluster_status`].
fn status_banner(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    freshness: &str,
    model_judging: bool,
) -> String {
    let status = cluster_status(findings, armed, last_pass, model_judging);
    let exposed = findings
        .iter()
        .filter(|f| f.breach_relevant)
        .map(|f| f.entry.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let flagged_n = findings
        .iter()
        .filter(|f| f.breach_relevant && flagged(f.verdict.as_deref()))
        .map(|f| f.entry.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    // The detail line states the count and (for a breach) anchors to the endpoint cards.
    let detail = match status {
        ClusterStatus::WarmingUp => "first pass not yet complete — verdicts loading".to_string(),
        ClusterStatus::Isolated => format!(
            "{flagged_n} exploitable path{} — <a href=\"#attack-paths\">cut applied, contained</a>",
            if flagged_n == 1 { "" } else { "s" }
        ),
        ClusterStatus::BreachLive => format!(
            "{flagged_n} exploitable path{} — <a href=\"#attack-paths\">needs attention now</a>",
            if flagged_n == 1 { "" } else { "s" }
        ),
        ClusterStatus::Unjudged => format!(
            "{exposed} exposed path{} — <a href=\"#coverage\">the model isn't judging right now, \
             so none are confirmed safe</a>",
            if exposed == 1 { "" } else { "s" }
        ),
        ClusterStatus::Watching => format!(
            "{exposed} exposed path{} watched, none exploitable — the model cleared them",
            if exposed == 1 { "" } else { "s" }
        ),
        ClusterStatus::Quiet => "no internet-facing service can reach a target".to_string(),
    };

    // The arm-state half of the subtitle: shadow (proposing only) vs live (acting).
    let arm = if armed {
        "armed (acting)"
    } else {
        "shadow mode (proposing only)"
    };

    format!(
        "<div class=\"banner banner-{tone}\" role=\"status\" aria-live=\"polite\">\
         <div class=\"banner-head\"><span class=\"banner-glyph\" aria-hidden=\"true\">{glyph}</span>\
         <span class=\"banner-word\">{word}</span></div>\
         <div class=\"banner-detail\">{detail}</div>\
         <div class=\"banner-sub\">last scan {freshness} · auto-refresh 30s · {arm}</div>\
         </div>",
        tone = status.tone(),
        glyph = status.glyph(),
        word = status.word(),
    )
}

/// The persistent nav (JEF-159) shown across the read-only views. `current` is the path
/// of the page being rendered, marked `aria-current="page"`.
fn nav_bar(current: &str) -> String {
    // Trimmed to answer-first (JEF-175): dashboard · why · shadow log. `/readiness`,
    // `/bake`, and `/reversions` are de-listed (their routes stay reachable — they're
    // surfaced as the collapsed "Engine & coverage" sections / the "Recently lifted"
    // section's json link).
    const LINKS: [(&str, &str); 3] = [
        ("/", "dashboard"),
        ("/judgements", "why"),
        ("/report", "shadow log"),
    ];
    let items: String = LINKS
        .iter()
        .map(|(href, label)| {
            if *href == current {
                format!("<a href=\"{href}\" aria-current=\"page\">{label}</a>")
            } else {
                format!("<a href=\"{href}\">{label}</a>")
            }
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<nav class=\"nav\" aria-label=\"views\">{items}</nav>")
}

/// Render the dashboard: graph-based sections plus the freshness line and the
/// recent-reversions panel (JEF-141).
///   1. Remediations the engine applies (or proposes, in shadow), each a graph with
///      the cut marked.
///   2. Possible attack paths, one coalesced graph per internet-facing endpoint,
///      each terminal edge labeled with why it isn't remediated.
fn render_html(
    findings: &[Finding],
    armed: bool,
    bake: &BakeStats,
    reversions: &[ReversionRecord],
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> String {
    // One pass over the breach-relevant findings: the auto-eligible ones are
    // remediations; the rest group by endpoint (entry) for the attack-path graphs.
    let mut remediations: Vec<&Finding> = Vec::new();
    let mut endpoints: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        if f.disposition == AUTO_ELIGIBLE {
            remediations.push(f);
        } else {
            endpoints.entry(f.entry.as_str()).or_default().push(f);
        }
    }

    // Remediations verb (JEF-175): answer-first phrasing — "What protector would do"
    // (shadow, proposing) vs "What protector is doing" (armed, acting) — replacing the
    // old "Proposed/Active Remediations" engine label.
    let rem_title = if armed {
        "What protector is doing"
    } else {
        "What protector would do"
    };
    let rem_body = if remediations.is_empty() {
        "<p class=\"muted\">none</p>".to_string()
    } else {
        remediations
            .iter()
            .map(|f| remediation_card(f, armed))
            .collect()
    };

    // Rank "look at this first" (JEF-163): the OPERATOR-PRIORITY tiers first
    // (flagged → watch → context, via `endpoint_attention_rank`), with the blast
    // radius (graph size) only as the FINAL tiebreaker WITHIN a tier. This is a
    // presentation-only sort key — a view, never a gate (ADR-0016): it reorders the
    // already-decided cards and touches no verdict/disposition and no model input. A
    // flagged-exploitable endpoint therefore ALWAYS sorts above a larger-but-unflagged
    // one (AC #2). `sort_by` is STABLE, so equal keys keep their (entry-sorted, since
    // `endpoints` is a BTreeMap) order — and we tiebreak on the entry key last anyway
    // to make the order fully deterministic.
    let mut ranked: Vec<(&&str, &Vec<&Finding>)> = endpoints.iter().collect();
    ranked.sort_by(|a, b| {
        let (ap, _) = endpoint_attention_rank(a.1);
        let (bp, _) = endpoint_attention_rank(b.1);
        ap.cmp(&bp) // priority level: lower = more attention, first
            .then_with(|| b.1.len().cmp(&a.1.len())) // then widest blast radius
            .then_with(|| a.0.cmp(b.0)) // then entry key, for a stable total order
    });

    // Answer-first split (JEF-175): the findings lead the page, partitioned into the two
    // operator questions. "Needs attention" is the Flagged tier (the model judged a real
    // breach); "Watching" is everything else (watch + the already-collapsed context cards).
    // The partition keys on the SAME `endpoint_attention_rank` tier the cards already
    // carry, so a card's section and its tier chip can never drift, and the stable, total
    // sort above is preserved within each section.
    let mut attention_cards = String::new();
    let mut watching_cards = String::new();
    for (entry, fs) in &ranked {
        let (priority, tier) = endpoint_attention_rank(fs);
        let card = endpoint_card(entry, fs, tier_of_priority(priority));
        if tier == Tier::Flagged {
            attention_cards.push_str(&card);
        } else {
            watching_cards.push_str(&card);
        }
    }

    let vectors_body = attack_vectors(findings);
    let bake_body = bake_panel(bake);
    let reversions_body = reversions_panel(reversions);
    let readiness_body = readiness_panel(readiness);
    let freshness = relative_time(last_pass);

    // The instructional first-run state (JEF-160): when the engine has NO breach-relevant
    // findings AND a decision input is unmet, an empty findings body would otherwise read
    // as a (possibly false) "all clear". Replace the whole findings region with the guided
    // checklist so a blind cluster is never indistinguishable from a clean one. A clean
    // cluster with every input wired keeps the existing honest-empty idiom.
    let no_breach_findings = !findings.iter().any(|f| f.breach_relevant);
    let first_run = no_breach_findings && readiness.has_unmet();

    // The findings region (JEF-175) — first content below the banner. Answer-first:
    // "Needs attention" (flagged endpoints; OMITTED entirely when there are none, AC #2)
    // then "Watching" (watch + the collapsed context cards). On first run the guided
    // checklist replaces the whole region (preserving the JEF-160 path, AC #1).
    let findings_body = if first_run {
        first_run_checklist(readiness)
    } else {
        let attention = if attention_cards.is_empty() {
            String::new()
        } else {
            format!(
                "<h2 id=\"attack-paths\">Needs attention</h2>\
                 <p class=\"sum\">Internet-facing endpoints the model judged a real breach — \
                 look here first.</p>{attention_cards}"
            )
        };
        let watching = format!(
            "<h2 id=\"watching\">Watching</h2>\
             <p class=\"sum\">Exposed paths the model is watching but has not flagged — a way \
             in that's only a risk if exploited, carrying a CVE, or seen happening live. \
             Background paths (proven-reachable, neither flagged nor seen live) are collapsed \
             below.</p>{}",
            if watching_cards.is_empty() {
                "<p class=\"muted\">no internet-facing service can reach a target</p>".to_string()
            } else {
                watching_cards
            }
        );
        format!(
            "{attention}{watching}\
             <p class=\"legend\">edge legend — \
             <code>mounts (direct read)</code>: the secret is mounted into the pod, read with no API call (just that one secret) · \
             <code>RBAC … (API)</code>: the pod's ServiceAccount can read via the Kubernetes API (often any secret in scope) · \
             <code>network reach</code>: a NetworkPolicy- or Linkerd-authorized connection · \
             <code>runs as</code>: assumes the ServiceAccount identity · \
             <code>escapes via</code>: a container-escape primitive to the host node</p>"
        )
    };

    // NOTE: this HTML is a single `\`-continued string literal, so every source-line
    // newline is STRIPPED — the whole thing collapses to one line. Never put a `//`
    // line comment inside the inline <script>: it would comment out the rest of the
    // collapsed line (the import + all rendering). Use /* */ block comments only.
    // The graph renderer is beautiful-mermaid (ELK layout), vendored + bundled into
    // web/dist and served SAME-ORIGIN at /assets — never a third-party CDN.
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta http-equiv=\"refresh\" content=\"30\">\
         <title>protector</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         h1{{font-size:1.2rem;font-weight:600;margin:0}}\
         h2{{font-size:1rem;font-weight:600;margin:1.6rem 0 .4rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}}\
         details.diag{{margin:1.6rem 0 .4rem}}\
         details.diag>summary,details.diag details>summary{{cursor:pointer;list-style:revert}}\
         h2.diag-h{{display:inline-block;margin:0;border-bottom:none;padding:0}}\
         h3.diag-h{{display:inline-block;font-size:.92rem;font-weight:600;margin:0;padding:0}}\
         details.diag>details{{margin:.2rem 0 .2rem 1rem}}\
         .sum{{margin:.4rem 0 1rem;color:#444;font-size:.9rem}}\
         .card{{border:1px solid #e3e3e3;border-radius:0;padding:.5rem .7rem;margin:.6rem 0}}\
         .kc{{font-family:ui-monospace,monospace;font-size:.85rem;font-weight:600}}\
         .kc2{{font-size:.75rem;color:#666;margin:.15rem 0 .3rem}}\
         .verdict{{font-size:.78rem;color:#333;background:#f4f4f4;border-left:2px solid #888;padding:.2rem .5rem;margin:.2rem 0 .4rem}}\
         .vline{{font-size:.92rem;line-height:1.4;margin:.1rem 0 .5rem}}\
         .vwords{{color:#111}}\
         .chip{{font-family:ui-monospace,monospace;font-size:.72rem;font-weight:700;letter-spacing:.02em;padding:.05rem .35rem;border-radius:2px;border:1px solid;margin-right:.35rem;white-space:nowrap}}\
         .chip-breach{{color:#7a0000;background:#fdecec;border-color:#b00000}}\
         .chip-safe{{color:#155f29;background:#eef7f0;border-color:#1a7f37}}\
         .chip-awaiting{{color:#555;background:#f4f4f4;border-color:#ccc}}\
         .tier-flagged{{color:#7a0000;background:#fdecec;border-color:#b00000}}\
         .tier-watch{{color:#7a4a00;background:#fbf6ee;border-color:#9a5b00}}\
         .tier-context{{color:#555;background:#f4f4f4;border-color:#ccc}}\
         details.card-context{{border:1px solid #e3e3e3;border-radius:0;padding:.5rem .7rem;margin:.6rem 0;opacity:.7}}\
         details.card-context summary{{cursor:pointer;color:#555;font-size:.85rem}}\
         details.card-context[open]{{opacity:1}}\
         .rail{{font-size:.78rem;margin:.2rem 0 .5rem;border-left:2px solid #1a7f37;padding:.1rem 0 .1rem .6rem}}\
         .rail-cap{{font-weight:600;color:#155f29}}\
         .rail ul{{margin:.15rem 0 0;padding-left:1.1rem}}\
         .rail li{{margin:.1rem 0;color:#333}}\
         .rail code{{background:#f4f4f4;padding:0 .2rem}}\
         .breadth{{font-size:.78rem;margin:.1rem 0 .4rem}}\
         .todo{{font-size:.82rem;color:#333;background:#f8f8f8;border-left:2px solid #06c;padding:.25rem .5rem;margin:.3rem 0 .1rem}}\
         .todo code{{background:#eee;padding:0 .2rem}}\
         .applied{{color:#b00000;font-weight:600}}\
         .proposed{{color:#9a5b00;font-weight:600}}\
         .muted{{color:#777}}\
         a{{color:#06c}}\
         .mermaid{{margin:.2rem 0;white-space:pre;font-family:ui-monospace,monospace;font-size:.75rem;color:#999}}\
         .graph svg{{max-width:100%;height:auto}}\
         .verdict.muted{{color:#777;border-left-color:#ccc}}\
         .why{{font-size:.78rem;color:#333;margin-top:.3rem}}\
         .why ul{{margin:.15rem 0 0;padding-left:1.1rem}}\
         .why li{{margin:.1rem 0}}\
         .expand{{font-size:.78rem;margin-top:.3rem}}\
         .expand summary{{cursor:pointer;color:#06c}}\
         .expand ul{{margin:.15rem 0 .4rem;padding-left:1.1rem;columns:2}}\
         .expand li{{margin:.05rem 0;font-family:ui-monospace,monospace}}\
         .evidence{{font-size:.78rem;margin:.2rem 0 .5rem}}\
         .ev-head{{font-weight:600;color:#444;margin:.1rem 0 .2rem}}\
         .ev{{border-left:2px solid #ccc;padding:.1rem 0 .1rem .6rem;margin:.2rem 0}}\
         .ev-cve{{border-left-color:#9a5b00}}\
         .ev-runtime{{border-left-color:#b00000}}\
         .ev-cap{{font-weight:600;color:#333}}\
         .ev-sum{{margin:.1rem 0}}\
         .ev ul{{margin:.15rem 0 0;padding-left:1.1rem}}\
         .ev li{{margin:.1rem 0;color:#333}}\
         .ev code{{background:#f4f4f4;padding:0 .2rem}}\
         .ev summary{{cursor:pointer;color:#06c}}\
         .ev details ul{{margin:.1rem 0 .3rem}}\
         .sev-critical{{color:#7a0000;background:#fdecec;border-color:#b00000}}\
         .sev-high{{color:#9a5b00;background:#fff3e0;border-color:#cc7a00}}\
         .sev-medium{{color:#555;background:#f4f4f4;border-color:#bbb}}\
         .sev-low{{color:#555;background:#f4f4f4;border-color:#ddd}}\
         .kev{{font-family:ui-monospace,monospace;font-size:.7rem;font-weight:700;color:#7a0000;background:#fdecec;border:1px solid #b00000;border-radius:2px;padding:0 .25rem}}\
         .legend{{font-size:.75rem;color:#555;margin:.2rem 0 .6rem}}\
         .legend code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors{{border-collapse:collapse;font-size:.82rem;margin:.2rem 0 .6rem;width:100%}}\
         table.vectors th{{text-align:left;font-weight:600;color:#444;border-bottom:1px solid #ddd;padding:.25rem .5rem}}\
         table.vectors td{{padding:.25rem .5rem;border-bottom:1px solid #f0f0f0}}\
         table.vectors code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors .flagged{{color:#b00000;font-weight:600}}\
         .nav{{display:flex;gap:.1rem;font-size:.85rem;margin:0 0 1rem}}\
         .nav a{{padding:.2rem .55rem;color:#06c;text-decoration:none;border-bottom:2px solid transparent}}\
         .nav a[aria-current=\"page\"]{{color:#111;font-weight:600;border-bottom-color:#111}}\
         .banner{{display:block;width:100%;box-sizing:border-box;border-radius:0;padding:.6rem .8rem;margin:0 0 1rem;border:1px solid #ddd}}\
         .banner-head{{display:flex;align-items:baseline;gap:.4rem}}\
         .banner-glyph{{font-size:1rem;line-height:1}}\
         .banner-word{{font-size:1.05rem;font-weight:700;letter-spacing:.01em}}\
         .banner-detail{{font-size:.85rem;margin-top:.15rem}}\
         .banner-detail a{{color:inherit;text-decoration:underline}}\
         .banner-sub{{font-size:.78rem;margin-top:.2rem;opacity:.85}}\
         .banner-ok{{background:#eef7f0;border-color:#1a7f37;color:#155f29}}\
         .banner-ok .banner-glyph,.banner-ok .banner-word{{color:#1a7f37}}\
         .banner-breach{{background:#fdecec;border-color:#b00000;color:#7a0000}}\
         .banner-breach .banner-glyph,.banner-breach .banner-word{{color:#b00000}}\
         .banner-isolated{{background:#f4f4f4;border:2px solid #b00000;color:#5a2a2a}}\
         .banner-isolated .banner-glyph,.banner-isolated .banner-word{{color:#b00000}}\
         .banner-warming{{background:#f4f4f4;border-color:#ccc;color:#555}}\
         .banner-warming .banner-glyph,.banner-warming .banner-word{{color:#777}}\
         .banner-unjudged{{background:#fbf6ee;border-color:#9a5b00;color:#7a4a00}}\
         .banner-unjudged .banner-glyph,.banner-unjudged .banner-word{{color:#9a5b00}}\
         ol.readiness{{list-style:none;padding:0;margin:.2rem 0 .6rem;font-size:.85rem}}\
         ol.readiness li.r-row{{padding:.4rem .6rem;margin:.3rem 0;border:1px solid #e3e3e3;border-left-width:3px}}\
         ol.readiness li.r-ok{{border-left-color:#1a7f37}}\
         ol.readiness li.r-absent{{border-left-color:#b00000;background:#fdf3f3}}\
         ol.readiness li.r-degraded{{border-left-color:#9a5b00;background:#fbf6ee}}\
         .r-label{{font-weight:600}}\
         .r-state{{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:0 .3rem;border-radius:2px}}\
         .r-state-ok{{color:#155f29}}\
         .r-state-absent{{color:#7a0000}}\
         .r-state-degraded{{color:#7a4a00}}\
         .r-weak{{font-size:.72rem;font-weight:600;color:#7a0000;border:1px solid #b00000;border-radius:2px;padding:0 .25rem}}\
         .r-why{{color:#444}}\
         .r-detail{{color:#666}}\
         .r-enable{{color:#444}}\
         .r-enable code{{background:#f4f4f4;padding:0 .2rem}}\
         .r-cold{{font-size:.82rem;color:#555;background:#f4f4f4;border-left:3px solid #ccc;padding:.4rem .6rem;margin:.3rem 0}}\
         .firstrun{{border:1px solid #e3e3e3;border-radius:0;padding:.7rem .9rem;margin:.6rem 0;background:#fafafa}}\
         ol.checklist{{font-size:.85rem;margin:.3rem 0;padding-left:1.3rem}}\
         ol.checklist li{{margin:.3rem 0}}\
         ol.checklist li.r-done{{color:#155f29}}\
         ol.checklist li.r-todo{{color:#333}}\
         ol.checklist code{{background:#f4f4f4;padding:0 .2rem}}\
         </style>\
         <script type=\"module\">\
         import {{ renderMermaidSVG }} from '/assets/beautiful-mermaid.js';\
         for (const pre of document.querySelectorAll('pre.mermaid')) {{\
           const aria = pre.getAttribute('data-aria');\
           try {{\
             const svg = renderMermaidSVG(pre.textContent, {{ font: 'system-ui, sans-serif', accent: '#b00000', padding: 16, nodeSpacing: 28, layerSpacing: 52 }});\
             const g = document.createElement('div'); g.className = 'graph'; g.innerHTML = svg;\
             /* a11y: the client-rendered SVG carries the path summary in words */\
             const el = g.querySelector('svg') || g;\
             el.setAttribute('role', 'img');\
             if (aria) el.setAttribute('aria-label', aria);\
             pre.replaceWith(g);\
           }} catch (e) {{ /* leave the source text as a fallback */ if (aria) {{ pre.setAttribute('role', 'img'); pre.setAttribute('aria-label', aria); }} }}\
         }}\
         </script></head><body>\
         {banner}\
         <h1>protector</h1>\
         {nav}\
         <p class=\"sum\"><b>{rem_n}</b> {rem_word} · <b>{ep_n}</b> exposed endpoint{ep_plural} with \
         possible attack paths · last pass <b>{freshness}</b> \
         &nbsp;|&nbsp; <a href=\"/findings\">json</a></p>\
         {findings_body}\
         <h2>{rem_title} <span class=\"muted\">({rem_n})</span></h2>{rem_body}\
         <details class=\"diag\"{readiness_open_outer}>\
         <summary><h2 class=\"diag-h\">Engine &amp; coverage</h2></summary>\
         <details id=\"coverage\"{readiness_open}>\
         <summary><h3 class=\"diag-h\">Readiness <span class=\"muted\">(decision inputs)</span></h3></summary>\
         <p class=\"sum\">Each decision input and its LIVE state — so an unconfigured or down \
         input is visible, not silent. An <b>absent</b> input that weakens decisions is called \
         out: the model's call is only as good as the evidence it judges with. \
         &nbsp;|&nbsp; <a href=\"/readiness\">json</a></p>\
         {readiness_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">What an attacker could reach</h3></summary>\
         <p class=\"sum\">What an internet-facing service can reach. \
         <b>Reachable</b> = proven the service can get there; <b>model-flagged</b> = the model \
         judged it a real breach.</p>\
         {vectors_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">Live activity the sensors saw <span class=\"muted\">(shadow)</span></h3></summary>\
         <p class=\"sum\">What the behavioral agent observed last pass — protector is only \
         watching, not acting. A sanity check before relying on these signals: volume looks \
         reasonable, most events map to a workload (low unresolved), and <b>corroborations</b> \
         counts findings a live signal backed up.</p>\
         {bake_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">Recently lifted <span class=\"muted\">(lifted cuts)</span></h3></summary>\
         <p class=\"sum\">Cuts the engine lifted, and why. An isolation stays only while the \
         breach lasts, then lifts on its own once the path is gone or the evidence clears. \
         &nbsp;|&nbsp; <a href=\"/reversions\">json</a></p>\
         {reversions_body}\
         </details>\
         </details>\
         </body></html>",
        banner = status_banner(
            findings,
            armed,
            last_pass,
            &freshness,
            readiness.model_judging
        ),
        nav = nav_bar("/"),
        rem_n = remediations.len(),
        rem_word = if armed { "active" } else { "proposed" },
        ep_n = endpoints.len(),
        ep_plural = if endpoints.len() == 1 { "" } else { "s" },
        // AC #3: a degraded/absent decision-weakening input must still surface — the
        // Readiness section (and its enclosing diagnostics region) auto-open ONLY when
        // `has_unmet()`; a healthy cluster gets a one-line summary it can expand.
        readiness_open = if readiness.has_unmet() { " open" } else { "" },
        readiness_open_outer = if readiness.has_unmet() { " open" } else { "" },
    )
}

/// Shared state for the dashboard's HTML view: the findings handle plus the reversions
/// ring (JEF-141), so the rendered page can show lifted cuts alongside the findings.
#[derive(Clone)]
struct DashboardState {
    findings: Arc<Findings>,
    reversions: Arc<ReversionLog>,
}

/// The LIVE readiness snapshot (JEF-160) from the shared findings handle — the same data
/// the HTML panel and `/readiness` render. Pure over the engine's config summary + live
/// state (model health, this pass's bake, last-pass freshness); no model call.
fn readiness_of(findings: &Findings) -> Readiness {
    derive_readiness(
        &findings.readiness_config(),
        findings.model_health(),
        &findings.bake(),
        findings.last_pass(),
    )
}

async fn html_view(State(state): State<DashboardState>) -> Html<String> {
    Html(render_html(
        &state.findings.snapshot(),
        state.findings.is_armed(),
        &state.findings.bake(),
        &state.reversions.snapshot(),
        state.findings.last_pass(),
        &readiness_of(&state.findings),
    ))
}

/// The readiness / coverage panel as JSON (JEF-160) — the same per-input LIVE state the
/// HTML panel shows, for scripting / alerting. On its own route so the `/findings`
/// contract is unchanged. Read-only; presence/health only, no values.
async fn readiness_view(State(findings): State<Arc<Findings>>) -> Json<Readiness> {
    Json(readiness_of(&findings))
}

async fn json_view(State(findings): State<Arc<Findings>>) -> Json<Vec<Finding>> {
    Json(findings.snapshot())
}

/// The recent-reversions view as JSON (JEF-141) — the machine-readable form of the
/// lifted-cuts panel, on its own route so the `/findings` contract is unchanged.
async fn reversions_view(
    State(reversions): State<Arc<ReversionLog>>,
) -> Json<Vec<ReversionRecord>> {
    Json(reversions.snapshot())
}

/// The behavioral-bake snapshot as JSON (JEF-48) — the machine-readable form of the
/// dashboard panel, so the bake's exit criteria can be scraped/asserted, not only
/// eyeballed. Kept on its own route so the `/findings` array contract is unchanged.
async fn bake_view(State(findings): State<Arc<Findings>>) -> Json<BakeStats> {
    Json(findings.bake())
}

/// The `/judgements` HTML view (JEF-161): the human "why" — one card per recent
/// judgement, led by the posture chip + the model's prose, the raw prompt behind an
/// expander. The machine-readable form is `/judgements.json`.
async fn judgements_html_view(State(journal): State<Arc<JudgementLog>>) -> Html<String> {
    Html(render_judgements_html(&journal.snapshot()))
}

/// The `/judgements.json` view: the diagnostic JSON (full prompt + raw reply + verdict
/// per recent judgement), unchanged from the prior `/judgements` contract — only the path
/// moved when the human HTML view took over `/judgements` (JEF-161).
async fn judgements_json_view(State(journal): State<Arc<JudgementLog>>) -> Json<Vec<Judgement>> {
    Json(journal.snapshot())
}

/// Replay the durable decision journal and aggregate the would-have-acted report over
/// the request's window (JEF-143). Read-only; the journal is append-only, so each
/// request sees the current durable history (pre-restart on disk + this run's writes).
fn build_report(journal: &DecisionJournal, query: &ReportQuery) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        query.window(),
        query.short_lived(),
    )
}

/// Aggregate the would-have-acted report over the DEFAULT window from a journal handle
/// (JEF-143), for the engine to mirror its headline counts to OTLP per pass — the same
/// figures `/report` shows by default, the in-process mirror like the bake counts. A
/// disabled journal replays nothing, so this is an empty report (all-zero headline).
pub fn default_window_report(journal: &DecisionJournal) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    )
}

/// The `/report` HTML view (JEF-143): the shadow would-have-acted diff over a rolling
/// window. Window + thresholds come from the query string (see [`ReportQuery`]).
async fn report_html_view(
    State(journal): State<Arc<DecisionJournal>>,
    Query(query): Query<ReportQuery>,
) -> Html<String> {
    Html(render_report_html(&build_report(&journal, &query)))
}

/// The `/report.json` view (JEF-143): the same aggregation as machine-readable JSON, so
/// the would-have-acted diff can be scraped/asserted, not only eyeballed.
async fn report_json_view(
    State(journal): State<Arc<DecisionJournal>>,
    Query(query): Query<ReportQuery>,
) -> Json<Report> {
    Json(build_report(&journal, &query))
}

/// The vendored, self-hosted graph renderer (beautiful-mermaid + elkjs, bundled in
/// `web/dist` and embedded in the binary). Served same-origin so the dashboard never
/// loads third-party JS — see the import in [`render_html`].
const BEAUTIFUL_MERMAID_JS: &str = include_str!("../../web/dist/beautiful-mermaid.js");

async fn beautiful_mermaid_js() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        BEAUTIFUL_MERMAID_JS,
    )
}

/// Serve the findings dashboard (`/` HTML, `/findings` JSON, `/bake` JSON, `/readiness`
/// JSON) plus the human `/judgements` HTML "why" view (JEF-161) with its diagnostic
/// `/judgements.json` (full prompt + raw reply + verdict per recent judgement), the
/// `/reversions` JSON (lifted cuts + why, JEF-141), and the
/// `/report` + `/report.json` shadow would-have-acted diff (JEF-143). Read-only;
/// cluster-facing glue around the tested classification + aggregation. The `/readiness`
/// view (JEF-160) reports each decision input's LIVE presence/health for alerting.
pub async fn serve_dashboard(
    addr: SocketAddr,
    findings: Arc<Findings>,
    judgements: Arc<JudgementLog>,
    reversions: Arc<ReversionLog>,
    journal: Arc<DecisionJournal>,
) -> anyhow::Result<()> {
    let html_state = DashboardState {
        findings: findings.clone(),
        reversions: reversions.clone(),
    };
    let app = Router::new()
        .route("/findings", get(json_view))
        .route("/bake", get(bake_view))
        .route("/readiness", get(readiness_view))
        .route("/assets/beautiful-mermaid.js", get(beautiful_mermaid_js))
        .with_state(findings)
        .merge(
            Router::new()
                .route("/judgements", get(judgements_html_view))
                .route("/judgements.json", get(judgements_json_view))
                .with_state(judgements),
        )
        .merge(
            Router::new()
                .route("/reversions", get(reversions_view))
                .with_state(reversions),
        )
        .merge(
            Router::new()
                .route("/report", get(report_html_view))
                .route("/report.json", get(report_json_view))
                .with_state(journal),
        )
        .merge(
            Router::new()
                .route("/", get(html_view))
                .with_state(html_state),
        );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "findings dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::NodeKey;
    use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
    use crate::engine::reason::proof::Link;

    /// A default readiness snapshot for the render tests that don't exercise the panel
    /// itself — every input absent, post-warmup. The readiness-specific behavior is
    /// covered by the dedicated JEF-160 tests below.
    fn ready() -> Readiness {
        derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        )
    }

    fn judgement(entry: &str) -> Judgement {
        Judgement {
            entry: entry.to_string(),
            objectives: 1,
            verdict: "Refuted(..)".to_string(),
            prompt: None,
            reply: None,
        }
    }

    #[test]
    fn judgement_log_is_newest_first_and_capped() {
        let log = JudgementLog::new();
        // Overflow the ring by one so the oldest is evicted.
        for n in 0..=JudgementLog::CAP {
            log.record(judgement(&format!("entry-{n}")));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), JudgementLog::CAP, "ring is bounded by CAP");
        assert_eq!(
            snap[0].entry,
            format!("entry-{}", JudgementLog::CAP),
            "newest judgement is first"
        );
        assert_eq!(
            snap.last().unwrap().entry,
            "entry-1",
            "the oldest (entry-0) was evicted"
        );
    }

    /// A breach-relevant finding for one entry with no verdict of its own — the shape the
    /// engine publishes (the verdict is resolved from the shared store at snapshot time).
    fn breach_finding(entry: &str) -> Finding {
        Finding {
            entry: entry.into(),
            objective: "secret/app/session-key".into(),
            tactic: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            technique: "T1552".into(),
            technique_name: "Unsecured Credentials".into(),
            foothold: false,
            corroborated: false,
            adjudicated: true,
            promoted: false,
            disposition: "no-cut".into(),
            cut: None,
            breach_relevant: true,
            killchain: "T1552 Unsecured Credentials".into(),
            verdict: None,
            path: Vec::new(),
            evidence: EntryEvidence::default(),
        }
    }

    /// JEF-157 (the no-lag fix): a verdict written to the shared store is visible on the
    /// `/findings` snapshot WITHOUT re-publishing the rows. This is exactly the bug the
    /// ticket fixes — `/findings` used to update only at the end-of-pass re-publish, so a
    /// just-judged entry showed in `/judgements` but not yet on the dashboard. With the
    /// single store, the same rows published once reflect the verdict the instant it lands.
    #[test]
    fn findings_snapshot_reflects_a_store_write_without_republishing() {
        let findings = Findings::new();
        let verdicts = findings.verdicts();

        // Publish the rows ONCE, with no verdict (what the engine does before judging).
        findings.replace(vec![breach_finding("workload/app/Pod/web")]);
        assert!(
            findings.snapshot()[0].verdict.is_none(),
            "no verdict before the model has judged the entry"
        );

        // The model judges the entry: write its verdict to the store. NO `replace` follows.
        verdicts.set_display(
            "workload/app/Pod/web",
            Verdict::Exploitable("RCE reaches the secret".into()),
        );

        // The verdict is visible on the very next snapshot — no re-publish needed.
        let snap = findings.snapshot();
        assert_eq!(
            snap[0].verdict.as_deref(),
            Some("exploitable — RCE reaches the secret"),
            "a store write surfaces on /findings immediately, mid-pass"
        );
    }

    /// JEF-157 carry-forward: a journal-restored verdict shows until a live verdict
    /// supersedes it, and the live verdict then wins — the precedence the engine used to
    /// apply per-chain at publish time, now in one place.
    #[test]
    fn restored_verdict_shows_until_a_live_verdict_supersedes_it() {
        let store = VerdictStore::new();
        store.seed_restored(
            "workload/app/Pod/web",
            "exploitable — from before restart".into(),
        );
        assert_eq!(
            store.display_summary("workload/app/Pod/web").as_deref(),
            Some("exploitable — from before restart"),
            "the restored verdict shows on boot"
        );

        // A live verdict supersedes the restored one (and clears the restored slot).
        store.set_display(
            "workload/app/Pod/web",
            Verdict::Refuted("benign on review".into()),
        );
        assert_eq!(
            store.display_summary("workload/app/Pod/web").as_deref(),
            Some("not exploitable — benign on review"),
            "a live verdict supersedes the restored one"
        );
    }

    /// JEF-157 cache: a decisive verdict is served from the store for a matching
    /// fingerprint (no re-judge), and a changed fingerprint misses (re-judge).
    #[test]
    fn cache_serves_a_matching_fingerprint_and_misses_a_changed_one() {
        let store = VerdictStore::new();
        store.cache_decisive("e", "fp-1".into(), Verdict::Refuted("r".into()));
        assert!(
            store.cached_for("e", "fp-1").is_some(),
            "an unchanged fingerprint serves the cached verdict"
        );
        assert!(
            store.cached_for("e", "fp-2").is_none(),
            "a changed fingerprint misses (re-judge)"
        );
        assert!(
            store.cached_for("other", "fp-1").is_none(),
            "an unknown entry misses"
        );
    }

    fn reversion(cut: &str) -> ReversionRecord {
        ReversionRecord {
            cut: cut.to_string(),
            reason: "no proven chain still justifies this control".to_string(),
            at_ms: 1,
        }
    }

    #[test]
    fn reversion_log_is_newest_first_and_capped() {
        // The recent-reversions ring (JEF-141) is bounded and newest-first, like the
        // judgement ring — so a restart-seeded history can't grow unbounded.
        let log = ReversionLog::new();
        for n in 0..=ReversionLog::CAP {
            log.record(reversion(&format!("cut-{n}")));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), ReversionLog::CAP, "ring is bounded by CAP");
        assert_eq!(
            snap[0].cut,
            format!("cut-{}", ReversionLog::CAP),
            "newest reversion is first"
        );
        assert_eq!(snap.last().unwrap().cut, "cut-1", "the oldest was evicted");
    }

    #[test]
    fn relative_time_renders_human_freshness() {
        // The "last pass NNs ago" freshness (JEF-141): None reads as waiting, a recent
        // time as seconds, older as minutes/hours — never a raw timestamp.
        assert_eq!(relative_time(None), "waiting for first pass");
        assert_eq!(relative_time(Some(SystemTime::now())), "just now");
        let ninety_s = SystemTime::now() - std::time::Duration::from_secs(90);
        assert_eq!(relative_time(Some(ninety_s)), "1m ago");
        let two_h = SystemTime::now() - std::time::Duration::from_secs(7200);
        assert_eq!(relative_time(Some(two_h)), "2h ago");
    }

    #[test]
    fn reversions_panel_shows_lifted_cuts_or_a_quiet_default() {
        // Empty ⇒ a quiet (not error) message; non-empty ⇒ the cut + reason rendered.
        assert!(reversions_panel(&[]).contains("no cuts have been lifted"));
        let panel = reversions_panel(&[ReversionRecord {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
            at_ms: unix_now_ms(),
        }]);
        assert!(panel.contains("workload/app/Pod/web"));
        assert!(panel.contains("no proven chain still justifies"));
    }

    /// Now as Unix-millis, for building a `ReversionRecord` with a sane stamp in tests.
    fn unix_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn render_html_shows_the_freshness_line_and_reversions_section() {
        // The dashboard surfaces "last pass NNs ago" and a recent-reversions section
        // (JEF-141), both populated.
        let revs = vec![ReversionRecord {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
            at_ms: unix_now_ms(),
        }];
        let html = render_html(
            &[],
            false,
            &BakeStats::default(),
            &revs,
            Some(SystemTime::now()),
            &ready(),
        );
        assert!(
            html.contains("last pass <b>just now</b>"),
            "freshness line present"
        );
        assert!(
            html.contains("Recently lifted"),
            "lifted-cuts section header present"
        );
        assert!(
            html.contains("no proven chain still justifies"),
            "the lifted cut's reason is shown"
        );
    }

    // -- JEF-159: the glanceable cluster status banner --------------------------------

    /// A breach-relevant finding with the model's resolved verdict set (and an optional
    /// auto-eligible disposition), for the cluster-status states.
    fn judged(entry: &str, verdict: &str, auto_eligible: bool) -> Finding {
        let mut f = breach_finding(entry);
        f.verdict = Some(verdict.to_string());
        if auto_eligible {
            f.disposition = AUTO_ELIGIBLE.to_string();
        }
        f
    }

    #[test]
    fn cluster_status_warming_up_when_no_pass_has_completed() {
        // `last_pass` None ⇒ no verdicts yet ⇒ never claim OK, even with findings present.
        assert_eq!(
            cluster_status(&[], false, None, true),
            ClusterStatus::WarmingUp,
            "no pass yet ⇒ warming, not Quiet"
        );
        let exploitable = vec![judged("workload/app/Pod/web", "exploitable — RCE", false)];
        assert_eq!(
            cluster_status(&exploitable, false, None, true),
            ClusterStatus::WarmingUp,
            "no pass yet ⇒ warming even with an exploitable finding (verdicts not trusted)"
        );
    }

    #[test]
    fn cluster_status_quiet_when_no_breach_relevant_exposure() {
        // A pass completed, no breach-relevant exposure at all ⇒ Quiet (distinct from
        // Watching, which has exposure).
        let mut non_breach = breach_finding("workload/app/Pod/web");
        non_breach.breach_relevant = false;
        assert_eq!(
            cluster_status(&[], false, Some(SystemTime::now()), false),
            ClusterStatus::Quiet,
            "no exposure ⇒ Quiet even with the model down — nothing to clear, no claim made"
        );
        assert_eq!(
            cluster_status(&[non_breach], false, Some(SystemTime::now()), false),
            ClusterStatus::Quiet,
            "non-breach-relevant rows don't count as exposure"
        );
    }

    #[test]
    fn cluster_status_watching_when_exposed_but_model_cleared() {
        // Exposed breach-relevant endpoints, none exploitable (model said "not
        // exploitable" or hasn't flagged) ⇒ Watching, NOT Quiet.
        let cleared = vec![
            judged(
                "workload/app/Pod/web",
                "not exploitable — RBAC denies",
                false,
            ),
            breach_finding("workload/app/Pod/api"), // awaiting verdict (None)
        ];
        assert_eq!(
            cluster_status(&cleared, false, Some(SystemTime::now()), true),
            ClusterStatus::Watching,
            "exposure with no exploitable verdict AND a live model ⇒ Watching"
        );
    }

    #[test]
    fn cluster_status_breach_live_when_exploitable_and_no_cut() {
        // ≥1 exploitable verdict, not armed (so no cut is in force) ⇒ Breach — live.
        let breach = vec![judged(
            "workload/app/Pod/web",
            "exploitable — RCE reaches the secret",
            true,
        )];
        assert_eq!(
            cluster_status(&breach, false, Some(SystemTime::now()), true),
            ClusterStatus::BreachLive,
            "exploitable + shadow (no cut) ⇒ live breach"
        );
        // Armed but the chain is NOT auto-eligible (propose-only) ⇒ no cut ⇒ still live.
        let propose_only = vec![judged("workload/app/Pod/web", "exploitable — RCE", false)];
        assert_eq!(
            cluster_status(&propose_only, true, Some(SystemTime::now()), true),
            ClusterStatus::BreachLive,
            "armed but propose-only (no auto cut) ⇒ still live, not Isolated"
        );
    }

    #[test]
    fn cluster_status_isolated_when_exploitable_and_cut_applied() {
        // ≥1 exploitable verdict, armed, auto-eligible ⇒ a cut is applied ⇒ Isolated.
        let contained = vec![judged("workload/app/Pod/web", "exploitable — RCE", true)];
        assert_eq!(
            cluster_status(&contained, true, Some(SystemTime::now()), true),
            ClusterStatus::Isolated,
            "exploitable + armed + auto-eligible ⇒ contained (Isolated)"
        );
    }

    #[test]
    fn status_banner_renders_each_state_with_word_glyph_and_aria() {
        let now = Some(SystemTime::now());
        let breach = vec![judged("workload/app/Pod/web", "exploitable — RCE", true)];

        // Every banner carries role/aria-live and a tone class; meaning is in the WORD.
        let watching = status_banner(
            &[judged(
                "workload/app/Pod/web",
                "not exploitable — denied",
                false,
            )],
            false,
            now,
            "5s ago",
            true, // model is judging ⇒ a real clearance ⇒ Watching/green
        );
        assert!(watching.contains("role=\"status\""));
        assert!(watching.contains("aria-live=\"polite\""));
        assert!(watching.contains("Watching"), "watching word");
        assert!(watching.contains("banner-ok"), "calm/green tone");
        assert!(watching.contains("1 exposed path"), "states paths watched");
        assert!(
            watching.contains("shadow mode (proposing only)"),
            "arm-state in subtitle"
        );
        assert!(
            watching.contains("last scan 5s ago"),
            "freshness in subtitle"
        );
        assert!(
            watching.contains("auto-refresh 30s"),
            "refresh cadence noted"
        );

        let quiet = status_banner(&[], false, now, "5s ago", true);
        assert!(quiet.contains("Quiet"));
        assert!(quiet.contains("banner-ok"));

        let breach_banner = status_banner(&breach, false, now, "5s ago", true);
        assert!(breach_banner.contains("Breach — live"));
        assert!(breach_banner.contains("banner-breach"));
        assert!(
            breach_banner.contains("1 exploitable path"),
            "names the count"
        );
        assert!(
            breach_banner.contains("href=\"#attack-paths\""),
            "anchors to the card(s)"
        );

        let isolated = status_banner(&breach, true, now, "5s ago", true);
        assert!(isolated.contains("Isolated"));
        assert!(isolated.contains("banner-isolated"));
        assert!(isolated.contains("armed (acting)"));

        let warming = status_banner(&[], false, None, "waiting for first pass", true);
        assert!(warming.contains("Warming up"));
        assert!(warming.contains("banner-warming"));
        assert!(
            !warming.contains("Quiet") && !warming.contains("Watching"),
            "warming never claims OK"
        );
    }

    // -- JEF-174: the banner must not claim "the model cleared them" with no live model -----

    /// Acceptance #1 & #3: exposed-but-unflagged paths are `Watching` (green clearance) ONLY
    /// while the model is judging; with NO live model they are `Unjudged` (non-green). The
    /// engine's skeptic default is unchanged — this is banner-state only.
    #[test]
    fn cluster_status_unjudged_when_exposed_and_model_not_judging() {
        let exposed = vec![
            judged("workload/app/Pod/web", "not exploitable — denied", false),
            breach_finding("workload/app/Pod/api"), // awaiting a verdict (None)
        ];
        let now = Some(SystemTime::now());

        // Model NOT judging (down / timed out / no model) ⇒ Unjudged, NOT Watching.
        assert_eq!(
            cluster_status(&exposed, false, now, false),
            ClusterStatus::Unjudged,
            "exposure with no live model ⇒ Unjudged, not a false clearance"
        );
        // Same findings, model judging ⇒ a real clearance ⇒ Watching (acceptance #3).
        assert_eq!(
            cluster_status(&exposed, false, now, true),
            ClusterStatus::Watching,
            "exposure cleared by a live model ⇒ Watching (unchanged)"
        );
    }

    /// `Unjudged` is non-green and the model-health distinction lives in the TEXT, not color
    /// alone (acceptance #1, #5), with the `role`/`aria-live` contract preserved.
    #[test]
    fn unjudged_banner_is_non_green_and_carries_status_in_text() {
        let exposed = vec![judged(
            "workload/app/Pod/web",
            "not exploitable — denied",
            false,
        )];
        let banner = status_banner(&exposed, false, Some(SystemTime::now()), "5s ago", false);

        assert!(banner.contains("Unjudged"), "leads with the word");
        assert!(
            banner.contains("banner-unjudged") && !banner.contains("banner-ok"),
            "non-green amber tone, never the green/ok token"
        );
        assert!(
            banner.contains("the model isn't judging right now"),
            "the meaning is in the text, not color alone"
        );
        assert!(banner.contains("1 exposed path"), "states the count");
        // Acceptance #5: the aria contract is preserved verbatim.
        assert!(banner.contains("role=\"status\""));
        assert!(banner.contains("aria-live=\"polite\""));
    }

    /// Acceptance #4: in EVERY state with no live verdict, the detail text must never claim
    /// the model cleared anything. The only "cleared" claim is the live-model `Watching`.
    #[test]
    fn detail_never_claims_clearance_without_a_live_verdict() {
        let exposed = vec![judged("workload/app/Pod/web", "not exploitable", false)];
        let now = Some(SystemTime::now());

        // No model (acceptance #1): unjudged, never "cleared".
        let no_model = status_banner(&exposed, false, now, "5s ago", false);
        assert!(
            !no_model.contains("cleared"),
            "no live model ⇒ never claims a clearance"
        );

        // Warming up (no pass yet): never "cleared".
        let warming = status_banner(&exposed, false, None, "warming", false);
        assert!(!warming.contains("cleared"));

        // Quiet (no exposure, model down): makes no clearance claim either.
        let quiet = status_banner(&[], false, now, "5s ago", false);
        assert!(!quiet.contains("cleared"));

        // The ONLY place "cleared" appears is a live-model Watching.
        let watching = status_banner(&exposed, false, now, "5s ago", true);
        assert!(
            watching.contains("the model cleared them"),
            "a live model's clearance is still stated plainly"
        );
    }

    /// Acceptance #2: a model attached but whose last call timed out is NOT judging, so the
    /// readiness signal the banner reads is false — wiring it end-to-end through
    /// [`derive_readiness`] (the engine's `ModelHealth::Timeout`), not just the banner fn.
    #[test]
    fn timed_out_model_is_not_judging_so_banner_does_not_clear() {
        let attached = ReadinessConfig {
            model_attached: true,
            ..ReadinessConfig::default()
        };
        let now = Some(SystemTime::now());

        // Attached + Ok ⇒ judging.
        let live = derive_readiness(&attached, ModelHealth::Ok, &BakeStats::default(), now);
        assert!(live.model_judging, "attached + last call ok ⇒ judging");

        // Attached + Timeout ⇒ NOT judging (acceptance #2).
        let stale = derive_readiness(&attached, ModelHealth::Timeout, &BakeStats::default(), now);
        assert!(
            !stale.model_judging,
            "attached but last call timed out ⇒ not judging"
        );

        // No model at all ⇒ NOT judging (acceptance #1).
        let absent = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            now,
        );
        assert!(!absent.model_judging, "no model configured ⇒ not judging");

        // And the banner driven by the timed-out signal refuses the clearance.
        let exposed = vec![judged("workload/app/Pod/web", "not exploitable", false)];
        let banner = status_banner(&exposed, false, now, "5s ago", stale.model_judging);
        assert!(banner.contains("Unjudged") && !banner.contains("cleared"));
    }

    #[test]
    fn render_html_includes_the_banner_nav_and_meta_refresh() {
        // The dashboard leads with the status banner, has a persistent nav with the
        // current page marked, and a 30s meta-refresh.
        let html = render_html(
            &[],
            false,
            &BakeStats::default(),
            &[],
            Some(SystemTime::now()),
            &ready(),
        );
        // Banner is the first child of <body>, above <h1>.
        let body_at = html.find("<body>").expect("body present");
        let banner_at = html.find("class=\"banner").expect("banner present");
        let h1_at = html.find("<h1>").expect("h1 present");
        assert!(
            banner_at > body_at && banner_at < h1_at,
            "banner above <h1>"
        );
        assert!(
            html.contains("role=\"status\""),
            "banner is a status region"
        );
        // Trimmed nav (JEF-175): only dashboard · why · shadow log, with aria-current on
        // the dashboard. `/readiness`, `/bake`, and `/reversions` are de-listed from nav.
        assert!(html.contains("<a href=\"/\" aria-current=\"page\">dashboard</a>"));
        assert!(html.contains("<a href=\"/judgements\">why</a>"));
        assert!(html.contains("<a href=\"/report\">shadow log</a>"));
        let nav_at = html.find("class=\"nav\"").expect("nav present");
        let nav_end = html[nav_at..].find("</nav>").expect("nav closes") + nav_at;
        let nav = &html[nav_at..nav_end];
        assert!(
            !nav.contains("href=\"/reversions\""),
            "reversions de-listed"
        );
        assert!(!nav.contains("href=\"/readiness\""), "readiness de-listed");
        assert!(!nav.contains("href=\"/bake\""), "bake de-listed");
        assert_eq!(nav.matches("<a ").count(), 3, "exactly three nav items");
        // 30s meta-refresh.
        assert!(html.contains("<meta http-equiv=\"refresh\" content=\"30\">"));
    }

    // -- JEF-175: answer-first reorder (findings on top, engine internals collapsed) -----

    /// A readiness snapshot with EVERY decision input met — `has_unmet()` is false. The
    /// counterpart to the default `ready()` (which is degraded/absent on every input).
    fn ready_all_met() -> Readiness {
        let mut bake = BakeStats::default();
        // One Falco (`alert`) signal + one eBPF (any other variant) signal so both
        // behavioral feeds read Present this pass.
        bake.signals_by_variant.insert("alert".to_string(), 1);
        bake.signals_by_variant.insert("connection".to_string(), 1);
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 3,
                advisory_count: 3,
                journal_durable: true,
                ..Default::default()
            },
            ModelHealth::Ok,
            &bake,
            Some(SystemTime::now()),
        );
        assert!(!r.has_unmet(), "fixture: every decision input is met");
        r
    }

    /// AC #1+#2+#3: the findings lead the page and the engine internals are collapsed
    /// BELOW them. Concretely: findings (Needs attention / Watching) come before the
    /// single "Engine & coverage" diagnostics region, which is a <details>, and the
    /// readiness/attack-surface/sensor-activity/recently-lifted sections live inside it.
    #[test]
    fn render_html_puts_findings_above_a_collapsed_diagnostics_region() {
        let findings = vec![
            // A model-flagged endpoint ⇒ "Needs attention".
            finding(
                "workload/app/Pod/web",
                "secret/app/session-key",
                "latent foothold — propose",
                "can-read",
                true,
                Some("exploitable — CVE-2021-44228 reaches the secret"),
            ),
        ];
        let html = render_html(
            &findings,
            false,
            &bake(80, 20),
            &[],
            Some(SystemTime::now()),
            &ready_all_met(),
        );

        let needs = html
            .find("Needs attention")
            .expect("needs-attention section");
        let watching = html.find("Watching").expect("watching section");
        let diag = html
            .find("Engine &amp; coverage")
            .expect("diagnostics region");
        let readiness = html.find("Readiness").expect("readiness section");
        let surface = html
            .find("What an attacker could reach")
            .expect("attack-surface section");
        let sensor = html
            .find("Live activity the sensors saw")
            .expect("sensor-activity section");
        let lifted = html
            .find("Recently lifted")
            .expect("recently-lifted section");

        // Findings (both sub-sections) precede the diagnostics region.
        assert!(
            needs < diag,
            "Needs attention is above the diagnostics region"
        );
        assert!(watching < diag, "Watching is above the diagnostics region");
        // Remediations render between the findings and the diagnostics region (AC #2):
        // the remediations heading sits after the findings and before "Engine & coverage".
        let rem = html
            .find("What protector would do")
            .expect("remediations section");
        assert!(
            needs < rem && rem < diag,
            "remediations after findings, before diag"
        );
        // All four engine sub-sections live inside the diagnostics region.
        for (name, at) in [
            ("Readiness", readiness),
            ("What an attacker could reach", surface),
            ("Live activity the sensors saw", sensor),
            ("Recently lifted", lifted),
        ] {
            assert!(at > diag, "{name} is inside the diagnostics region");
        }
        // The diagnostics region is ONE collapsible <details>.
        assert!(
            html.contains("<details class=\"diag\""),
            "diagnostics is a <details> region"
        );
    }

    /// AC #3: the Readiness section auto-opens (<details open>) iff a decision-weakening
    /// input is absent/degraded — a healthy cluster gets a collapsed one-line summary.
    #[test]
    fn readiness_section_auto_opens_only_when_inputs_are_unmet() {
        // Degraded/absent inputs (default `ready()`) ⇒ the readiness sub-section opens
        // (and so does the enclosing region) so the gap surfaces prominently.
        let unmet = render_html(&[], false, &BakeStats::default(), &[], None, &ready());
        assert!(
            unmet.contains("<details id=\"coverage\" open>"),
            "readiness auto-opens when inputs unmet"
        );
        assert!(
            unmet.contains("<details class=\"diag\" open>"),
            "diagnostics region auto-opens when inputs unmet"
        );

        // Every input met ⇒ the readiness sub-section (and the region) stay collapsed.
        let met = render_html(
            &[],
            false,
            &bake(80, 20),
            &[],
            Some(SystemTime::now()),
            &ready_all_met(),
        );
        assert!(
            met.contains("<details id=\"coverage\">"),
            "readiness stays collapsed when every input is met"
        );
        assert!(
            !met.contains("<details id=\"coverage\" open>"),
            "readiness has no open attribute when every input is met"
        );
        assert!(
            met.contains("<details class=\"diag\">"),
            "diagnostics region stays collapsed when every input is met"
        );
    }

    /// AC #5: NO JSON endpoint or route is removed — the readiness/bake/reversions JSON
    /// routes are only DE-LISTED from the human nav, but still reachable. The diagnostics
    /// sections link to the readiness + reversions JSON (bake stays reachable at /bake).
    #[test]
    fn diagnostics_sections_keep_the_json_links() {
        let html = render_html(&[], false, &bake(80, 20), &[], None, &ready_all_met());
        assert!(
            html.contains("<a href=\"/readiness\">json</a>"),
            "readiness json link kept"
        );
        assert!(
            html.contains("<a href=\"/reversions\">json</a>"),
            "reversions json link kept (folded into Recently lifted)"
        );
    }

    /// AC #2: "Needs attention" is OMITTED entirely when no endpoint is model-flagged —
    /// the operator's eye isn't drawn to an empty alarm section.
    #[test]
    fn needs_attention_section_is_omitted_when_nothing_is_flagged() {
        // A breach-relevant endpoint the model did NOT flag ⇒ Watching only.
        let findings = vec![finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "latent foothold — propose",
            "can-read",
            true,
            Some("not exploitable — the CVE is in a code path this service never invokes"),
        )];
        let html = render_html(
            &findings,
            false,
            &BakeStats::default(),
            &[],
            Some(SystemTime::now()),
            &ready_all_met(),
        );
        assert!(
            !html.contains("Needs attention"),
            "no flagged ⇒ no attention section"
        );
        assert!(
            html.contains("Watching"),
            "the watching section is still present"
        );
    }

    /// A chain with a single-edge cut on `cut_relation` (what the disposition now
    /// keys on), plus the evidence flags.
    fn chain(
        cut_relation: &str,
        foothold: bool,
        corroborated: bool,
        adjudicated: bool,
    ) -> ProvenChain {
        let cut = Link {
            from: NodeKey("workload/app/Pod/web".into()),
            to: NodeKey("workload/app/Pod/store".into()),
            relation: cut_relation.to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        };
        ProvenChain {
            entry: NodeKey("workload/app/Pod/web".into()),
            objective: NodeKey("secret/app/s".into()),
            attack: CREDENTIAL_ACCESS,
            foothold: foothold.then_some(EXPLOIT_PUBLIC_FACING),
            corroborated,
            adjudicated,
            promoted: false,
            // The disposition tests below key on the cut + evidence, not on
            // breach-relevance; treat the entry as a front door so the chain is a
            // finding (bucket gating is exercised in the render test instead).
            exposed_entry: true,
            verdict: None,
            links: vec![cut.clone()],
            single_edge_cuts: vec![cut],
        }
    }

    #[test]
    fn disposition_keys_on_what_the_cut_can_actually_do() {
        // Disposition keys on the cut + chain flags, not on the per-entry evidence, so an
        // empty graph (no CVEs/behaviors) is fine here.
        let g = SecurityGraph::new();
        let disp = |c: &ProvenChain| Finding::from_chain(c, &g).disposition;

        // A network cut that meets the bar is the only thing that auto-applies.
        assert_eq!(
            disp(&chain("reaches/Tcp", false, true, true)),
            "auto-eligible"
        );
        assert_eq!(
            disp(&chain("reaches/Tcp", true, false, true)),
            "latent foothold — propose"
        );
        assert_eq!(
            disp(&chain("reaches/Tcp", false, false, true)),
            "structural — propose"
        );
        assert_eq!(
            disp(&chain("reaches/Tcp", false, true, false)),
            "vetoed — propose"
        );

        // Corroborated, but the cut is subtractive (RBAC/data) → NOT auto-eligible;
        // it's a durable-fix PR. This is the "198 auto-eligible" mislabel, fixed.
        assert_eq!(
            disp(&chain("can-do/get/secrets", false, true, true)),
            "durable-fix PR"
        );
        assert_eq!(
            disp(&chain("can-read", false, true, true)),
            "durable-fix PR"
        );
        // An escape primitive is irreversible — never auto.
        assert_eq!(
            disp(&chain("escapes-to/privileged", false, true, true)),
            "forbidden"
        );

        // A model-promoted network chain is auto-eligible even without corroboration.
        let promoted = ProvenChain {
            promoted: true,
            ..chain("reaches/Tcp", false, false, true)
        };
        assert_eq!(
            Finding::from_chain(&promoted, &g).disposition,
            "auto-eligible"
        );
    }

    /// Build a Finding with a two-hop path entry →reaches→ store →&lt;rel&gt;→ objective.
    fn finding(
        entry: &str,
        objective: &str,
        disposition: &str,
        terminal_rel: &str,
        breach_relevant: bool,
        verdict: Option<&str>,
    ) -> Finding {
        Finding {
            entry: entry.into(),
            objective: objective.into(),
            tactic: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            technique: "T1552".into(),
            technique_name: "Unsecured Credentials".into(),
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            disposition: disposition.into(),
            // The cut is the first hop (the reaches edge entry → store), matching
            // the first PathStep below so the remediation graph can mark it.
            cut: Some(format!("{entry} -[reaches/Tcp]-> workload/app/Pod/store")),
            breach_relevant,
            killchain: "T1190 Exploit Public-Facing Application → T1552 Unsecured Credentials"
                .into(),
            verdict: verdict.map(str::to_string),
            path: vec![
                PathStep {
                    from: entry.into(),
                    relation: "reaches/Tcp".into(),
                    to: "workload/app/Pod/store".into(),
                },
                PathStep {
                    from: "workload/app/Pod/store".into(),
                    relation: terminal_rel.into(),
                    to: objective.into(),
                },
            ],
            // Most render tests don't exercise the evidence blocks; the dedicated
            // JEF-133 tests below build findings with populated evidence.
            evidence: EntryEvidence::default(),
        }
    }

    #[test]
    fn mm_strips_html_metacharacters_to_prevent_xss() {
        // A malicious label can't break out of the <pre> or inject into the SVG.
        let evil = mm("</pre><img src=x onerror=\"alert(1)\">&");
        for c in ['<', '>', '&', '"'] {
            assert!(!evil.contains(c), "mm must strip {c:?}");
        }
    }

    #[test]
    fn renders_two_graph_sections_and_drops_internal_paths() {
        let findings = vec![
            // Remediation: the model judged it exploitable → auto-eligible cut.
            finding(
                "workload/app/Pod/web",
                "secret/app/session-key",
                "auto-eligible",
                "reaches/Tcp",
                true,
                Some("exploitable — CVE-2021-44228 is a remote RCE reaching the secret"),
            ),
            // Un-remediated paths from the SAME endpoint (coalesce into one graph).
            finding(
                "workload/app/Pod/web",
                "capability/cluster/create/pods",
                "durable-fix PR",
                "can-do/create/pods",
                true,
                None,
            ),
            // The model's NEGATIVE call is kept too — shown as the reason.
            finding(
                "workload/app/Pod/web",
                "secret/app/other",
                "latent foothold — propose",
                "can-read",
                true,
                Some("not exploitable — the CVE is in a code path this service never invokes"),
            ),
            // Internal (not breach-relevant): must NOT appear in either section.
            finding(
                "workload/argocd/Pod/argocd-application-controller-0",
                "secret/argocd/argocd-secret",
                "durable-fix PR",
                "can-do/get/secrets",
                false,
                None,
            ),
        ];

        let html = render_html(&findings, false, &BakeStats::default(), &[], None, &ready());
        // Remediations verb (JEF-175): shadow → "What protector would do"; armed →
        // "What protector is doing".
        assert!(html.contains("What protector would do"));
        assert!(
            render_html(&findings, true, &BakeStats::default(), &[], None, &ready())
                .contains("What protector is doing")
        );
        // The findings region carries the answer-first "Watching" section (the web
        // endpoint's card is not model-flagged, so it lands under Watching, not the
        // omitted-when-empty "Needs attention").
        assert!(html.contains("Watching"));
        // The attack-vector summary names the ATT&CK outcomes reachable, with the
        // model-flagged count (one objective was judged exploitable above). Plain-English
        // heading "What an attacker could reach" under the diagnostics region (JEF-176).
        assert!(html.contains("What an attacker could reach"));
        assert!(html.contains("Credential Access"));
        assert!(html.contains("Unsecured Credentials"));
        assert!(html.contains("class=\"flagged\""));
        // Graphs are Mermaid flowcharts with an Internet source.
        assert!(html.contains("class=\"mermaid\""));
        assert!(html.contains("flowchart LR"));
        assert!(html.contains("Internet"));
        // The remediation graph marks the cut (dashed edge + scissors).
        assert!(html.contains("✂"));
        // BOTH the positive verdict (on the remediation) and the negative one (on the
        // un-remediated path) are surfaced with the model's reasoning.
        assert!(html.contains("exploitable — CVE-2021-44228 is a remote RCE"));
        assert!(html.contains("not exploitable — the CVE is in a code path"));
        // The internal control-plane path is dropped entirely (one endpoint: web).
        assert!(!html.contains("argocd-secret"));
        assert!(html.contains("1</b> exposed endpoint"));
        // Dump for eyeballing the UX (ignored by CI artifacts; just a dev aid).
        let _ = std::fs::write("/tmp/protector-dashboard.html", &html);
    }

    fn bake(resolved: u64, unresolved: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        signals_by_variant.insert("connection".to_string(), 12);
        signals_by_variant.insert("secret-read".to_string(), 3);
        signals_by_variant.insert("library-load".to_string(), 5);
        BakeStats {
            signals_by_variant,
            resolved,
            unresolved,
            runtime_store: 7,
            corroborations: 2,
        }
    }

    #[test]
    fn bake_stats_total_and_unresolved_fraction() {
        let b = bake(80, 20);
        assert_eq!(b.total_signals(), 20, "sum across the three variants");
        assert!(
            (b.unresolved_fraction() - 0.2).abs() < 1e-9,
            "20 of 100 attributed are unresolved"
        );
        // No attributed signals → no misses (avoid a divide-by-zero NaN).
        assert_eq!(BakeStats::default().unresolved_fraction(), 0.0);
    }

    #[test]
    fn bake_panel_renders_volume_attribution_and_corroborations() {
        let panel = bake_panel(&bake(80, 20));
        // Per-variant volume rows the JEF-48 "connect / secret-read / library-load" watch
        // wants to see by name.
        assert!(panel.contains("connection"));
        assert!(panel.contains("secret-read"));
        assert!(panel.contains("library-load"));
        // The attribution line surfaces resolved + the unresolved share, highlighted.
        assert!(panel.contains("80"), "resolved count");
        assert!(panel.contains("class=\"flagged\""), "unresolved is flagged");
        assert!(panel.contains("20.0%"), "unresolved fraction shown");
        // The live store size and corroborations-fired (the bake's promotion proxy).
        assert!(panel.contains("live store"));
        assert!(panel.contains("corroborations"));
    }

    #[test]
    fn bake_panel_is_quiet_when_nothing_observed() {
        let panel = bake_panel(&BakeStats::default());
        assert!(
            panel.contains("no behavioral signals observed yet"),
            "an empty bake reads as quiet, not as an error"
        );
        // A fully-resolved pass shows no flagged unresolved share.
        let clean = bake_panel(&bake(15, 0));
        assert!(
            !clean.contains("unresolved ("),
            "0 unresolved is not flagged"
        );
    }

    #[test]
    fn render_html_includes_the_behavioral_bake_section() {
        let html = render_html(&[], false, &bake(80, 20), &[], None, &ready());
        assert!(
            html.contains("Live activity the sensors saw"),
            "the section header is present"
        );
        assert!(
            html.contains("connection"),
            "the per-variant volume renders"
        );
    }

    // ====================================================================
    // The shadow would-have-acted report (JEF-143)
    // ====================================================================

    /// A `now` to anchor the report's relative-time math deterministically.
    fn report_now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// A breach journal entry for `entry` at `secs_before` seconds before [`report_now`],
    /// carrying `verdict` (the model's own words) and explicit structured
    /// enrichment-coverage (JEF-145) — the evidence the model was handed, independent of
    /// the verdict prose.
    fn breach_cov(
        entry: &str,
        verdict: &str,
        secs_before: u64,
        coverage: Option<EnrichmentCoverage>,
    ) -> JournalEntry {
        let at = report_now() - Duration::from_secs(secs_before);
        JournalEntry {
            at_ms: at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            decision: Decision::Breach {
                entry: entry.to_string(),
                objectives: 1,
                verdict: verdict.to_string(),
                coverage,
            },
        }
    }

    /// A breach entry whose structured coverage is derived from the verdict's CVE
    /// mentions — convenience for the lifetime/episode/ranking tests, which only care that
    /// a "CVE-…" verdict reads as enrichment-backed and a CVE-less one as a gap. Coverage
    /// classification itself is exercised independently below.
    fn breach(entry: &str, verdict: &str, secs_before: u64) -> JournalEntry {
        let cves: Vec<String> = verdict
            .match_indices("CVE-")
            .map(|(i, _)| {
                verdict[i..]
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        breach_cov(
            entry,
            verdict,
            secs_before,
            Some(EnrichmentCoverage {
                cves,
                behavioral: false,
            }),
        )
    }

    const WEEK: Duration = Duration::from_secs(7 * 24 * 3600);
    const FIVE_MIN: Duration = Duration::from_secs(300);

    #[test]
    fn verdict_classification_matches_the_findings_convention() {
        assert!(verdict_would_act(
            "exploitable — CVE-2021-44228 reaches the secret"
        ));
        assert!(verdict_would_act("Exploitable — RCE"));
        assert!(verdict_would_act("confirmed — live attack should stand"));
        assert!(!verdict_would_act(
            "not exploitable — code path never invoked"
        ));
        assert!(!verdict_would_act("refuted — same-ns own DB"));
        assert!(!verdict_would_act("uncertain — model unavailable"));
    }

    #[test]
    fn coverage_gap_reads_the_structured_field_not_the_verdict_prose() {
        // JEF-145: a gap is classified from the STRUCTURED enrichment-coverage the model
        // was given, never the verdict wording.
        // No CVE and no behavioral signal ⇒ a gap.
        assert!(is_coverage_gap(Some(&EnrichmentCoverage {
            cves: vec![],
            behavioral: false,
        })));
        // A CVE backs it ⇒ NOT a gap.
        assert!(!is_coverage_gap(Some(&EnrichmentCoverage {
            cves: vec!["CVE-2021-44228".into()],
            behavioral: false,
        })));
        // A behavioral signal backs it ⇒ NOT a gap.
        assert!(!is_coverage_gap(Some(&EnrichmentCoverage {
            cves: vec![],
            behavioral: true,
        })));
        // Back-compat: an old line with no structured coverage is "unknown", NOT a gap.
        assert!(!is_coverage_gap(None));
    }

    #[test]
    fn empty_journal_is_an_honest_no_decisions_state() {
        // The acceptance criterion: an empty journal reads as "no decisions yet", not
        // an error or a misleading zero-diff.
        let report = aggregate_report(&[], report_now(), WEEK, FIVE_MIN);
        assert!(report.journal_empty, "no breach decisions ⇒ journal_empty");
        assert_eq!(report.would_act_count(), 0);
        assert_eq!(report.left_alone_count(), 0);
        let panel = report_panel(&report);
        assert!(panel.contains("no decisions yet"), "honest empty state");
        // The full page wraps it and stays a valid document.
        let page = render_report_html(&report);
        assert!(page.contains("would-have-acted report"));
        assert!(page.contains("no decisions yet"));
    }

    #[test]
    fn window_filtering_excludes_decisions_outside_the_window() {
        // A breach 8 days ago is outside a 7-day window; an in-window decision survives.
        // The journal is NOT empty (history exists), but nothing falls in the window.
        let entries = vec![breach(
            "workload/app/Pod/old",
            "exploitable — CVE-2020-0001 RCE",
            8 * 24 * 3600,
        )];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert!(!report.journal_empty, "the journal has history");
        assert_eq!(
            report.decisions_in_window, 0,
            "but none in the 7-day window"
        );
        assert_eq!(report.would_act_count(), 0);
        // A wider window pulls it back in.
        let wide = aggregate_report(
            &entries,
            report_now(),
            Duration::from_secs(30 * 24 * 3600),
            FIVE_MIN,
        );
        assert_eq!(
            wide.would_act_count(),
            1,
            "30-day window includes the old one"
        );
    }

    #[test]
    fn a_sustained_then_cleared_path_is_a_would_act_with_a_real_lifetime() {
        // Breach held exploitable for an hour (two decisions an hour apart), then cleared.
        // The projected cut lifetime is ~1h — sustained, not short-lived — and the entry
        // shows in would-act, NOT left-alone (it WOULD have been cut, even though it later
        // cleared: that's the whole point of the lifetime).
        let entries = vec![
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                7200,
            ),
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                3600,
            ),
            breach("workload/app/Pod/web", "not exploitable — patched", 0),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 1);
        let w = &report.would_act[0];
        assert_eq!(w.entry, "workload/app/Pod/web");
        assert_eq!(
            w.would_act_decisions, 2,
            "two exploitable decisions in the run"
        );
        assert_eq!(w.episodes, 1);
        assert!(!w.open, "it cleared, so the episode is closed");
        assert_eq!(
            w.max_lifetime_secs, 7200,
            "first exploitable → the clear at now-3600"
        );
        assert!(!w.short_lived, "a 2h cut is sustained, not an FP");
        // It is NOT double-counted as left-alone.
        assert_eq!(report.left_alone_count(), 0);
    }

    #[test]
    fn a_short_lived_would_act_is_flagged_as_a_likely_false_positive() {
        // Exploitable once, then cleared 60s later: a 60s would-be cut — under the 5-min
        // threshold ⇒ short-lived ⇒ likely FP.
        let entries = vec![
            breach(
                "workload/app/Pod/blip",
                "exploitable — CVE-2022-1 brief RCE",
                120,
            ),
            breach(
                "workload/app/Pod/blip",
                "not exploitable — scanner artifact",
                60,
            ),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 1);
        assert!(report.would_act[0].short_lived, "a 60s cut is short-lived");
        assert_eq!(report.short_lived_count(), 1);
    }

    #[test]
    fn an_open_episode_projects_to_now_and_is_never_short_lived() {
        // Exploitable 30s ago and never cleared: the cut would still be standing. Even
        // though only 30s old, an OPEN episode is sustained-by-definition (not an FP yet).
        let entries = vec![breach(
            "workload/app/Pod/live",
            "exploitable — CVE-2023-9 active",
            30,
        )];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 1);
        let w = &report.would_act[0];
        assert!(w.open, "still standing");
        assert!(!w.short_lived, "an open cut is never an FP");
        assert_eq!(w.max_lifetime_secs, 30);
    }

    #[test]
    fn a_cleared_only_path_is_left_alone_trust_evidence() {
        // The model proved the path reachable but cleared it (never exploitable). This is
        // the trust half: a proven path deliberately left alone, NOT a would-act.
        let entries = vec![breach(
            "workload/app/Pod/safe",
            "not exploitable — the CVE is in a code path this service never invokes",
            600,
        )];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 0);
        assert_eq!(report.left_alone_count(), 1);
        assert_eq!(report.left_alone[0].entry, "workload/app/Pod/safe");
        assert!(report.left_alone[0].verdict.contains("not exploitable"));
    }

    #[test]
    fn coverage_gap_would_acts_are_counted_and_flagged() {
        // JEF-145 acceptance: a breach with NO enrichment (no CVE, no behavioral signal)
        // is flagged as a gap...
        let gap = vec![breach_cov(
            "workload/app/Pod/escape",
            "exploitable — a privileged container escape reaches the node",
            45,
            Some(EnrichmentCoverage {
                cves: vec![],
                behavioral: false,
            }),
        )];
        let report = aggregate_report(&gap, report_now(), WEEK, FIVE_MIN);
        assert_eq!(
            report.coverage_gap_count(),
            1,
            "no enrichment ⇒ coverage gap"
        );
        assert!(report.would_act[0].coverage_gap);

        // ...and a breach WITH CVE/behavioral backing is NOT flagged — regardless of the
        // verdict wording. Here the verdict prose mentions no CVE token at all, yet the
        // structured coverage carries one, so the prose heuristic would have misfired.
        let backed_cve = vec![breach_cov(
            "workload/app/Pod/web",
            "exploitable — a remote code-execution path reaches the secret",
            45,
            Some(EnrichmentCoverage {
                cves: vec!["CVE-2021-44228".into()],
                behavioral: false,
            }),
        )];
        let r2 = aggregate_report(&backed_cve, report_now(), WEEK, FIVE_MIN);
        assert_eq!(
            r2.coverage_gap_count(),
            0,
            "CVE backing ⇒ not a gap, even with no CVE in the prose"
        );
        assert!(!r2.would_act[0].coverage_gap);

        // The inverse misclassification is also gone: a verdict whose PROSE cites a CVE
        // but whose structured backing is empty IS still a gap (the old grep would have
        // read it as covered).
        let prose_only = vec![breach_cov(
            "workload/app/Pod/prose",
            "exploitable — resembles CVE-2099-0001 in shape but no advisory matched",
            45,
            Some(EnrichmentCoverage {
                cves: vec![],
                behavioral: false,
            }),
        )];
        let r3 = aggregate_report(&prose_only, report_now(), WEEK, FIVE_MIN);
        assert_eq!(
            r3.coverage_gap_count(),
            1,
            "empty structured backing ⇒ a gap, even with a CVE in the prose"
        );

        // A behavioral signal (no CVE) also backs the decision ⇒ not a gap.
        let backed_behavioral = vec![breach_cov(
            "workload/app/Pod/runtime",
            "exploitable — live reverse shell observed",
            45,
            Some(EnrichmentCoverage {
                cves: vec![],
                behavioral: true,
            }),
        )];
        let r4 = aggregate_report(&backed_behavioral, report_now(), WEEK, FIVE_MIN);
        assert_eq!(r4.coverage_gap_count(), 0, "behavioral backing ⇒ not a gap");
    }

    #[test]
    fn a_pre_jef145_breach_with_no_structured_coverage_is_not_a_false_gap() {
        // Back-compat (AC #3): an old journal line has `coverage: None`. It is a would-act
        // (exploitable), but its coverage is "unknown" — it must NOT be counted as a gap.
        let entries = vec![breach_cov(
            "workload/app/Pod/legacy",
            "exploitable — reaches the secret",
            45,
            None,
        )];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 1, "still a would-act");
        assert_eq!(
            report.coverage_gap_count(),
            0,
            "unknown coverage is not a gap (no false positive on old records)"
        );
        assert!(!report.would_act[0].coverage_gap);
    }

    #[test]
    fn recurring_breach_counts_multiple_episodes() {
        // Exploitable, cleared, then exploitable again: two distinct would-act episodes
        // for the same workload (the breach condition recurred). The entry is a would-act
        // (its latest run is exploitable), with episodes == 2.
        let entries = vec![
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                3000,
            ),
            breach("workload/app/Pod/web", "not exploitable — patched", 2000),
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 regressed",
                1000,
            ),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 1);
        assert_eq!(report.would_act[0].episodes, 2, "the breach recurred");
        assert!(
            report.would_act[0].open,
            "latest run is exploitable ⇒ still open"
        );
    }

    #[test]
    fn report_panel_renders_the_diff_headline_and_both_tables() {
        // The HTML panel frames the diff (isolated N / left M alone), distinguishes
        // short-lived from sustained, and calls out the coverage-gap subset.
        let entries = vec![
            // A sustained, CVE-backed would-act (cleared after 2h).
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                7200,
            ),
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                3600,
            ),
            breach("workload/app/Pod/web", "not exploitable — patched", 0),
            // A short-lived, coverage-gap would-act (60s, no CVE).
            breach("workload/app/Pod/blip", "exploitable — brief escape", 120),
            breach("workload/app/Pod/blip", "not exploitable — gone", 60),
            // A left-alone proven path.
            breach(
                "workload/app/Pod/safe",
                "not exploitable — never invoked",
                600,
            ),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.would_act_count(), 2);
        assert_eq!(report.left_alone_count(), 1);
        assert_eq!(report.short_lived_count(), 1);
        assert_eq!(report.coverage_gap_count(), 1);

        let panel = report_panel(&report);
        // The diff headline frames both halves.
        assert!(panel.contains("would have isolated"));
        assert!(panel.contains("left alone") || panel.contains("left <b>1</b>"));
        // Short-lived is visually distinct, sustained too.
        assert!(panel.contains("short-lived"), "FP tell rendered");
        assert!(panel.contains("class=\"shortlived\""));
        assert!(panel.contains("class=\"sustained\""));
        // The coverage-gap would-act is flagged for scrutiny.
        assert!(panel.contains("coverage gap"));
        assert!(panel.contains("class=\"flagged\""));
        // Both workloads and the left-alone one appear (short labels).
        assert!(panel.contains("web"));
        assert!(panel.contains("blip"));
        assert!(panel.contains("safe"));

        // The full page is a self-contained document.
        let page = render_report_html(&report);
        assert!(page.contains("<!doctype html>"));
        assert!(page.contains("would-have-acted report"));
        assert!(page.contains("Shadow would-have-acted diff"));
        let _ = std::fs::write("/tmp/protector-report.html", &page);
    }

    #[test]
    fn most_sustained_would_act_is_ranked_first() {
        // Open (still standing) ranks above a closed long one, which ranks above a short one.
        let entries = vec![
            breach("workload/app/Pod/short", "exploitable — x", 200),
            breach("workload/app/Pod/short", "not exploitable — gone", 100),
            breach("workload/app/Pod/longclosed", "exploitable — y", 10_000),
            breach(
                "workload/app/Pod/longclosed",
                "not exploitable — patched",
                100,
            ),
            breach("workload/app/Pod/open", "exploitable — z", 50),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(
            report.would_act[0].entry, "workload/app/Pod/open",
            "open first"
        );
        assert_eq!(report.would_act[1].entry, "workload/app/Pod/longclosed");
        assert_eq!(report.would_act[2].entry, "workload/app/Pod/short");
    }

    #[test]
    fn report_query_resolves_window_and_threshold_with_defaults() {
        // Defaults: 7-day window, 5-min short-lived.
        let q = ReportQuery::default();
        assert_eq!(q.window(), Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600));
        assert_eq!(
            q.short_lived(),
            Duration::from_secs(DEFAULT_SHORT_LIVED_SECS)
        );
        // `days` sugar, and `hours` taking precedence over `days`.
        let by_days = ReportQuery {
            days: Some(3),
            ..Default::default()
        };
        assert_eq!(by_days.window(), Duration::from_secs(3 * 24 * 3600));
        let both = ReportQuery {
            hours: Some(2),
            days: Some(30),
            short_lived_secs: Some(10),
        };
        assert_eq!(both.window(), Duration::from_secs(2 * 3600), "hours wins");
        assert_eq!(both.short_lived(), Duration::from_secs(10));
    }

    #[test]
    fn default_window_report_reads_an_in_memory_disabled_journal_as_empty() {
        // The OTLP-mirror helper on a disabled journal (no volume) is an empty report —
        // a cheap no-op, never a crash. (The enabled-journal round trip is covered by the
        // journal module's own tests; here we only need the headline math to be zero.)
        let report = default_window_report(&DecisionJournal::disabled());
        assert!(report.journal_empty);
        assert_eq!(report.would_act_count(), 0);
        assert_eq!(report.left_alone_count(), 0);
    }

    // ====================================================================
    // The readiness / coverage panel (JEF-160)
    // ====================================================================

    /// A bake snapshot with a Falco `alert` count and one eBPF (`connection`) count, so
    /// the two behavioral feeds can be split in the readiness rows.
    fn feeds_bake(falco: u64, ebpf: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        if falco > 0 {
            signals_by_variant.insert("alert".to_string(), falco);
        }
        if ebpf > 0 {
            signals_by_variant.insert("connection".to_string(), ebpf);
        }
        BakeStats {
            signals_by_variant,
            ..Default::default()
        }
    }

    /// A config summary with every input wired (a fully-covered cluster).
    fn full_config() -> ReadinessConfig {
        ReadinessConfig {
            model_attached: true,
            kev_count: 1500,
            advisory_count: 800,
            journal_durable: true,
            armed: false,
        }
    }

    /// Look a readiness row up by its stable id.
    fn rrow<'a>(r: &'a Readiness, id: &str) -> &'a ReadinessRow {
        r.inputs
            .iter()
            .find(|row| row.id == id)
            .unwrap_or_else(|| panic!("readiness row {id} present"))
    }

    #[test]
    fn readiness_reports_each_input_from_live_state() {
        // Acceptance #1: every input shows present/absent/degraded from LIVE state.
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Ok,
            &feeds_bake(3, 12),
            Some(SystemTime::now()),
        );
        assert!(!r.warming_up, "a pass completed");
        assert_eq!(rrow(&r, "model").state, InputState::Present);
        assert!(rrow(&r, "model").detail.contains("last call ok"));
        assert_eq!(rrow(&r, "kev").state, InputState::Present);
        assert!(rrow(&r, "kev").detail.contains("1500"));
        assert_eq!(rrow(&r, "advisory").state, InputState::Present);
        assert_eq!(rrow(&r, "falco").state, InputState::Present);
        assert!(rrow(&r, "falco").detail.contains("3 signals last pass"));
        assert_eq!(rrow(&r, "ebpf-agent").state, InputState::Present);
        assert!(
            rrow(&r, "ebpf-agent")
                .detail
                .contains("12 signals last pass")
        );
        assert_eq!(rrow(&r, "journal").state, InputState::Present);
        // Arm-state is posture, always present; reports the shadow default here.
        assert_eq!(rrow(&r, "arm-state").state, InputState::Present);
        assert!(rrow(&r, "arm-state").detail.contains("shadow"));
        // Fully covered ⇒ nothing unmet.
        assert!(!r.has_unmet(), "every input wired ⇒ no unmet inputs");
    }

    #[test]
    fn absent_enrichment_inputs_are_marked_and_flagged_as_weakening() {
        // Acceptance #1: an absent input that weakens decisions is distinct. With nothing
        // configured, every enrichment input is Absent AND flagged `weakens_decisions`.
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        for id in ["kev", "advisory", "falco", "ebpf-agent"] {
            assert_eq!(rrow(&r, id).state, InputState::Absent, "{id} absent");
            assert!(rrow(&r, id).weakens_decisions, "{id} weakens decisions");
        }
        // The journal absent is a durability gap, NOT a decision-weakening one.
        assert_eq!(rrow(&r, "journal").state, InputState::Absent);
        assert!(!rrow(&r, "journal").weakens_decisions);
        assert!(r.has_unmet());
    }

    #[test]
    fn no_model_says_so_explicitly_and_that_no_calls_are_made() {
        // Acceptance #3: no model configured ⇒ explicit, and that no exploitability calls
        // are made.
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: false,
                ..full_config()
            },
            ModelHealth::Unknown,
            &feeds_bake(1, 1),
            Some(SystemTime::now()),
        );
        let model = rrow(&r, "model");
        assert_eq!(model.state, InputState::Absent);
        assert!(model.weakens_decisions);
        assert!(
            model.detail.contains("no exploitability calls")
                || model.detail.contains("no model configured"),
            "explicit that no calls are made: {}",
            model.detail
        );
        let panel = readiness_panel(&r);
        assert!(panel.contains("no exploitability calls are made"));
    }

    #[test]
    fn attached_model_that_timed_out_is_degraded_not_absent() {
        // A model that's wired but whose last call timed out is Degraded — the model IS
        // configured, it just isn't answering. Distinct from Absent.
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Timeout,
            &feeds_bake(1, 1),
            Some(SystemTime::now()),
        );
        let model = rrow(&r, "model");
        assert_eq!(model.state, InputState::Degraded);
        assert!(model.detail.contains("timed out"));
    }

    #[test]
    fn readiness_warming_up_when_no_pass_has_completed() {
        // Cold start: no pass ⇒ warming_up, so the bake window reads as expected.
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            None,
        );
        assert!(r.warming_up);
        let panel = readiness_panel(&r);
        assert!(
            panel.contains("warming up") && panel.contains("CPU model"),
            "cold-start note explains the bake window"
        );
    }

    #[test]
    fn readiness_panel_states_are_in_text_not_glyph_only() {
        // Accessibility: the status word is IN TEXT for every row.
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                ..ReadinessConfig::default()
            },
            ModelHealth::Ok,
            &feeds_bake(0, 0),
            Some(SystemTime::now()),
        );
        let panel = readiness_panel(&r);
        // It's an ordered list with the state words present as text.
        assert!(panel.contains("<ol class=\"readiness\">"));
        assert!(panel.contains(">present<"));
        assert!(panel.contains(">absent<"));
        // An absent decision-weakening input carries the explicit tag.
        assert!(panel.contains("weakens decisions"));
        // The enable hint for an unmet input is shown.
        assert!(panel.contains("PROTECTOR_KEV_FILE"));
    }

    #[test]
    fn first_run_checklist_replaces_the_empty_body_when_inputs_unmet() {
        // Acceptance #4: empty + unmet inputs ⇒ the instructional checklist, never a bare
        // page. No breach findings, nothing configured → the checklist, with each unmet
        // input linking its enable var.
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        let html = render_html(
            &[],
            false,
            &BakeStats::default(),
            &[],
            Some(SystemTime::now()),
            &r,
        );
        assert!(
            html.contains(r#"class="firstrun""#) && html.contains(r#"ol class="checklist""#),
            "the instructional checklist replaces the empty findings body"
        );
        assert!(
            html.contains("PROTECTOR_ENGINE_MODEL"),
            "model enable linked"
        );
        assert!(
            html.contains("PROTECTOR_ADVISORY_FILE"),
            "advisory enable linked"
        );
        // It frames itself as a guided start, never a bare/error-looking page.
        assert!(html.contains("guided start, not a blank page"));
    }

    #[test]
    fn clean_cluster_with_full_coverage_keeps_the_honest_empty_state() {
        // First-run discrimination: no findings BUT every input wired ⇒ NOT first-run; the
        // existing honest-empty idiom stands (a genuinely clean, fully-covered cluster).
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Ok,
            &feeds_bake(2, 5),
            Some(SystemTime::now()),
        );
        assert!(!r.has_unmet());
        let html = render_html(
            &[],
            false,
            &feeds_bake(2, 5),
            &[],
            Some(SystemTime::now()),
            &r,
        );
        assert!(
            html.contains("no internet-facing service can reach a target"),
            "a clean, covered cluster keeps the honest-empty state"
        );
        assert!(
            !html.contains(r#"class="firstrun""#),
            "no first-run checklist when every input is covered"
        );
    }

    #[test]
    fn render_html_includes_the_readiness_panel_section() {
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Ok,
            &feeds_bake(1, 1),
            Some(SystemTime::now()),
        );
        // A breach finding is present so the body is the normal graph (not the checklist),
        // and the coverage panel still renders above it.
        let findings = vec![breach_finding("workload/app/Pod/web")];
        let html = render_html(
            &findings,
            false,
            &feeds_bake(1, 1),
            &[],
            Some(SystemTime::now()),
            &r,
        );
        // Renamed to "Readiness" inside the collapsed diagnostics region (JEF-175).
        assert!(html.contains("Readiness"));
        assert!(html.contains("<a href=\"/readiness\">json</a>"));
        assert!(html.contains("Model adjudicator"));
        assert!(html.contains("<ol class=\"readiness\">"));
    }

    #[test]
    fn readiness_json_shape_matches_the_panel_data() {
        // Acceptance #2: `/readiness` returns the same data as JSON. Assert the serialized
        // shape: kebab-case states, the stable ids, and the live fields.
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                advisory_count: 7,
                ..ReadinessConfig::default()
            },
            ModelHealth::Ok,
            &feeds_bake(0, 4),
            Some(SystemTime::now()),
        );
        let json = serde_json::to_value(&r).expect("readiness serializes");
        assert_eq!(json["warming_up"], serde_json::json!(false));
        let inputs = json["inputs"].as_array().expect("inputs array");
        // The ids are stable and the model row serializes its present state in kebab-case.
        let model = inputs
            .iter()
            .find(|r| r["id"] == "model")
            .expect("model row in json");
        assert_eq!(model["state"], serde_json::json!("present"));
        assert_eq!(model["weakens_decisions"], serde_json::json!(true));
        let kev = inputs
            .iter()
            .find(|r| r["id"] == "kev")
            .expect("kev row in json");
        assert_eq!(kev["state"], serde_json::json!("absent"));
        let ebpf = inputs
            .iter()
            .find(|r| r["id"] == "ebpf-agent")
            .expect("ebpf row in json");
        assert_eq!(ebpf["state"], serde_json::json!("present"));
        assert!(
            ebpf["detail"].as_str().unwrap().contains("4 signals"),
            "live signal count is in the json detail"
        );
    }

    #[test]
    fn findings_round_trips_the_readiness_config_and_model_health() {
        // The shared findings handle carries the config summary + live model health the
        // dashboard reads back — the engine writes them, the panel renders them.
        let findings = Findings::new();
        // Defaults: nothing configured, model unknown.
        assert!(!findings.readiness_config().model_attached);
        assert_eq!(findings.model_health(), ModelHealth::Unknown);
        findings.set_readiness_config(ReadinessConfig {
            model_attached: true,
            kev_count: 10,
            advisory_count: 5,
            journal_durable: true,
            armed: true,
        });
        findings.set_model_health(ModelHealth::Timeout);
        let cfg = findings.readiness_config();
        assert!(cfg.model_attached && cfg.armed && cfg.journal_durable);
        assert_eq!(cfg.kev_count, 10);
        assert_eq!(findings.model_health(), ModelHealth::Timeout);
    }

    // ===================================================================
    // JEF-161 — verdict-first card + human /judgements view
    // ===================================================================

    #[test]
    fn posture_chip_selection_per_verdict_state() {
        // The model's affirmation → [BREACH]; a "not exploitable" call → [SAFE]; no
        // verdict yet → [awaiting judgement]. The Debug form (capitalized) maps too.
        assert_eq!(Posture::of(None), Posture::Awaiting);
        assert_eq!(Posture::of(None).label(), "[awaiting judgement]");
        assert_eq!(
            Posture::of(Some("exploitable — RCE reaches the secret")),
            Posture::Breach
        );
        assert_eq!(
            Posture::of(Some("Exploitable(\"reason\")")),
            Posture::Breach
        );
        assert_eq!(Posture::Breach.label(), "[BREACH]");
        assert_eq!(
            Posture::of(Some("not exploitable — authorized RBAC, no CVE")),
            Posture::Safe
        );
        assert_eq!(Posture::of(Some("Refuted(\"benign\")")), Posture::Safe);
        assert_eq!(Posture::Safe.label(), "[SAFE]");
    }

    #[test]
    fn what_to_do_per_disposition_class() {
        // AC #1: the "what to do" line is derived per disposition class, no model call.
        assert_eq!(
            what_to_do(AUTO_ELIGIBLE),
            "would cut in shadow; arm `network` to act"
        );
        assert_eq!(
            what_to_do("latent foothold — propose"),
            "would cut in shadow; arm `network` to act"
        );
        assert_eq!(
            what_to_do("structural — propose"),
            "would cut in shadow; arm `network` to act"
        );
        assert!(what_to_do("durable-fix PR").contains("revoke the grant"));
        assert!(what_to_do("forbidden").starts_with("manual"));
        assert!(what_to_do("no-cut").starts_with("manual"));
        // An unknown/future disposition falls back to the safe, conservative default.
        assert!(what_to_do("unclassified").starts_with("manual"));
        assert!(what_to_do("something-new").starts_with("manual"));
    }

    #[test]
    fn cve_id_extracts_a_cited_cve_and_handles_absence() {
        assert_eq!(
            cve_id("exploitable — CVE-2021-44228 is a remote RCE reaching the secret"),
            Some("CVE-2021-44228")
        );
        // Trailing punctuation is trimmed.
        assert_eq!(cve_id("see CVE-2024-3094."), Some("CVE-2024-3094"));
        // No CVE cited → None (the rail then reads "none cited", never implied-absent).
        assert_eq!(cve_id("not exploitable — authorized RBAC"), None);
        assert_eq!(cve_id("CVE-"), None);
    }

    #[test]
    fn certainty_rail_reads_unknown_when_no_cve_cited() {
        // AC #2: missing evidence reads "unknown", never implied-absent.
        let f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "no-cut",
            "can-read",
            true,
            Some("not exploitable — authorized RBAC, nothing concerning"),
        );
        let facts = proven_facts(&f.entry, std::slice::from_ref(&&f));
        let joined = facts.join(" ");
        assert!(
            joined.contains("internet-reachable"),
            "the entry's internet-reachability is a proven fact"
        );
        assert!(
            joined.contains("mounts (direct read)"),
            "the terminal relation is humanized into the rail"
        );
        assert!(
            joined.contains("none cited") && joined.contains("unknown"),
            "no CVE cited reads as unknown, not implied-absent: {joined}"
        );
    }

    #[test]
    fn certainty_rail_surfaces_a_cited_cve() {
        let f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "auto-eligible",
            "can-read",
            true,
            Some("exploitable — CVE-2021-44228 is a remote RCE reaching the secret"),
        );
        let joined = proven_facts(&f.entry, std::slice::from_ref(&&f)).join(" ");
        assert!(
            joined.contains("CVE present") && joined.contains("CVE-2021-44228"),
            "a cited CVE surfaces on the rail: {joined}"
        );
    }

    #[test]
    fn endpoint_card_is_verdict_first_with_chip_rail_todo_and_aria() {
        // AC #1 + #4: chip + model words + proven rail + what-to-do, and the SVG carries
        // an aria-label summarizing the path in words.
        let f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "durable-fix PR",
            "can-do/get/secrets",
            true,
            Some("not exploitable — authorized RBAC, no CVE"),
        );
        let html = endpoint_card(
            "workload/app/Pod/web",
            &[&f],
            endpoint_attention_rank(&[&f]).1,
        );
        // Posture chip TEXT (not color/glyph alone).
        assert!(html.contains("[SAFE]"), "the posture chip carries text");
        assert!(html.contains("chip-safe"));
        // The model's words VERBATIM.
        assert!(html.contains("not exploitable — authorized RBAC, no CVE"));
        // The certainty rail and its caption.
        assert!(html.contains("what's proven"));
        assert!(html.contains("internet-reachable"));
        // The disposition-derived "what to do".
        assert!(html.contains("what to do:"));
        assert!(html.contains("revoke the grant"));
        // The graph's aria-label (data-aria on the <pre>, applied to the SVG by the JS).
        assert!(html.contains("data-aria=\""));
        assert!(html.contains("Attack-path graph"));
        // The verdict-first chip must come BEFORE the graph in source order.
        let chip_at = html.find("[SAFE]").unwrap();
        let graph_at = html.find("class=\"mermaid\"").unwrap();
        assert!(chip_at < graph_at, "the verdict leads the card");
    }

    #[test]
    fn endpoint_card_awaiting_state_is_honest_not_clear() {
        // AC #2 coverage-gap honesty: no verdict yet reads "awaiting", never "clear".
        let f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "no-cut",
            "can-read",
            true,
            None,
        );
        let html = endpoint_card(
            "workload/app/Pod/web",
            &[&f],
            endpoint_attention_rank(&[&f]).1,
        );
        assert!(html.contains("[awaiting judgement]"));
        assert!(html.contains("chip-awaiting"));
        assert!(html.contains("hasn't reached this entry yet"));
    }

    #[test]
    fn endpoint_card_calls_out_breadth_when_safe_and_wide() {
        // ADR-0016 severity ≠ breach: a broad, calm [SAFE] entry is the intended picture.
        let fs: Vec<Finding> = (0..25)
            .map(|n| {
                finding(
                    "workload/argocd/Pod/argocd-server",
                    &format!("secret/argocd/secret-{n}"),
                    "durable-fix PR",
                    "can-do/get/secrets",
                    true,
                    Some("not exploitable — authorized RBAC, no CVE, no behavior"),
                )
            })
            .collect();
        let refs: Vec<&Finding> = fs.iter().collect();
        let html = endpoint_card(
            "workload/argocd/Pod/argocd-server",
            &refs,
            endpoint_attention_rank(&refs).1,
        );
        assert!(
            html.contains("wide access isn't a break-in"),
            "a wide [SAFE] entry is framed as breadth, not a break-in"
        );
        // The same breadth, but BREACH, is not softened.
        let breach: Vec<Finding> = (0..25)
            .map(|n| {
                finding(
                    "workload/argocd/Pod/argocd-server",
                    &format!("secret/argocd/secret-{n}"),
                    "auto-eligible",
                    "can-do/get/secrets",
                    true,
                    Some("exploitable — CVE-2021-44228 reaches everything"),
                )
            })
            .collect();
        let brefs: Vec<&Finding> = breach.iter().collect();
        let bhtml = endpoint_card(
            "workload/argocd/Pod/argocd-server",
            &brefs,
            endpoint_attention_rank(&brefs).1,
        );
        assert!(!bhtml.contains("breadth is severity"));
    }

    // ---- JEF-163: presentation-only "look at this first" attention ranking ----

    /// A finding with explicit attention-relevant fields — the `finding` helper hardcodes
    /// `corroborated: true`, so this lets a test set the four signals independently.
    fn ranked_finding(
        entry: &str,
        disposition: &str,
        corroborated: bool,
        verdict: Option<&str>,
    ) -> Finding {
        let mut f = finding(
            entry,
            "secret/app/session-key",
            disposition,
            "can-do/get/secrets",
            true,
            verdict,
        );
        f.corroborated = corroborated;
        f.foothold = disposition.contains("latent foothold");
        f
    }

    #[test]
    fn attention_rank_assigns_each_tier_from_existing_fields() {
        // 1. model-flagged exploitable → priority 0, Flagged.
        let flagged_f = ranked_finding(
            "e",
            "auto-eligible",
            false,
            Some("exploitable — CVE-2021-44228 chains to the secret"),
        );
        assert_eq!(attention_rank(&flagged_f), (0, Tier::Flagged));

        // 2. latent foothold WITH a cited CVE → priority 1, Watch.
        let latent_cve = ranked_finding(
            "e",
            "latent foothold — propose",
            false,
            Some("uncertain — CVE-2023-1234 may be reachable"),
        );
        assert_eq!(attention_rank(&latent_cve), (1, Tier::Watch));

        // 3. runtime-corroborated (no flag, no latent+CVE) → priority 2, Watch.
        let corrob = ranked_finding("e", "structural — propose", true, None);
        assert_eq!(attention_rank(&corrob), (2, Tier::Watch));

        // 4. everything else → priority 3, Context.
        let other = ranked_finding("e", "structural — propose", false, None);
        assert_eq!(attention_rank(&other), (3, Tier::Context));
    }

    #[test]
    fn latent_foothold_without_a_cve_is_only_context() {
        // A latent foothold with NO cited CVE does NOT reach the watch tier — the CVE
        // signal is required for level 2 (the conservative reading of the missing
        // KEV/severity field: a cited CVE, not mere latency, promotes it).
        let latent_no_cve = ranked_finding(
            "e",
            "latent foothold — propose",
            false,
            Some("uncertain — no CVE cited, just reachable"),
        );
        assert_eq!(attention_rank(&latent_no_cve), (3, Tier::Context));
    }

    #[test]
    fn flagged_sorts_above_a_larger_unflagged_endpoint() {
        // AC #2 (explicit): a flagged-exploitable endpoint ALWAYS sorts above a
        // larger-but-unflagged one — blast radius can never overcome a higher tier.
        let small_flagged = ranked_finding(
            "e1",
            "auto-eligible",
            false,
            Some("exploitable — reaches it"),
        );
        // A big, calm endpoint: 50 unflagged, corroborated paths.
        let big_calm: Vec<Finding> = (0..50)
            .map(|n| {
                let mut f = ranked_finding(
                    "e2",
                    "structural — propose",
                    true,
                    Some("not exploitable — authorized RBAC"),
                );
                f.objective = format!("secret/app/s-{n}");
                f
            })
            .collect();

        let small_refs = vec![&small_flagged];
        let big_refs: Vec<&Finding> = big_calm.iter().collect();
        let mut endpoints: Vec<(&str, Vec<&Finding>)> = vec![("e2", big_refs), ("e1", small_refs)];
        // Apply EXACTLY the render-site key: priority, then blast radius desc, then entry.
        endpoints.sort_by(|a, b| {
            endpoint_attention_rank(&a.1)
                .0
                .cmp(&endpoint_attention_rank(&b.1).0)
                .then_with(|| b.1.len().cmp(&a.1.len()))
                .then_with(|| a.0.cmp(b.0))
        });
        assert_eq!(
            endpoints[0].0, "e1",
            "the small flagged endpoint outranks the 50-path calm one"
        );
    }

    #[test]
    fn blast_radius_only_tiebreaks_within_a_tier() {
        // Two endpoints in the SAME (context) tier: the larger graph sorts first.
        let make = |entry: &str, n: usize| -> Vec<Finding> {
            (0..n)
                .map(|i| {
                    let mut f = ranked_finding(entry, "structural — propose", false, None);
                    f.objective = format!("secret/app/{entry}-{i}");
                    f
                })
                .collect()
        };
        let small = make("a", 2);
        let large = make("b", 9);
        let small_refs: Vec<&Finding> = small.iter().collect();
        let large_refs: Vec<&Finding> = large.iter().collect();
        // Same tier.
        assert_eq!(endpoint_attention_rank(&small_refs).1, Tier::Context);
        assert_eq!(endpoint_attention_rank(&large_refs).1, Tier::Context);

        let mut endpoints: Vec<(&str, Vec<&Finding>)> = vec![("a", small_refs), ("b", large_refs)];
        endpoints.sort_by(|a, b| {
            endpoint_attention_rank(&a.1)
                .0
                .cmp(&endpoint_attention_rank(&b.1).0)
                .then_with(|| b.1.len().cmp(&a.1.len()))
                .then_with(|| a.0.cmp(b.0))
        });
        assert_eq!(
            endpoints[0].0, "b",
            "the wider graph wins the in-tier tiebreak"
        );
    }

    #[test]
    fn sort_is_stable_for_fully_equal_keys() {
        // Same priority AND same blast radius → the entry-key tiebreak gives a stable,
        // deterministic total order (so equal cards never shuffle between renders).
        let a = ranked_finding("aaa", "structural — propose", false, None);
        let b = ranked_finding("bbb", "structural — propose", false, None);
        let c = ranked_finding("ccc", "structural — propose", false, None);
        let mut endpoints: Vec<(&str, Vec<&Finding>)> =
            vec![("ccc", vec![&c]), ("aaa", vec![&a]), ("bbb", vec![&b])];
        endpoints.sort_by(|x, y| {
            endpoint_attention_rank(&x.1)
                .0
                .cmp(&endpoint_attention_rank(&y.1).0)
                .then_with(|| y.1.len().cmp(&x.1.len()))
                .then_with(|| x.0.cmp(y.0))
        });
        let order: Vec<&str> = endpoints.iter().map(|(e, _)| *e).collect();
        assert_eq!(order, vec!["aaa", "bbb", "ccc"]);
    }

    #[test]
    fn endpoint_attention_rank_takes_the_worst_case_in_the_group() {
        // A card coalesces a group; one flagged path makes the whole card flagged.
        let calm = ranked_finding(
            "e",
            "structural — propose",
            true,
            Some("not exploitable — ok"),
        );
        let one_flagged = ranked_finding("e", "auto-eligible", false, Some("exploitable — boom"));
        let group = vec![&calm, &one_flagged];
        assert_eq!(endpoint_attention_rank(&group), (0, Tier::Flagged));
    }

    #[test]
    fn context_tier_card_is_collapsible_and_de_emphasized() {
        // AC #3: the lowest tier is rendered behind a collapsible <details>, marked with
        // the de-emphasis class and the "context" tier label.
        let f = ranked_finding("workload/app/Pod/web", "structural — propose", false, None);
        let refs = vec![&f];
        let html = endpoint_card("workload/app/Pod/web", &refs, Tier::Context);
        assert!(html.contains("<details"), "context cards collapse");
        assert!(html.contains("card-context"), "de-emphasis class applied");
        assert!(html.contains(">context<"), "the tier label shows");
    }

    #[test]
    fn flagged_and_watch_cards_render_expanded_with_their_tier_label() {
        let f = ranked_finding(
            "workload/app/Pod/web",
            "auto-eligible",
            false,
            Some("exploitable — boom"),
        );
        let refs = vec![&f];
        let html = endpoint_card("workload/app/Pod/web", &refs, Tier::Flagged);
        assert!(
            html.contains("<div class=\"card\">"),
            "flagged cards stay open"
        );
        assert!(!html.contains("card-context"));
        assert!(html.contains(">flagged<"), "the flagged tier label shows");

        let w = ranked_finding("workload/app/Pod/web", "structural — propose", true, None);
        let wrefs = vec![&w];
        let whtml = endpoint_card("workload/app/Pod/web", &wrefs, Tier::Watch);
        assert!(whtml.contains(">watch<"), "the watch tier label shows");
    }

    #[test]
    fn render_html_splits_findings_into_attention_and_watching_with_tier_labels() {
        // Answer-first (JEF-175): a flagged endpoint heads "Needs attention"; a context
        // endpoint lands collapsed under "Watching". The tier labels still render. The
        // flagged finding uses a NON-auto-eligible disposition so it stays an endpoint
        // card (auto-eligible findings are pulled into the remediations section instead).
        let flagged = ranked_finding(
            "workload/app/Pod/web",
            "latent foothold — propose",
            false,
            Some("exploitable — boom"),
        );
        let context = {
            let mut f =
                ranked_finding("workload/argo/Pod/srv", "structural — propose", false, None);
            f.entry = "workload/argo/Pod/srv".into();
            f
        };
        let findings = vec![flagged, context];
        let html = render_html(
            &findings,
            false,
            &BakeStats::default(),
            &[],
            Some(SystemTime::now()),
            &ready(),
        );
        // Both answer-first sections render; Needs attention comes first.
        let needs = html
            .find("Needs attention")
            .expect("needs-attention section");
        let watching = html.find("Watching").expect("watching section");
        assert!(needs < watching, "Needs attention precedes Watching");
        assert!(html.contains(">flagged<"), "the flagged tier label appears");
        // The context-tier endpoint collapses behind <details class=\"card card-context\">.
        assert!(
            html.contains("card-context"),
            "the context tier is de-emphasized/collapsible"
        );
    }

    fn full_judgement(
        entry: &str,
        verdict: &str,
        prompt: Option<&str>,
        reply: Option<&str>,
    ) -> Judgement {
        Judgement {
            entry: entry.to_string(),
            objectives: 3,
            verdict: verdict.to_string(),
            prompt: prompt.map(str::to_string),
            reply: reply.map(str::to_string),
        }
    }

    #[test]
    fn judgements_html_renders_the_three_meta_states_with_prose_first() {
        // AC #3: prose-led, three honest meta-states, raw behind an expander.
        let rows = vec![
            // Normal: model answered → its prose verdict.
            full_judgement(
                "workload/app/Pod/web",
                "exploitable — RCE reaches the secret",
                Some("PROMPT TEXT the injection surface"),
                Some("the model raw reply"),
            ),
            // Pre-filter: prompt None → decided without the model.
            full_judgement(
                "workload/app/Pod/api",
                "Refuted(\"no promotion ground\")",
                None,
                None,
            ),
            // Timeout: reply None → safe fallback.
            full_judgement(
                "workload/app/Pod/cache",
                "Uncertain(\"model timed out\")",
                Some("PROMPT TEXT"),
                None,
            ),
        ];
        let html = render_judgements_html(&rows);

        // Prose verdict leads the normal card.
        assert!(html.contains("exploitable — RCE reaches the secret"));
        assert!(html.contains("[BREACH]"));
        // The three meta-states.
        assert!(html.contains("decided without the model (pre-filter)"));
        assert!(html.contains("model timed out — safe fallback"));
        // The raw prompt is behind an expander, not inline above the prose.
        assert!(html.contains("show full prompt"));
        assert!(html.contains("<details"));
        let prompt_at = html.find("PROMPT TEXT the injection surface").unwrap();
        let prose_at = html.find("exploitable — RCE reaches the secret").unwrap();
        assert!(
            prose_at < prompt_at,
            "the prose verdict comes before the raw prompt"
        );
        // The JSON link is documented on the page.
        assert!(html.contains("/judgements.json"));
    }

    #[test]
    fn judgements_html_empty_state_is_honest() {
        let html = render_judgements_html(&[]);
        assert!(html.contains("no model judgements yet"));
        assert!(html.contains("hasn't reached"));
    }

    #[test]
    fn render_html_card_has_aria_label_on_the_graph() {
        // AC #4: every rendered attack-path graph carries the words summary.
        let findings = vec![finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "durable-fix PR",
            "can-do/get/secrets",
            true,
            Some("not exploitable — authorized RBAC"),
        )];
        let html = render_html(&findings, false, &BakeStats::default(), &[], None, &ready());
        assert!(html.contains("data-aria=\""));
        assert!(html.contains("Attack-path graph"));
        // The JS wires data-aria → role="img" + aria-label on the rendered SVG.
        assert!(html.contains("setAttribute('role', 'img')"));
        assert!(html.contains("setAttribute('aria-label', aria)"));
    }

    #[test]
    fn judgements_json_shape_is_unchanged() {
        // The /judgements.json contract is the same Judgement shape as before JEF-161 —
        // entry, objectives, verdict, prompt, reply — so existing scrapers keep working.
        let j = full_judgement(
            "workload/app/Pod/web",
            "exploitable — RCE",
            Some("p"),
            Some("r"),
        );
        let v = serde_json::to_value(&j).unwrap();
        assert_eq!(v["entry"], "workload/app/Pod/web");
        assert_eq!(v["objectives"], 3);
        assert_eq!(v["verdict"], "exploitable — RCE");
        assert_eq!(v["prompt"], "p");
        assert_eq!(v["reply"], "r");
        // The pre-filter / timeout meta-states serialize as JSON null.
        let pre = full_judgement("e", "Refuted(\"x\")", None, None);
        let pv = serde_json::to_value(&pre).unwrap();
        assert!(pv["prompt"].is_null());
        assert!(pv["reply"].is_null());
    }

    // ---- JEF-133: per-path CVE + runtime-alert evidence blocks ----

    use crate::engine::graph::{Advisory, Reachability, Severity, Vulnerability};

    /// A `Vulnerability` with the fields the evidence block reads.
    fn vuln(id: &str, severity: Severity, kev: bool) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            severity,
            exploited_in_wild: kev,
            reachability: Reachability::NotObserved,
            ..Default::default()
        }
    }

    /// The view-shape `CveEvidence` for a vuln — what `EntryEvidence.cves` holds.
    fn cve(id: &str, severity: Severity, kev: bool) -> CveEvidence {
        CveEvidence::from_vuln(&vuln(id, severity, kev))
    }

    #[test]
    fn cve_block_summarizes_count_and_top_severities() {
        let ev = EntryEvidence {
            cves: vec![
                cve("CVE-2021-0001", Severity::Critical, true),
                cve("CVE-2021-0002", Severity::High, false),
                cve("CVE-2021-0003", Severity::Critical, false),
            ],
            runtime: vec![],
        };
        let html = cve_block(&ev);
        // Count + per-severity tally, worst first.
        assert!(html.contains("<b>3</b> CVEs"), "count: {html}");
        assert!(
            html.contains("2 critical, 1 high"),
            "tally worst-first: {html}"
        );
        // Each id surfaces, with its severity and reachability.
        assert!(html.contains("CVE-2021-0001"));
        assert!(html.contains("reachability: not-observed"));
        // The KEV-listed CVE is badged.
        assert!(html.contains(">KEV<"), "KEV badge: {html}");
        // Labeled as the severity-input block (ADR-0016) in plain words.
        assert!(html.contains("how bad it would be if exploited"));
    }

    #[test]
    fn cve_block_lists_long_sets_behind_a_details_expander() {
        let cves: Vec<CveEvidence> = (0..7)
            .map(|i| {
                CveEvidence::from_vuln(&vuln(&format!("CVE-2021-000{i}"), Severity::High, false))
            })
            .collect();
        let ev = EntryEvidence {
            cves,
            runtime: vec![],
        };
        let html = cve_block(&ev);
        // The inline cap is small; the remainder hides behind a "show all" details.
        assert!(
            html.contains("<details><summary>show all 7 CVEs"),
            "expander: {html}"
        );
        // The expander still names every CVE (all 7 appear somewhere in the block).
        for i in 0..7 {
            assert!(
                html.contains(&format!("CVE-2021-000{i}")),
                "CVE {i} present"
            );
        }
    }

    #[test]
    fn cve_block_empty_state_is_honest_not_implied_absent() {
        let html = cve_block(&EntryEvidence::default());
        assert!(
            html.contains("none on this service's image"),
            "honest none: {html}"
        );
        // Still a labeled block, never a missing/empty box.
        assert!(html.contains("how bad it would be if exploited"));
        // No phantom count or list.
        assert!(!html.contains("<ul>"), "no empty list: {html}");
    }

    #[test]
    fn cve_block_renders_cwe_and_advisory_title() {
        let mut v = vuln("CVE-2021-44228", Severity::Critical, true);
        v.title = Some("Log4Shell remote code execution".into());
        v.advisory = Some(Advisory {
            summary: "deserialization".into(),
            cwe: vec!["CWE-502".into()],
            fix_ref: None,
        });
        v.fixed_version = Some("2.17.0".into());
        v.installed_version = Some("2.14.0".into());
        let html = cve_block(&EntryEvidence {
            cves: vec![CveEvidence::from_vuln(&v)],
            runtime: vec![],
        });
        assert!(html.contains("CWE-502"), "cwe surfaced: {html}");
        assert!(html.contains("Log4Shell"), "title surfaced: {html}");
        assert!(
            html.contains("fix available: 2.14.0 to 2.17.0"),
            "fix phrasing matches the prompt: {html}"
        );
    }

    #[test]
    fn runtime_block_separates_corroborating_alerts_from_context_behaviors() {
        let ev = EntryEvidence {
            cves: vec![],
            runtime: vec![
                Behavior::Alert {
                    rule: "Terminal shell in container".into(),
                },
                Behavior::NetworkConnection {
                    peer: "10.0.0.5".into(),
                    internet: false,
                },
            ],
        };
        let html = runtime_block(&ev);
        // The alert is seen live; the connection is background (behind a details).
        assert!(html.contains("SEEN LIVE"), "alert seen live: {html}");
        assert!(html.contains("Terminal shell in container"));
        assert!(
            html.contains("1 agent behavior (background, not seen exploited)"),
            "background count: {html}"
        );
        assert!(html.contains("connects to 10.0.0.5"));
        // Labeled as the live-activity block (ADR-0016) in plain words.
        assert!(html.contains("is it being exploited right now"));
    }

    #[test]
    fn runtime_block_empty_state_is_honest() {
        let html = runtime_block(&EntryEvidence::default());
        assert!(
            html.contains("no live activity seen on this service"),
            "honest none: {html}"
        );
        assert!(html.contains("is it being exploited right now"));
        assert!(!html.contains("SEEN LIVE"));
    }

    #[test]
    fn runtime_block_behaviors_without_an_alert_read_as_context_only() {
        // Agent behaviors with no Falco alert: context, never an implied corroboration.
        let ev = EntryEvidence {
            cves: vec![],
            runtime: vec![Behavior::SecretRead {
                secret: "db-password".into(),
            }],
        };
        let html = runtime_block(&ev);
        assert!(!html.contains("SEEN LIVE"), "no false live signal: {html}");
        assert!(html.contains("nothing seen happening live"));
        assert!(html.contains("reads secret db-password"));
    }

    #[test]
    fn finding_carries_evidence_in_json_for_programmatic_use() {
        // A finding with both CVEs and a runtime alert: the /findings JSON must carry the
        // new fields (JEF-133 AC). Built via the render `finding` helper, then evidence set.
        let mut f = finding(
            "workload/app/Pod/web",
            "secret/app/s",
            "auto-eligible",
            "can-read",
            true,
            Some("exploitable — RCE"),
        );
        f.evidence = EntryEvidence {
            cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
            runtime: vec![Behavior::Alert {
                rule: "shell".into(),
            }],
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["evidence"]["cves"][0]["id"], "CVE-2021-44228");
        assert_eq!(v["evidence"]["cves"][0]["severity"], "critical");
        assert_eq!(v["evidence"]["cves"][0]["kev"], true);
        assert_eq!(v["evidence"]["cves"][0]["reachability"], "not-observed");
        // The runtime Behavior serializes via its wire tag (`kind`).
        assert_eq!(v["evidence"]["runtime"][0]["kind"], "alert");
        assert_eq!(v["evidence"]["runtime"][0]["rule"], "shell");
    }

    #[test]
    fn endpoint_card_renders_both_evidence_blocks() {
        let mut f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "auto-eligible",
            "can-read",
            true,
            Some("exploitable — RCE reaches the secret"),
        );
        f.evidence = EntryEvidence {
            cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
            runtime: vec![Behavior::Alert {
                rule: "Terminal shell in container".into(),
            }],
        };
        let refs = vec![&f];
        let html = endpoint_card("workload/app/Pod/web", &refs, Tier::Flagged);
        // Both ADR-0016 blocks present, clearly labeled and distinct (plain words).
        assert!(html.contains("evidence for this path"));
        assert!(
            html.contains("how bad it would be if exploited"),
            "CVE block: {html}"
        );
        assert!(
            html.contains("is it being exploited right now"),
            "runtime block: {html}"
        );
        assert!(html.contains("CVE-2021-44228"));
        assert!(html.contains("SEEN LIVE"));
    }

    #[test]
    fn endpoint_card_with_no_evidence_renders_both_honest_empty_states() {
        let f = finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "structural — propose",
            "can-read",
            true,
            None,
        );
        let refs = vec![&f];
        let html = endpoint_card("workload/app/Pod/web", &refs, Tier::Context);
        // Neither block is omitted; each shows its honest "none/unknown" (JEF-161 idiom).
        assert!(html.contains("none on this service's image"));
        assert!(html.contains("no live activity seen on this service"));
        assert!(!html.contains("SEEN LIVE"));
    }

    #[test]
    fn from_chain_pulls_entry_evidence_filtered_to_kev_or_critical() {
        use crate::engine::graph::{
            Edge, Exposure, Grade, Image, Node, Provenance, Relation, RuntimeSignal, Trust,
            Workload,
        };
        use crate::engine::reason::proof::Link;
        use std::time::SystemTime;

        // Build a minimal graph: an entry workload runs an image carrying three CVEs —
        // one critical, one KEV-high, one plain medium (must be filtered out — the
        // dashboard surfaces the same KEV-or-critical bar the foothold/model uses).
        let mut g = SecurityGraph::new();
        let wl = Node::Workload(Workload {
            namespace: "app".into(),
            name: "web".into(),
            kind: "Pod".into(),
            labels: Default::default(),
            meshed: false,
            exposure: Exposure::Internet,
            runtime: vec![RuntimeSignal {
                behavior: Behavior::Alert {
                    rule: "shell".into(),
                },
                provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
            }],
            persistent: false,
        });
        let entry_key = wl.key();
        let e = g.upsert_node(wl);
        let img = g.upsert_node(Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: Some("web:1".into()),
            trust: Trust::Unknown,
            vulnerabilities: vec![
                vuln("CVE-2021-0001", Severity::Critical, false),
                vuln("CVE-2021-0002", Severity::High, true), // KEV
                vuln("CVE-2021-0003", Severity::Medium, false), // filtered
            ],
        }));
        g.add_edge(
            e,
            img,
            Edge {
                relation: Relation::RunsImage,
                provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
                grade: Grade::Proof,
            },
        );

        let cut = Link {
            from: entry_key.clone(),
            to: NodeKey("secret/app/s".into()),
            relation: "can-read".into(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        };
        let chain = ProvenChain {
            entry: entry_key,
            objective: NodeKey("secret/app/s".into()),
            attack: CREDENTIAL_ACCESS,
            foothold: Some(EXPLOIT_PUBLIC_FACING),
            corroborated: false,
            adjudicated: true,
            promoted: false,
            exposed_entry: true,
            verdict: None,
            links: vec![cut.clone()],
            single_edge_cuts: vec![cut],
        };

        let f = Finding::from_chain(&chain, &g);
        let ids: Vec<&str> = f.evidence.cves.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"CVE-2021-0001"), "critical kept: {ids:?}");
        assert!(ids.contains(&"CVE-2021-0002"), "KEV kept: {ids:?}");
        assert!(
            !ids.contains(&"CVE-2021-0003"),
            "plain medium filtered (same bar as the foothold): {ids:?}"
        );
        // The entry's runtime alert is pulled too (the live-corroboration signal).
        assert_eq!(f.evidence.runtime.len(), 1, "entry runtime signal carried");
        assert!(f.evidence.runtime[0].is_alert());
    }

    // ---- JEF-176: no ADR-/JEF- token leaks into operator-facing rendered output ----

    /// Assert a rendered surface never prints an `ADR-` or `JEF-` token. Code comments
    /// keep their refs; this is the RENDERED-output invariant (JEF-176 AC #1).
    fn assert_no_internal_refs(label: &str, rendered: &str) {
        assert!(
            !rendered.contains("ADR-"),
            "{label}: leaked an ADR- ref into operator-facing output"
        );
        assert!(
            !rendered.contains("JEF-"),
            "{label}: leaked a JEF- ref into operator-facing output"
        );
    }

    /// A finding with full evidence (CVEs + a live alert) and an auto-eligible cut, so a
    /// rendered page exercises the card, the certainty rail, both evidence blocks, the
    /// attack-steps caption and the remediation card at once.
    fn rich_finding(entry: &str, verdict: Option<&str>) -> Finding {
        let mut f = finding(
            entry,
            "secret/app/session-key",
            AUTO_ELIGIBLE,
            "can-read",
            true,
            verdict,
        );
        f.foothold = true;
        f.evidence = EntryEvidence {
            cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
            runtime: vec![Behavior::Alert {
                rule: "Terminal shell in container".into(),
            }],
        };
        f
    }

    /// AC #1: rendering every representative operator surface — a populated dashboard with
    /// a finding card, /judgements, /report, the first-run checklist, and each banner
    /// state — never emits an `ADR-` or `JEF-` substring.
    #[test]
    fn rendered_output_never_leaks_adr_or_jef_refs() {
        // The main dashboard, populated: a flagged card (Needs attention), a watched card,
        // remediations, and the full diagnostics region (readiness/attack-surface/sensor).
        let findings = vec![
            rich_finding(
                "workload/app/Pod/web",
                Some("exploitable — CVE-2021-44228 reaches the secret"),
            ),
            rich_finding(
                "workload/api/Pod/svc",
                Some("not exploitable — unreachable"),
            ),
            rich_finding("workload/argo/Pod/server", None),
        ];

        // Armed and shadow, all-met and with-unmet readiness — exercises every banner
        // state (contained / needs-attention / unjudged / quiet) and the first-run path.
        for armed in [false, true] {
            for ready in [ready(), ready_all_met()] {
                let html = render_html(
                    &findings,
                    armed,
                    &bake(80, 20),
                    &[],
                    Some(SystemTime::now()),
                    &ready,
                );
                assert_no_internal_refs("dashboard", &html);
            }
        }

        // First-run checklist: no findings + an unmet input replaces the findings region.
        let first_run = render_html(
            &[],
            false,
            &BakeStats::default(),
            &[],
            Some(SystemTime::now()),
            &ready(),
        );
        assert!(first_run.contains("checklist") || first_run.contains("done"));
        assert_no_internal_refs("first-run dashboard", &first_run);

        // /judgements — a model verdict, a pre-filter meta-state, and a timeout meta-state.
        let judgements = vec![
            Judgement {
                entry: "workload/app/Pod/web".into(),
                objectives: 3,
                verdict: "Exploitable(\"RCE\")".into(),
                prompt: Some("system: judge this chain".into()),
                reply: Some("exploitable".into()),
            },
            judgement("workload/api/Pod/svc"),
        ];
        let judgements_html = render_judgements_html(&judgements);
        assert_no_internal_refs("/judgements", &judgements_html);
        // The empty state too.
        assert_no_internal_refs("/judgements empty", &render_judgements_html(&[]));

        // /report — a populated would-have-acted diff and the empty state.
        let entries = vec![
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                60,
            ),
            breach("workload/api/Pod/svc", "not exploitable — cleared", 120),
        ];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_no_internal_refs("/report", &render_report_html(&report));
        let empty_report = aggregate_report(&[], report_now(), WEEK, FIVE_MIN);
        assert_no_internal_refs("/report empty", &render_report_html(&empty_report));
    }

    /// AC #3: the finding card's attack steps lead with the plain technique name and keep
    /// the MITRE code only inside an `<abbr>` tooltip — never bare on the line.
    #[test]
    fn killchain_leads_with_plain_name_mitre_code_in_abbr() {
        let f = rich_finding("workload/app/Pod/web", Some("exploitable — RCE"));
        let kc = killchain_html(&f);
        // Plain technique name leads.
        assert!(
            kc.contains("Unsecured Credentials"),
            "plain name present: {kc}"
        );
        assert!(
            kc.contains("internet-facing service"),
            "plain foothold phrasing: {kc}"
        );
        // The MITRE code is present but only inside an abbr title (not bare text).
        assert!(kc.contains("<abbr title="), "code tucked in abbr: {kc}");
        assert!(kc.contains("T1552"), "code available in tooltip: {kc}");
        // The card caption is plain English — "attack steps", never "kill chain".
        let card = remediation_card(&f, false);
        assert!(card.contains("attack steps:"), "plain label: {card}");
        assert!(!card.contains("kill chain"), "no jargon label: {card}");
    }
}
