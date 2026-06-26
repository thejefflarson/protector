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

use super::journal::{Decision, DecisionJournal, JournalEntry};
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
}

/// One hop of a proven chain: `from -[relation]-> to`, with the **full** node keys
/// (so the renderer can derive both a short label and the node kind/shape).
#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub from: String,
    pub relation: String,
    pub to: String,
}

impl Finding {
    pub fn from_chain(chain: &ProvenChain) -> Self {
        let action = chain
            .single_edge_cuts
            .first()
            .map(super::respond::ProposedAction::for_cut);
        Finding {
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

/// The ATT&CK kill chain in plain terms: the Initial Access foothold (T1190), when
/// the entry is an exploitable front door, through the objective's own technique.
fn killchain(chain: &ProvenChain) -> String {
    let goal = format!("{} {}", chain.attack.technique_id, chain.attack.technique);
    if chain.foothold.is_some() {
        format!("T1190 Exploit Public-Facing Application → {goal}")
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
    // The model's verdict (why it decided to act), when a model judged this chain.
    let verdict = match &f.verdict {
        Some(v) => format!("<div class=\"verdict\">model: {}</div>", escape(v)),
        None => String::new(),
    };
    format!(
        "<div class=\"card\"><div class=\"kc\">{} → {}  {status}</div>\
         <div class=\"kc2\">kill chain: {}</div>{}<pre class=\"mermaid\">{}</pre></div>",
        escape(&short(&f.entry)),
        escape(&short(&f.objective)),
        escape(&f.killchain),
        verdict,
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

fn endpoint_card(entry: &str, fs: &[&Finding]) -> String {
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
    let judgement = match fs.iter().find_map(|f| f.verdict.as_deref()) {
        Some(v) => format!(
            "<div class=\"verdict\">model judgement: {}</div>",
            escape(v)
        ),
        None => "<div class=\"verdict muted\">awaiting model judgement</div>".to_string(),
    };

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

    format!(
        "<div class=\"card\"><div class=\"kc\">{} <span class=\"muted\">({} objective{} reachable)</span></div>\
         {}<pre class=\"mermaid\">{}</pre>{}</div>",
        escape(&short(entry)),
        objectives,
        if objectives == 1 { "" } else { "s" },
        judgement,
        m.finish(),
        if expand.is_empty() {
            String::new()
        } else {
            format!("<div class=\"expand\">{expand}</div>")
        },
    )
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
        return "<p class=\"muted\">no internet-facing exposure reaches an objective</p>"
            .to_string();
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
                "<tr><td>{}</td><td><code>{}</code> {}</td><td>{}</td><td>{}</td></tr>",
                escape(tactic),
                escape(tid),
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

/// A would-act verdict that fired WITHOUT a CVE backing it is an enrichment-coverage
/// gap: the model affirmed exploitability but no advisory enrichment matched (the
/// verdict cites no `CVE-` id). These are the would-acts to scrutinize — the call was
/// made blind to the very vulnerability data that would corroborate it.
fn is_coverage_gap(verdict: &str) -> bool {
    !verdict.to_ascii_uppercase().contains("CVE-")
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
    type Breach<'a> = (u64, &'a str); // (at_ms, verdict)
    let mut by_entry: BTreeMap<&str, Vec<Breach>> = BTreeMap::new();
    let mut sorted: Vec<&JournalEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.at_ms);
    let mut decisions_in_window = 0usize;
    for e in sorted {
        if let Decision::Breach { entry, verdict, .. } = &e.decision {
            any_breach = true;
            if e.at_ms >= window_start_ms {
                by_entry
                    .entry(entry.as_str())
                    .or_default()
                    .push((e.at_ms, verdict));
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
            let (start_ms, verdict) = decisions[i];
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
                if is_coverage_gap(decisions[j].1) {
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
            if let Some((_, verdict)) = decisions.last() {
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
         path{left_s} alone. {short} short-lived (likely FP) · {gap} during an \
         enrichment-coverage gap (scrutinize first).</div>",
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
         <th>Projected cut lifetime</th><th>Enrichment</th><th>Latest verdict</th></tr></thead>\
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
         <p class=\"sum\">The shadow diff that gates exiting shadow (JEF-50): over a rolling \
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

    let rem_title = if armed {
        "Active Remediations"
    } else {
        "Proposed Remediations"
    };
    let rem_body = if remediations.is_empty() {
        "<p class=\"muted\">none</p>".to_string()
    } else {
        remediations
            .iter()
            .map(|f| remediation_card(f, armed))
            .collect()
    };
    let path_body = if endpoints.is_empty() {
        "<p class=\"muted\">no internet-facing exposure reaches an objective</p>".to_string()
    } else {
        // Rank by graph size — the widest blast radius (most objectives) first.
        let mut ranked: Vec<(&&str, &Vec<&Finding>)> = endpoints.iter().collect();
        ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
        ranked
            .iter()
            .map(|(entry, fs)| endpoint_card(entry, fs))
            .collect()
    };
    let vectors_body = attack_vectors(findings);
    let bake_body = bake_panel(bake);
    let reversions_body = reversions_panel(reversions);
    let freshness = relative_time(last_pass);

    // NOTE: this HTML is a single `\`-continued string literal, so every source-line
    // newline is STRIPPED — the whole thing collapses to one line. Never put a `//`
    // line comment inside the inline <script>: it would comment out the rest of the
    // collapsed line (the import + all rendering). Use /* */ block comments only.
    // The graph renderer is beautiful-mermaid (ELK layout), vendored + bundled into
    // web/dist and served SAME-ORIGIN at /assets — never a third-party CDN.
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>protector</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         h1{{font-size:1.2rem;font-weight:600;margin:0}}\
         h2{{font-size:1rem;font-weight:600;margin:1.6rem 0 .4rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}}\
         .sum{{margin:.4rem 0 1rem;color:#444;font-size:.9rem}}\
         .card{{border:1px solid #e3e3e3;border-radius:0;padding:.5rem .7rem;margin:.6rem 0}}\
         .kc{{font-family:ui-monospace,monospace;font-size:.85rem;font-weight:600}}\
         .kc2{{font-size:.75rem;color:#666;margin:.15rem 0 .3rem}}\
         .verdict{{font-size:.78rem;color:#333;background:#f4f4f4;border-left:2px solid #888;padding:.2rem .5rem;margin:.2rem 0 .4rem}}\
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
         .legend{{font-size:.75rem;color:#555;margin:.2rem 0 .6rem}}\
         .legend code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors{{border-collapse:collapse;font-size:.82rem;margin:.2rem 0 .6rem;width:100%}}\
         table.vectors th{{text-align:left;font-weight:600;color:#444;border-bottom:1px solid #ddd;padding:.25rem .5rem}}\
         table.vectors td{{padding:.25rem .5rem;border-bottom:1px solid #f0f0f0}}\
         table.vectors code{{background:#f4f4f4;padding:0 .2rem}}\
         table.vectors .flagged{{color:#b00000;font-weight:600}}\
         </style>\
         <script type=\"module\">\
         import {{ renderMermaidSVG }} from '/assets/beautiful-mermaid.js';\
         for (const pre of document.querySelectorAll('pre.mermaid')) {{\
           try {{\
             const svg = renderMermaidSVG(pre.textContent, {{ font: 'system-ui, sans-serif', accent: '#b00000', padding: 16, nodeSpacing: 28, layerSpacing: 52 }});\
             const g = document.createElement('div'); g.className = 'graph'; g.innerHTML = svg;\
             pre.replaceWith(g);\
           }} catch (e) {{ /* leave the source text as a fallback */ }}\
         }}\
         </script></head><body>\
         <h1>protector</h1>\
         <p class=\"sum\"><b>{rem_n}</b> {rem_word} · <b>{ep_n}</b> exposed endpoint{ep_plural} with \
         possible attack paths · last pass <b>{freshness}</b> \
         &nbsp;|&nbsp; <a href=\"/report\">would-have-acted report</a> \
         &nbsp;|&nbsp; <a href=\"/findings\">json</a></p>\
         <h2>{rem_title} <span class=\"muted\">({rem_n})</span></h2>{rem_body}\
         <h2>Attack vectors <span class=\"muted\">(ATT&amp;CK)</span></h2>\
         <p class=\"sum\">ATT&amp;CK outcomes an internet-facing entry can reach. \
         <b>Reachable</b> = proven the entry can get there; <b>model-flagged</b> = the model \
         judged it a real breach.</p>\
         {vectors_body}\
         <h2>Behavioral bake <span class=\"muted\">(shadow)</span></h2>\
         <p class=\"sum\">What the behavioral agent observed last pass — protector is only \
         watching, not acting. A sanity check before relying on these signals: volume looks \
         reasonable, most events map to a workload (low unresolved), and <b>corroborations</b> \
         counts findings a live signal backed up.</p>\
         {bake_body}\
         <h2>Recent reversions <span class=\"muted\">(lifted cuts)</span></h2>\
         <p class=\"sum\">Cuts the engine lifted, and why. An isolation stays only while the \
         breach lasts, then lifts on its own once the path is gone or the evidence clears.</p>\
         {reversions_body}\
         <h2>Possible attack paths <span class=\"muted\">({ep_n} endpoint{ep_plural})</span></h2>\
         <p class=\"legend\">edge legend — \
         <code>mounts (direct read)</code>: the secret is mounted into the pod, read with no API call (just that one secret) · \
         <code>RBAC … (API)</code>: the pod's ServiceAccount can read via the Kubernetes API (often any secret in scope) · \
         <code>network reach</code>: a NetworkPolicy- or Linkerd-authorized connection · \
         <code>runs as</code>: assumes the ServiceAccount identity · \
         <code>escapes via</code>: a container-escape primitive to the host node</p>\
         {path_body}\
         </body></html>",
        rem_n = remediations.len(),
        rem_word = if armed { "active" } else { "proposed" },
        ep_n = endpoints.len(),
        ep_plural = if endpoints.len() == 1 { "" } else { "s" },
    )
}

/// Shared state for the dashboard's HTML view: the findings handle plus the reversions
/// ring (JEF-141), so the rendered page can show lifted cuts alongside the findings.
#[derive(Clone)]
struct DashboardState {
    findings: Arc<Findings>,
    reversions: Arc<ReversionLog>,
}

async fn html_view(State(state): State<DashboardState>) -> Html<String> {
    Html(render_html(
        &state.findings.snapshot(),
        state.findings.is_armed(),
        &state.findings.bake(),
        &state.reversions.snapshot(),
        state.findings.last_pass(),
    ))
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

async fn judgements_view(State(journal): State<Arc<JudgementLog>>) -> Json<Vec<Judgement>> {
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

/// Serve the findings dashboard (`/` HTML, `/findings` JSON, `/bake` JSON) plus the
/// diagnostic `/judgements` JSON (full prompt + raw reply + verdict per recent
/// judgement), the `/reversions` JSON (lifted cuts + why, JEF-141), and the
/// `/report` + `/report.json` shadow would-have-acted diff (JEF-143). Read-only;
/// cluster-facing glue around the tested classification + aggregation.
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
        .route("/assets/beautiful-mermaid.js", get(beautiful_mermaid_js))
        .with_state(findings)
        .merge(
            Router::new()
                .route("/judgements", get(judgements_view))
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
        );
        assert!(
            html.contains("last pass <b>just now</b>"),
            "freshness line present"
        );
        assert!(
            html.contains("Recent reversions"),
            "reversions section header present"
        );
        assert!(
            html.contains("no proven chain still justifies"),
            "the lifted cut's reason is shown"
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
        let disp = |c: &ProvenChain| Finding::from_chain(c).disposition;

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
        assert_eq!(Finding::from_chain(&promoted).disposition, "auto-eligible");
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

        let html = render_html(&findings, false, &BakeStats::default(), &[], None);
        // Shadow → "Proposed Remediations"; armed → "Active Remediations".
        assert!(html.contains("Proposed Remediations"));
        assert!(
            render_html(&findings, true, &BakeStats::default(), &[], None)
                .contains("Active Remediations")
        );
        assert!(html.contains("Possible attack paths"));
        // The attack-vector summary names the ATT&CK outcomes reachable, with the
        // model-flagged count (one objective was judged exploitable above).
        assert!(html.contains("Attack vectors"));
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
        assert!(html.contains("1 endpoint"));
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
        let html = render_html(&[], false, &bake(80, 20), &[], None);
        assert!(
            html.contains("Behavioral bake"),
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
    /// carrying `verdict` (the model's own words).
    fn breach(entry: &str, verdict: &str, secs_before: u64) -> JournalEntry {
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
            },
        }
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
    fn coverage_gap_is_an_exploitable_verdict_with_no_cve() {
        // An exploitable call with a CVE is enrichment-backed; without one it's a gap.
        assert!(!is_coverage_gap(
            "exploitable — CVE-2021-44228 is a remote RCE"
        ));
        assert!(is_coverage_gap(
            "exploitable — a privileged container escape reaches the node"
        ));
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
        // An exploitable call with NO CVE backing it (e.g. a container-escape primitive)
        // is the would-act to scrutinize: it fired during an enrichment-coverage gap.
        let entries = vec![breach(
            "workload/app/Pod/escape",
            "exploitable — a privileged container escape reaches the node",
            45,
        )];
        let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        assert_eq!(report.coverage_gap_count(), 1, "no CVE ⇒ coverage gap");
        assert!(report.would_act[0].coverage_gap);
        // A CVE-backed exploitable is NOT a coverage gap.
        let backed = vec![breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 is a remote RCE",
            45,
        )];
        let r2 = aggregate_report(&backed, report_now(), WEEK, FIVE_MIN);
        assert_eq!(r2.coverage_gap_count(), 0);
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
}
