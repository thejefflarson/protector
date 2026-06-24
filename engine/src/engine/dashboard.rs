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

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

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

/// The current findings snapshot, shared between the engine (writer) and the HTTP
/// server (reader).
#[derive(Default)]
pub struct Findings {
    rows: Mutex<Vec<Finding>>,
    /// Whether any action class is armed (`engine.enable` non-empty). Drives the
    /// remediations section title: "Active" when armed, "Proposed" in shadow.
    armed: std::sync::atomic::AtomicBool,
    /// The most recent behavioral-bake snapshot (JEF-48), replaced each pass alongside
    /// the findings rows.
    bake: Mutex<BakeStats>,
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

    /// Replace the snapshot with this pass's findings.
    pub fn replace(&self, findings: Vec<Finding>) {
        *self.rows.lock().expect("findings mutex poisoned") = findings;
    }

    pub fn snapshot(&self) -> Vec<Finding> {
        self.rows.lock().expect("findings mutex poisoned").clone()
    }

    /// Replace the behavioral-bake snapshot (JEF-48) with this pass's figures.
    pub fn set_bake(&self, bake: BakeStats) {
        *self.bake.lock().expect("bake mutex poisoned") = bake;
    }

    /// The most recent behavioral-bake snapshot, for the dashboard / `/findings` view.
    pub fn bake(&self) -> BakeStats {
        self.bake.lock().expect("bake mutex poisoned").clone()
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

/// Render the dashboard: two sections, both graph-based.
///   1. Remediations the engine applies (or proposes, in shadow), each a graph with
///      the cut marked.
///   2. Possible attack paths, one coalesced graph per internet-facing endpoint,
///      each terminal edge labeled with why it isn't remediated.
fn render_html(findings: &[Finding], armed: bool, bake: &BakeStats) -> String {
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
         possible attack paths &nbsp;|&nbsp; <a href=\"/findings\">json</a></p>\
         <h2>{rem_title} <span class=\"muted\">({rem_n})</span></h2>{rem_body}\
         <h2>Attack vectors <span class=\"muted\">(ATT&amp;CK)</span></h2>\
         <p class=\"sum\">ATT&amp;CK outcomes reachable from an internet-facing front door. \
         <b>Reachable</b> is what proof winnows to; <b>model-flagged</b> is where the model \
         affirmed exploitability (ADR-0013).</p>\
         {vectors_body}\
         <h2>Behavioral bake <span class=\"muted\">(shadow)</span></h2>\
         <p class=\"sum\">What the behavioral port saw last pass (ADR-0014 rollout step 2). \
         The shadow-bake gate before corroboration is armed: signal volume should be sane, \
         attribution should resolve (low unresolved), and corroborations are the countable \
         &ldquo;would this have promoted?&rdquo; — all here without an OTLP collector.</p>\
         {bake_body}\
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

async fn html_view(State(findings): State<Arc<Findings>>) -> Html<String> {
    Html(render_html(
        &findings.snapshot(),
        findings.is_armed(),
        &findings.bake(),
    ))
}

async fn json_view(State(findings): State<Arc<Findings>>) -> Json<Vec<Finding>> {
    Json(findings.snapshot())
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
/// judgement). Read-only; cluster-facing glue around the tested classification.
pub async fn serve_dashboard(
    addr: SocketAddr,
    findings: Arc<Findings>,
    judgements: Arc<JudgementLog>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(html_view))
        .route("/findings", get(json_view))
        .route("/bake", get(bake_view))
        .route("/assets/beautiful-mermaid.js", get(beautiful_mermaid_js))
        .with_state(findings)
        .merge(
            Router::new()
                .route("/judgements", get(judgements_view))
                .with_state(judgements),
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

        let html = render_html(&findings, false, &BakeStats::default());
        // Shadow → "Proposed Remediations"; armed → "Active Remediations".
        assert!(html.contains("Proposed Remediations"));
        assert!(
            render_html(&findings, true, &BakeStats::default()).contains("Active Remediations")
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
        let html = render_html(&[], false, &bake(80, 20));
        assert!(
            html.contains("Behavioral bake"),
            "the section header is present"
        );
        assert!(
            html.contains("connection"),
            "the per-variant volume renders"
        );
    }
}
