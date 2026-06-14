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

use super::proof::ProvenChain;

/// One row: a proven chain, its ATT&CK label and evidence, and what the engine
/// does with it.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub entry: String,
    pub objective: String,
    pub tactic: String,
    pub technique: String,
    pub foothold: bool,
    pub corroborated: bool,
    pub adjudicated: bool,
    /// The model promoted this chain to auto-eligible (ADR-0011), as opposed to live
    /// runtime corroboration.
    pub promoted: bool,
    /// Short evidence-class tag (auto-eligible / latent / structural / durable-fix /
    /// forbidden) — what kind of finding this is.
    pub disposition: String,
    /// What the engine would actually *do* with it, and why — the `decide()` verdict
    /// in plain words. The honest answer to "auto-eligible?": a corroborated chain
    /// whose only cut is a subtractive RBAC/mount edge is NOT auto-applied, it's a
    /// durable-fix PR. This is what the flat "auto-eligible" disposition hid.
    pub decision: String,
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
            .map(super::response::ProposedAction::for_cut);
        let (disposition, decision) = classify(chain, action);

        Finding {
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            tactic: chain.attack.tactic.id().to_string(),
            technique: chain.attack.technique_id.to_string(),
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            adjudicated: chain.adjudicated,
            promoted: chain.promoted,
            disposition,
            decision,
            cut: chain
                .single_edge_cuts
                .first()
                .map(super::response::cut_signature),
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

/// Classify a chain into (disposition, decision) by what its minimal cut can
/// actually do — mirroring [`super::actuator::decide`] without the runtime-only
/// gates (enabled class, live blast radius). Only a network cut (`DenyNetworkPath`)
/// is ever auto-applied; subtractive cuts are durable-fix PRs, an escape primitive
/// is irreversible, and a chain with no live/foothold evidence is just a proposal.
fn classify(
    chain: &ProvenChain,
    action: Option<super::response::ProposedAction>,
) -> (String, String) {
    use super::response::ProposedAction as A;
    let s = |a: &str, b: &str| (a.to_string(), b.to_string());
    match action {
        None => s("no-cut", "no single edge severs this — no minimal fix"),
        Some(A::RemoveEscapePrimitive) => s(
            "forbidden",
            "irreversible container-escape — durable fix only",
        ),
        Some(A::RevokeRbacGrant) => s("durable-fix PR", "revoke the RBAC grant via GitOps"),
        Some(A::RemoveSecretMount) => s("durable-fix PR", "remove the secret mount via GitOps"),
        Some(A::RebindIdentity) => s(
            "durable-fix PR",
            "rebind to a least-privilege ServiceAccount",
        ),
        Some(A::Unclassified) => s("unclassified", "no action mapped — manual"),
        Some(A::DenyNetworkPath) => {
            if !chain.meets_action_bar() {
                if chain.is_latent_foothold() {
                    s(
                        "latent foothold — propose",
                        "exposed + CVE, no live signal — propose a cut",
                    )
                } else {
                    s(
                        "structural — propose",
                        "no live or foothold evidence — propose only",
                    )
                }
            } else if !chain.adjudicated {
                s(
                    "vetoed — propose",
                    "live, but the model vetoed the auto-cut",
                )
            } else {
                s(
                    "auto-eligible",
                    "auto-applies a reversible NetworkPolicy cut when `network` is armed",
                )
            }
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
}

/// Minimal HTML escape for the few values that could contain markup-special chars.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A short, human label for a node key — drop the kind prefix (`workload/`, …).
fn short(key: &str) -> String {
    key.split_once('/')
        .map_or_else(|| key.to_string(), |(_, rest)| rest.to_string())
}

/// The node kind — the key's first path segment (`secret`, `capability`, …).
fn kind(key: &str) -> &str {
    key.split('/').next().unwrap_or("node")
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
            step.relation.clone()
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
                m.edge(&step.from, &step.to, &step.relation, false);
            }
        }
    }

    for ((from, relation, kind), objs) in &groups {
        if objs.len() == 1 {
            m.edge(from, &objs[0], relation, false);
        } else {
            // Collapse the fan-out into one aggregate node.
            let agg_key = format!("{kind}/__agg/{from}/{relation}");
            let agg_label = format!("{} {}", objs.len(), plural(kind, objs.len()));
            m.edge_to_labeled(from, &agg_key, &agg_label, relation);
        }
    }

    // The model's verdict for this entry (uniform across the card — it's judged per
    // entry). `None` only when no model is configured.
    let judgement = match fs.iter().find_map(|f| f.verdict.as_deref()) {
        Some(v) => format!("<div class=\"verdict\">model: {}</div>", escape(v)),
        None => {
            "<div class=\"verdict muted\">no model configured — latent exposure, unjudged</div>"
                .to_string()
        }
    };

    format!(
        "<div class=\"card\"><div class=\"kc\">{} <span class=\"muted\">({} objective{})</span></div>\
         {}<pre class=\"mermaid\">{}</pre></div>",
        escape(&short(entry)),
        objectives,
        if objectives == 1 { "" } else { "s" },
        judgement,
        m.finish(),
    )
}

/// Render the dashboard: two sections, both graph-based.
///   1. Remediations the engine applies (or proposes, in shadow), each a graph with
///      the cut marked.
///   2. Possible attack paths, one coalesced graph per internet-facing endpoint,
///      each terminal edge labeled with why it isn't remediated.
fn render_html(findings: &[Finding], armed: bool) -> String {
    // One pass over the breach-relevant findings: the auto-eligible ones are
    // remediations; the rest group by endpoint (entry) for the attack-path graphs.
    let mut remediations: Vec<&Finding> = Vec::new();
    let mut endpoints: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        if f.disposition == "auto-eligible" {
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

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>protector</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111;max-width:64rem}}\
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
         </style>\
         <script type=\"module\">\
         // beautiful-mermaid: ELK layout, synchronous SVG. Served SAME-ORIGIN from\
         // protector (vendored + bundled, web/dist) — never a third-party CDN, so a\
         // compromised package registry can't inject JS into an operator's session.\
         // Render each graph source in place; on failure leave the coalesced source.\
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
         <h2>Possible attack paths <span class=\"muted\">({ep_n} endpoint{ep_plural})</span></h2>{path_body}\
         </body></html>",
        rem_n = remediations.len(),
        rem_word = if armed { "active" } else { "proposed" },
        ep_n = endpoints.len(),
        ep_plural = if endpoints.len() == 1 { "" } else { "s" },
    )
}

async fn html_view(State(findings): State<Arc<Findings>>) -> Html<String> {
    Html(render_html(&findings.snapshot(), findings.is_armed()))
}

async fn json_view(State(findings): State<Arc<Findings>>) -> Json<Vec<Finding>> {
    Json(findings.snapshot())
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

/// Serve the findings dashboard (`/` HTML, `/findings` JSON). Read-only;
/// cluster-facing glue around the tested classification.
pub async fn serve_dashboard(addr: SocketAddr, findings: Arc<Findings>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(html_view))
        .route("/findings", get(json_view))
        .route("/assets/beautiful-mermaid.js", get(beautiful_mermaid_js))
        .with_state(findings);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "findings dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
    use crate::engine::graph::NodeKey;
    use crate::engine::proof::Link;

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

        // A model-promoted network chain auto-applies; the `decision` explains why.
        let promoted = ProvenChain {
            promoted: true,
            ..chain("reaches/Tcp", false, false, true)
        };
        let f = Finding::from_chain(&promoted);
        assert_eq!(f.disposition, "auto-eligible");
        assert!(f.decision.contains("NetworkPolicy"));
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
            technique: "T1552".into(),
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            disposition: disposition.into(),
            decision: "decision".into(),
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

        let html = render_html(&findings, false);
        // Shadow → "Proposed Remediations"; armed → "Active Remediations".
        assert!(html.contains("Proposed Remediations"));
        assert!(render_html(&findings, true).contains("Active Remediations"));
        assert!(html.contains("Possible attack paths"));
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
}
