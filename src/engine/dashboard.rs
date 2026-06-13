//! The findings dashboard: a read-only view of the engine's current proven chains
//! and their disposition — built mainly to surface the **latent-foothold** case
//! (ADR-0009), the exposable front doors that are propose-only and want a human.
//!
//! The engine replaces the [`Findings`] snapshot each pass; a small HTTP server
//! renders it as a flat table (`/`) and as JSON (`/findings`). The classification
//! ([`Finding::from_chain`]) is pure and tested; the server is glue.

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
        }
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
        None => s(
            "no-cut",
            "no single edge severs this chain — needs more than one cut, no minimal fix",
        ),
        Some(A::RemoveEscapePrimitive) => s(
            "forbidden",
            "irreversible (container-escape primitive) — never auto-applied; durable fix only",
        ),
        Some(A::RevokeRbacGrant) => s(
            "durable-fix PR",
            "subtractive: revoke the RBAC grant via GitOps — not live-actuatable",
        ),
        Some(A::RemoveSecretMount) => s(
            "durable-fix PR",
            "subtractive: remove the secret mount/reference via GitOps — not live-actuatable",
        ),
        Some(A::RebindIdentity) => s(
            "durable-fix PR",
            "subtractive: rebind to a least-privilege ServiceAccount — not live-actuatable",
        ),
        Some(A::Unclassified) => s(
            "unclassified",
            "no automatic action mapped — manual remediation",
        ),
        Some(A::DenyNetworkPath) => {
            if !chain.meets_action_bar() {
                if chain.is_latent_foothold() {
                    s(
                        "latent foothold — propose",
                        "exposed + exploited/critical CVE but no live signal — propose a cut to a human",
                    )
                } else {
                    s(
                        "structural — propose",
                        "assume-breach path, no live or foothold evidence — propose only",
                    )
                }
            } else if !chain.adjudicated {
                s(
                    "vetoed — propose",
                    "live, but the model vetoed the auto-cut — downgraded to a human proposal",
                )
            } else {
                s(
                    "auto-eligible",
                    "auto-applies a reversible NetworkPolicy cut when `network` is enabled and no live workload is collateral",
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
    /// The attack graph as Graphviz DOT (internet → goal), served at `/graph`.
    graph_dot: Mutex<String>,
}

impl Findings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the snapshot with this pass's findings.
    pub fn replace(&self, findings: Vec<Finding>) {
        *self.rows.lock().expect("findings mutex poisoned") = findings;
    }

    pub fn snapshot(&self) -> Vec<Finding> {
        self.rows.lock().expect("findings mutex poisoned").clone()
    }

    /// Replace the attack-graph DOT for the `/graph` view.
    pub fn replace_graph(&self, dot: String) {
        *self.graph_dot.lock().expect("graph mutex poisoned") = dot;
    }

    pub fn graph_dot(&self) -> String {
        self.graph_dot.lock().expect("graph mutex poisoned").clone()
    }
}

/// Minimal HTML escape for the few values that could contain markup-special chars.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// CSS class for a disposition, for a touch of semantic colour (flat, no chrome).
fn disposition_class(disposition: &str) -> &'static str {
    if disposition.starts_with("auto-eligible") {
        "live"
    } else if disposition.starts_with("latent") {
        "latent"
    } else {
        "muted"
    }
}

/// Render the findings as a flat HTML table — system font, thin borders, no
/// gradients, no rounded corners.
fn render_html(findings: &[Finding]) -> String {
    let mut rows = String::new();
    for f in findings {
        let yn = |b: bool| if b { "yes" } else { "—" };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
            escape(&f.entry),
            escape(&f.objective),
            escape(&f.tactic),
            escape(&f.technique),
            yn(f.foothold),
            yn(f.corroborated),
            yn(f.adjudicated),
            disposition_class(&f.disposition),
            escape(&f.disposition),
            escape(&f.decision),
            escape(f.cut.as_deref().unwrap_or("—")),
        ));
    }
    if findings.is_empty() {
        rows.push_str("<tr><td colspan=\"9\" class=\"muted\">no proven chains</td></tr>");
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>protector</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}\
         h1{{font-size:1.2rem;font-weight:600;margin-bottom:1rem}}\
         table{{border-collapse:collapse;width:100%;font-size:.85rem}}\
         th,td{{border:1px solid #ccc;padding:4px 8px;text-align:left}}\
         th{{background:#f0f0f0;font-weight:600}}\
         .live{{color:#b00000;font-weight:600}}\
         .latent{{color:#9a5b00}}\
         .muted{{color:#666}}\
         </style></head><body>\
         <h1>protector — proven chains ({count})</h1>\
         <table><thead><tr>\
         <th>entry</th><th>objective</th><th>ATT&amp;CK</th><th>foothold</th>\
         <th>live</th><th>adjudicated</th><th>disposition</th><th>decision</th><th>cut</th>\
         </tr></thead><tbody>{rows}</tbody></table></body></html>",
        count = findings.len(),
        rows = rows,
    )
}

async fn html_view(State(findings): State<Arc<Findings>>) -> Html<String> {
    Html(render_html(&findings.snapshot()))
}

async fn json_view(State(findings): State<Arc<Findings>>) -> Json<Vec<Finding>> {
    Json(findings.snapshot())
}

/// The attack graph as Graphviz DOT (`curl .../graph | dot -Tsvg`).
async fn graph_view(
    State(findings): State<Arc<Findings>>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/vnd.graphviz")],
        findings.graph_dot(),
    )
}

/// Serve the findings dashboard (`/` HTML, `/findings` JSON, `/graph` DOT).
/// Read-only; cluster-facing glue around the tested classification.
pub async fn serve_dashboard(addr: SocketAddr, findings: Arc<Findings>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(html_view))
        .route("/findings", get(json_view))
        .route("/graph", get(graph_view))
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
}
