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
    /// Human-readable disposition (the classification ADR-0009 draws).
    pub disposition: String,
    /// The single-edge cut that severs it, if one exists.
    pub cut: Option<String>,
}

impl Finding {
    pub fn from_chain(chain: &ProvenChain) -> Self {
        let disposition = if chain.meets_action_bar() {
            if chain.adjudicated {
                "live — auto-eligible"
            } else {
                "live — vetoed by adjudicator (proposed)"
            }
        } else if chain.is_latent_foothold() {
            "latent foothold — proposed"
        } else {
            "structural — proposed"
        }
        .to_string();

        let cut = chain
            .single_edge_cuts
            .first()
            .map(super::response::cut_signature);

        Finding {
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            tactic: chain.attack.tactic.id().to_string(),
            technique: chain.attack.technique_id.to_string(),
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            adjudicated: chain.adjudicated,
            disposition,
            cut,
        }
    }
}

/// The current findings snapshot, shared between the engine (writer) and the HTTP
/// server (reader).
#[derive(Default)]
pub struct Findings {
    rows: Mutex<Vec<Finding>>,
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
}

/// Minimal HTML escape for the few values that could contain markup-special chars.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// CSS class for a disposition, for a touch of semantic colour (flat, no chrome).
fn disposition_class(disposition: &str) -> &'static str {
    if disposition.starts_with("live — auto") {
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
             <td class=\"{}\">{}</td><td>{}</td></tr>",
            escape(&f.entry),
            escape(&f.objective),
            escape(&f.tactic),
            escape(&f.technique),
            yn(f.foothold),
            yn(f.corroborated),
            yn(f.adjudicated),
            disposition_class(&f.disposition),
            escape(&f.disposition),
            escape(f.cut.as_deref().unwrap_or("—")),
        ));
    }
    if findings.is_empty() {
        rows.push_str("<tr><td colspan=\"8\" class=\"muted\">no proven chains</td></tr>");
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
         <th>live</th><th>adjudicated</th><th>disposition</th><th>cut</th>\
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

/// Serve the findings dashboard (`/` HTML, `/findings` JSON). Read-only; cluster-
/// facing glue around the tested [`Finding`] classification.
pub async fn serve_dashboard(addr: SocketAddr, findings: Arc<Findings>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(html_view))
        .route("/findings", get(json_view))
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

    fn chain(foothold: bool, corroborated: bool, adjudicated: bool) -> ProvenChain {
        ProvenChain {
            entry: NodeKey("workload/app/Pod/web".into()),
            objective: NodeKey("secret/app/s".into()),
            attack: CREDENTIAL_ACCESS,
            foothold: foothold.then_some(EXPLOIT_PUBLIC_FACING),
            corroborated,
            adjudicated,
            links: vec![],
            single_edge_cuts: vec![],
        }
    }

    #[test]
    fn disposition_reflects_the_asymmetric_classification() {
        assert_eq!(
            Finding::from_chain(&chain(false, true, true)).disposition,
            "live — auto-eligible"
        );
        assert_eq!(
            Finding::from_chain(&chain(true, true, false)).disposition,
            "live — vetoed by adjudicator (proposed)"
        );
        assert_eq!(
            Finding::from_chain(&chain(true, false, true)).disposition,
            "latent foothold — proposed"
        );
        assert_eq!(
            Finding::from_chain(&chain(false, false, true)).disposition,
            "structural — proposed"
        );
    }
}
