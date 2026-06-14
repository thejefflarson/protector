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
    /// Whether the entry is internet-facing — the discriminator between a real breach
    /// path and an assume-breach access path. Drives the bucket: a non-breach-relevant
    /// chain is context, no matter what it can reach. See [`ProvenChain::is_breach_relevant`].
    pub breach_relevant: bool,
    /// The proven attack path, hop by hop (entry → … → objective) — rendered as a
    /// small per-row graph so each finding reads on its own.
    pub path: Vec<PathStep>,
}

/// One hop of a proven chain: `from -[relation]-> to`, with short (kind-stripped)
/// node labels ready to render.
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
            path: chain
                .links
                .iter()
                .map(|l| PathStep {
                    from: short(&l.from.0),
                    relation: l.relation.clone(),
                    to: short(&l.to.0),
                })
                .collect(),
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

/// A short, human label for a node key — drop the kind prefix (`workload/`, …).
fn short(key: &str) -> String {
    key.split_once('/')
        .map_or_else(|| key.to_string(), |(_, rest)| rest.to_string())
}

/// Which "what do I do about it" bucket a finding falls in: 0 act, 1 fix, 2 watch,
/// 3 context. A chain is only a *finding* (buckets 0-2) if it's breach-relevant —
/// the entry is internet-facing, an origin an attacker can actually reach. Everything
/// else (an internal workload that can read a secret or reach the DB — normal cluster
/// topology) is the assume-breach blast-radius map: context, not a to-do.
fn bucket(f: &Finding) -> usize {
    if !f.breach_relevant {
        return 3; // assume-breach context: not reachable from the internet
    }
    match f.disposition.as_str() {
        "auto-eligible" => 0,
        "durable-fix PR" | "forbidden" => 1,
        "latent foothold — propose" | "vetoed — propose" => 2,
        _ => 3, // structural / no-cut / unclassified — assume-breach context
    }
}

/// Render the findings grouped by what to *do* — a one-line summary, then four
/// collapsible buckets (act / fix / watch / context), each item a plain sentence.
/// Flat, system font, no gradients, no rounded corners.
fn render_html(findings: &[Finding]) -> String {
    let mut counts = [0usize; 4];
    for f in findings {
        counts[bucket(f)] += 1;
    }

    let item = |f: &Finding| {
        let evidence = if f.corroborated {
            "live (runtime signal)"
        } else if f.promoted {
            "model-promoted"
        } else if f.foothold {
            "internet-exposed + CVE"
        } else {
            "reachable"
        };
        // The attack path as a small inline graph: entry, then each hop's relation
        // and next node. Falls back to the endpoints if no links were recorded.
        let path = if f.path.is_empty() {
            format!(
                "{} <span class=\"arr\">→</span> {}",
                escape(&short(&f.entry)),
                escape(&short(&f.objective)),
            )
        } else {
            let mut s = format!("<span class=\"node\">{}</span>", escape(&f.path[0].from));
            for step in &f.path {
                s.push_str(&format!(
                    " <span class=\"rel\">{}</span> <span class=\"arr\">→</span> \
                     <span class=\"node\">{}</span>",
                    escape(&step.relation),
                    escape(&step.to),
                ));
            }
            s
        };
        format!(
            "<li><div class=\"path\">{path}</div> <span class=\"ev\">{}</span></li>",
            escape(evidence),
        )
    };
    let section = |title: &str, b: usize, open: bool| {
        let body = if counts[b] == 0 {
            "<p class=\"muted\">none</p>".to_string()
        } else {
            let items: String = findings
                .iter()
                .filter(|f| bucket(f) == b)
                .map(&item)
                .collect();
            format!("<ul>{items}</ul>")
        };
        format!(
            "<details class=\"b{b}\"{}><summary><b>{}</b> <span class=\"n\">{}</span>\
             </summary>{}</details>",
            if open { " open" } else { "" },
            escape(title),
            counts[b],
            body,
        )
    };

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>protector</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#111;max-width:60rem}}\
         h1{{font-size:1.2rem;font-weight:600;margin:0}}\
         .sum{{margin:.5rem 0 1.5rem;color:#444}}\
         details{{border-left:3px solid #ccc;padding:.3rem .8rem;margin:.6rem 0}}\
         details.b0{{border-color:#b00000}} details.b1{{border-color:#9a5b00}}\
         details.b2{{border-color:#888}} details.b3{{border-color:#ddd}}\
         summary{{cursor:pointer;font-size:.95rem}}\
         .n{{display:inline-block;min-width:1.5rem;color:#000;font-weight:600}}\
         ul{{list-style:none;padding:0;margin:.5rem 0}}\
         li{{padding:.35rem 0;border-top:1px solid #eee}}\
         .path{{font-family:ui-monospace,monospace;font-size:.85rem;line-height:1.6}}\
         .node{{color:#111}}\
         .rel{{color:#999;font-size:.72rem}}\
         .arr{{color:#bbb}}\
         .ev{{font-size:.75rem;color:#666;margin-left:.4rem}}\
         .muted{{color:#777;font-weight:400}}\
         a{{color:#06c}}\
         </style></head><body>\
         <h1>protector</h1>\
         <p class=\"sum\"><b>{breach}</b> breach path{plural} reachable from the internet — \
         <b>{act}</b> to act on · <b>{fix}</b> to fix in code · <b>{watch}</b> to watch. \
         <span class=\"muted\">{ctx} internal access paths are assume-breach context, not findings.</span> \
         &nbsp;|&nbsp; <a href=\"/graph\">attack graph</a> · <a href=\"/findings\">json</a></p>\
         {s_act}{s_fix}{s_watch}{s_ctx}\
         </body></html>",
        breach = counts[0] + counts[1] + counts[2],
        plural = if counts[0] + counts[1] + counts[2] == 1 {
            ""
        } else {
            "s"
        },
        act = counts[0],
        fix = counts[1],
        watch = counts[2],
        ctx = counts[3],
        s_act = section("Act now", 0, true),
        s_fix = section("Fix in code", 1, true),
        s_watch = section("Watch", 2, true),
        s_ctx = section("Assume-breach", 3, false),
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
            // The disposition tests below key on the cut + evidence, not on
            // breach-relevance; treat the entry as a front door so the chain is a
            // finding (bucket gating is exercised in the render test instead).
            exposed_entry: true,
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

    #[test]
    fn render_groups_by_what_to_do_and_dumps_a_sample() {
        // Shaped like the real cluster: a couple of internet-facing breach paths
        // (the only real findings), and a big internal RBAC/access mass that is
        // assume-breach context — exactly the "everything that can read secrets"
        // noise that must NOT be flagged as fix-in-code.
        let f = |entry: &str,
                 objective: &str,
                 disposition: &str,
                 decision: &str,
                 breach_relevant: bool| Finding {
            entry: entry.into(),
            objective: objective.into(),
            tactic: "TA0006".into(),
            technique: "T1552".into(),
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            disposition: disposition.into(),
            decision: decision.into(),
            cut: Some(format!("{entry} -[…]-> {objective}")),
            breach_relevant,
            path: vec![
                PathStep {
                    from: short(entry),
                    relation: "reaches/Tcp".into(),
                    to: "app/Pod/store".into(),
                },
                PathStep {
                    from: "app/Pod/store".into(),
                    relation: "can-read".into(),
                    to: short(objective),
                },
            ],
        };
        // Two internet-facing front doors: one auto-cuttable, one durable-fix.
        let mut findings = vec![
            f(
                "workload/app/Pod/web",
                "secret/app/session-key",
                "auto-eligible",
                "auto-applies a reversible NetworkPolicy cut when `network` is armed",
                true,
            ),
            f(
                "workload/app/Pod/web",
                "capability/cluster/create/pods",
                "durable-fix PR",
                "revoke the RBAC grant via GitOps",
                true,
            ),
        ];
        // The internal mass: control-plane + workloads that can read secrets / reach
        // the DB. Real cluster topology, NOT a breach — must land in context.
        for o in [
            "secret/argocd/argocd-secret",
            "secret/analytics/postgres.creds",
            "capability/cluster/create/pods",
        ] {
            findings.push(f(
                "workload/argocd/Pod/argocd-application-controller-0",
                o,
                "durable-fix PR",
                "revoke the RBAC grant via GitOps",
                false,
            ));
        }
        for i in 0..40 {
            findings.push(f(
                &format!("workload/kube-system/Pod/p{i}"),
                "secret/kube-system/sh.helm.release.v1.x",
                "structural — propose",
                "no live or foothold evidence — propose only",
                false,
            ));
        }

        let html = render_html(&findings);
        assert!(html.contains("breach path"));
        assert!(html.contains("Act now"));
        assert!(html.contains("Fix in code"));
        assert!(html.contains("Assume-breach"));
        assert!(html.contains("not findings"));
        // The internal RBAC mass is context, not fix-in-code: only the one
        // internet-facing durable-fix is in bucket 1.
        assert_eq!(findings.iter().filter(|f| bucket(f) == 1).count(), 1);
        // The argocd + kube-system mass (43) all collapses into context.
        assert_eq!(findings.iter().filter(|f| bucket(f) == 3).count(), 43);
        // The per-row attack path renders as an inline graph (hop relations shown).
        assert!(html.contains("class=\"rel\">can-read"));
        assert!(html.contains("app/Pod/store"));
        // Header explanations are gone — no "—"-prefixed description in summaries.
        assert!(!html.contains("auto-cut when armed"));
        // Dump for eyeballing the UX (ignored by CI artifacts; just a dev aid).
        let _ = std::fs::write("/tmp/protector-dashboard.html", &html);
    }
}
