//! The adjudicator (ADR-0008): the model's primary job — *judge* a
//! deterministically-proven chain, never authorize one.
//!
//! Adjudication runs only on a chain that already meets the full action bar. The
//! model is asked the two questions a deterministic check answers worst: is this
//! KEV CVE actually exploitable *in this deployment*, and is this Falco signal
//! actually an attack (vs a benign exec)? Its verdict is **one-way**: `Refuted` or
//! `Uncertain` downgrades an eligible auto-action to a human proposal; nothing the
//! model says can *create* permission. A wrong model causes at worst a missed
//! auto-action, never a bad cut — so "only deterministic proof moves privilege"
//! survives a model that hallucinates or flatters. The model never runs an exploit
//! (the named bound): it reasons about exploitability; it does not exercise it.
//!
//! The prompt-building and verdict-parsing are pure and tested; the model call is
//! the shared glue in [`super::model`].

use petgraph::visit::EdgeRef;
use serde_json::Value;

use super::graph::{Node, Relation, SecurityGraph};
use super::proof::ProvenChain;

/// The model's judgement on a proven chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A real, contextually-exploitable attack — let the deterministic decision stand.
    Confirmed,
    /// Not a real/exploitable attack (benign exec, non-exploitable version, mitigated).
    Refuted(String),
    /// The model couldn't tell — treated as a downgrade (skeptic default).
    Uncertain(String),
}

impl Verdict {
    /// Only `Confirmed` lets an otherwise-eligible auto-action proceed. Everything
    /// else demotes it to a human proposal — the one-way veto.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Verdict::Confirmed)
    }
}

/// Judges a proven chain. Implementations are a model (the real one) or a fixed
/// verdict (the default / tests).
#[async_trait::async_trait]
pub trait Adjudicator: Send + Sync {
    async fn judge(&self, chain: &ProvenChain, graph: &SecurityGraph) -> Verdict;
}

/// The default: confirm everything. Absent a model the deterministic action bar
/// alone governs — behaviour is unchanged, no veto is applied.
pub struct NullAdjudicator;

#[async_trait::async_trait]
impl Adjudicator for NullAdjudicator {
    async fn judge(&self, _chain: &ProvenChain, _graph: &SecurityGraph) -> Verdict {
        Verdict::Confirmed
    }
}

/// The evidence behind a chain's entry: the CVEs its image carries and the runtime
/// signals observed on it — what the model needs to judge contextual realness.
fn entry_evidence(graph: &SecurityGraph, chain: &ProvenChain) -> (Vec<String>, Vec<String>) {
    let g = graph.inner();
    let Some(entry) = graph.index_of(&chain.entry) else {
        return (Vec::new(), Vec::new());
    };
    let runtime = match g.node_weight(entry) {
        Some(Node::Workload(w)) => w.runtime.iter().map(|s| s.rule.clone()).collect(),
        _ => Vec::new(),
    };
    let mut cves = Vec::new();
    for edge in g.edges(entry) {
        if matches!(edge.weight().relation, Relation::RunsImage)
            && let Some(Node::Image(image)) = g.node_weight(edge.target())
        {
            cves.extend(
                image
                    .vulnerabilities
                    .iter()
                    .filter(|v| v.exploited_in_wild)
                    .map(|v| v.id.clone()),
            );
        }
    }
    (cves, runtime)
}

/// Build the adjudication prompt from a chain and its evidence. Skeptic by
/// instruction: refute when uncertain.
pub fn build_judgment_prompt(chain: &ProvenChain, graph: &SecurityGraph) -> String {
    let (cves, runtime) = entry_evidence(graph, chain);
    format!(
        "A deterministic analysis found an attack chain that meets the action bar.\n\
         Entry workload: {entry}\n\
         Exploited-in-wild CVEs on its image: {cves}\n\
         Runtime signals observed on it: {runtime}\n\
         Objective: {objective} (ATT&CK {technique} {technique_name})\n\n\
         Judge whether this is a REAL, contextually-exploitable attack right now, \
         or a false positive — a benign exec, a non-exploitable version/config, an \
         already-mitigated CVE. Do not assume; if you cannot tell, refute.\n\
         Reply with ONLY JSON: {{\"verdict\": \"confirmed\"|\"refuted\"|\"uncertain\", \"reason\": \"...\"}}",
        entry = chain.entry.0,
        cves = if cves.is_empty() {
            "(none)".into()
        } else {
            cves.join(", ")
        },
        runtime = if runtime.is_empty() {
            "(none)".into()
        } else {
            runtime.join(", ")
        },
        objective = chain.objective.0,
        technique = chain.attack.technique_id,
        technique_name = chain.attack.technique,
    )
}

/// Parse a model verdict, tolerating surrounding prose. Anything not clearly
/// `confirmed` or `refuted` — including an unparseable reply — is `Uncertain`,
/// which downgrades (skeptic default).
pub fn parse_verdict(reply: &str) -> Verdict {
    let object = reply
        .find('{')
        .zip(reply.rfind('}'))
        .and_then(|(start, end)| serde_json::from_str::<Value>(&reply[start..=end]).ok());
    let Some(object) = object else {
        return Verdict::Uncertain("unparseable model reply".to_string());
    };
    let reason = object["reason"].as_str().unwrap_or("").to_string();
    match object["verdict"].as_str().map(str::trim) {
        Some("confirmed") => Verdict::Confirmed,
        Some("refuted") => Verdict::Refuted(reason),
        _ => Verdict::Uncertain(reason),
    }
}

/// A model-backed adjudicator (OpenAI-compatible endpoint via [`super::model`]).
pub struct ModelAdjudicator {
    endpoint: String,
    model: String,
    client: reqwest::Client,
}

impl ModelAdjudicator {
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
            client: super::model::client(),
        }
    }
}

#[async_trait::async_trait]
impl Adjudicator for ModelAdjudicator {
    async fn judge(&self, chain: &ProvenChain, graph: &SecurityGraph) -> Verdict {
        let prompt = build_judgment_prompt(chain, graph);
        match super::model::chat(&self.client, &self.endpoint, &self.model, &prompt).await {
            Some(reply) => parse_verdict(&reply),
            // Model unavailable → skeptic: do not let an auto-action proceed.
            None => Verdict::Uncertain("model unavailable".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::{build_graph, default_adapters};
    use crate::engine::attack::EXPLOIT_PUBLIC_FACING;
    use crate::engine::graph::{NodeKey, Provenance, Severity, Vulnerability};
    use crate::engine::observe::{ImageVulnerabilities, RuntimeObservation, Snapshot};
    use crate::engine::proof::prove;
    use serde_json::json;
    use std::time::SystemTime;

    #[test]
    fn parses_verdicts_and_defaults_to_uncertain() {
        assert_eq!(
            parse_verdict(r#"{"verdict":"confirmed","reason":"reachable RCE"}"#),
            Verdict::Confirmed
        );
        assert!(matches!(
            parse_verdict("Looks benign. {\"verdict\":\"refuted\",\"reason\":\"debug exec\"}"),
            Verdict::Refuted(_)
        ));
        // No parseable JSON ⇒ uncertain (skeptic) ⇒ not confirmed.
        assert!(!parse_verdict("I think it's fine").is_confirmed());
    }

    #[test]
    fn prompt_includes_the_chain_evidence() {
        // A foothold chain: exposed + KEV CVE + runtime signal → meets the bar.
        let web = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]}
        }))
        .unwrap();
        let lb = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        let snap = Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![crate::engine::observe::SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2021-44228".into(),
                    severity: Severity::Critical,
                    exploited_in_wild: true,
                    epss: None,
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                }],
            }],
            runtime_events: vec![RuntimeObservation {
                namespace: "app".into(),
                pod: "web".into(),
                rule: "Terminal shell in container".into(),
            }],
            ..Default::default()
        };
        let graph = build_graph(&snap, &default_adapters());
        let chains = prove(&graph);
        let chain = chains
            .iter()
            .find(|c| {
                c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key"
            })
            .expect("foothold chain");
        assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));

        let prompt = build_judgment_prompt(chain, &graph);
        assert!(prompt.contains("CVE-2021-44228"), "names the exploited CVE");
        assert!(
            prompt.contains("Terminal shell in container"),
            "names the runtime signal"
        );
        assert!(prompt.contains("refute"), "instructs skeptic default");
    }

    #[tokio::test]
    async fn null_adjudicator_confirms() {
        let graph = build_graph(&Snapshot::default(), &default_adapters());
        let chain = ProvenChain {
            entry: NodeKey("workload/app/Pod/x".into()),
            objective: NodeKey("secret/app/s".into()),
            attack: EXPLOIT_PUBLIC_FACING,
            foothold: Some(EXPLOIT_PUBLIC_FACING),
            corroborated: true,
            adjudicated: true,
            links: vec![],
            single_edge_cuts: vec![],
        };
        assert_eq!(
            NullAdjudicator.judge(&chain, &graph).await,
            Verdict::Confirmed
        );
    }
}
