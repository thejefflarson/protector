//! Render the attack graph as Graphviz DOT — the chains *from the internet to the
//! goal*, collapsed into one navigable graph instead of a flat list of (entry,
//! objective) rows. Scoped to what matters: chains with live/foothold/promoted
//! evidence, or an internet-exposed entry. The structural assume-breach mass (the
//! "if this were compromised…" paths) is left out, so a broadly-privileged
//! workload's fan-out reads as one node with many edges, not hundreds of rows.
//!
//! `curl .../graph | dot -Tsvg > attack.svg` (or any DOT viewer).

use std::collections::{BTreeMap, BTreeSet};

use super::graph::{Exposure, Node, NodeKey, SecurityGraph};
use super::proof::ProvenChain;

const INTERNET: &str = "__internet__";

/// DOT node shape by node kind, parsed from the key prefix.
fn shape_for(key: &str) -> &'static str {
    match key.split('/').next().unwrap_or("") {
        "secret" => "cylinder",
        "capability" => "diamond",
        "host" => "box3d",
        "identity" => "ellipse",
        _ => "box", // workload / image / endpoint
    }
}

/// A short label: drop the kind prefix, keep the ns/name tail.
fn short(key: &str) -> String {
    key.split_once('/')
        .map_or_else(|| key.to_string(), |(_, rest)| rest.to_string())
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn entry_internet_exposed(graph: &SecurityGraph, key: &str) -> bool {
    matches!(
        graph.index_of(&NodeKey(key.to_string())).and_then(|i| graph.node(i)),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    )
}

/// Build a DOT graph of the internet→goal attack subgraph from the proven chains.
pub fn attack_graph_dot(graph: &SecurityGraph, chains: &[ProvenChain]) -> String {
    let included: Vec<&ProvenChain> = chains
        .iter()
        .filter(|c| {
            c.meets_action_bar()
                || c.foothold.is_some()
                || entry_internet_exposed(graph, &c.entry.0)
        })
        .collect();

    let mut node_keys: BTreeSet<String> = BTreeSet::new();
    let mut live_entries: BTreeSet<String> = BTreeSet::new();
    let mut foothold_entries: BTreeSet<String> = BTreeSet::new();
    let mut internet_entries: BTreeSet<String> = BTreeSet::new();
    // (from, to) -> relation label (dedup; one edge per pair).
    let mut edges: BTreeMap<(String, String), String> = BTreeMap::new();

    for c in &included {
        node_keys.insert(c.entry.0.clone());
        node_keys.insert(c.objective.0.clone());
        if c.meets_action_bar() {
            live_entries.insert(c.entry.0.clone());
        }
        if c.foothold.is_some() {
            foothold_entries.insert(c.entry.0.clone());
        }
        if entry_internet_exposed(graph, &c.entry.0) {
            internet_entries.insert(c.entry.0.clone());
        }
        for l in &c.links {
            node_keys.insert(l.from.0.clone());
            node_keys.insert(l.to.0.clone());
            edges.insert((l.from.0.clone(), l.to.0.clone()), l.relation.clone());
        }
    }

    let mut out = String::from("digraph protector {\n  rankdir=LR;\n  node [fontsize=10];\n");
    if node_keys.is_empty() {
        out.push_str(
            "  \"none\" [label=\"no internet-origin, foothold, or live chains\", shape=note];\n}\n",
        );
        return out;
    }
    if !internet_entries.is_empty() {
        out.push_str(&format!(
            "  \"{INTERNET}\" [label=\"Internet\", shape=doublecircle];\n"
        ));
    }
    for k in &node_keys {
        // red = live/auto-eligible entry, orange = foothold entry, else default.
        let style = if live_entries.contains(k) {
            ", color=red, penwidth=2"
        } else if foothold_entries.contains(k) {
            ", color=orange, penwidth=2"
        } else {
            ""
        };
        out.push_str(&format!(
            "  \"{}\" [label=\"{}\", shape={}{}];\n",
            dot_escape(k),
            dot_escape(&short(k)),
            shape_for(k),
            style,
        ));
    }
    for e in &internet_entries {
        out.push_str(&format!(
            "  \"{INTERNET}\" -> \"{}\" [label=\"exposed\", style=bold];\n",
            dot_escape(e)
        ));
    }
    for ((from, to), rel) in &edges {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            dot_escape(from),
            dot_escape(to),
            dot_escape(rel),
        ));
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::{build_graph, default_adapters};
    use crate::engine::observe::{SecretMeta, Snapshot};
    use crate::engine::proof::prove;
    use serde_json::json;

    #[test]
    fn dot_maps_internet_to_goal_and_scopes_out_assume_breach() {
        // web (annotated internet-exposed) -reaches-> store -can-read-> secret.
        let pod = |v: serde_json::Value| serde_json::from_value(v).unwrap();
        let snap = Snapshot {
            pods: vec![
                pod(json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"web","namespace":"app","labels":{"role":"web"},"annotations":{"protector.jeffl.es/exposure":"internet"}},"spec":{"containers":[{"name":"web","image":"web:1"}]}})),
                pod(json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"store","namespace":"app","labels":{"role":"store"}},"spec":{"containers":[{"name":"store","image":"store:1","envFrom":[{"secretRef":{"name":"session-key"}}]}]}})),
            ],
            services: vec![serde_json::from_value(json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"web","namespace":"app","annotations":{"protector.jeffl.es/exposure":"internet"}},"spec":{"selector":{"role":"web"}}})).unwrap()],
            secrets: vec![SecretMeta { namespace: "app".into(), name: "session-key".into() }],
            network_policies: vec![serde_json::from_value(json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"store-ingress","namespace":"app"},"spec":{"podSelector":{"matchLabels":{"role":"store"}},"policyTypes":["Ingress"],"ingress":[{"from":[{"podSelector":{"matchLabels":{"role":"web"}}}]}]}})).unwrap()],
            ..Default::default()
        };
        let graph = build_graph(&snap, &default_adapters());
        let dot = attack_graph_dot(&graph, &prove(&graph));

        assert!(dot.contains("Internet"), "has an Internet source node");
        assert!(
            dot.contains("__internet__\" -> \"workload/app/Pod/web\""),
            "internet → exposed web"
        );
        assert!(
            dot.contains("secret/app/session-key"),
            "reaches the secret objective"
        );
        assert!(dot.contains("digraph protector"));
    }

    #[test]
    fn dot_is_empty_note_when_nothing_is_exposed_or_live() {
        let graph = build_graph(&Snapshot::default(), &default_adapters());
        let dot = attack_graph_dot(&graph, &prove(&graph));
        assert!(dot.contains("no internet-origin, foothold, or live chains"));
    }
}
