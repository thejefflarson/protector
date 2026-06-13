//! The change-driven core (ADR-0002, Question 1): diff two graph states and emit
//! the **threat delta** — the attack surface a change added or removed.
//!
//! This is the deterministic, no-model, easy-mode stage: it observes, builds,
//! diffs, and *reports*. It takes no privileged action. The report mirrors the
//! webhook's audit stream — a structured log line per change — so the delta is
//! discoverable the same way policy violations already are.

use std::collections::BTreeSet;

use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use super::graph::SecurityGraph;

/// A canonical, comparable projection of a graph: the set of node keys and the set
/// of edge signatures (`source -[label]-> target`). Diffing reduces to set
/// difference over these strings, which is exact at this scale and trivially
/// testable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GraphSnapshot {
    nodes: BTreeSet<String>,
    edges: BTreeSet<String>,
}

impl GraphSnapshot {
    /// Project `graph` into its comparable form.
    pub fn of(graph: &SecurityGraph) -> Self {
        let nodes = graph
            .inner()
            .node_indices()
            .filter_map(|i| graph.key_of(i).map(|k| k.0))
            .collect();

        let edges = graph
            .inner()
            .edge_references()
            .filter_map(|e| {
                let src = graph.key_of(e.source())?.0;
                let dst = graph.key_of(e.target())?.0;
                Some(format!("{src} -[{}]-> {dst}", e.weight().relation.label()))
            })
            .collect();

        Self { nodes, edges }
    }
}

/// What changed between two graph states. Each field lists the items added or
/// removed, by their canonical signature.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ThreatDelta {
    pub added_nodes: Vec<String>,
    pub removed_nodes: Vec<String>,
    pub added_edges: Vec<String>,
    pub removed_edges: Vec<String>,
}

/// Compute the delta from `prev` to `next`.
pub fn diff(prev: &GraphSnapshot, next: &GraphSnapshot) -> ThreatDelta {
    let difference = |a: &BTreeSet<String>, b: &BTreeSet<String>| -> Vec<String> {
        a.difference(b).cloned().collect()
    };
    ThreatDelta {
        added_nodes: difference(&next.nodes, &prev.nodes),
        removed_nodes: difference(&prev.nodes, &next.nodes),
        added_edges: difference(&next.edges, &prev.edges),
        removed_edges: difference(&prev.edges, &next.edges),
    }
}

impl ThreatDelta {
    /// True when nothing changed — the common case, in which the loop stays quiet.
    pub fn is_empty(&self) -> bool {
        self.added_nodes.is_empty()
            && self.removed_nodes.is_empty()
            && self.added_edges.is_empty()
            && self.removed_edges.is_empty()
    }

    /// Emit the delta as structured logs. A summary line carries the counts; each
    /// added or removed edge — the actual change to the attack surface — is logged
    /// individually so it is greppable, exactly like a policy audit finding.
    pub fn emit(&self) {
        tracing::info!(
            added_nodes = self.added_nodes.len(),
            removed_nodes = self.removed_nodes.len(),
            added_edges = self.added_edges.len(),
            removed_edges = self.removed_edges.len(),
            "threat-delta"
        );
        for edge in &self.added_edges {
            tracing::info!(change = "added", %edge, "threat-delta edge");
        }
        for edge in &self.removed_edges {
            tracing::info!(change = "removed", %edge, "threat-delta edge");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::{build_graph, default_adapters};
    use crate::engine::observe::Snapshot;
    use serde_json::json;

    fn snapshot_with_pod(name: &str) -> Snapshot {
        Snapshot {
            pods: vec![
                serde_json::from_value(json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": name, "namespace": "app"},
                    "spec": {"containers": [{"name": "c", "image": "img:1"}]}
                }))
                .unwrap(),
            ],
            network_policies: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn identical_states_produce_an_empty_delta() {
        let g = build_graph(&snapshot_with_pod("api"), &default_adapters());
        let a = GraphSnapshot::of(&g);
        let b = a.clone();
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn adding_a_workload_shows_up_as_added_nodes_and_edges() {
        let before = GraphSnapshot::of(&build_graph(&Snapshot::default(), &default_adapters()));
        let after = GraphSnapshot::of(&build_graph(&snapshot_with_pod("api"), &default_adapters()));
        let d = diff(&before, &after);
        assert!(!d.is_empty());
        // Workload, Identity, Image nodes appear.
        assert!(
            d.added_nodes
                .iter()
                .any(|n| n.starts_with("workload/app/Pod/api"))
        );
        assert!(d.added_nodes.iter().any(|n| n.starts_with("identity/app/")));
        assert!(d.added_nodes.iter().any(|n| n.starts_with("image/")));
        // Structural edges appear; nothing was removed.
        assert!(d.added_edges.iter().any(|e| e.contains("runs-image")));
        assert!(d.removed_nodes.is_empty());
        assert!(d.removed_edges.is_empty());
    }

    #[test]
    fn removing_a_workload_shows_up_as_removed() {
        let before =
            GraphSnapshot::of(&build_graph(&snapshot_with_pod("api"), &default_adapters()));
        let after = GraphSnapshot::of(&build_graph(&Snapshot::default(), &default_adapters()));
        let d = diff(&before, &after);
        assert!(d.added_nodes.is_empty());
        assert!(
            d.removed_nodes
                .iter()
                .any(|n| n.starts_with("workload/app/Pod/api"))
        );
        assert!(d.removed_edges.iter().any(|e| e.contains("runs-image")));
    }
}
