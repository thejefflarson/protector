use super::*;

/// `scheduled-on` edges from every scheduled pod to the `Host` it landed on (ADR-0040
/// §3, build-settled 2026-08-02): pure pod→node **placement** ("this pod is running on
/// this node"), derived from `pod.spec.node_name` — the same field
/// [`super::escape::HostEscapeAdapter`] already reads to point its `escapes-to` edges
/// at a concrete `Host`, so this needs no new watch and no new RBAC (`pods` get/list/
/// watch is already granted).
///
/// Deliberately a DISTINCT relation from [`Relation::EscapesTo`], never a reuse: an
/// escape edge asserts "this workload can break out to this node's host" (a
/// precondition on the pod spec — a container-escape primitive), while `ScheduledOn`
/// asserts only "this workload is on this node", true of every scheduled pod whether
/// or not it carries any escape primitive. Folding placement into `EscapesTo` would
/// silently grant escape-reachability to every ordinary pod. `ScheduledOn` is the
/// node-containment predicate's (`engine::reason::proof::boundary_break`) source of
/// co-residency — trigger (d) walks this edge to find the workloads sharing a
/// compromised pod's host.
pub struct PlacementAdapter;

impl Adapter for PlacementAdapter {
    fn name(&self) -> &'static str {
        "placement"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            // Unscheduled pods have no host yet — nothing to place, mirroring
            // HostEscapeAdapter's own node_name gate.
            let Some(node_name) = pod.spec.as_ref().and_then(|s| s.node_name.clone()) else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let wl = graph.ensure_node(workload_node(&namespace, &name));
            let host = graph.upsert_node(Node::Host(Host { name: node_name }));
            graph.add_edge(wl, host, observed(self.name(), Relation::ScheduledOn));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use petgraph::visit::EdgeRef;
    use serde_json::json;

    #[test]
    fn a_scheduled_pod_gets_a_placement_edge_to_its_host() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "api", "namespace": "app"},
                "spec": {
                    "nodeName": "node-1",
                    "containers": [{"name": "api", "image": "api:1"}]
                }
            }))],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let wl = g.index_of(&workload_node("app", "api").key()).unwrap();
        let host = g
            .index_of(
                &Node::Host(Host {
                    name: "node-1".to_string(),
                })
                .key(),
            )
            .unwrap();
        let scheduled = g
            .inner()
            .edges(wl)
            .any(|e| matches!(e.weight().relation, Relation::ScheduledOn) && e.target() == host);
        assert!(
            scheduled,
            "scheduled pod must carry a scheduled-on edge to its host"
        );
    }

    #[test]
    fn an_unscheduled_pod_gets_no_placement_edge_and_no_host_node() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "pending", "namespace": "app"},
                "spec": {
                    "containers": [{"name": "app", "image": "app:1"}]
                }
            }))],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let wl = g.index_of(&workload_node("app", "pending").key()).unwrap();
        assert_eq!(
            g.inner()
                .edges(wl)
                .filter(|e| matches!(e.weight().relation, Relation::ScheduledOn))
                .count(),
            0,
            "an unscheduled pod has no host to be placed on"
        );
    }

    #[test]
    fn co_resident_pods_share_one_host_node() {
        let snap = Snapshot {
            pods: vec![
                pod(json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "a", "namespace": "app"},
                    "spec": {"nodeName": "node-1", "containers": [{"name": "a", "image": "a:1"}]}
                })),
                pod(json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "b", "namespace": "app"},
                    "spec": {"nodeName": "node-1", "containers": [{"name": "b", "image": "b:1"}]}
                })),
            ],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let a = g.index_of(&workload_node("app", "a").key()).unwrap();
        let b = g.index_of(&workload_node("app", "b").key()).unwrap();
        let host_a = g
            .inner()
            .edges(a)
            .find(|e| matches!(e.weight().relation, Relation::ScheduledOn))
            .map(|e| e.target());
        let host_b = g
            .inner()
            .edges(b)
            .find(|e| matches!(e.weight().relation, Relation::ScheduledOn))
            .map(|e| e.target());
        assert!(
            host_a.is_some() && host_a == host_b,
            "both pods land on the same Host node"
        );
    }
}
