use super::*;

/// Workload, Image, and Identity nodes plus their structural edges.
pub struct WorkloadAdapter;

impl Adapter for WorkloadAdapter {
    fn name(&self) -> &'static str {
        "workload"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let spec = pod.spec.as_ref();

            let meshed = spec.is_some_and(|s| {
                s.containers.iter().any(|c| c.name == MESH_PROXY)
                    || s.init_containers
                        .as_ref()
                        .is_some_and(|ics| ics.iter().any(|c| c.name == MESH_PROXY))
            });

            // A mounted PersistentVolumeClaim marks the workload as a data store (data
            // at rest) — the signal the Data-from-Repositories objective (T1213) keys on.
            let persistent = spec.is_some_and(|s| {
                s.volumes
                    .iter()
                    .flatten()
                    .any(|v| v.persistent_volume_claim.is_some())
            });

            let wl = graph.upsert_node(Node::Workload(Workload {
                namespace: namespace.clone(),
                name: name.clone(),
                kind: "Pod".to_string(),
                labels: pod_labels(pod),
                meshed,
                // Exposure inference needs Services/Ingress we don't observe yet;
                // Internal is the honest default until that adapter lands.
                exposure: Exposure::Internal,
                runtime: vec![],
                persistent,
                misconfigs: vec![],
                rbac_findings: vec![],
            }));

            let sa = spec
                .and_then(|s| s.service_account_name.clone())
                .unwrap_or_else(|| "default".to_string());
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: namespace.clone(),
                name: sa,
            }));
            graph.add_edge(wl, id, observed(self.name(), Relation::RunsAs));

            if let Some(spec) = spec {
                let images = spec
                    .containers
                    .iter()
                    .chain(spec.init_containers.iter().flatten())
                    .filter_map(|c| c.image.clone());
                for image in images {
                    // Key on the canonical form so trivy findings (which carry a
                    // fully-qualified ref) attach to the same node as this pod's
                    // possibly-short ref; keep the raw ref for display.
                    let img = graph.upsert_node(Node::Image(Image {
                        digest: canonical_image(&image),
                        reference: Some(image),
                        trust: Trust::Unknown,
                        vulnerabilities: vec![],
                        exposed_secrets: vec![],
                        // Linkage is unknown at structural-build time (JEF-404): the engine
                        // holds no in-cluster access to the image's entrypoint bytes here, so
                        // it stays `None` and reachability behaves as before. An ELF-classified
                        // signal (see `engine::observe::elf`) would populate it once the bytes
                        // are plumbed in — see the ticket's DECISION NEEDED note.
                        static_binary: None,
                    }));
                    graph.add_edge(wl, img, observed(self.name(), Relation::RunsImage));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use serde_json::json;

    #[test]
    fn workload_adapter_builds_nodes_and_structural_edges() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "api", "namespace": "app", "labels": {"app": "api"}},
                "spec": {
                    "serviceAccountName": "api-sa",
                    "containers": [
                        {"name": "api", "image": "ghcr.io/x/api:1"},
                        {"name": "linkerd-proxy", "image": "linkerd/proxy:stable"}
                    ]
                }
            }))],
            network_policies: vec![],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());
        // Workload + Identity + 2 Images.
        assert_eq!(g.node_count(), 4);
        // runs-as + 2 runs-image.
        assert_eq!(g.edge_count(), 3);

        let wl_key = workload_node("app", "api").key();
        let wl = g.index_of(&wl_key).and_then(|i| g.node(i)).unwrap();
        match wl {
            Node::Workload(w) => {
                assert!(w.meshed, "linkerd-proxy container ⇒ meshed");
                assert!(!w.persistent, "no PVC ⇒ not a data store");
            }
            other => panic!("expected workload, got {other:?}"),
        }
    }

    #[test]
    fn a_pvc_mount_marks_the_workload_as_a_data_store() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "db-0", "namespace": "data", "labels": {"app": "db"}},
                "spec": {
                    "containers": [{"name": "postgres", "image": "postgres:16"}],
                    "volumes": [{
                        "name": "pgdata",
                        "persistentVolumeClaim": {"claimName": "pgdata-db-0"}
                    }]
                }
            }))],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());
        let wl = g
            .index_of(&workload_node("data", "db-0").key())
            .and_then(|i| g.node(i))
            .unwrap();
        match wl {
            Node::Workload(w) => assert!(w.persistent, "a PVC volume ⇒ data store (T1213)"),
            other => panic!("expected workload, got {other:?}"),
        }
    }
}
