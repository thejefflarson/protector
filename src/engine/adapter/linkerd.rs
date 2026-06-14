use super::*;
use crate::engine::linkerd::AuthClient;

/// `reaches` edges granted by Linkerd authorization, the mesh-native counterpart to
/// the `NetworkPolicy`-based [`ReachabilityAdapter`](super::ReachabilityAdapter). On
/// a Linkerd cluster the east-west allow-list lives in `AuthorizationPolicy` +
/// `Server` + `MeshTLSAuthentication`, not `NetworkPolicy`, so without this the graph
/// misses the real topology (e.g. watcher-server → watcher-db on 5432).
///
/// For each `AuthorizationPolicy` that targets a `Server`: the Server's `podSelector`
/// picks the target pods + port; the policy's authorized client ServiceAccounts
/// (resolved through its `MeshTLSAuthentication`, or named directly) pick the source
/// pods (those running as one of those SAs, cross-namespace included); an edge is
/// drawn from each source pod to each target pod on the Server's port.
///
/// Documented subset: Server-targeted policies authenticated by MeshTLSAuthentication
/// or a direct ServiceAccount. Namespace/HTTPRoute targets, NetworkAuthentication
/// (IP-based), and legacy ServerAuthorization are not modeled yet.
pub struct LinkerdReachabilityAdapter;

impl Adapter for LinkerdReachabilityAdapter {
    fn name(&self) -> &'static str {
        "linkerd"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Index pods by namespace+labels (target matching) and by the SA they run as
        // (client resolution). serviceAccountName defaults to "default".
        struct PodInfo {
            namespace: String,
            name: String,
            labels: BTreeMap<String, String>,
            service_account: String,
        }
        let pods: Vec<PodInfo> = snapshot
            .pods
            .iter()
            .filter_map(|p| {
                Some(PodInfo {
                    namespace: pod_namespace(p),
                    name: p.metadata.name.clone()?,
                    labels: pod_labels(p),
                    service_account: p
                        .spec
                        .as_ref()
                        .and_then(|s| s.service_account_name.clone())
                        .unwrap_or_else(|| "default".to_string()),
                })
            })
            .collect();

        for policy in &snapshot.linkerd_authz_policies {
            let Some(server_name) = &policy.target_server else {
                continue;
            };
            // Resolve the target Server (same namespace as the policy).
            let Some(server) = snapshot
                .linkerd_servers
                .iter()
                .find(|s| s.namespace == policy.namespace && &s.name == server_name)
            else {
                continue;
            };
            if has_match_expressions(&server.pod_selector) {
                graph.mark_reachability_incomplete();
            }
            let targets: Vec<&PodInfo> = pods
                .iter()
                .filter(|p| {
                    p.namespace == server.namespace
                        && selector_matches(&server.pod_selector, &p.labels)
                })
                .collect();
            if targets.is_empty() {
                continue;
            }

            // Resolve the authorized client ServiceAccounts.
            let mut client_sas: Vec<(String, String)> = Vec::new(); // (namespace, name)
            for client in &policy.clients {
                match client {
                    AuthClient::ServiceAccount { namespace, name } => {
                        client_sas.push((namespace.clone(), name.clone()));
                    }
                    AuthClient::MeshTls(auth_name) => {
                        // The MeshTLSAuthentication lives in the policy's namespace.
                        if let Some(auth) = snapshot
                            .linkerd_mtls_auths
                            .iter()
                            .find(|a| a.namespace == policy.namespace && &a.name == auth_name)
                        {
                            for sa in &auth.identities {
                                client_sas.push((sa.namespace.clone(), sa.name.clone()));
                            }
                        }
                    }
                }
            }

            let sources: Vec<&PodInfo> = pods
                .iter()
                .filter(|p| {
                    client_sas
                        .iter()
                        .any(|(ns, sa)| *ns == p.namespace && *sa == p.service_account)
                })
                .collect();

            for src in &sources {
                for tgt in &targets {
                    if src.namespace == tgt.namespace && src.name == tgt.name {
                        continue; // no self-edge
                    }
                    let s = graph.ensure_node(workload_node(&src.namespace, &src.name));
                    let t = graph.ensure_node(workload_node(&tgt.namespace, &tgt.name));
                    graph.add_edge(
                        s,
                        t,
                        observed(
                            self.name(),
                            Relation::Reaches {
                                port: server.port,
                                protocol: Protocol::Tcp,
                            },
                        ),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::test_support::*;
    use crate::engine::linkerd::{
        AuthClient, LinkerdAuthzPolicy, LinkerdMeshTlsAuth, LinkerdServer, ServiceAccountRef,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn label_selector(pairs: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            match_expressions: None,
        }
    }

    /// watcher-server (SA watcher-server) → watcher-db pods on 5432, authorized via a
    /// MeshTLSAuthentication — and NO NetworkPolicy, the real shape on the cluster.
    #[test]
    fn mints_reaches_from_linkerd_authz() {
        let server_pod = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "watcher-db-0", "namespace": "watcher",
                         "labels": {"application": "spilo", "cluster-name": "watcher-db"}},
            "spec": {"containers": [{"name": "db", "image": "spilo:1"}]}
        }));
        let client_pod = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "watcher-server-x", "namespace": "watcher", "labels": {"app": "watcher-server"}},
            "spec": {"serviceAccountName": "watcher-server", "containers": [{"name": "s", "image": "srv:1"}]}
        }));
        // An unrelated pod with a different SA must NOT get an edge.
        let other = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "stranger", "namespace": "watcher", "labels": {"app": "x"}},
            "spec": {"serviceAccountName": "stranger", "containers": [{"name": "c", "image": "x:1"}]}
        }));

        let snap = Snapshot {
            pods: vec![server_pod, client_pod, other],
            linkerd_servers: vec![LinkerdServer {
                namespace: "watcher".into(),
                name: "watcher-db".into(),
                pod_selector: label_selector(&[
                    ("application", "spilo"),
                    ("cluster-name", "watcher-db"),
                ]),
                port: Some(5432),
            }],
            linkerd_authz_policies: vec![LinkerdAuthzPolicy {
                namespace: "watcher".into(),
                target_server: Some("watcher-db".into()),
                clients: vec![AuthClient::MeshTls("watcher-db-clients".into())],
            }],
            linkerd_mtls_auths: vec![LinkerdMeshTlsAuth {
                namespace: "watcher".into(),
                name: "watcher-db-clients".into(),
                identities: vec![ServiceAccountRef {
                    namespace: "watcher".into(),
                    name: "watcher-server".into(),
                }],
            }],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let client = g
            .index_of(&workload_node("watcher", "watcher-server-x").key())
            .unwrap();
        let reaches: Vec<_> = g
            .inner()
            .edges(client)
            .filter_map(|e| match &e.weight().relation {
                Relation::Reaches { port, protocol } => Some((*port, *protocol)),
                _ => None,
            })
            .collect();
        assert_eq!(reaches, vec![(Some(5432), Protocol::Tcp)]);

        // The stranger SA is not authorized → no reaches edge.
        let stranger = g
            .index_of(&workload_node("watcher", "stranger").key())
            .unwrap();
        assert!(
            !g.inner()
                .edges(stranger)
                .any(|e| matches!(e.weight().relation, Relation::Reaches { .. })),
            "an unauthorized SA must not reach the Server"
        );
    }
}
