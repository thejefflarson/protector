use super::*;

/// `reaches` edges granted by NetworkPolicy **ingress** rules.
///
/// Documented subset: same-namespace `podSelector` peers only. A policy's targets
/// are the pods its `podSelector` matches; for each ingress rule, each `from` peer
/// that uses a `podSelector` (and neither `namespaceSelector` nor `ipBlock`)
/// contributes `reaches` edges from the matched source pods to the target pods.
/// `namespaceSelector`, `ipBlock`, default-allow (no policy), and `matchExpressions`
/// are not yet modeled — so this captures declared in-namespace allow-lists, not
/// the full reachability closure.
pub struct ReachabilityAdapter;

impl ReachabilityAdapter {
    fn ingress_active(policy: &NetworkPolicy) -> bool {
        let Some(spec) = &policy.spec else {
            return false;
        };
        match &spec.policy_types {
            Some(types) => types.iter().any(|t| t == "Ingress"),
            None => spec.ingress.is_some(),
        }
    }

    fn ports(
        rule_ports: Option<&Vec<k8s_openapi::api::networking::v1::NetworkPolicyPort>>,
    ) -> Vec<(Option<u16>, Protocol)> {
        let Some(ports) = rule_ports.filter(|p| !p.is_empty()) else {
            return vec![(None, Protocol::Tcp)];
        };
        ports
            .iter()
            .map(|p| {
                let protocol = match p.protocol.as_deref() {
                    Some("UDP") => Protocol::Udp,
                    _ => Protocol::Tcp,
                };
                let port = match &p.port {
                    Some(IntOrString::Int(n)) => u16::try_from(*n).ok(),
                    _ => None,
                };
                (port, protocol)
            })
            .collect()
    }
}

impl Adapter for ReachabilityAdapter {
    fn name(&self) -> &'static str {
        "networkpolicy"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Index pods by namespace with their labels, for selector matching.
        let pods: Vec<(String, String, BTreeMap<String, String>)> = snapshot
            .pods
            .iter()
            .filter_map(|p| {
                p.metadata
                    .name
                    .clone()
                    .map(|n| (pod_namespace(p), n, pod_labels(p)))
            })
            .collect();

        for policy in &snapshot.network_policies {
            if !Self::ingress_active(policy) {
                continue;
            }
            let Some(spec) = &policy.spec else { continue };
            // A target selector using matchExpressions is under-matched by
            // selector_matches, so the edges we derive may be incomplete.
            if spec
                .pod_selector
                .as_ref()
                .is_some_and(has_match_expressions)
            {
                graph.mark_reachability_incomplete();
            }
            let ns = policy
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());

            let targets: Vec<&(String, String, BTreeMap<String, String>)> = pods
                .iter()
                .filter(|(pns, _, labels)| {
                    *pns == ns && selector_matches_opt(&spec.pod_selector, labels)
                })
                .collect();
            if targets.is_empty() {
                continue;
            }

            for rule in spec.ingress.iter().flatten() {
                let port_specs = Self::ports(rule.ports.as_ref());
                for peer in rule.from.iter().flatten() {
                    // Documented subset: podSelector-only peers in the same namespace.
                    // A namespaceSelector/ipBlock peer is a reachability path we don't
                    // model — flag the graph incomplete so the actuation gate fails safe.
                    if peer.namespace_selector.is_some() || peer.ip_block.is_some() {
                        graph.mark_reachability_incomplete();
                        continue;
                    }
                    let Some(peer_selector) = &peer.pod_selector else {
                        continue;
                    };
                    if has_match_expressions(peer_selector) {
                        graph.mark_reachability_incomplete();
                    }
                    let sources: Vec<&(String, String, BTreeMap<String, String>)> = pods
                        .iter()
                        .filter(|(pns, _, labels)| {
                            *pns == ns && selector_matches(peer_selector, labels)
                        })
                        .collect();

                    for (sns, sname, _) in &sources {
                        for (tns, tname, _) in &targets {
                            if sns == tns && sname == tname {
                                continue; // no self-edge
                            }
                            let src = graph.ensure_node(workload_node(sns, sname));
                            let tgt = graph.ensure_node(workload_node(tns, tname));
                            for (port, protocol) in &port_specs {
                                graph.add_edge(
                                    src,
                                    tgt,
                                    observed(
                                        self.name(),
                                        Relation::Reaches {
                                            port: *port,
                                            protocol: *protocol,
                                        },
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use serde_json::{Value, json};

    fn netpol(value: Value) -> NetworkPolicy {
        serde_json::from_value(value).expect("valid NetworkPolicy fixture")
    }

    #[test]
    fn reachability_adapter_emits_declared_ingress_edges() {
        let pods = vec![
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
                "spec": {"containers": [{"name": "web", "image": "web:1"}]}
            })),
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
                "spec": {"containers": [{"name": "db", "image": "db:1"}]}
            })),
        ];
        // Allow web → db on TCP 5432.
        let policy = netpol(json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-ingress", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": "db"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"role": "web"}}}],
                    "ports": [{"protocol": "TCP", "port": 5432}]
                }]
            }
        }));
        let snap = Snapshot {
            pods,
            network_policies: vec![policy],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let web = g.index_of(&workload_node("app", "web").key()).unwrap();
        let reaches: Vec<_> = g
            .inner()
            .edges(web)
            .filter_map(|e| match &e.weight().relation {
                Relation::Reaches { port, protocol } => Some((*port, *protocol)),
                _ => None,
            })
            .collect();
        assert_eq!(reaches, vec![(Some(5432), Protocol::Tcp)]);

        // Regression: the ReachabilityAdapter references web/db as edge endpoints
        // via `ensure_node`, which must NOT clobber the labels the workload builder
        // set — the network actuator needs them to render a pod-scoped selector.
        let labels = match g.node(web) {
            Some(Node::Workload(w)) => w.labels.clone(),
            _ => panic!("web is a workload"),
        };
        assert_eq!(labels.get("role").map(String::as_str), Some("web"));
        let db = g.index_of(&workload_node("app", "db").key()).unwrap();
        assert!(matches!(
            g.node(db),
            Some(Node::Workload(w)) if w.labels.get("role").map(String::as_str) == Some("db")
        ));
    }
}
