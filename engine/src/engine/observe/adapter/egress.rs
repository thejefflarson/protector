use super::*;

/// The annotation that declares a workload has an internet-egress channel (ADR-0012
/// mirror of the ingress [`EXPOSURE_ANNOTATION`]) — used when egress can't be observed
/// from in-cluster objects (e.g. a tunnel/sidecar that ships data out).
pub(super) const EGRESS_ANNOTATION: &str = "protector.jeffl.es/egress";

/// `can-egress` edges from a workload to the shared `internet` endpoint — an
/// **exfiltration channel** (ATT&CK T1041): a compromise there can ship accessed data
/// out of the cluster. Set only on an EXPLICIT internet-egress posture: a declared
/// [`EGRESS_ANNOTATION`], or a NetworkPolicy egress rule allowing `0.0.0.0/0` (`::/0`).
///
/// Deliberately conservative. Most workloads have no egress NetworkPolicy at all
/// (default-allow), so inferring egress from a *missing* policy would flag everything
/// and make exfil meaningless. Requiring an explicit signal keeps an exfil channel a
/// real distinguisher — and pairs with the compromise gate (ADR-0002): the attacker
/// must control the egress workload to use its channel.
pub struct EgressAdapter;

impl EgressAdapter {
    fn declares_egress(annotations: Option<&BTreeMap<String, String>>) -> bool {
        annotations
            .and_then(|a| a.get(EGRESS_ANNOTATION))
            .is_some_and(|v| v.eq_ignore_ascii_case("internet"))
    }

    fn is_open_cidr(cidr: &str) -> bool {
        cidr == "0.0.0.0/0" || cidr == "::/0"
    }

    /// True if some NetworkPolicy in `ns` selects `labels`, declares Egress, and has an
    /// egress rule allowing an open (internet) ipBlock.
    fn open_egress(snapshot: &Snapshot, ns: &str, labels: &BTreeMap<String, String>) -> bool {
        snapshot.network_policies.iter().any(|policy| {
            if policy.metadata.namespace.as_deref() != Some(ns) {
                return false;
            }
            let Some(spec) = &policy.spec else {
                return false;
            };
            let egress_active = match &spec.policy_types {
                Some(types) => types.iter().any(|t| t == "Egress"),
                None => spec.egress.is_some(),
            };
            if !egress_active || !selector_matches_opt(&spec.pod_selector, labels) {
                return false;
            }
            spec.egress.iter().flatten().any(|rule| {
                rule.to.iter().flatten().any(|peer| {
                    peer.ip_block
                        .as_ref()
                        .is_some_and(|b| Self::is_open_cidr(&b.cidr))
                })
            })
        })
    }
}

impl Adapter for EgressAdapter {
    fn name(&self) -> &'static str {
        "egress"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let ns = pod_namespace(pod);
            let labels = pod_labels(pod);
            let via = if Self::declares_egress(pod.metadata.annotations.as_ref()) {
                "annotation"
            } else if Self::open_egress(snapshot, &ns, &labels) {
                "egress-0.0.0.0/0"
            } else {
                continue;
            };
            let wl = graph.ensure_node(workload_node(&ns, &name));
            let net = graph.ensure_node(Node::Endpoint(Endpoint {
                address: "internet".to_string(),
            }));
            graph.add_edge(
                wl,
                net,
                observed(
                    self.name(),
                    Relation::CanEgress {
                        via: via.to_string(),
                    },
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use serde_json::json;

    #[test]
    fn declared_and_open_egress_make_an_exfil_channel() {
        let declared = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "tunneled", "namespace": "app",
                         "annotations": {"protector.jeffl.es/egress": "internet"}},
            "spec": {"containers": [{"name": "c", "image": "c:1"}]}
        }));
        // A pod with no egress signal — must NOT get an exfil edge (default-allow is
        // not modeled as egress; that would flag everything).
        let plain = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "plain", "namespace": "app", "labels": {"role": "x"}},
            "spec": {"containers": [{"name": "c", "image": "c:1"}]}
        }));
        let snap = Snapshot {
            pods: vec![declared, plain],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let egress_of = |name: &str| {
            let idx = g.index_of(&workload_node("app", name).key()).unwrap();
            g.inner()
                .edges(idx)
                .any(|e| matches!(e.weight().relation, Relation::CanEgress { .. }))
        };
        assert!(egress_of("tunneled"), "declared egress → exfil channel");
        assert!(!egress_of("plain"), "no egress signal → no exfil channel");
        // The shared internet endpoint exists and is the exfil objective node.
        assert!(
            g.index_of(
                &Node::Endpoint(Endpoint {
                    address: "internet".into()
                })
                .key()
            )
            .is_some()
        );
    }
}
