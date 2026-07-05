use petgraph::visit::EdgeRef;

use super::*;
use crate::engine::graph::{Behavior, SecretReadSource};

/// Attributes API secret-reads from the apiserver audit log (JEF-269) to the workloads
/// whose ServiceAccount made them — the corroborating runtime signal for a proven
/// `CanRead [RBAC-GRANTED]` chain that the eBPF agent can't observe (an API GET is a TLS
/// call to the apiserver, not a file read).
///
/// The audit event names the requesting **ServiceAccount**, not a pod. An SA may back many
/// pods, so this attaches the signal to **every** Workload that `RunsAs` that identity —
/// the ambiguity is represented honestly, never falsely narrowed to one pod. It reads the
/// structural `RunsAs` edges the [`WorkloadAdapter`] created, so it runs after it.
///
/// Attaching a [`Behavior::SecretRead`] with [`SecretReadSource::Api`] to the workload lets
/// the existing corroboration seam (`corroborates` — a SecretRead evidences a
/// CREDENTIAL_ACCESS objective) flip `corroborated-now` on the RBAC-granted chain, exactly
/// as a mounted read or an `Alert` does (the JEF-117 pattern). It is shadow-gated like
/// all corroboration: it only sets `corroborated`, never actuates.
pub struct AuditSecretReadAdapter;

impl Adapter for AuditSecretReadAdapter {
    fn name(&self) -> &'static str {
        "audit-secret-read"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        if snapshot.audit_secret_reads.is_empty() {
            return;
        }
        let (mut attached, mut unresolved) = (0usize, 0usize);
        for read in &snapshot.audit_secret_reads {
            let id_key = Node::Identity(Identity {
                namespace: read.sa_namespace.clone(),
                name: read.sa_name.clone(),
            })
            .key();
            let Some(id_idx) = graph.index_of(&id_key) else {
                // No modeled identity for this SA (no observed workload runs as it) — there
                // is nothing to corroborate. Drop it, don't invent a target.
                unresolved += 1;
                continue;
            };
            // Every Workload that runs as this identity: the incoming `RunsAs` edges. An SA
            // → many pods, so all of them get the signal (honest ambiguity, JEF-269).
            let workloads: Vec<NodeKey> = graph
                .inner()
                .edges_directed(id_idx, petgraph::Direction::Incoming)
                .filter(|e| matches!(e.weight().relation, Relation::RunsAs))
                .filter_map(|e| graph.inner().node_weight(e.source()).map(Node::key))
                .collect();
            if workloads.is_empty() {
                unresolved += 1;
                continue;
            }
            let behavior = Behavior::SecretRead {
                secret: read.secret_display(),
                source: SecretReadSource::Api,
            };
            for wl_key in workloads {
                graph.update_node(&wl_key, |node| {
                    if let Node::Workload(w) = node {
                        w.runtime.push(RuntimeSignal {
                            behavior: behavior.clone(),
                            // The audit log is the sensor. Ingest-time is stamped (the
                            // apiserver's event timestamp is RFC3339 — parsing it is a
                            // follow-up; the TTL store already windows on receipt).
                            provenance: Provenance::new("k8s-audit", SystemTime::now()),
                        });
                        attached += 1;
                    }
                });
            }
        }
        tracing::info!(
            attached,
            unresolved,
            reads = snapshot.audit_secret_reads.len(),
            "audit API secret-read signals"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::attack::CREDENTIAL_ACCESS;
    use crate::engine::observe::adapter::test_support::pod;
    use crate::engine::observe::{AuditSecretRead, SecretMeta, Snapshot};
    use crate::engine::reason::proof::prove;
    use serde_json::json;

    /// A pod `app/web` running as ServiceAccount `reader-sa`, an RBAC Role granting that SA
    /// `get secrets`, and the secret it can read — the proven `CanRead [RBAC-GRANTED]`
    /// chain the audit signal is meant to corroborate.
    fn rbac_granted_snapshot(audit: Vec<AuditSecretRead>) -> Snapshot {
        let web = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {
                "serviceAccountName": "reader-sa",
                "containers": [{"name": "web", "image": "web:1"}]
            }
        }));
        let role: k8s_openapi::api::rbac::v1::Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "secret-reader", "namespace": "app"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        }))
        .unwrap();
        let binding: k8s_openapi::api::rbac::v1::RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "reader-binding", "namespace": "app"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "secret-reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "reader-sa", "namespace": "app"}]
        }))
        .unwrap();
        Snapshot {
            pods: vec![web],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "db-creds".into(),
            }],
            roles: vec![role],
            role_bindings: vec![binding],
            audit_secret_reads: audit,
            ..Default::default()
        }
    }

    fn read(sa_ns: &str, sa: &str, secret_ns: &str, secret: &str) -> AuditSecretRead {
        AuditSecretRead {
            sa_namespace: sa_ns.into(),
            sa_name: sa.into(),
            secret_namespace: Some(secret_ns.into()),
            secret_name: Some(secret.into()),
            verb: "get".into(),
        }
    }

    /// The runtime signals attached to workload `app/web` after the full adapter pipeline.
    fn web_signals(snap: Snapshot) -> Vec<Behavior> {
        let graph = super::super::build_graph(&snap, &super::super::default_adapters());
        let idx = graph
            .index_of(&workload_node("app", "web").key())
            .expect("web workload");
        match graph.node(idx) {
            Some(Node::Workload(w)) => w.runtime.iter().map(|s| s.behavior.clone()).collect(),
            _ => panic!("expected workload"),
        }
    }

    #[test]
    fn api_read_attaches_to_the_workload_running_as_the_sa() {
        let signals = web_signals(rbac_granted_snapshot(vec![read(
            "app",
            "reader-sa",
            "app",
            "db-creds",
        )]));
        assert_eq!(
            signals,
            vec![Behavior::SecretRead {
                secret: "app/db-creds".into(),
                source: SecretReadSource::Api,
            }]
        );
    }

    #[test]
    fn api_read_corroborates_the_rbac_granted_chain_end_to_end() {
        // The acceptance case: an allowed `get secrets` audit event on a workload's SA flips
        // corroborated-now on that entry's RBAC-granted credential-access chain to the secret.
        let snap = rbac_granted_snapshot(vec![read("app", "reader-sa", "app", "db-creds")]);
        let chains = prove(&super::super::build_graph(
            &snap,
            &super::super::default_adapters(),
        ));
        let chain = chains
            .iter()
            .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/db-creds")
            .expect("web → secret RBAC chain");
        assert_eq!(chain.attack, CREDENTIAL_ACCESS);
        assert!(
            chain.corroborated,
            "an API secret-read corroborates the RBAC-granted credential-access chain"
        );
    }

    #[test]
    fn a_read_for_an_unmodeled_sa_corroborates_nothing() {
        // An audit read attributed to an SA no observed workload runs as has no target — it
        // must be dropped, never invent a corroboration.
        let signals = web_signals(rbac_granted_snapshot(vec![read(
            "app", "other-sa", "app", "db-creds",
        )]));
        assert!(signals.is_empty(), "no workload runs as other-sa");
    }

    #[test]
    fn an_sa_backing_many_pods_corroborates_all_of_them_not_one() {
        // Honest ambiguity (JEF-269): when two pods share the SA, the API read — which names
        // only the SA — attaches to BOTH, since audit can't disambiguate which pod called.
        let mut snap = rbac_granted_snapshot(vec![read("app", "reader-sa", "app", "db-creds")]);
        snap.pods.push(pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web-2", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"serviceAccountName": "reader-sa", "containers": [{"name": "web", "image": "web:1"}]}
        })));
        let graph = super::super::build_graph(&snap, &super::super::default_adapters());
        for pod_name in ["web", "web-2"] {
            let idx = graph
                .index_of(&workload_node("app", pod_name).key())
                .expect("workload");
            let Some(Node::Workload(w)) = graph.node(idx) else {
                panic!("expected workload");
            };
            assert!(
                w.runtime.iter().any(|s| matches!(
                    &s.behavior,
                    Behavior::SecretRead {
                        source: SecretReadSource::Api,
                        ..
                    }
                )),
                "{pod_name} should carry the API secret-read signal"
            );
        }
    }
}
