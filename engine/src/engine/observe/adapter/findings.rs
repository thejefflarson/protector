//! Scan-finding enrichment adapters for the other trivy-operator report kinds (JEF-244):
//! exposed secrets onto Images, config-audit misconfigurations and RBAC-assessment findings
//! onto Workloads. Like the [`VulnerabilityAdapter`](super::VulnerabilityAdapter), these
//! enrich nodes the structural adapters already built, so they run last. Each maps the
//! normalized [`ScanFinding`]s the observer listed onto the matching node; the report→graph
//! parsing itself is unit-tested in the `observe::trivy_*` modules.

use super::*;
use crate::engine::graph::ScanFinding;

/// Attaches exposed-secret findings to Image nodes (JEF-244). Secrets are baked into the
/// IMAGE, so — exactly like [`VulnerabilityAdapter`](super::VulnerabilityAdapter) — the
/// finding is canonicalized to the Image key the workload adapter built and lands there,
/// shared by every workload running that digest.
pub struct ExposedSecretAdapter;

impl Adapter for ExposedSecretAdapter {
    fn name(&self) -> &'static str {
        "exposed-secret"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for finding in &snapshot.image_secrets {
            let key = NodeKey::image(&canonical_image(&finding.image));
            graph.update_node(&key, |node| {
                if let Node::Image(img) = node {
                    img.exposed_secrets = finding.findings.clone();
                }
            });
        }
    }
}

/// Attaches config-audit misconfiguration findings to Workload nodes (JEF-244). The report
/// names its audited resource by `trivy-operator.resource.*`; the graph models workloads as
/// Pods, so a report targeting a Pod attaches directly, and a report targeting a controller
/// (Deployment/DaemonSet/…) attaches to every Pod in that namespace whose name the
/// controller's name PREFIXES (a ReplicaSet/Pod is `<controller>-<hash>`). Best-effort
/// owner correlation without an owner-reference walk (out of scope, JEF-244 notes); a Pod
/// report is the exact case.
pub struct ConfigAuditAdapter;

impl Adapter for ConfigAuditAdapter {
    fn name(&self) -> &'static str {
        "config-audit"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for report in &snapshot.config_audits {
            for key in matching_workloads(graph, &report.resource.namespace, &report.resource) {
                attach_misconfigs(graph, &key, &report.findings);
            }
        }
    }
}

/// Attaches RBAC-assessment findings to the Workload nodes in the report's namespace
/// (JEF-244). A namespaced `RbacAssessmentReport` assesses a Role used within one namespace;
/// the finding is surfaced on that namespace's workloads as structural RBAC-exposure
/// EVIDENCE that informs the model's JEF-79 authorization reasoning — it does not
/// re-implement or double-count it. (Cluster-scoped reports are dropped upstream.)
pub struct RbacAssessmentAdapter;

impl Adapter for RbacAssessmentAdapter {
    fn name(&self) -> &'static str {
        "rbac-assessment"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for report in &snapshot.rbac_assessments {
            for key in workloads_in_namespace(graph, &report.namespace) {
                graph.update_node(&key, |node| {
                    if let Node::Workload(w) = node {
                        w.rbac_findings = report.findings.clone();
                    }
                });
            }
        }
    }
}

/// Set a workload's misconfiguration findings (overwrite, mirroring how the vulnerability
/// adapter replaces a node's vuln list each pass).
fn attach_misconfigs(graph: &mut SecurityGraph, key: &NodeKey, findings: &[ScanFinding]) {
    graph.update_node(key, |node| {
        if let Node::Workload(w) = node {
            w.misconfigs = findings.to_vec();
        }
    });
}

/// The Workload node keys a config-audit report's resource maps to. A `Pod` report matches
/// the Pod of that exact name; any controller kind matches every Pod in the namespace whose
/// name begins with `<controller-name>-` (the ReplicaSet/Pod naming rule), the conservative
/// best-effort attachment without an owner-reference walk.
fn matching_workloads(
    graph: &SecurityGraph,
    namespace: &str,
    resource: &crate::engine::observe::WorkloadRef,
) -> Vec<NodeKey> {
    if resource.kind == "Pod" {
        let key = NodeKey::workload(namespace, "Pod", &resource.name);
        return if graph.index_of(&key).is_some() {
            vec![key]
        } else {
            Vec::new()
        };
    }
    let prefix = format!("{}-", resource.name);
    workloads_in_namespace(graph, namespace)
        .into_iter()
        .filter(|k| k.name().is_some_and(|n| n.starts_with(&prefix)))
        .collect()
}

/// Every Workload node key in `namespace`.
fn workloads_in_namespace(graph: &SecurityGraph, namespace: &str) -> Vec<NodeKey> {
    let g = graph.inner();
    g.node_indices()
        .filter_map(|idx| match g.node_weight(idx) {
            Some(node @ Node::Workload(w)) if w.namespace == namespace => Some(node.key()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::{Provenance, Severity};
    use crate::engine::observe::{
        ImageScanFindings, RbacFindings, Snapshot, WorkloadFindings, WorkloadRef,
    };
    use std::time::SystemTime;

    fn finding(id: &str, severity: Severity) -> ScanFinding {
        ScanFinding {
            id: id.into(),
            severity,
            category: None,
            title: Some(format!("{id} title")),
            target: None,
            sources: vec![Provenance::new("trivy-test", SystemTime::UNIX_EPOCH)],
        }
    }

    fn workload_pod(namespace: &str, name: &str, image: &str) -> Snapshot {
        Snapshot {
            pods: vec![
                serde_json::from_value(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {"containers": [{"name": "c", "image": image}]}
                }))
                .expect("valid pod"),
            ],
            ..Default::default()
        }
    }

    fn graph_for(snap: &Snapshot) -> SecurityGraph {
        let mut g = SecurityGraph::new();
        WorkloadAdapter.contribute(snap, &mut g);
        g
    }

    #[test]
    fn exposed_secret_attaches_to_the_image_node() {
        let snap = Snapshot {
            image_secrets: vec![ImageScanFindings {
                image: "ghcr.io/app/api:1".into(),
                findings: vec![finding("aws-access-key-id", Severity::Critical)],
            }],
            ..workload_pod("app", "api", "ghcr.io/app/api:1")
        };
        let mut g = graph_for(&snap);
        ExposedSecretAdapter.contribute(&snap, &mut g);
        let key = NodeKey::workload("app", "Pod", "api");
        let (secrets, _, _) = g.entry_findings(&key);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].id, "aws-access-key-id");
    }

    #[test]
    fn config_audit_attaches_to_a_pod_by_exact_name() {
        let snap = Snapshot {
            config_audits: vec![WorkloadFindings {
                resource: WorkloadRef {
                    namespace: "app".into(),
                    kind: "Pod".into(),
                    name: "api".into(),
                },
                findings: vec![finding("KSV017", Severity::High)],
            }],
            ..workload_pod("app", "api", "ghcr.io/app/api:1")
        };
        let mut g = graph_for(&snap);
        ConfigAuditAdapter.contribute(&snap, &mut g);
        let (_, misconfigs, _) = g.entry_findings(&NodeKey::workload("app", "Pod", "api"));
        assert_eq!(misconfigs.len(), 1);
        assert_eq!(misconfigs[0].id, "KSV017");
    }

    #[test]
    fn config_audit_attaches_to_controller_pods_by_name_prefix() {
        // A Deployment report attaches to its ReplicaSet/Pod children (`web-<hash>-<hash>`).
        let snap = Snapshot {
            config_audits: vec![WorkloadFindings {
                resource: WorkloadRef {
                    namespace: "app".into(),
                    kind: "Deployment".into(),
                    name: "web".into(),
                },
                findings: vec![finding("KSV014", Severity::Medium)],
            }],
            ..workload_pod("app", "web-7d9-abc", "ghcr.io/app/web:1")
        };
        let mut g = graph_for(&snap);
        ConfigAuditAdapter.contribute(&snap, &mut g);
        let (_, misconfigs, _) = g.entry_findings(&NodeKey::workload("app", "Pod", "web-7d9-abc"));
        assert_eq!(misconfigs.len(), 1, "controller report reaches its pod");
    }

    #[test]
    fn config_audit_does_not_cross_namespaces_or_unrelated_pods() {
        let snap = Snapshot {
            config_audits: vec![WorkloadFindings {
                resource: WorkloadRef {
                    namespace: "app".into(),
                    kind: "Deployment".into(),
                    name: "web".into(),
                },
                findings: vec![finding("KSV014", Severity::Medium)],
            }],
            ..workload_pod("app", "api-xyz", "ghcr.io/app/api:1")
        };
        let mut g = graph_for(&snap);
        ConfigAuditAdapter.contribute(&snap, &mut g);
        // `api-xyz` does not start with `web-`, so it gets nothing.
        let (_, misconfigs, _) = g.entry_findings(&NodeKey::workload("app", "Pod", "api-xyz"));
        assert!(misconfigs.is_empty());
    }

    #[test]
    fn rbac_assessment_attaches_to_namespace_workloads() {
        let snap = Snapshot {
            rbac_assessments: vec![RbacFindings {
                namespace: "app".into(),
                findings: vec![finding("KSV041", Severity::Critical)],
            }],
            ..workload_pod("app", "api", "ghcr.io/app/api:1")
        };
        let mut g = graph_for(&snap);
        RbacAssessmentAdapter.contribute(&snap, &mut g);
        let (_, _, rbac) = g.entry_findings(&NodeKey::workload("app", "Pod", "api"));
        assert_eq!(rbac.len(), 1);
        assert_eq!(rbac[0].id, "KSV041");
    }

    #[test]
    fn absent_reports_attach_nothing() {
        let snap = workload_pod("app", "api", "ghcr.io/app/api:1");
        let mut g = graph_for(&snap);
        ExposedSecretAdapter.contribute(&snap, &mut g);
        ConfigAuditAdapter.contribute(&snap, &mut g);
        RbacAssessmentAdapter.contribute(&snap, &mut g);
        let (s, m, r) = g.entry_findings(&NodeKey::workload("app", "Pod", "api"));
        assert!(s.is_empty() && m.is_empty() && r.is_empty());
    }
}
