//! trivy-operator `ConfigAuditReport` → misconfiguration [`ScanFinding`]s on a workload
//! (a Vulnerability-port-adjacent adapter, ADR-0003; JEF-244).
//!
//! Same trust boundary as the `VulnerabilityReport` adapter ([`super::trivy`]): a pure
//! mapping from a `DynamicObject`'s `report` field into the graph's vocabulary, unit-tested
//! without a cluster. The report's `checks[]` are Kubernetes-config posture checks (a
//! hostPath mount, a missing `securityContext`, a privileged container) against the audited
//! resource. Only FAILED checks (`success: false`) are kept — a passing check is not
//! evidence. All free-text (`title`/`description`) is UNTRUSTED scanner output, fenced/
//! escaped downstream exactly as the CVE `title` is.
//!
//! The report is attributed to its resource by the labels trivy-operator stamps on the CR
//! (`trivy-operator.resource.namespace` / `.kind` / `.name`); the adapter resolves those to
//! the namespace + name a workload node is keyed by ([`WorkloadFindings`]). Best-effort: a
//! report whose resource can't be identified is skipped rather than guessed.

use kube::core::DynamicObject;
use serde_json::Value;

use super::{WorkloadFindings, report_resource, scan_finding};

/// This adapter's provenance source.
const SOURCE: &str = "trivy-config-audit";

/// Parse a trivy-operator `ConfigAuditReport`. The checks live under `report.checks`; the
/// audited resource is identified from the CR's `trivy-operator.resource.*` labels.
pub fn parse_report(object: &DynamicObject) -> Option<WorkloadFindings> {
    let resource = report_resource(object)?;
    let report = object.data.get("report")?;
    let findings = report
        .get("checks")
        .and_then(Value::as_array)
        // A config-audit check is keyed by `checkID`, falls back to `description` for its
        // title, and carries no `target`. The shared builder drops passing/id-less checks.
        .map(|items| {
            items
                .iter()
                .filter_map(|v| scan_finding(v, SOURCE, "checkID", "description"))
                .collect()
        })
        .unwrap_or_default();
    Some(WorkloadFindings { resource, findings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::Severity;
    use crate::engine::observe::WorkloadRef;
    use serde_json::json;

    fn object() -> DynamicObject {
        let mut o = DynamicObject {
            types: None,
            metadata: Default::default(),
            data: json!({
                "report": {
                    "checks": [
                        {
                            "checkID": "KSV017",
                            "severity": "HIGH",
                            "success": false,
                            "category": "Kubernetes Security Check",
                            "title": "Privileged container",
                            "description": "A privileged container can access host devices"
                        },
                        {"checkID": "KSV001", "severity": "LOW", "success": true},
                        {"checkID": "KSV014", "severity": "MEDIUM", "success": false},
                        {"severity": "HIGH", "success": false}
                    ]
                }
            }),
        };
        o.metadata.namespace = Some("app".into());
        o.metadata.labels = Some(
            [
                (
                    "trivy-operator.resource.kind".to_string(),
                    "Deployment".to_string(),
                ),
                (
                    "trivy-operator.resource.name".to_string(),
                    "web".to_string(),
                ),
            ]
            .into(),
        );
        o
    }

    #[test]
    fn maps_failed_checks_to_workload_findings() {
        let parsed = parse_report(&object()).expect("parses");
        assert_eq!(
            parsed.resource,
            WorkloadRef {
                namespace: "app".into(),
                kind: "Deployment".into(),
                name: "web".into()
            }
        );
        // The passing check (KSV001) and the check missing a checkID are skipped; two
        // failed-with-id checks remain.
        assert_eq!(parsed.findings.len(), 2);
        let f0 = &parsed.findings[0];
        assert_eq!(f0.id, "KSV017");
        assert_eq!(f0.severity, Severity::High);
        assert_eq!(f0.title.as_deref(), Some("Privileged container"));
        assert_eq!(f0.sources[0].source, SOURCE);
        assert_eq!(parsed.findings[1].id, "KSV014");
        // A failed check with no title falls back to None (no description either).
        assert_eq!(parsed.findings[1].title, None);
    }

    #[test]
    fn report_without_resource_labels_is_none() {
        let o = DynamicObject {
            types: None,
            metadata: Default::default(),
            data: json!({"report": {"checks": []}}),
        };
        assert!(parse_report(&o).is_none());
    }

    #[test]
    fn malformed_report_is_skipped_not_panicked() {
        let mut o = object();
        o.data = json!({"report": {"checks": "not-an-array"}});
        let parsed = parse_report(&o).expect("parses with no checks");
        assert!(parsed.findings.is_empty());
    }
}
