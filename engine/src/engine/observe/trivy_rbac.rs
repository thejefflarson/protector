//! trivy-operator `RbacAssessmentReport` → RBAC-exposure [`ScanFinding`]s (a
//! Vulnerability-port-adjacent adapter, ADR-0003; JEF-244).
//!
//! Same trust boundary and pure-mapping discipline as the other trivy adapters. The report
//! assesses a Role / ClusterRole's `checks[]` (a role granting `*` verbs, wildcard secret
//! access, escalate/bind/impersonate). Only FAILED checks (`success: false`) are kept.
//!
//! These findings INFORM the model's existing authorization reasoning — JEF-79 already
//! reasons about RBAC-authorized breadth from the privilege graph — so they are surfaced as
//! structural EVIDENCE (severity/context), NOT re-implemented as a parallel authorization
//! computation and NOT counted as exploitation evidence. The report names the assessed Role
//! by the `trivy-operator.resource.*` labels; the finding is attributed to the workloads in
//! that role's namespace (a cluster-scoped ClusterRole report has no namespace, so it is
//! skipped — it has no single workload to attach to, and double-counting cluster RBAC is
//! exactly what JEF-79 already owns).

use std::time::SystemTime;

use kube::core::DynamicObject;
use serde_json::Value;

use super::{RbacFindings, opt_str, report_resource, severity};
use crate::engine::graph::{Provenance, ScanFinding};

/// This adapter's provenance source.
const SOURCE: &str = "trivy-rbac";

/// Parse a trivy-operator `RbacAssessmentReport`. The checks live under `report.checks`; the
/// assessed Role is identified from the CR's `trivy-operator.resource.*` labels. A
/// namespace-less (cluster-scoped) report is skipped — see the module note.
pub fn parse_report(object: &DynamicObject) -> Option<RbacFindings> {
    let resource = report_resource(object)?;
    let report = object.data.get("report")?;
    let findings = report
        .get("checks")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(check_finding).collect())
        .unwrap_or_default();
    Some(RbacFindings {
        namespace: resource.namespace,
        findings,
    })
}

/// Map one FAILED `checks[]` entry into a [`ScanFinding`]. Identical check shape to the
/// config-audit report; a passing or id-less check is dropped.
fn check_finding(value: &Value) -> Option<ScanFinding> {
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let id = opt_str(value, "checkID")?;
    let title = opt_str(value, "title").or_else(|| opt_str(value, "description"));
    Some(ScanFinding {
        id,
        severity: severity(
            value
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("LOW"),
        ),
        category: opt_str(value, "category"),
        title,
        target: opt_str(value, "target"),
        sources: vec![Provenance::new(SOURCE, SystemTime::now())],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::Severity;
    use serde_json::json;

    fn object(namespace: Option<&str>) -> DynamicObject {
        let mut o = DynamicObject {
            types: None,
            metadata: Default::default(),
            data: json!({
                "report": {
                    "checks": [
                        {
                            "checkID": "KSV041",
                            "severity": "CRITICAL",
                            "success": false,
                            "category": "Kubernetes Security Check",
                            "title": "Manage secrets",
                            "target": "Role/app-admin"
                        },
                        {"checkID": "KSV042", "severity": "HIGH", "success": true}
                    ]
                }
            }),
        };
        o.metadata.namespace = namespace.map(str::to_string);
        let mut labels = vec![
            (
                "trivy-operator.resource.kind".to_string(),
                "Role".to_string(),
            ),
            (
                "trivy-operator.resource.name".to_string(),
                "app-admin".to_string(),
            ),
        ];
        if let Some(ns) = namespace {
            labels.push((
                "trivy-operator.resource.namespace".to_string(),
                ns.to_string(),
            ));
        }
        o.metadata.labels = Some(labels.into_iter().collect());
        o
    }

    #[test]
    fn maps_failed_role_checks_to_namespace_findings() {
        let parsed = parse_report(&object(Some("app"))).expect("parses");
        assert_eq!(parsed.namespace, "app");
        // Only the failed check with an id is kept (the passing KSV042 is dropped).
        assert_eq!(parsed.findings.len(), 1);
        let f = &parsed.findings[0];
        assert_eq!(f.id, "KSV041");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.title.as_deref(), Some("Manage secrets"));
        assert_eq!(f.target.as_deref(), Some("Role/app-admin"));
        assert_eq!(f.sources[0].source, SOURCE);
    }

    #[test]
    fn cluster_scoped_report_with_no_namespace_is_skipped() {
        // A ClusterRole assessment has no namespace; JEF-79 already owns cluster RBAC, so the
        // adapter skips it rather than double-counting (report_resource returns None).
        assert!(parse_report(&object(None)).is_none());
    }

    #[test]
    fn malformed_report_is_skipped_not_panicked() {
        let mut o = object(Some("app"));
        o.data = json!({});
        assert!(parse_report(&o).is_none());
    }
}
