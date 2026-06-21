//! trivy-operator `VulnerabilityReport` → normalized [`ImageVulnerabilities`] (a
//! Vulnerability-port adapter, ADR-0003).
//!
//! The cluster-facing list lives in [`super`]; this module is the pure
//! mapping from a report's JSON into the graph's vocabulary, so it is unit-tested
//! without a cluster. trivy reports vulnerability *presence and severity*;
//! `exploited_in_wild` stays `false` here — that predicate is the ExploitIntel
//! port's job (a CISA KEV lookup), which enriches the same nodes.

use std::time::SystemTime;

use kube::core::DynamicObject;
use serde_json::Value;

use super::ImageVulnerabilities;
use crate::engine::graph::{Provenance, Reachability, Severity, Vulnerability};

/// Parse a trivy-operator `VulnerabilityReport` object. The report payload lives
/// under the top-level `report` field.
pub fn parse_report(object: &DynamicObject) -> Option<ImageVulnerabilities> {
    from_report(object.data.get("report")?)
}

/// A non-empty string field from a report entry, or `None`. Empty strings (trivy
/// omits a fix by emitting `""`, not by dropping the key) collapse to `None`.
fn opt_str(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn severity(label: &str) -> Severity {
    match label {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Reconstruct the deployed image reference (`server/repository:tag`) so the
/// finding lands on the right Image node. Best-effort: digest-level matching would
/// be canonical, but the report's artifact fields are what we have.
fn image_ref(report: &Value) -> Option<String> {
    let artifact = report.get("artifact")?;
    let repository = artifact.get("repository")?.as_str()?;
    let base = match report
        .get("registry")
        .and_then(|r| r.get("server"))
        .and_then(Value::as_str)
    {
        Some(server) => format!("{server}/{repository}"),
        None => repository.to_string(),
    };
    Some(match artifact.get("tag").and_then(Value::as_str) {
        Some(tag) => format!("{base}:{tag}"),
        None => base,
    })
}

fn from_report(report: &Value) -> Option<ImageVulnerabilities> {
    let image = image_ref(report)?;
    let vulnerabilities = report
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| {
                    Some(Vulnerability {
                        id: v.get("vulnerabilityID")?.as_str()?.to_string(),
                        severity: severity(
                            v.get("severity").and_then(Value::as_str).unwrap_or("LOW"),
                        ),
                        // trivy gives presence + severity; KEV/EPSS is ExploitIntel.
                        exploited_in_wild: false,
                        epss: None,
                        sources: vec![Provenance::new("trivy", SystemTime::now())],
                        // Package coordinates (trivy-operator field names): `resource`
                        // is the package name, `installedVersion`/`fixedVersion` the
                        // versions. `pkg_name` drives the JEF-51 runtime correlation.
                        pkg_name: opt_str(v, "resource"),
                        installed_version: opt_str(v, "installedVersion"),
                        fixed_version: opt_str(v, "fixedVersion"),
                        // Reachability is correlated later (ReachabilityAdapter); the
                        // scanner alone never asserts it.
                        reachability: Reachability::Unknown,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ImageVulnerabilities {
        image,
        vulnerabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_report_image_and_vulnerabilities() {
        let report = json!({
            "registry": {"server": "ghcr.io"},
            "artifact": {"repository": "thejefflarson/api", "tag": "1.2.3"},
            "vulnerabilities": [
                {
                    "vulnerabilityID": "CVE-2026-1", "severity": "CRITICAL",
                    "resource": "log4j-core",
                    "installedVersion": "2.14.0", "fixedVersion": "2.17.0"
                },
                {"vulnerabilityID": "CVE-2026-2", "severity": "LOW",
                 "resource": "zlib", "installedVersion": "1.2.11", "fixedVersion": ""},
                {"severity": "HIGH"}
            ]
        });
        let parsed = from_report(&report).expect("parses");
        assert_eq!(parsed.image, "ghcr.io/thejefflarson/api:1.2.3");
        // The entry missing a vulnerabilityID is skipped.
        assert_eq!(parsed.vulnerabilities.len(), 2);
        let v0 = &parsed.vulnerabilities[0];
        assert_eq!(v0.id, "CVE-2026-1");
        assert_eq!(v0.severity, Severity::Critical);
        // trivy alone never asserts active exploitation.
        assert!(!v0.exploited_in_wild);
        // Package coordinates are now preserved (JEF-51).
        assert_eq!(v0.pkg_name.as_deref(), Some("log4j-core"));
        assert_eq!(v0.installed_version.as_deref(), Some("2.14.0"));
        assert_eq!(v0.fixed_version.as_deref(), Some("2.17.0"));
        // Reachability is not asserted by the scanner — it starts Unknown.
        assert_eq!(v0.reachability, Reachability::Unknown);
        // An empty fixedVersion ("" = no fix yet) collapses to None.
        assert_eq!(parsed.vulnerabilities[1].fixed_version, None);
        assert_eq!(parsed.vulnerabilities[1].pkg_name.as_deref(), Some("zlib"));
    }

    #[test]
    fn report_without_artifact_is_none() {
        assert!(from_report(&json!({"vulnerabilities": []})).is_none());
    }
}
