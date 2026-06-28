//! trivy-operator `ExposedSecretReport` → exposed-secret [`ScanFinding`]s on an Image
//! (a Vulnerability-port-adjacent adapter, ADR-0003; JEF-244).
//!
//! Same trust boundary as the `VulnerabilityReport` adapter ([`super::trivy`]): a pure
//! mapping from a `DynamicObject`'s `report` field into the graph's vocabulary, unit-tested
//! without a cluster. The report flags secrets baked into the IMAGE (an AWS key, a private
//! key, a token committed into the layers) — a real breach primitive, so the findings land
//! on the Image node alongside its CVEs and are shared by every workload on that digest.
//!
//! REDACTION GUARANTEE (JEF-244): only trivy's `ruleID`, `category`, `severity`, target
//! path, and the already-**redacted** `match` are read. The raw secret value is NEVER a
//! field of trivy's report (trivy redacts before emitting the CR) and is never parsed,
//! stored, or rendered here. The unit tests assert no plaintext secret reaches the output.

use kube::core::DynamicObject;
use serde_json::Value;

use super::{ImageScanFindings, scan_finding};

/// This adapter's provenance source — distinguishes an exposed-secret finding from the CVE
/// findings the `trivy` adapter asserts on the same Image (corroboration, ADR-0003).
const SOURCE: &str = "trivy-exposed-secret";

/// Parse a trivy-operator `ExposedSecretReport`. The payload lives under `report`, and the
/// image it describes under `report.artifact`/`report.registry` — same shape as the
/// `VulnerabilityReport`, so the findings attach to the same Image node.
pub fn parse_report(object: &DynamicObject) -> Option<ImageScanFindings> {
    from_report(object.data.get("report")?)
}

fn from_report(report: &Value) -> Option<ImageScanFindings> {
    let image = super::image_ref(report)?;
    // One `secrets[]` entry → one [`ScanFinding`], via the shared builder, keyed by `ruleID`
    // (vs the checks' `checkID`) and falling back to trivy's already-**redacted** `match` for
    // the title (vs the checks' `description`). REDACTION GUARANTEE: the builder reads ONLY
    // the structured coordinates (`ruleID`, `severity`, `category`, `target`, `title`/`match`)
    // — the raw secret value is never a field it touches, so it can't surface (the module note
    // + the `never_surfaces_the_raw_secret_value` test). An exposed-secret entry has no
    // `success` field, so the builder's passing-check gate is a no-op here.
    let findings = report
        .get("secrets")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| scan_finding(v, SOURCE, "ruleID", "match"))
                .collect()
        })
        .unwrap_or_default();
    Some(ImageScanFindings { image, findings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::Severity;
    use serde_json::json;

    /// A representative `ExposedSecretReport` payload. trivy redacts the secret in `match`
    /// before emitting the CR, so the fixture's `match` already shows `*****`; the raw value
    /// `SUPERSECRETVALUE` is placed ONLY in a field we must never read, to prove it can't leak.
    fn report() -> Value {
        json!({
            "registry": {"server": "ghcr.io"},
            "artifact": {"repository": "thejefflarson/api", "tag": "1.2.3"},
            "secrets": [
                {
                    "ruleID": "aws-access-key-id",
                    "category": "AWS",
                    "severity": "CRITICAL",
                    "target": "/app/.env",
                    "title": "AWS Access Key ID",
                    "match": "AWS_ACCESS_KEY_ID=*****",
                    // A field the adapter must IGNORE — proves redaction even if a future
                    // trivy added a raw field, our parser never reaches it.
                    "rawValue": "SUPERSECRETVALUE"
                },
                {"ruleID": "private-key", "severity": "HIGH", "match": "-----BEGIN *****"},
                {"category": "GitHub", "severity": "MEDIUM"}
            ]
        })
    }

    #[test]
    fn maps_image_and_exposed_secret_findings() {
        let parsed = from_report(&report()).expect("parses");
        assert_eq!(parsed.image, "ghcr.io/thejefflarson/api:1.2.3");
        // The entry missing a ruleID is skipped.
        assert_eq!(parsed.findings.len(), 2);
        let f0 = &parsed.findings[0];
        assert_eq!(f0.id, "aws-access-key-id");
        assert_eq!(f0.severity, Severity::Critical);
        assert_eq!(f0.category.as_deref(), Some("AWS"));
        assert_eq!(f0.target.as_deref(), Some("/app/.env"));
        assert_eq!(f0.title.as_deref(), Some("AWS Access Key ID"));
        assert_eq!(f0.sources[0].source, SOURCE);
        // The second finding has no title, so it falls back to the redacted `match`.
        assert_eq!(parsed.findings[1].id, "private-key");
        assert_eq!(
            parsed.findings[1].title.as_deref(),
            Some("-----BEGIN *****")
        );
    }

    #[test]
    fn never_surfaces_the_raw_secret_value() {
        // The redaction guarantee: nothing the parser produces may contain the plaintext
        // secret, no matter what fields the report carries.
        let parsed = from_report(&report()).expect("parses");
        for f in &parsed.findings {
            let rendered = format!("{f:?}");
            assert!(
                !rendered.contains("SUPERSECRETVALUE"),
                "raw secret leaked into finding: {rendered}"
            );
        }
    }

    #[test]
    fn report_without_artifact_is_none() {
        assert!(from_report(&json!({"secrets": []})).is_none());
    }

    #[test]
    fn malformed_report_is_skipped_not_panicked() {
        // No `report` field, a non-array `secrets`, and a wholly empty object must all
        // degrade to None / empty rather than panicking.
        assert!(
            parse_report(&DynamicObject {
                types: None,
                metadata: Default::default(),
                data: json!({}),
            })
            .is_none()
        );
        let parsed = from_report(&json!({
            "artifact": {"repository": "x"}, "secrets": "not-an-array"
        }))
        .expect("parses with no secrets");
        assert!(parsed.findings.is_empty());
    }
}
