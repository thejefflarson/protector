//! The Advisory port: structured, injection-safe advisory enrichment for a CVE.
//!
//! Where the ExploitIntel port (`exploit_intel.rs`) answers "is this CVE being sprayed
//! right now?", this port answers "what is this CVE, and is there a fix?" — a CWE class,
//! a fixing reference, and a short summary an operator can sync from a public advisory
//! feed. That lets the model reason "a fix exists but the workload is still on the
//! vulnerable version" vs "no fix at all" (the JEF-52 payoff), fully offline.
//!
//! ADR-0015 governs the shape: **mounted-snapshot-only, zero egress.** The store is
//! loaded from a file (a mounted ConfigMap an operator syncs from OSV/NVD/GHSA) — the
//! engine never reaches out. Opt-in live OSV fetch (JEF-110) is deferred and NOT built
//! here. Fix-diffs are out of scope for the local model.
//!
//! Because the advisory text is **untrusted third-party data** flowing into a
//! promote-capable model (ADR-0013), JEF-106's hardening applies: prefer the structured
//! fields (CWE id + fix-version), and hard length-cap the free-text summary. The
//! sanitize/fence pass at prompt-build time is the second layer; this port caps at parse
//! time so an oversized snapshot entry can never bloat the prompt or the verdict cache.
//!
//! The parse and the enrichment are pure and unit-tested; reading the file is the only
//! glue, and it is **empty-on-missing** — an absent or malformed snapshot yields no
//! advisories, never an error (a misconfigured source degrades to "no enrichment").

use std::collections::HashMap;

use serde_json::Value;

use super::ImageVulnerabilities;
use crate::engine::graph::Advisory;

/// Hard cap on a stored advisory summary (JEF-106). Applied at PARSE time so an
/// oversized snapshot entry can never bloat the prompt or the verdict fingerprint; the
/// cap is deterministic, so the same snapshot always yields the same stored string.
const SUMMARY_CAP: usize = 280;

/// Hard cap on the number of CWE ids kept per CVE — bounds prompt/fingerprint
/// cardinality from a pathological snapshot entry. CWEs are sorted+deduped first.
const MAX_CWE: usize = 8;

/// A CVE-keyed advisory snapshot, mounted from a file (ADR-0015). Maps a CVE id to its
/// structured, length-capped [`Advisory`] enrichment.
#[derive(Debug, Default, Clone)]
pub struct AdvisoryStore {
    by_cve: HashMap<String, Advisory>,
}

impl AdvisoryStore {
    /// An empty store — no advisory enrichment. The honest default when no snapshot is
    /// configured: every vulnerability keeps `advisory: None`, byte-identical to today.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The advisory for a CVE, if the snapshot carries one.
    pub fn get(&self, cve: &str) -> Option<&Advisory> {
        self.by_cve.get(cve)
    }

    pub fn len(&self) -> usize {
        self.by_cve.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_cve.is_empty()
    }

    /// Parse the snapshot. Accepts either shape (mirroring `KevCatalog::parse`'s
    /// tolerance):
    ///
    /// - an object keyed by CVE id:
    ///   `{"CVE-2021-44228": {"summary": "...", "cwe": ["CWE-502"], "fix_ref": "2.17.0"}}`
    /// - an array of entries each carrying their own id:
    ///   `{"advisories": [{"id": "CVE-...", "summary": "...", "cwe": [...], "fix_ref": "..."}]}`
    ///
    /// Each entry's fields are structurally extracted and length-capped (JEF-106): the
    /// summary is truncated to [`SUMMARY_CAP`] chars, CWE ids are sorted/deduped/capped to
    /// [`MAX_CWE`]. `cwe` also accepts a single string. Unparseable input ⇒ empty store.
    pub fn parse(contents: &str) -> Self {
        let Ok(root) = serde_json::from_str::<Value>(contents) else {
            return Self::empty();
        };
        let mut by_cve = HashMap::new();
        match root {
            // Array shape: each entry names its own CVE id.
            Value::Object(ref obj) if obj.contains_key("advisories") => {
                if let Some(Value::Array(entries)) = obj.get("advisories") {
                    for entry in entries {
                        if let Some(id) = entry.get("id").and_then(Value::as_str)
                            && let Some(advisory) = Self::extract(entry)
                        {
                            by_cve.insert(id.to_string(), advisory);
                        }
                    }
                }
            }
            // Map shape: keyed by CVE id.
            Value::Object(obj) => {
                for (id, entry) in obj {
                    if let Some(advisory) = Self::extract(&entry) {
                        by_cve.insert(id, advisory);
                    }
                }
            }
            _ => {}
        }
        Self { by_cve }
    }

    /// Structurally extract one advisory entry, capping the free-text summary and
    /// bounding the CWE list (JEF-106). Returns `None` for an entry that carries no
    /// usable field (so a junk entry is dropped rather than stored empty).
    fn extract(entry: &Value) -> Option<Advisory> {
        let summary = entry
            .get("summary")
            .and_then(Value::as_str)
            .map(|s| s.trim().chars().take(SUMMARY_CAP).collect::<String>())
            .unwrap_or_default();

        let mut cwe: Vec<String> = match entry.get("cwe") {
            // A single CWE id as a bare string.
            Some(Value::String(s)) => vec![s.trim().to_string()],
            // A list of CWE ids.
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };
        cwe.sort();
        cwe.dedup();
        cwe.truncate(MAX_CWE);

        let fix_ref = entry
            .get("fix_ref")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // Drop an entry that carries nothing usable.
        if summary.is_empty() && cwe.is_empty() && fix_ref.is_none() {
            return None;
        }
        Some(Advisory {
            summary,
            cwe,
            fix_ref,
        })
    }

    /// Load the snapshot from a file. Returns an empty store (with a logged warning) if
    /// the file is missing or unreadable, so a misconfigured advisory source degrades to
    /// "no enrichment" rather than failing the engine (empty-on-missing).
    pub fn from_file(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let store = Self::parse(&contents);
                tracing::info!(path, count = store.len(), "loaded advisory snapshot");
                store
            }
            Err(error) => {
                tracing::warn!(path, %error, "could not read advisory snapshot; advisory enrichment disabled");
                Self::empty()
            }
        }
    }

    /// Attach the matching advisory to every vulnerability whose CVE the snapshot
    /// carries. Mirrors `KevCatalog::mark_exploited` — a pure enrichment over the
    /// vulnerability list, applied where KEV is applied. Vulnerabilities with no
    /// snapshot entry are left untouched (`advisory` stays `None`).
    pub fn apply(&self, image_vulns: &mut [ImageVulnerabilities]) {
        if self.by_cve.is_empty() {
            return;
        }
        for image in image_vulns.iter_mut() {
            for vuln in image.vulnerabilities.iter_mut() {
                if let Some(advisory) = self.by_cve.get(&vuln.id) {
                    vuln.advisory = Some(advisory.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::{Severity, Vulnerability};

    fn vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            severity: Severity::Critical,
            ..Default::default()
        }
    }

    #[test]
    fn empty_on_missing_file() {
        // An absent file is not an error — it yields an empty store, never panics.
        let store = AdvisoryStore::from_file("/nonexistent/advisory-snapshot.json");
        assert!(store.is_empty());
    }

    #[test]
    fn malformed_input_yields_empty_store() {
        // Garbage JSON ⇒ empty (empty-on-missing extends to malformed).
        assert!(AdvisoryStore::parse("not json at all {{{").is_empty());
        assert!(AdvisoryStore::parse("[1, 2, 3]").is_empty());
    }

    #[test]
    fn parses_map_and_array_shapes() {
        let map = r#"{
            "CVE-2021-44228": {"summary":"Log4Shell JNDI RCE","cwe":["CWE-502","CWE-917"],"fix_ref":"2.17.0"},
            "CVE-2014-0160": {"summary":"Heartbleed","cwe":"CWE-125"}
        }"#;
        let store = AdvisoryStore::parse(map);
        assert_eq!(store.len(), 2);
        let a = store.get("CVE-2021-44228").unwrap();
        assert_eq!(a.summary, "Log4Shell JNDI RCE");
        assert_eq!(a.cwe, vec!["CWE-502", "CWE-917"]);
        assert_eq!(a.fix_ref.as_deref(), Some("2.17.0"));
        // A single-string cwe is accepted.
        assert_eq!(store.get("CVE-2014-0160").unwrap().cwe, vec!["CWE-125"]);

        let array = r#"{"advisories":[
            {"id":"CVE-2021-44228","summary":"Log4Shell","cwe":["CWE-502"],"fix_ref":"2.17.0"}
        ]}"#;
        let store = AdvisoryStore::parse(array);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("CVE-2021-44228").unwrap().summary, "Log4Shell");
    }

    #[test]
    fn summary_is_length_capped_and_cwe_bounded() {
        // JEF-106: an oversized summary is truncated at parse time; an absurd CWE list is
        // sorted/deduped/bounded — neither can bloat the prompt or the verdict cache.
        let big_summary = "A".repeat(1000);
        let many_cwe: Vec<String> = (0..50).map(|i| format!("\"CWE-{i}\"")).collect();
        let json = format!(
            r#"{{"CVE-2026-0001":{{"summary":"{big_summary}","cwe":[{}]}}}}"#,
            many_cwe.join(",")
        );
        let store = AdvisoryStore::parse(&json);
        let a = store.get("CVE-2026-0001").unwrap();
        assert_eq!(a.summary.chars().count(), SUMMARY_CAP);
        assert!(a.cwe.len() <= MAX_CWE);
    }

    #[test]
    fn junk_entry_with_no_usable_field_is_dropped() {
        let store = AdvisoryStore::parse(r#"{"CVE-2026-0002":{"unrelated":"x"}}"#);
        assert!(store.is_empty());
    }

    #[test]
    fn apply_attaches_only_matching_cves() {
        let store = AdvisoryStore::parse(
            r#"{"CVE-2021-44228":{"summary":"Log4Shell","cwe":["CWE-502"],"fix_ref":"2.17.0"}}"#,
        );
        let mut images = vec![ImageVulnerabilities {
            image: "app:1".into(),
            vulnerabilities: vec![vuln("CVE-2021-44228"), vuln("CVE-2020-0001")],
        }];
        store.apply(&mut images);
        let v = &images[0].vulnerabilities;
        assert_eq!(
            v[0].advisory.as_ref().map(|a| a.summary.as_str()),
            Some("Log4Shell"),
            "matched CVE gets its advisory"
        );
        assert!(v[1].advisory.is_none(), "unmatched CVE left untouched");
    }

    #[test]
    fn apply_with_empty_store_is_a_noop() {
        let store = AdvisoryStore::empty();
        let mut images = vec![ImageVulnerabilities {
            image: "app:1".into(),
            vulnerabilities: vec![vuln("CVE-2021-44228")],
        }];
        store.apply(&mut images);
        assert!(
            images[0].vulnerabilities[0].advisory.is_none(),
            "empty store changes nothing"
        );
    }
}
