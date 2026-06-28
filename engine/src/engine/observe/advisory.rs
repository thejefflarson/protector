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

/// Hard cap on a stored `fix_ref` string (Fix 8). A fix reference is a version or a
/// short URL; like `summary`, it's the operator-controlled-but-untrusted free text that
/// rides into the prompt/fingerprint, so cap it at parse time so a pathological snapshot
/// entry can't bloat them. Applied with `.chars().take(..)` so the cap is char-safe.
const FIX_REF_CAP: usize = 64;

/// Hard cap on the length of each individual CWE id string (Fix 8). A CWE id is short
/// (`CWE-502`); bound each entry so a junk snapshot can't smuggle a long string in
/// through the otherwise-uncapped CWE list elements.
const CWE_CAP: usize = 32;

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

    /// Parse the snapshot. Accepts three shapes (mirroring `KevCatalog::parse`'s
    /// tolerance):
    ///
    /// - an object keyed by CVE id:
    ///   `{"CVE-2021-44228": {"summary": "...", "cwe": ["CWE-502"], "fix_ref": "2.17.0"}}`
    /// - an array of entries each carrying their own id:
    ///   `{"advisories": [{"id": "CVE-...", "summary": "...", "cwe": [...], "fix_ref": "..."}]}`
    /// - the **public NVD CVE JSON 2.0** feed shape verbatim (JEF-238):
    ///   `{"vulnerabilities": [{"cve": {"id": "CVE-...", "descriptions": [...],
    ///   "weaknesses": [...], "references": [...]}}]}`. This lets the feed-fetcher sidecar
    ///   stay a plain `curl` (no `jq`, no extra image): it just fetches+gunzips NVD's
    ///   `recent`/`modified` feeds and the engine maps them onto [`Advisory`] here, under
    ///   the SAME parse-time caps as the curated shapes — no new dependency, the untrusted
    ///   third-party text never escapes the engine's bounded parser (JEF-106 / ADR-0015).
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
            // NVD CVE JSON 2.0 feed shape: `{"vulnerabilities": [{"cve": {...}}]}`. Each
            // wrapper carries one `cve` object naming its own id; we reshape it (NVD's
            // verbose schema → the three capped fields) without a sidecar transform.
            Value::Object(ref obj) if obj.contains_key("vulnerabilities") => {
                if let Some(Value::Array(entries)) = obj.get("vulnerabilities") {
                    for entry in entries {
                        if let Some(cve) = entry.get("cve")
                            && let Some(id) = cve.get("id").and_then(Value::as_str)
                            && let Some(advisory) = Self::extract_nvd(cve)
                        {
                            by_cve.insert(id.to_string(), advisory);
                        }
                    }
                }
            }
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

        // Each CWE id is capped to CWE_CAP chars (Fix 8) so a junk snapshot can't smuggle
        // a long string in through an otherwise-uncapped list element.
        let cap_cwe = |s: &str| s.trim().chars().take(CWE_CAP).collect::<String>();
        let mut cwe: Vec<String> = match entry.get("cwe") {
            // A single CWE id as a bare string.
            Some(Value::String(s)) => vec![cap_cwe(s)],
            // A list of CWE ids.
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(cap_cwe)
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };
        cwe.sort();
        cwe.dedup();
        cwe.truncate(MAX_CWE);

        // `fix_ref` is the last free-text advisory field; cap it at parse time like
        // `summary` (Fix 8) so it can't bloat the prompt/fingerprint.
        let fix_ref = entry
            .get("fix_ref")
            .and_then(Value::as_str)
            .map(|s| s.trim().chars().take(FIX_REF_CAP).collect::<String>())
            .filter(|s| !s.is_empty());

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

    /// Reshape ONE NVD CVE JSON 2.0 `cve` object into the curated `{summary, cwe, fix_ref}`
    /// shape, then delegate to [`Self::extract`] so the parse-time caps (JEF-106) are
    /// applied in exactly ONE place. The NVD field mapping (JEF-238):
    ///
    /// - `summary`  ← the first English (`lang == "en"`) `descriptions[].value`.
    /// - `cwe`      ← every English `weaknesses[].description[].value` that is a real
    ///   `CWE-<n>` id (NVD also emits placeholders like `NVD-CWE-noinfo` / `NVD-CWE-Other`,
    ///   which carry no class and are dropped here).
    /// - `fix_ref`  ← a reference url, preferring one tagged `"Patch"`, else the first url.
    ///
    /// Returns `None` (entry dropped) when none of the three fields is usable — same
    /// contract as [`Self::extract`].
    fn extract_nvd(cve: &Value) -> Option<Advisory> {
        // First English description → summary.
        let summary = cve
            .get("descriptions")
            .and_then(Value::as_array)
            .and_then(|ds| {
                ds.iter()
                    .find(|d| d.get("lang").and_then(Value::as_str) == Some("en"))
                    .and_then(|d| d.get("value").and_then(Value::as_str))
            })
            .unwrap_or_default();

        // English weakness values that are genuine CWE ids (skip NVD's no-info placeholders).
        let cwe: Vec<Value> = cve
            .get("weaknesses")
            .and_then(Value::as_array)
            .map(|ws| {
                ws.iter()
                    .filter_map(|w| w.get("description").and_then(Value::as_array))
                    .flatten()
                    .filter(|d| d.get("lang").and_then(Value::as_str) == Some("en"))
                    .filter_map(|d| d.get("value").and_then(Value::as_str))
                    .filter(|v| v.starts_with("CWE-"))
                    .map(|v| Value::String(v.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // A reference url: prefer one tagged "Patch", else the first listed.
        let refs = cve.get("references").and_then(Value::as_array);
        let fix_ref = refs.and_then(|rs| {
            let patch = rs
                .iter()
                .find(|r| {
                    r.get("tags")
                        .and_then(Value::as_array)
                        .is_some_and(|ts| ts.iter().any(|t| t.as_str() == Some("Patch")))
                })
                .and_then(|r| r.get("url").and_then(Value::as_str));
            patch
                .or_else(|| {
                    rs.first()
                        .and_then(|r| r.get("url").and_then(Value::as_str))
                })
                .map(str::to_string)
        });

        // Hand the normalized entry to the shared extractor so the caps apply once.
        let mut normalized = serde_json::Map::new();
        normalized.insert("summary".into(), Value::String(summary.to_string()));
        normalized.insert("cwe".into(), Value::Array(cwe));
        if let Some(fix_ref) = fix_ref {
            normalized.insert("fix_ref".into(), Value::String(fix_ref));
        }
        Self::extract(&Value::Object(normalized))
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
    fn parses_nvd_cve_json_2_0_shape() {
        // JEF-238: the engine maps the raw NVD CVE JSON 2.0 feed (what the curl+gunzip
        // sidecar drops in, no transform) onto Advisory — first English description ->
        // summary, real CWE ids -> cwe (NVD-CWE-* placeholders dropped), a Patch-tagged
        // reference preferred for fix_ref.
        let nvd = r#"{"vulnerabilities":[
            {"cve":{
                "id":"CVE-2021-44228",
                "descriptions":[
                    {"lang":"es","value":"ignored non-english"},
                    {"lang":"en","value":"Log4Shell JNDI RCE"}
                ],
                "weaknesses":[{"description":[
                    {"lang":"en","value":"CWE-502"},
                    {"lang":"en","value":"NVD-CWE-noinfo"},
                    {"lang":"en","value":"CWE-917"}
                ]}],
                "references":[
                    {"url":"https://example.com/first"},
                    {"url":"https://logging.apache.org/security.html","tags":["Patch"]}
                ]
            }}
        ]}"#;
        let store = AdvisoryStore::parse(nvd);
        assert_eq!(store.len(), 1);
        let a = store.get("CVE-2021-44228").unwrap();
        assert_eq!(a.summary, "Log4Shell JNDI RCE");
        // Real CWE ids survive (sorted/deduped); the NVD placeholder is dropped.
        assert_eq!(a.cwe, vec!["CWE-502", "CWE-917"]);
        // The Patch-tagged reference wins over the first-listed one.
        assert_eq!(
            a.fix_ref.as_deref(),
            Some("https://logging.apache.org/security.html")
        );
    }

    #[test]
    fn nvd_entry_falls_back_to_first_reference_when_no_patch_tag() {
        // No Patch tag → fix_ref is the first reference url.
        let nvd = r#"{"vulnerabilities":[{"cve":{
            "id":"CVE-2026-0001",
            "descriptions":[{"lang":"en","value":"desc"}],
            "references":[{"url":"https://example.com/a"},{"url":"https://example.com/b"}]
        }}]}"#;
        let store = AdvisoryStore::parse(nvd);
        assert_eq!(
            store.get("CVE-2026-0001").unwrap().fix_ref.as_deref(),
            Some("https://example.com/a")
        );
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
    fn fix_ref_and_cwe_strings_are_length_capped() {
        // Fix 8: `fix_ref` was the only free-text advisory field never capped, and CWE
        // list elements were uncapped. Both must be bounded at parse time.
        let big_fix_ref = "F".repeat(500);
        let long_cwe = "C".repeat(200);
        let json = format!(
            r#"{{"CVE-2026-0003":{{"summary":"s","cwe":["{long_cwe}"],"fix_ref":"{big_fix_ref}"}}}}"#
        );
        let store = AdvisoryStore::parse(&json);
        let a = store.get("CVE-2026-0003").unwrap();
        assert_eq!(
            a.fix_ref.as_ref().unwrap().chars().count(),
            FIX_REF_CAP,
            "fix_ref must be truncated to the cap"
        );
        assert_eq!(
            a.cwe[0].chars().count(),
            CWE_CAP,
            "each CWE string must be truncated to the cap"
        );
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
