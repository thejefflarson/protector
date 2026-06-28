//! The EPSS store: the FIRST.org Exploit Prediction Scoring System (EPSS) probability
//! per CVE — the **predictive** exploitation axis.
//!
//! Where the KEV catalogue ([`super::exploit_intel`]) asserts a CVE is *exploited in the
//! wild right now* (a binary fact) and trivy's CVSS score states *static severity*, EPSS
//! supplies the third axis the adjudication prompt already reserves a slot for (JEF-66):
//! a `[0, 1]` probability that a CVE will be exploited in the next 30 days. The model
//! weighs "high severity but unlikely to be hit" differently from "moderate severity but
//! a high exploit probability" — that is exactly what EPSS adds.
//!
//! Like KEV, the scores are loaded from a file in the cluster (the feed-fetcher sidecar
//! syncs the FIRST.org CSV into a shared volume; the engine only reads it — no egress,
//! ADR-0015). The parse is pure, lenient, and unit-tested; reading the file is the only
//! glue. A missing or malformed feed degrades to an empty store ("no EPSS evidence")
//! rather than failing the engine — the same honest default KEV uses.

use std::collections::HashMap;

/// The longest input line we will look at. The FIRST.org rows are tiny
/// (`CVE-2021-44228,0.94334,0.99` — under 40 bytes); a line longer than this is
/// malformed (or hostile) and is skipped rather than parsed, so a corrupt feed can never
/// drive an unbounded allocation.
const MAX_LINE_LEN: usize = 256;

/// The maximum fields we will split a row into before bailing. The format is exactly
/// `cve,epss,percentile` (three fields); we read the first two and ignore the rest, but
/// cap the split so a comma-heavy malformed line can't fan out.
const MAX_FIELDS: usize = 8;

/// Per-CVE EPSS exploit-prediction probabilities, keyed by CVE id.
#[derive(Debug, Default, Clone)]
pub struct EpssStore {
    scores: HashMap<String, f32>,
}

impl EpssStore {
    /// An empty store — no EPSS scores are known. The honest default when no EPSS source
    /// is configured (or the feed is unreadable): `get` returns `None`, so a CVE's `epss`
    /// stays `None` and the prompt simply omits the `[epss: …]` token, exactly as before
    /// this feed existed.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The EPSS probability for a CVE, if the feed carried one. `None` for an unknown CVE.
    pub fn get(&self, cve: &str) -> Option<f32> {
        self.scores.get(cve).copied()
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Parse the FIRST.org EPSS CSV. The format is:
    ///
    /// ```text
    /// #model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000
    /// cve,epss,percentile
    /// CVE-2021-44228,0.94334,0.99
    /// CVE-2014-0160,0.84521,0.98
    /// ```
    ///
    /// The leading `#`-comment line (the model/score-date metadata) and the `cve,…`
    /// header are skipped; each data row contributes `cve -> epss`. Parsing is lenient by
    /// design: any line that is too long, has too few fields, carries a non-CVE id, or
    /// whose score is not a finite probability in `[0, 1]` is dropped — a malformed feed
    /// yields fewer (or zero) scores, never a panic. Only the parsed `f32` is retained; no
    /// untrusted free-text from the feed ever reaches the prompt.
    pub fn parse(contents: &str) -> Self {
        let mut scores = HashMap::new();
        for line in contents.lines() {
            let line = line.trim();
            // Skip blanks, the `#`-metadata comment, and over-long (malformed/hostile)
            // lines before doing any field work.
            if line.is_empty() || line.starts_with('#') || line.len() > MAX_LINE_LEN {
                continue;
            }
            let mut fields = line.splitn(MAX_FIELDS, ',');
            let Some(cve) = fields.next() else { continue };
            let cve = cve.trim();
            // The `cve,epss,percentile` header row — skip it (and anything that isn't a
            // CVE id, which also drops a stray header or junk line).
            if !is_cve_id(cve) {
                continue;
            }
            let Some(epss) = fields.next() else { continue };
            let Ok(epss) = epss.trim().parse::<f32>() else {
                continue;
            };
            // A probability must be finite and in `[0, 1]`; anything else is malformed.
            if !epss.is_finite() || !(0.0..=1.0).contains(&epss) {
                continue;
            }
            scores.insert(cve.to_string(), epss);
        }
        Self { scores }
    }

    /// Load the store from a file. Returns an empty store (with a logged warning) if the
    /// file is missing or unreadable, so a misconfigured EPSS source degrades to "no EPSS
    /// evidence" rather than failing the engine — mirrors [`KevCatalog::from_file`].
    ///
    /// [`KevCatalog::from_file`]: super::exploit_intel::KevCatalog::from_file
    pub fn from_file(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let store = Self::parse(&contents);
                tracing::info!(path, count = store.len(), "loaded EPSS scores");
                store
            }
            Err(error) => {
                tracing::warn!(path, %error, "could not read EPSS feed; exploit prediction disabled");
                Self::empty()
            }
        }
    }

    /// Annotate every vulnerability with its EPSS probability (when the feed carried one).
    /// This is the ExploitIntel enrichment the adjudication prompt's `[epss: …]` token
    /// reads — set alongside KEV's `exploited_in_wild` flip in the enrichment step. Leaves
    /// `epss` untouched (so it stays `None`) for CVEs the feed didn't score.
    pub fn annotate(&self, image_vulns: &mut [super::ImageVulnerabilities]) {
        if self.scores.is_empty() {
            return;
        }
        for image in image_vulns.iter_mut() {
            for vuln in image.vulnerabilities.iter_mut() {
                if let Some(score) = self.scores.get(&vuln.id) {
                    vuln.epss = Some(*score);
                }
            }
        }
    }
}

/// A cheap shape check that a field looks like a CVE id (`CVE-YYYY-NNNN…`). Used to skip
/// the CSV header (`cve`) and any junk line without a full parse — case-insensitive on the
/// `CVE` prefix to tolerate feed casing.
fn is_cve_id(s: &str) -> bool {
    let mut parts = s.split('-');
    let prefix = parts.next().unwrap_or_default();
    if !prefix.eq_ignore_ascii_case("CVE") {
        return false;
    }
    let year = parts.next();
    let seq = parts.next();
    matches!((year, seq), (Some(y), Some(n))
        if !y.is_empty() && y.bytes().all(|b| b.is_ascii_digit())
        && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::{Severity, Vulnerability};
    use crate::engine::observe::ImageVulnerabilities;

    fn vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            severity: Severity::Critical,
            epss: None,
            ..Default::default()
        }
    }

    #[test]
    fn parses_the_firstorg_csv_skipping_metadata_and_header() {
        let csv = "#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000\n\
             cve,epss,percentile\n\
             CVE-2021-44228,0.94334,0.99\n\
             CVE-2014-0160,0.84521,0.98\n";
        let store = EpssStore::parse(csv);
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("CVE-2021-44228"), Some(0.94334));
        assert_eq!(store.get("CVE-2014-0160"), Some(0.84521));
        assert_eq!(store.get("CVE-2020-0001"), None);
    }

    #[test]
    fn malformed_lines_are_dropped_never_panic() {
        let csv = "#header only metadata\n\
             cve,epss,percentile\n\
             CVE-2021-44228,not-a-number,0.99\n\
             CVE-2021-45046\n\
             CVE-2021-99999,2.5,0.5\n\
             CVE-2021-88888,-0.1,0.5\n\
             ,,\n\
             garbage line with no commas\n\
             CVE-2021-44832,0.5,0.7\n";
        let store = EpssStore::parse(csv);
        // Only the one well-formed, in-range row survives.
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("CVE-2021-44832"), Some(0.5));
    }

    #[test]
    fn over_long_lines_are_skipped() {
        let long_seq = "9".repeat(MAX_LINE_LEN);
        let csv = format!("cve,epss,percentile\nCVE-2021-{long_seq},0.5,0.5\n");
        let store = EpssStore::parse(&csv);
        assert!(store.is_empty());
    }

    #[test]
    fn empty_or_garbage_input_yields_an_empty_store() {
        assert!(EpssStore::parse("").is_empty());
        assert!(EpssStore::parse("not a csv at all").is_empty());
        assert!(EpssStore::empty().is_empty());
    }

    #[test]
    fn annotate_sets_epss_only_for_scored_cves() {
        let store = EpssStore::parse("CVE-2021-44228,0.94,0.99\n");
        let mut images = vec![ImageVulnerabilities {
            image: "app:1".into(),
            vulnerabilities: vec![vuln("CVE-2021-44228"), vuln("CVE-2020-0001")],
        }];
        store.annotate(&mut images);
        let v = &images[0].vulnerabilities;
        assert_eq!(v[0].epss, Some(0.94), "scored CVE annotated");
        assert_eq!(v[1].epss, None, "unscored CVE left alone");
    }

    #[test]
    fn empty_store_annotate_is_a_noop() {
        let mut images = vec![ImageVulnerabilities {
            image: "app:1".into(),
            vulnerabilities: vec![vuln("CVE-2021-44228")],
        }];
        EpssStore::empty().annotate(&mut images);
        assert_eq!(images[0].vulnerabilities[0].epss, None);
    }

    #[test]
    fn is_cve_id_accepts_cve_ids_and_rejects_the_header() {
        assert!(is_cve_id("CVE-2021-44228"));
        assert!(is_cve_id("cve-2021-44228"));
        assert!(!is_cve_id("cve"));
        assert!(!is_cve_id("percentile"));
        assert!(!is_cve_id("CVE-2021"));
    }
}
