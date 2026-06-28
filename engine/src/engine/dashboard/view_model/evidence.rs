//! Evidence view-model (JEF-255): the dense-row GLYPH strip and the expanded evidence BLOCKS.
//!
//! The glyph strip is the at-a-glance "what's the evidence" for the dense table row —
//! `cvss·epss·kev·secret·runtime` markers. The blocks are the full per-entry evidence ADR-0016
//! keeps distinct: CVEs (a severity/reachability input) vs runtime signals (live
//! corroboration) vs scanner findings. Pure data shaping over [`EntryEvidence`]; the renderer
//! (`components::evidence`) never sees a domain type (ADR-0019). All untrusted text (CVE id,
//! advisory title, redacted secret match, behavior summary) rides as plain `String`s and is
//! auto-escaped at the maud brace.

use crate::engine::dashboard::model::{CveEvidence, EntryEvidence, FindingEvidence};

/// The compact glyph strip for a dense row (JEF-255): one marker per kind of evidence
/// present, each carrying its meaning in TEXT (never color/icon alone).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlyphStrip {
    /// The highest CVSS score across the entry's CVEs, as a token (`"cvss 9.8"`), if any.
    pub cvss: Option<String>,
    /// The highest EPSS percent across the entry's CVEs (`"epss 90%"`), if any.
    pub epss: Option<String>,
    /// At least one CVE is KEV (known-exploited) — the strongest static signal.
    pub kev: bool,
    /// An exposed secret is baked into the entry's image.
    pub secret: bool,
    /// A live runtime ALERT corroborated the chain (Falco-style) — "something is happening".
    pub runtime: bool,
}

impl GlyphStrip {
    /// Whether the strip has anything to show — the renderer omits it entirely when empty
    /// (an empty strip reads worse than no strip).
    pub fn is_empty(&self) -> bool {
        self.cvss.is_none() && self.epss.is_none() && !self.kev && !self.secret && !self.runtime
    }
}

/// Build the glyph strip from an entry's evidence and its corroboration flag.
pub fn glyph_strip(ev: &EntryEvidence, corroborated: bool) -> GlyphStrip {
    GlyphStrip {
        cvss: max_cvss(&ev.cves).map(|s| format!("cvss {s}")),
        epss: max_epss(&ev.cves).map(|s| format!("epss {s}")),
        kev: ev.cves.iter().any(|c| c.kev),
        secret: !ev.exposed_secrets.is_empty(),
        runtime: corroborated || ev.runtime.iter().any(|b| b.is_alert()),
    }
}

/// The highest CVSS token across the entry's CVEs (string-compare on the `"9.8"` form is fine
/// for one-decimal scores within `[0, 9.9]`; "10.0" sorts below "9.x" lexically, so compare
/// numerically by re-parsing the already-formatted token).
fn max_cvss(cves: &[CveEvidence]) -> Option<String> {
    cves.iter()
        .filter_map(|c| c.score.as_ref())
        .max_by(|a, b| {
            let pa = a.parse::<f64>().unwrap_or(0.0);
            let pb = b.parse::<f64>().unwrap_or(0.0);
            pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// The highest EPSS percent across the entry's CVEs, compared numerically.
fn max_epss(cves: &[CveEvidence]) -> Option<String> {
    cves.iter()
        .filter_map(|c| c.epss.as_ref())
        .max_by(|a, b| {
            let pa = a.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
            let pb = b.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
            pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// One CVE line for the expanded evidence block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveLine {
    pub id: String,
    pub severity: String,
    pub kev: bool,
    pub cvss: Option<String>,
    pub epss: Option<String>,
    pub fix: String,
    pub title: Option<String>,
}

/// One scanner-finding line (exposed secret / misconfig / RBAC) for the expanded block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLine {
    pub id: String,
    pub severity: String,
    pub category: Option<String>,
    pub title: Option<String>,
}

/// The full expanded evidence for one entry — the labeled blocks ADR-0016 keeps distinct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceBlocks {
    pub cves: Vec<CveLine>,
    /// Corroborating live alerts (Falco-style) — the "happening now" signal.
    pub alerts: Vec<String>,
    /// Non-corroborating context behaviors (exec/connect/secret-read/etc).
    pub context: Vec<String>,
    pub exposed_secrets: Vec<ScanLine>,
    pub misconfigs: Vec<ScanLine>,
    pub rbac: Vec<ScanLine>,
}

impl EvidenceBlocks {
    /// Whether there is no evidence at all — the honest "none" block.
    pub fn is_empty(&self) -> bool {
        self.cves.is_empty()
            && self.alerts.is_empty()
            && self.context.is_empty()
            && self.exposed_secrets.is_empty()
            && self.misconfigs.is_empty()
            && self.rbac.is_empty()
    }
}

/// Shape an entry's evidence into the labeled blocks the detail renders.
pub fn evidence_blocks(ev: &EntryEvidence) -> EvidenceBlocks {
    EvidenceBlocks {
        cves: ev.cves.iter().map(cve_line).collect(),
        alerts: ev.corroborating().map(|b| b.summary()).collect(),
        context: ev.context_behaviors().map(|b| b.summary()).collect(),
        exposed_secrets: ev.exposed_secrets.iter().map(scan_line).collect(),
        misconfigs: ev.misconfigs.iter().map(scan_line).collect(),
        rbac: ev.rbac_findings.iter().map(scan_line).collect(),
    }
}

fn cve_line(c: &CveEvidence) -> CveLine {
    CveLine {
        id: c.id.clone(),
        severity: c.severity.clone(),
        kev: c.kev,
        cvss: c.score.clone(),
        epss: c.epss.clone(),
        fix: c.fix.clone(),
        title: c.title.clone(),
    }
}

fn scan_line(f: &FindingEvidence) -> ScanLine {
    ScanLine {
        id: f.id.clone(),
        severity: f.severity.clone(),
        category: f.category.clone(),
        title: f.title.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::{Behavior, Reachability, Severity, Vulnerability};

    fn vuln(
        id: &str,
        sev: Severity,
        kev: bool,
        score: Option<f64>,
        epss: Option<f32>,
    ) -> CveEvidence {
        CveEvidence::from_vuln(&Vulnerability {
            id: id.into(),
            severity: sev,
            exploited_in_wild: kev,
            reachability: Reachability::NotObserved,
            score,
            epss,
            ..Default::default()
        })
    }

    #[test]
    fn glyph_strip_takes_the_max_cvss_and_epss_and_flags_kev() {
        let ev = EntryEvidence {
            cves: vec![
                vuln("CVE-1", Severity::High, false, Some(7.5), Some(0.10)),
                vuln("CVE-2", Severity::Critical, true, Some(9.8), Some(0.90)),
            ],
            ..Default::default()
        };
        let g = glyph_strip(&ev, false);
        assert_eq!(g.cvss.as_deref(), Some("cvss 9.8"));
        assert_eq!(g.epss.as_deref(), Some("epss 90%"));
        assert!(g.kev);
        assert!(!g.secret);
        assert!(!g.runtime);
    }

    #[test]
    fn runtime_glyph_set_by_alert_or_corroboration() {
        let ev = EntryEvidence {
            runtime: vec![Behavior::Alert {
                rule: "shell in container".into(),
            }],
            ..Default::default()
        };
        assert!(
            glyph_strip(&ev, false).runtime,
            "an alert sets the runtime glyph"
        );
        assert!(
            glyph_strip(&EntryEvidence::default(), true).runtime,
            "corroboration alone sets it"
        );
    }

    #[test]
    fn empty_strip_is_empty() {
        assert!(glyph_strip(&EntryEvidence::default(), false).is_empty());
    }

    #[test]
    fn blocks_split_alerts_from_context_and_carry_cve_lines() {
        let ev = EntryEvidence {
            cves: vec![vuln(
                "CVE-9",
                Severity::Critical,
                true,
                Some(9.8),
                Some(0.9),
            )],
            runtime: vec![
                Behavior::Alert {
                    rule: "shell in container".into(),
                },
                Behavior::ProcessExec {
                    path: "/bin/sh".into(),
                },
            ],
            ..Default::default()
        };
        let b = evidence_blocks(&ev);
        assert_eq!(b.cves.len(), 1);
        assert_eq!(b.cves[0].cvss.as_deref(), Some("9.8"));
        assert_eq!(b.cves[0].epss.as_deref(), Some("90%"));
        assert_eq!(b.alerts.len(), 1);
        assert_eq!(b.context.len(), 1);
        assert!(!b.is_empty());
    }
}
