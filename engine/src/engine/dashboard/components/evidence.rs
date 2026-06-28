//! The evidence renderers (JEF-255): the dense-row glyph STRIP and the expanded evidence
//! BLOCKS. Pure `Props -> Markup`; no `engine::` domain type (ADR-0019). ADR-0016 keeps CVEs
//! (a severity/reachability input) and runtime alerts (live corroboration) visually distinct.
//! All untrusted text (ids, titles, redacted secret matches, behavior summaries) is
//! auto-escaped at the maud brace.

use maud::{Markup, html};

use crate::engine::dashboard::components::chips;
use crate::engine::dashboard::view_model::evidence::{
    CveLine, EvidenceBlocks, GlyphStrip, ScanLine,
};

/// The compact glyph strip for a dense row.
pub fn glyph_strip(g: &GlyphStrip) -> Markup {
    html! {
        @if !g.is_empty() {
            span class="glyphs" {
                @if let Some(cvss) = &g.cvss { (chips::glyph(cvss, "g-cvss")) }
                @if let Some(epss) = &g.epss { (chips::glyph(epss, "g-epss")) }
                @if g.kev { (chips::glyph("KEV", "g-kev")) }
                @if g.secret { (chips::glyph("secret", "g-secret")) }
                @if g.runtime { (chips::glyph("runtime", "g-runtime")) }
            }
        }
    }
}

/// The full expanded evidence blocks — the labeled "what the model weighed" detail.
pub fn evidence_blocks(b: &EvidenceBlocks) -> Markup {
    html! {
        div class="evidence" {
            @if b.is_empty() {
                p class="muted" { "no evidence on this entry (no CVEs, scanner findings, or runtime signals)" }
            } @else {
                @if !b.cves.is_empty() { (cve_block(&b.cves)) }
                @if !b.alerts.is_empty() || !b.context.is_empty() {
                    (runtime_block(&b.alerts, &b.context))
                }
                @if !b.exposed_secrets.is_empty() {
                    (scan_block("Exposed secrets", &b.exposed_secrets))
                }
                @if !b.misconfigs.is_empty() {
                    (scan_block("Misconfigurations", &b.misconfigs))
                }
                @if !b.rbac.is_empty() {
                    (scan_block("RBAC findings", &b.rbac))
                }
            }
        }
    }
}

fn cve_block(cves: &[CveLine]) -> Markup {
    html! {
        div class="ev-block ev-cves" {
            h4 { "CVEs " span class="muted" { "(severity / reachability input)" } }
            ul {
                @for c in cves {
                    li {
                        code { (c.id) } " "
                        (chips::severity_badge(&c.severity, c.kev, chips::severity_tone(&c.severity)))
                        @if let Some(cvss) = &c.cvss { " " span class="muted" { "cvss " (cvss) } }
                        @if let Some(epss) = &c.epss { " " span class="muted" { "epss " (epss) } }
                        " · " (c.fix)
                        @if let Some(title) = &c.title { " — " (title) }
                    }
                }
            }
        }
    }
}

fn runtime_block(alerts: &[String], context: &[String]) -> Markup {
    html! {
        div class="ev-block ev-runtime" {
            h4 { "Runtime signals " span class="muted" { "(live corroboration)" } }
            @if !alerts.is_empty() {
                p class="ev-alerts" { b { "alerts:" } }
                ul {
                    @for a in alerts { li class="alert" { (a) } }
                }
            }
            @if !context.is_empty() {
                p class="ev-context" { span class="muted" { "context (not corroboration):" } }
                ul {
                    @for c in context { li class="muted" { (c) } }
                }
            }
        }
    }
}

fn scan_block(title: &str, lines: &[ScanLine]) -> Markup {
    html! {
        div class="ev-block ev-scan" {
            h4 { (title) }
            ul {
                @for l in lines {
                    li {
                        code { (l.id) } " "
                        (chips::severity_badge(&l.severity, false, chips::severity_tone(&l.severity)))
                        @if let Some(cat) = &l.category { " · " (cat) }
                        @if let Some(t) = &l.title { " — " (t) }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_strip_renders_nothing() {
        assert_eq!(glyph_strip(&GlyphStrip::default()).into_string(), "");
    }

    #[test]
    fn strip_shows_present_glyphs() {
        let g = GlyphStrip {
            cvss: Some("cvss 9.8".into()),
            epss: Some("epss 90%".into()),
            kev: true,
            secret: true,
            runtime: true,
        };
        let m = glyph_strip(&g).into_string();
        assert!(m.contains("cvss 9.8"));
        assert!(m.contains("epss 90%"));
        assert!(m.contains("KEV"));
        assert!(m.contains("secret"));
        assert!(m.contains("runtime"));
    }

    #[test]
    fn empty_blocks_say_no_evidence() {
        let m = evidence_blocks(&EvidenceBlocks::default()).into_string();
        assert!(m.contains("no evidence on this entry"));
    }

    #[test]
    fn cve_title_is_escaped() {
        let b = EvidenceBlocks {
            cves: vec![CveLine {
                id: "CVE-1".into(),
                severity: "critical".into(),
                kev: true,
                cvss: Some("9.8".into()),
                epss: Some("90%".into()),
                fix: "no fix available".into(),
                title: Some("<script>alert(1)</script>".into()),
            }],
            ..Default::default()
        };
        let m = evidence_blocks(&b).into_string();
        assert!(!m.contains("<script>alert"));
        assert!(m.contains("&lt;script&gt;"));
        assert!(m.contains("KEV"));
    }
}
