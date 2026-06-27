//! The "what's proven" certainty rail (JEF-161): the deterministic facts beneath the
//! verbatim verdict — the proof side of the proof-vs-judgement line (ADR-0016). Pure
//! `Props -> Markup`; imports only its props + maud. NO `engine::` domain type.

use crate::engine::dashboard::view_model::findings::{CveFact, RailProps};
use maud::{Markup, PreEscaped, html};

/// The CVE fact line for the rail — a short counts-only summary, or the honest-empty state.
/// The counts are derived data (not free-text), so the few inline `<b>`/`<code>` spans are
/// `PreEscaped` child markup; the only interpolated values are numbers.
fn cve_fact(cve: &CveFact) -> Markup {
    match cve {
        CveFact::None => PreEscaped(
            "CVE: <span class=\"muted\">no KEV or critical CVE on this service's image \
             (lower-severity CVEs not shown here)</span>"
                .to_string(),
        ),
        CveFact::Present { n, critical, kev } => {
            let mut parts: Vec<String> = Vec::new();
            if *critical > 0 {
                parts.push(format!("{critical} critical"));
            }
            if *kev > 0 {
                parts.push(format!("{kev} KEV-listed"));
            }
            let detail = if parts.is_empty() {
                String::new()
            } else {
                format!(" — {}", parts.join(", "))
            };
            html! {
                "CVE present: " b { (n) } " known vuln"
                @if *n != 1 { "s" }
                (detail) " on this image (full list below)"
            }
        }
    }
}

/// The certainty rail (JEF-161): the internet-reachability fact, the humanized terminal
/// relations, and the CVE fact, as a `<ul>` under a "proven facts" cap. The entry short name
/// and each relation are auto-escaped maud braces (untrusted node text).
pub fn rail(props: &RailProps) -> Markup {
    html! {
        div class="rail" {
            div class="rail-cap" { "proven facts" }
            ul {
                li {
                    "internet-reachable: " code { (props.entry_short) }
                    " is an internet-facing service (a front door)"
                }
                @for rel in &props.relations {
                    li { "reaches a target by " b { (rel) } }
                }
                li { (cve_fact(&props.cve)) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rail_renders_facts_and_honest_empty_cve() {
        let props = RailProps {
            entry_short: "web".into(),
            relations: vec!["mounts (direct read)".into()],
            cve: CveFact::None,
        };
        let html = rail(&props).into_string();
        assert!(html.contains("<div class=\"rail-cap\">proven facts</div>"));
        assert!(html.contains("internet-reachable: <code>web</code>"));
        assert!(html.contains("reaches a target by <b>mounts (direct read)</b>"));
        assert!(html.contains("no KEV or critical CVE"));
    }

    #[test]
    fn rail_cve_fact_reports_real_counts() {
        let props = RailProps {
            entry_short: "web".into(),
            relations: vec![],
            cve: CveFact::Present {
                n: 3,
                critical: 2,
                kev: 1,
            },
        };
        let html = rail(&props).into_string();
        assert!(html.contains("CVE present: <b>3</b> known vulns"));
        assert!(html.contains("2 critical, 1 KEV-listed"));
    }

    #[test]
    fn rail_escapes_an_untrusted_entry_name() {
        let props = RailProps {
            entry_short: "<img src=x>".into(),
            relations: vec![],
            cve: CveFact::None,
        };
        let html = rail(&props).into_string();
        assert!(!html.contains("<img"), "raw tag must not survive: {html}");
        assert!(html.contains("&lt;img"), "entry name escaped: {html}");
    }

    /// ADR-0019 boundary guard: the rail component takes only its props.
    #[test]
    fn rail_imports_no_engine_domain_type() {
        let _: fn(&RailProps) -> Markup = rail;
    }
}
