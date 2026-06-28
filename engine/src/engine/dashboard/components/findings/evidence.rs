//! The two ADR-0016 evidence blocks (JEF-133): the CVE block (severity/reachability input)
//! and the runtime-alert block (live corroboration), wrapped as one "evidence for this path"
//! section. Pure `Props -> Markup`; imports only its props + maud + `components::chips`. NO
//! `engine::` domain type.

use crate::engine::dashboard::view_model::findings::{
    CveBlockProps, CveRow, EvidenceProps, FindingBlockProps, FindingRow, RuntimeBlockProps,
};
use maud::{Markup, html};

/// One CVE list item: id, a severity chip, the CVSS score (JEF-242), KEV/reachability/fix,
/// and the title when present. All free-text (title) rides an auto-escaping maud brace — it
/// is untrusted third-party data. The severity uses the card's chip idiom (`chip {tone}`),
/// distinct from the shared `chips::severity_badge` (`badge {tone}`), kept for byte-stability.
fn cve_li(c: &CveRow) -> Markup {
    html! {
        li {
            code { (c.id) } " "
            span class=(format!("chip {}", c.severity_tone)) { (c.severity) }
            @if let Some(s) = &c.score { " " span class="muted" { "CVSS " (s) } }
            @if c.kev { " " span class="kev" title="CISA Known-Exploited" { "KEV" } }
            " " span class="muted" { "reachability: " (c.reachability) " · " (c.fix) }
            @if let Some(t) = &c.title { @if !t.is_empty() { " — " (t) } }
        }
    }
}

/// The CVE evidence block (JEF-133): a count + per-severity tally summary, the inline top-N,
/// and the rest behind a "show all" expander. `None` props ⇒ the honest-empty state.
fn cve_block(block: Option<&CveBlockProps>) -> Markup {
    match block {
        None => html! {
            div class="ev ev-cve" {
                div class="ev-cap" {
                    "CVEs " span class="muted" { "— how bad it would be if exploited" }
                }
                div class="muted" {
                    "none on this service's image "
                    span class="muted" { "(KEV or critical; lower-severity CVEs not shown)" }
                }
            }
        },
        Some(b) => {
            let tally: Vec<String> = b.tally.iter().map(|(s, n)| format!("{n} {s}")).collect();
            html! {
                div class="ev ev-cve" {
                    div class="ev-cap" {
                        "CVEs " span class="muted" { "— how bad it would be if exploited" }
                    }
                    div class="ev-sum" {
                        b { (b.n) } " CVE"
                        @if b.n != 1 { "s" }
                        " " span class="muted" { "(" (tally.join(", ")) ")" }
                    }
                    ul {
                        @for c in &b.inline { (cve_li(c)) }
                    }
                    @if !b.rest.is_empty() {
                        details {
                            summary { "show all " (b.n) " CVEs" }
                            ul {
                                @for c in &b.rest { (cve_li(c)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The runtime-alert block (JEF-133): corroborating Falco alerts first ("SEEN LIVE"), then
/// the non-corroborating agent behaviors as context behind a `<details>`. Honest-empty when
/// nothing was seen.
fn runtime_block(rt: &RuntimeBlockProps) -> Markup {
    html! {
        div class="ev ev-runtime" {
            div class="ev-cap" {
                "live activity " span class="muted" { "— is it being exploited right now" }
            }
            @if rt.corroborating.is_empty() && rt.context.is_empty() {
                div class="muted" {
                    "no live activity seen on this service "
                    span class="muted" { "(no Falco alert, no agent behavior attributed)" }
                }
            } @else {
                @if rt.corroborating.is_empty() {
                    div class="muted" {
                        "nothing seen happening live "
                        "(no live activity backs this up as being exploited now)"
                    }
                } @else {
                    ul {
                        @for c in &rt.corroborating {
                            li { span class="chip chip-breach" { "SEEN LIVE" } " " (c) }
                        }
                    }
                }
                @if !rt.context.is_empty() {
                    details {
                        summary {
                            (rt.context.len()) " agent behavior"
                            @if rt.context.len() != 1 { "s" }
                            " (background, not seen exploited)"
                        }
                        ul {
                            @for (variant, summary) in &rt.context {
                                li { span class="muted" { "[" (variant) "]" } " " (summary) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One non-CVE findings list item (JEF-244): id, a severity chip, the category, and the
/// untrusted title — the title rides an auto-escaping maud brace (third-party scanner text).
fn finding_li(f: &FindingRow) -> Markup {
    html! {
        li {
            code { (f.id) } " "
            span class=(format!("chip {}", f.severity_tone)) { (f.severity) }
            @if let Some(c) = &f.category { " " span class="muted" { "(" (c) ")" } }
            @if let Some(t) = &f.title { @if !t.is_empty() { " — " (t) } }
        }
    }
}

/// A non-CVE findings block (JEF-244): a captioned count + list. Rendered only when present
/// (`None` ⇒ nothing) — the CVE + runtime blocks already carry the entry's honest-empty
/// narrative, so an absent scanner report adds no noise. `cap` is the human caption and `cls`
/// the block's CSS class so the exploitation-grade exposed-secret block reads distinctly from
/// the static-posture blocks.
fn finding_block(block: Option<&FindingBlockProps>, cls: &str, cap: &str, note: &str) -> Markup {
    match block {
        None => html! {},
        Some(b) => html! {
            div class=(format!("ev {cls}")) {
                div class="ev-cap" { (cap) " " span class="muted" { "— " (note) } }
                div class="ev-sum" {
                    b { (b.n) } " finding"
                    @if b.n != 1 { "s" }
                }
                ul {
                    @for f in &b.rows { (finding_li(f)) }
                }
            }
        },
    }
}

/// Both ADR-0016 evidence blocks wrapped as one "evidence for this path" section (JEF-133):
/// CVEs (severity input) then runtime alerts (live corroboration), each with its own honest
/// empty state — plus the JEF-244 scanner-finding blocks (exposed secrets first, as
/// exploitation-grade exposure, then the static-posture misconfig / RBAC blocks) when present.
pub fn evidence(props: &EvidenceProps) -> Markup {
    html! {
        div class="evidence" {
            div class="ev-head" { "evidence for this path" }
            (cve_block(props.cve.as_ref()))
            (finding_block(
                props.exposed_secrets.as_ref(),
                "ev-secret",
                "exposed secrets",
                "a usable credential baked into the image (exploitation evidence)",
            ))
            (runtime_block(&props.runtime))
            (finding_block(
                props.misconfigs.as_ref(),
                "ev-misconfig",
                "misconfigurations",
                "config-audit checks that failed (how severe a fix would be)",
            ))
            (finding_block(
                props.rbac_findings.as_ref(),
                "ev-rbac",
                "RBAC exposure",
                "role checks that failed (structural authorization breadth)",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{CveEvidence, EntryEvidence};
    use crate::engine::dashboard::view_model::findings::{cve_block_props, runtime_block_props};
    use crate::engine::graph::{Behavior, Reachability, Severity, Vulnerability};

    fn cve(id: &str, severity: Severity, kev: bool) -> CveEvidence {
        CveEvidence::from_vuln(&Vulnerability {
            id: id.into(),
            severity,
            exploited_in_wild: kev,
            reachability: Reachability::NotObserved,
            ..Default::default()
        })
    }

    fn block(ev: &EntryEvidence) -> String {
        cve_block(cve_block_props(ev).as_ref()).into_string()
    }

    fn runtime(ev: &EntryEvidence) -> String {
        runtime_block(&runtime_block_props(ev)).into_string()
    }

    fn finding(
        id: &str,
        severity: &str,
        title: &str,
    ) -> crate::engine::dashboard::model::FindingEvidence {
        crate::engine::dashboard::model::FindingEvidence::from_finding(
            &crate::engine::graph::ScanFinding {
                id: id.into(),
                severity: match severity {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                },
                category: None,
                title: Some(title.into()),
                target: None,
                sources: vec![],
            },
        )
    }

    fn full(ev: &EntryEvidence) -> String {
        evidence(&crate::engine::dashboard::view_model::findings::evidence_props(ev)).into_string()
    }

    #[test]
    fn jef244_finding_blocks_render_with_their_calibrated_captions() {
        let ev = EntryEvidence {
            exposed_secrets: vec![finding(
                "aws-access-key-id",
                "critical",
                "AWS_ACCESS_KEY_ID=*****",
            )],
            misconfigs: vec![finding("KSV017", "high", "Privileged container")],
            rbac_findings: vec![finding("KSV041", "critical", "Manage secrets")],
            ..Default::default()
        };
        let html = full(&ev);
        // Exposed-secret block: exploitation-grade caption + the redacted match (not a value).
        assert!(html.contains("exposed secrets"), "secret caption: {html}");
        assert!(html.contains("exploitation evidence"));
        assert!(html.contains("aws-access-key-id"));
        assert!(html.contains("AWS_ACCESS_KEY_ID=*****"));
        // Misconfig + RBAC blocks render as static posture.
        assert!(html.contains("misconfigurations"));
        assert!(html.contains("KSV017"));
        assert!(html.contains("RBAC exposure"));
        assert!(html.contains("KSV041"));
    }

    #[test]
    fn jef244_absent_finding_reports_render_nothing() {
        // No scanner reports ⇒ no finding blocks at all (the CVE/runtime blocks carry the
        // honest-empty narrative; absent reports must not add empty noise).
        let html = full(&EntryEvidence::default());
        assert!(!html.contains("exposed secrets"));
        assert!(!html.contains("misconfigurations"));
        assert!(!html.contains("RBAC exposure"));
    }

    #[test]
    fn jef244_finding_title_is_html_escaped() {
        let ev = EntryEvidence {
            misconfigs: vec![finding("KSV017", "high", "<img src=x onerror=alert(1)>")],
            ..Default::default()
        };
        let html = full(&ev);
        assert!(!html.contains("<img"), "raw tag must not survive: {html}");
        assert!(html.contains("&lt;img"), "title HTML-escaped: {html}");
    }

    #[test]
    fn cve_block_summarizes_count_and_top_severities() {
        let ev = EntryEvidence {
            cves: vec![
                cve("CVE-2021-0001", Severity::Critical, true),
                cve("CVE-2021-0002", Severity::High, false),
                cve("CVE-2021-0003", Severity::Critical, false),
            ],
            runtime: vec![],
            ..Default::default()
        };
        let html = block(&ev);
        assert!(html.contains("<b>3</b> CVEs"), "count: {html}");
        assert!(
            html.contains("2 critical, 1 high"),
            "tally worst-first: {html}"
        );
        assert!(html.contains("CVE-2021-0001"));
        assert!(html.contains("reachability: not-observed"));
        assert!(html.contains(">KEV<"), "KEV badge: {html}");
        assert!(html.contains("how bad it would be if exploited"));
    }

    #[test]
    fn cve_block_lists_long_sets_behind_a_details_expander() {
        let ev = EntryEvidence {
            cves: (0..7)
                .map(|i| cve(&format!("CVE-2021-000{i}"), Severity::High, false))
                .collect(),
            runtime: vec![],
            ..Default::default()
        };
        let html = block(&ev);
        assert!(
            html.contains("<details><summary>show all 7 CVEs"),
            "expander: {html}"
        );
        for i in 0..7 {
            assert!(
                html.contains(&format!("CVE-2021-000{i}")),
                "CVE {i} present"
            );
        }
    }

    #[test]
    fn cve_block_empty_state_is_honest_not_implied_absent() {
        let html = block(&EntryEvidence::default());
        assert!(
            html.contains("none on this service's image"),
            "honest none: {html}"
        );
        assert!(html.contains("how bad it would be if exploited"));
        assert!(!html.contains("<ul>"), "no empty list: {html}");
    }

    #[test]
    fn cve_block_renders_cvss_score_and_title() {
        // JEF-242: the CVSS score trivy reports surfaces alongside the title and fix; the
        // retired advisory CWE block is gone. Score formats to one decimal.
        let mut v = Vulnerability {
            id: "CVE-2021-44228".into(),
            severity: Severity::Critical,
            exploited_in_wild: true,
            reachability: Reachability::NotObserved,
            ..Default::default()
        };
        v.title = Some("Log4Shell remote code execution".into());
        v.score = Some(10.0);
        v.fixed_version = Some("2.17.0".into());
        v.installed_version = Some("2.14.0".into());
        let html = block(&EntryEvidence {
            cves: vec![CveEvidence::from_vuln(&v)],
            runtime: vec![],
            ..Default::default()
        });
        assert!(html.contains("CVSS 10.0"), "cvss score surfaced: {html}");
        assert!(html.contains("Log4Shell"), "title surfaced: {html}");
        assert!(
            html.contains("fix available: 2.14.0 to 2.17.0"),
            "fix phrasing: {html}"
        );
    }

    #[test]
    fn cve_li_escapes_an_untrusted_title() {
        let mut v = Vulnerability {
            id: "CVE-2021-9999".into(),
            severity: Severity::High,
            exploited_in_wild: false,
            reachability: Reachability::NotObserved,
            ..Default::default()
        };
        v.title = Some("<img src=x onerror=alert(1)>".into());
        let html = block(&EntryEvidence {
            cves: vec![CveEvidence::from_vuln(&v)],
            runtime: vec![],
            ..Default::default()
        });
        assert!(!html.contains("<img"), "raw tag must not survive: {html}");
        assert!(html.contains("&lt;img"), "title HTML-escaped: {html}");
    }

    #[test]
    fn runtime_block_separates_corroborating_alerts_from_context() {
        let ev = EntryEvidence {
            cves: vec![],
            runtime: vec![
                Behavior::Alert {
                    rule: "Terminal shell in container".into(),
                },
                Behavior::NetworkConnection {
                    peer: "10.0.0.5".into(),
                    internet: false,
                },
            ],
            ..Default::default()
        };
        let html = runtime(&ev);
        assert!(html.contains("SEEN LIVE"), "alert seen live: {html}");
        assert!(html.contains("Terminal shell in container"));
        assert!(
            html.contains("1 agent behavior (background, not seen exploited)"),
            "{html}"
        );
        assert!(html.contains("connects to 10.0.0.5"));
        assert!(html.contains("is it being exploited right now"));
    }

    #[test]
    fn runtime_block_empty_state_is_honest() {
        let html = runtime(&EntryEvidence::default());
        assert!(
            html.contains("no live activity seen on this service"),
            "{html}"
        );
        assert!(html.contains("is it being exploited right now"));
        assert!(!html.contains("SEEN LIVE"));
    }

    #[test]
    fn runtime_block_behaviors_without_an_alert_read_as_context_only() {
        let ev = EntryEvidence {
            cves: vec![],
            runtime: vec![Behavior::SecretRead {
                secret: "db-password".into(),
            }],
            ..Default::default()
        };
        let html = runtime(&ev);
        assert!(!html.contains("SEEN LIVE"), "no false live signal: {html}");
        assert!(html.contains("nothing seen happening live"));
        assert!(html.contains("reads secret db-password"));
    }

    /// ADR-0019 boundary guard: the evidence components take only their props.
    #[test]
    fn evidence_imports_no_engine_domain_type() {
        let _: fn(&EvidenceProps) -> Markup = evidence;
    }
}
