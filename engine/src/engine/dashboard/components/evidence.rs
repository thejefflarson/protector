//! The evidence tables for a finding's detail panel (brief §5): the CVE table
//! (id/sev/CVSS/KEV/EPSS/reachability/fix), the runtime split (corroborating vs context),
//! the exposed-secrets / misconfig / RBAC tables. Severity is the COOLER, subordinate channel
//! (style guide principle 2) — never as loud as posture. Empty blocks render an explicit "none"
//! (invariant #3). Pure component; no domain types; all free-text auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    BehaviorProps, CveProps, EvidenceProps, ScanProps,
};

/// Render all evidence tables for a finding. The whole-empty case is the honest "no evidence",
/// never a blank.
pub(super) fn evidence_tables(ev: &EvidenceProps) -> Markup {
    html! {
        section.detail-section.evidence-block {
            h3.detail-h { "evidence" }
            @if ev.is_empty() {
                p.evidence-none { "no evidence on this entry \u{2014} no CVEs, runtime signals, or scanner findings" }
            } @else {
                (cve_table(&ev.cves))
                (runtime_block(&ev.corroborating, &ev.context))
                (scan_table("exposed secrets", "exposed-secrets", &ev.exposed_secrets))
                (scan_table("misconfigurations", "misconfigs", &ev.misconfigs))
                (scan_table("RBAC findings", "rbac", &ev.rbac_findings))
            }
        }
    }
}

/// The CVE table — the subordinate severity channel, numerics right-aligned.
fn cve_table(cves: &[CveProps]) -> Markup {
    if cves.is_empty() {
        return html! {};
    }
    html! {
        div.ev-group {
            h4.detail-h { "CVEs" }
            table.ev-table {
                thead {
                    tr {
                        th { "id" } th { "sev" } th.num { "cvss" } th { "kev" }
                        th.num { "epss" } th { "reachability" } th { "fix" }
                    }
                }
                tbody {
                    @for c in cves {
                        tr {
                            td.mono { (c.id) }
                            td { span class={ "sev sev-" (c.severity) } { (c.severity) } }
                            td.num { (c.score.as_deref().unwrap_or("\u{2014}")) }
                            td {
                                @if c.kev { span.ev.ev-kev { "KEV" } } @else { span.muted { "\u{2014}" } }
                            }
                            td.num { (c.epss.as_deref().unwrap_or("\u{2014}")) }
                            td.mono { (c.reachability) }
                            td { (c.fix) }
                        }
                        @if let Some(title) = &c.title {
                            tr.ev-subrow { td colspan="7" { span.muted { (title) } } }
                        }
                    }
                }
            }
        }
    }
}

/// The runtime block: corroborating (alert) behaviors first, then context behaviors. Each is
/// labelled so a corroboration is distinguished from mere context (ADR-0016).
fn runtime_block(corroborating: &[BehaviorProps], context: &[BehaviorProps]) -> Markup {
    if corroborating.is_empty() && context.is_empty() {
        return html! {};
    }
    html! {
        div.ev-group {
            h4.detail-h { "runtime" }
            @if !corroborating.is_empty() {
                p.ev-sublabel { "corroborating (live)" }
                ul.behavior-list {
                    @for b in corroborating { (behavior_item(b)) }
                }
            }
            @if !context.is_empty() {
                p.ev-sublabel.muted { "context" }
                ul.behavior-list {
                    @for b in context { (behavior_item(b)) }
                }
            }
        }
    }
}

/// One runtime behavior line. The variant token + the (untrusted) summary.
fn behavior_item(b: &BehaviorProps) -> Markup {
    let cls = if b.corroborating {
        "behavior behavior-alert"
    } else {
        "behavior"
    };
    html! {
        li class=(cls) {
            span class={ "behavior-variant var-" (b.variant) } { (b.variant) }
            span.behavior-summary { (b.summary) }
        }
    }
}

/// A generic scanner-findings table (exposed secrets / misconfigs / RBAC). Empty groups render
/// nothing here (the whole-empty case is handled by the parent's "no evidence").
fn scan_table(title: &str, css: &str, findings: &[ScanProps]) -> Markup {
    if findings.is_empty() {
        return html! {};
    }
    html! {
        div class={ "ev-group ev-" (css) } {
            h4.detail-h { (title) }
            table.ev-table {
                thead { tr { th { "id" } th { "sev" } th { "category" } th { "detail" } } }
                tbody {
                    @for s in findings {
                        tr {
                            td.mono { (s.id) }
                            td { span class={ "sev sev-" (s.severity) } { (s.severity) } }
                            td { (s.category.as_deref().unwrap_or("\u{2014}")) }
                            td { (s.title.as_deref().unwrap_or("\u{2014}")) }
                        }
                    }
                }
            }
        }
    }
}
