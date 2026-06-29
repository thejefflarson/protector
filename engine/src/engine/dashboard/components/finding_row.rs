//! One Findings-table row: the posture rail+chip, entry→objective, Δ, evidence cluster,
//! disposition, and the live/judged sub-tag — with the expand-in-place `<details>` "why" panel
//! (brief §5). Pure component; no domain types. The row is a real `<tr>` and the expander is a
//! `<button>` with `aria-expanded` (style guide accessibility gate §6).

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    DeltaProps, EvidenceSummary, FindingProps, LiveTag, Posture,
};

use super::finding_detail::detail_panel;

/// Render one finding as a `<tr>` (the summary cells) followed by a full-width `<tr>` carrying
/// the expand-in-place detail panel inside a `<details>` (so list context is kept on expand).
pub(super) fn finding_row(f: &FindingProps) -> Markup {
    html! {
        tr.row id=(f.id) data-posture=(f.posture.token()) {
            td.cell.cell-delta { (delta_cell(&f.delta)) }
            td.cell.cell-posture { (posture_cell(f.posture, f.live_tag)) }
            td.cell.cell-entry { (entry_objective(f)) }
            td.cell.cell-path { (path_summary(f)) }
            td.cell.cell-evidence { (evidence_cluster(&f.evidence_summary)) }
            td.cell.cell-disposition { span.disp { (f.disposition) } }
            td.cell.cell-live { (live_tag(f.live_tag)) }
        }
        tr.row-detail {
            td.detail-host colspan="7" {
                details.why data-finding=(f.id) {
                    summary.why-toggle role="button" aria-expanded="false" {
                        span.why-open { "why \u{2014} verdict, path, evidence" }
                    }
                    (detail_panel(f))
                }
            }
        }
    }
}

/// The Δ cell — an alarm glyph for a change, or the muted age for a steady entry (never an
/// alarm for steady state).
fn delta_cell(d: &DeltaProps) -> Markup {
    match d.token() {
        Some(token) => html! {
            span class={ "delta delta-" (token) } title=(d.label()) {
                span.glyph { (d.glyph()) }
            }
        },
        None => {
            // Steady: show the age, muted — not an alarm.
            let age = match d {
                DeltaProps::Unchanged { age: Some(a) } => a.clone(),
                _ => "\u{2014}".to_string(),
            };
            html! { span.delta.delta-steady title=(d.label()) { (age) } }
        }
    }
}

/// The posture cell: a coloured rail + chip carrying colour + glyph + word. Uncertain &
/// awaiting are texturally distinct (dashed/dotted rails) and never green.
fn posture_cell(p: Posture, _tag: LiveTag) -> Markup {
    html! {
        span class={ "posture rail-" (p.token()) } {
            span class={ "posture-chip chip-" (p.token()) } {
                span.glyph { (p.glyph()) }
                span.posture-word { (p.word()) }
            }
        }
    }
}

/// Entry → objective, with the entry node-kind glyph (🌐 for an internet foothold) and the
/// fan-out collapse (`→ ×N`) when the entry reaches many objectives.
fn entry_objective(f: &FindingProps) -> Markup {
    html! {
        span.eo {
            span.entry {
                span.kind-glyph { (f.entry_glyph) }
                span.entry-label { (f.entry) }
            }
            span.arrow { " \u{2192} " }
            @match f.fanout {
                Some(n) => span.objective.fanout { "\u{00D7}" (n) " reachable" }
                None => span.objective { (f.objective) }
            }
        }
    }
}

/// A one-line path summary for the row (the full hop-list lives in the detail panel): the
/// entry, an arrow, and the objective, with the cut marker if a cut exists.
fn path_summary(f: &FindingProps) -> Markup {
    html! {
        span.path-summary {
            (f.entry)
            span.hop-arrow { " \u{2500}\u{2192} " }
            @if f.cut.is_some() {
                span.cut-mark title="severable here" { "\u{2702}" }
                " "
            }
            (f.objective)
        }
    }
}

/// The compact evidence cluster glyphs (CVE count + KEV + runtime alerts + secrets). Empty
/// evidence renders an explicit "no evidence" — never a blank (invariant #3).
fn evidence_cluster(s: &EvidenceSummary) -> Markup {
    if s.is_empty() {
        return html! { span.evidence-none { "no evidence" } };
    }
    html! {
        span.evidence-cluster {
            @if s.kev {
                span.ev.ev-kev { "KEV" }
            }
            @if s.cve_count > 0 {
                span.ev.ev-cve { (s.cve_count) " CVE" @if s.cve_count != 1 { "s" } }
            }
            @if s.runtime_alerts > 0 {
                span.ev.ev-runtime { span.glyph { "\u{26A1}" } (s.runtime_alerts) }
            }
            @if s.exposed_secrets > 0 {
                span.ev.ev-secret { span.glyph { "\u{1F511}" } (s.exposed_secrets) }
            }
        }
    }
}

/// The live/judged sub-tag, or an em-dash when neither applies.
fn live_tag(tag: LiveTag) -> Markup {
    match tag {
        LiveTag::Live => html! { span.subtag.subtag-live { "live" } },
        LiveTag::Judged => html! { span.subtag.subtag-judged { "judged" } },
        LiveTag::None => html! { span.subtag.subtag-none { "\u{2014}" } },
    }
}
