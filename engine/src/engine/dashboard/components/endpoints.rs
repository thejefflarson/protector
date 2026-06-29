//! The dense ENDPOINTS table — the core of the v2 page (JEF-255). One row per exposed entry:
//! posture chip · `entry → reaches` · the decisive verdict clause · evidence glyphs · Δ · age.
//! Each row EXPANDS (a row-toggle `<button aria-controls>` over a hidden detail `<tr>`, the
//! valid-table idiom the page JS persists) to the [`detail`] body. Pure
//! `Props -> Markup`; no `engine::` domain type (ADR-0019).

use maud::{Markup, html};

use crate::engine::dashboard::components::{chips, detail, evidence};
use crate::engine::dashboard::view_model::entry::{DetailProps, RowProps};

/// The number of columns in the dense table — the detail `<tr>` spans all of them.
pub const COLS: usize = 6;

/// Render the whole endpoints table from the per-entry (row, detail) prop pairs, already
/// ordered by the caller (breach first). Renders an honest empty state when there are none.
pub fn endpoints_table(rows: &[(RowProps, DetailProps)]) -> Markup {
    html! {
        table class="endpoints" {
            thead {
                tr {
                    th { "posture" }
                    th { "endpoint → reaches" }
                    th { "model verdict" }
                    th { "evidence" }
                    th { "Δ" }
                    th { "age" }
                }
            }
            tbody {
                @if rows.is_empty() {
                    tr {
                        td colspan=(COLS) class="muted" {
                            "no internet-facing service can reach a target"
                        }
                    }
                } @else {
                    @for (row, det) in rows {
                        (endpoint_rows(row, det))
                    }
                }
            }
        }
    }
}

/// One endpoint: the summary `<tr>` (clickable to expand) plus its hidden detail `<tr>`.
pub fn endpoint_rows(row: &RowProps, det: &DetailProps) -> Markup {
    html! {
        tr class=(format!("ep-row {}", row.posture.tone())) {
            td {
                button class="row-toggle" type="button"
                    aria-expanded="false" aria-controls=(row.detail_id) {
                    (chips::posture_chip(row.posture.label(), row.posture.tone()))
                }
            }
            td class="ep-reach" {
                b { (row.entry) } " "
                span class="arrow" aria-hidden="true" { "→" }
                " " (row.reaches)
            }
            td class="ep-clause" {
                @if row.clause.is_empty() {
                    span class="muted" { "not yet judged" }
                } @else {
                    (row.clause)
                }
            }
            td class="ep-evidence" { (evidence::glyph_strip(&row.glyphs)) }
            td class="ep-delta" {
                @if let Some(d) = &row.delta {
                    span class="delta" aria-label=(d.aria) { (d.glyph) }
                } @else {
                    span class="muted" aria-hidden="true" { "·" }
                }
            }
            td class="ep-age" {
                @if let Some(age) = &row.age { (age) } @else { span class="muted" { "—" } }
            }
        }
        tr id=(row.detail_id) class="ep-detail" hidden {
            td colspan=(COLS) { (detail::detail(det)) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::entry::{DeltaCell, Rail};
    use crate::engine::dashboard::view_model::evidence::{EvidenceBlocks, GlyphStrip};
    use crate::engine::dashboard::view_model::hops::HopList;
    use crate::engine::dashboard::view_model::posture::Posture;

    fn pair(posture: Posture, clause: &str) -> (RowProps, DetailProps) {
        (
            RowProps {
                detail_id: "detail-web".into(),
                posture,
                entry: "Pod/web".into(),
                reaches: "session-key".into(),
                clause: clause.into(),
                glyphs: GlyphStrip {
                    kev: true,
                    ..Default::default()
                },
                delta: Some(DeltaCell {
                    glyph: "NEW".into(),
                    aria: "new this pass".into(),
                }),
                age: Some("12s".into()),
            },
            DetailProps {
                detail_id: "detail-web".into(),
                posture,
                verdict: clause.into(),
                raw_prompt: None,
                rail: Rail {
                    proven: true,
                    corroborated: false,
                    internet_facing: true,
                    objectives: 1,
                },
                evidence: EvidenceBlocks::default(),
                hops: HopList {
                    entry: "Pod/web".into(),
                    internet_reachable: true,
                    hops: vec![],
                    cut_note: None,
                },
                what_to_do: None,
            },
        )
    }

    #[test]
    fn empty_table_has_honest_empty_state() {
        let m = endpoints_table(&[]).into_string();
        assert!(m.contains("no internet-facing service can reach a target"));
    }

    #[test]
    fn row_carries_posture_reach_clause_and_expands_to_detail() {
        let p = pair(Posture::Breach, "exploitable — RCE");
        let m = endpoints_table(std::slice::from_ref(&p)).into_string();
        assert!(m.contains("BREACH"));
        assert!(m.contains("Pod/web"));
        assert!(m.contains("session-key"));
        assert!(m.contains("exploitable — RCE"));
        assert!(m.contains("KEV"));
        assert!(m.contains("NEW"));
        // The detail row is present, hidden, and controlled by the toggle.
        assert!(m.contains(r#"aria-controls="detail-web""#));
        assert!(m.contains(r#"id="detail-web" class="ep-detail" hidden"#));
    }

    #[test]
    fn awaiting_row_shows_not_yet_judged() {
        let mut p = pair(Posture::Awaiting, "");
        p.0.delta = None;
        let m = endpoints_table(std::slice::from_ref(&p)).into_string();
        assert!(m.contains("not yet judged"));
        assert!(m.contains("awaiting"));
    }
}
