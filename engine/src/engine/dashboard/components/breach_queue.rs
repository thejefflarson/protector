//! The BREACH queue (JEF-255): the loud, decisive list of compromised entries — rendered
//! ONLY when there is at least one breach. Each item leads with the entry + the model's
//! decisive clause, then the what-to-do and the cut point (from the detail's hop-list). Pure
//! `Props -> Markup`; no `engine::` domain type (ADR-0019).

use maud::{Markup, html};

use crate::engine::dashboard::components::hops;
use crate::engine::dashboard::view_model::entry::{DetailProps, RowProps};

/// Render the breach queue from the breach (row, detail) pairs. Returns empty markup when
/// there are no breaches (the caller still calls it; the section simply renders nothing).
pub fn breach_queue(breaches: &[(RowProps, DetailProps)]) -> Markup {
    html! {
        @if !breaches.is_empty() {
            section class="breach-queue" aria-label="active breaches" {
                h2 class="breach-h" {
                    span class="chip p-breach" { (breaches.len()) " BREACH" }
                    " — act now"
                }
                @for (row, det) in breaches {
                    article class="breach-item" {
                        div class="breach-lead" {
                            b { (row.entry) }
                            " "
                            span class="arrow" aria-hidden="true" { "→" }
                            " " (row.reaches)
                        }
                        p class="breach-clause" { (det.verdict) }
                        @if let Some(todo) = &det.what_to_do {
                            p class="breach-todo" { b { "do: " } (todo) }
                        }
                        (hops::hops(&det.hops))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::entry::Rail;
    use crate::engine::dashboard::view_model::evidence::{EvidenceBlocks, GlyphStrip};
    use crate::engine::dashboard::view_model::hops::{Hop, HopList};
    use crate::engine::dashboard::view_model::posture::Posture;

    fn breach() -> (RowProps, DetailProps) {
        (
            RowProps {
                detail_id: "detail-web".into(),
                posture: Posture::Breach,
                entry: "Pod/web".into(),
                reaches: "session-key".into(),
                clause: "exploitable — RCE".into(),
                glyphs: GlyphStrip::default(),
                delta: None,
                age: None,
            },
            DetailProps {
                detail_id: "detail-web".into(),
                posture: Posture::Breach,
                verdict: "exploitable — RCE via CVE-2021-44228".into(),
                raw_prompt: None,
                rail: Rail {
                    proven: true,
                    corroborated: true,
                    internet_facing: true,
                    objectives: 1,
                },
                evidence: EvidenceBlocks::default(),
                hops: HopList {
                    entry: "Pod/web".into(),
                    internet_reachable: true,
                    hops: vec![Hop {
                        relation: "reaches".into(),
                        node: "Pod/store".into(),
                        is_cut: true,
                        is_objective: true,
                    }],
                    cut_note: Some("✂ cut here (arm network)".into()),
                },
                what_to_do: Some("arm the network class".into()),
            },
        )
    }

    #[test]
    fn no_breaches_renders_nothing() {
        assert_eq!(breach_queue(&[]).into_string(), "");
    }

    #[test]
    fn breach_item_is_loud_with_clause_todo_and_cut() {
        let b = breach();
        let m = breach_queue(std::slice::from_ref(&b)).into_string();
        assert!(m.contains("1 BREACH"));
        assert!(m.contains("act now"));
        assert!(m.contains("Pod/web"));
        assert!(m.contains("exploitable — RCE via CVE-2021-44228"));
        assert!(m.contains("arm the network class"));
        assert!(m.contains("✂ cut here (arm network)"));
    }
}
