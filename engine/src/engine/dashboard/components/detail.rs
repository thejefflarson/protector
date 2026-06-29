//! The expanded ENDPOINT-DETAIL renderer (JEF-255): the "why" surface revealed when a dense
//! row expands — the verbatim model verdict (+ a raw-prompt expander), the proof/certainty
//! rail, the evidence blocks, the text hop-list, and the posture-gated what-to-do. Pure
//! `DetailProps -> Markup`; no `engine::` domain type (ADR-0019). The verdict prose, the raw
//! prompt, and every node name are auto-escaped at the maud brace.

use maud::{Markup, html};

use crate::engine::dashboard::components::{evidence, hops};
use crate::engine::dashboard::view_model::entry::{DetailProps, Rail};

/// Render the detail body (the content of the expandable detail `<tr>`'s cell).
pub fn detail(p: &DetailProps) -> Markup {
    html! {
        div class="detail" {
            // The verbatim model verdict IS the "why" surface — no separate tab. Shown as the
            // model's own words; the raw prompt that produced them sits behind an expander.
            div class=(format!("verdict {}", p.posture.tone())) {
                b { "verdict: " } (p.verdict)
            }
            @if let Some(prompt) = &p.raw_prompt {
                details class="rawprompt" {
                    summary { "raw model prompt" }
                    pre { (prompt) }
                }
            }
            (rail(&p.rail))
            (evidence::evidence_blocks(&p.evidence))
            div class="path" {
                h4 { "Attack path" }
                (hops::hops(&p.hops))
            }
            @if let Some(todo) = &p.what_to_do {
                div class="todo" {
                    b { "What to do: " } (todo)
                }
            }
        }
    }
}

/// The proof / certainty rail — the deterministic facts that bound the model's call.
fn rail(r: &Rail) -> Markup {
    html! {
        ul class="rail" aria-label="proof and certainty" {
            li class="ok" { "✔ proven-reachable (deterministic chain)" }
            @if r.internet_facing {
                li class="ok" { "✔ internet-facing front door" }
            } @else {
                li class="muted" { "internal reach only (assume-breach path)" }
            }
            @if r.corroborated {
                li class="hot" { "✔ live-corroborated (a runtime signal fired)" }
            } @else {
                li class="muted" { "no live corroboration this pass" }
            }
            li class="muted" {
                "reaches " b { (r.objectives) }
                " objective" (plural(r.objectives))
            }
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::evidence::EvidenceBlocks;
    use crate::engine::dashboard::view_model::hops::{Hop, HopList};
    use crate::engine::dashboard::view_model::posture::Posture;

    fn props(posture: Posture, prompt: Option<&str>, todo: Option<&str>) -> DetailProps {
        DetailProps {
            detail_id: "detail-web".into(),
            posture,
            verdict: "exploitable — RCE via CVE-2021-44228".into(),
            raw_prompt: prompt.map(str::to_string),
            rail: Rail {
                proven: true,
                corroborated: true,
                internet_facing: true,
                objectives: 2,
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
            what_to_do: todo.map(str::to_string),
        }
    }

    #[test]
    fn detail_has_verdict_rail_evidence_hops() {
        let m = detail(&props(
            Posture::Breach,
            Some("PROMPT TEXT"),
            Some("arm network"),
        ))
        .into_string();
        assert!(m.contains("verdict:"));
        assert!(m.contains("exploitable — RCE via CVE-2021-44228"));
        assert!(m.contains("raw model prompt"));
        assert!(m.contains("PROMPT TEXT"));
        assert!(m.contains("proven-reachable"));
        assert!(m.contains("live-corroborated"));
        assert!(m.contains("Attack path"));
        assert!(m.contains("✂ cut here"));
        assert!(m.contains("What to do:"));
    }

    #[test]
    fn no_prompt_no_expander() {
        let m = detail(&props(Posture::Safe, None, None)).into_string();
        assert!(!m.contains("raw model prompt"));
        assert!(!m.contains("What to do:"));
    }

    #[test]
    fn raw_prompt_is_escaped() {
        let m = detail(&props(Posture::Breach, Some("<script>x</script>"), None)).into_string();
        assert!(!m.contains("<script>x"));
        assert!(m.contains("&lt;script&gt;"));
    }
}
