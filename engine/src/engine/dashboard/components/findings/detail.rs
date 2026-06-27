//! The dense findings table's EXPANDED detail body (JEF-202): the full finding card —
//! verdict-first (the verbatim model words lead), then the broad-reach lead, the certainty
//! rail, both ADR-0016 evidence blocks, the collapsed graph, the disposition "what to do",
//! and the fan-out expanders. Pure `Props -> Markup`; imports only its props + maud + sibling
//! findings components + `components::chips`. NO `engine::` domain type.

use crate::engine::dashboard::components::chips::posture_tag;
use crate::engine::dashboard::components::findings::evidence::evidence;
use crate::engine::dashboard::components::findings::graph::{fanout_expanders, graph};
use crate::engine::dashboard::components::findings::rail::rail;
use crate::engine::dashboard::view_model::findings::{BroadLead, DetailProps, Posture};
use maud::{Markup, html};

/// The posture chip + the model's verdict VERBATIM (never paraphrased — ADR-0013),
/// foregrounded above everything (JEF-161). When the model hasn't judged the entry, the chip
/// stands alone with a muted "the model hasn't reached this entry yet".
pub fn verdict_line(posture: Posture, verdict: Option<&str>) -> Markup {
    html! {
        div class="vline" {
            (posture_tag(posture.label(), posture.tone()))
            @match verdict {
                Some(v) => { " " span class="vwords" { (v) } }
                None => {
                    " " span class="muted" {
                        "the model hasn't reached this entry yet — paths below are proven, \
                         the breach call is pending"
                    }
                }
            }
        }
    }
}

/// The broad-reach lead (ADR-0016, the argocd case). The verbose reassurance prose is GONE
/// (JEF-200): a Safe + broad entry is the calm case (no lead, the row carries it); an
/// Awaiting + broad entry keeps a one-line honest note that the model hasn't finished.
fn broad_lead(lead: BroadLead) -> Markup {
    html! {
        @if let BroadLead::AwaitingNote = lead {
            p class="broad-lead" {
                "Broad reach — the model hasn't finished judging this one. Wide access \
                 isn't itself a break-in."
            }
        }
    }
}

/// The expandable card BODY for one endpoint (JEF-202): verdict-first, then the broad-reach
/// lead, the proof rail, both evidence blocks, the collapsed graph, the posture-gated "what to
/// do" (JEF-225 — present ONLY for a flagged breach; a non-breach finding renders no
/// remediation line), and the fan-out expanders (last — the legacy ordering).
pub fn detail(props: &DetailProps) -> Markup {
    html! {
        (verdict_line(props.posture, props.verdict.as_deref()))
        (broad_lead(props.broad_lead))
        (rail(&props.rail))
        (evidence(&props.evidence))
        (graph(&props.graph))
        @if let Some(todo) = &props.todo {
            div class="todo" { b { "what to do:" } " " (todo) }
        }
        (fanout_expanders(&props.graph.fanouts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_line_leads_with_the_posture_chip_and_verbatim_words() {
        let html = verdict_line(Posture::Safe, Some("not exploitable — RBAC")).into_string();
        assert_eq!(
            html,
            "<div class=\"vline\"><span class=\"chip chip-safe\">[SAFE]</span> \
             <span class=\"vwords\">not exploitable — RBAC</span></div>"
        );
        let awaiting = verdict_line(Posture::Awaiting, None).into_string();
        assert!(awaiting.contains("[awaiting judgement]"));
        assert!(awaiting.contains("hasn't reached this entry yet"));
    }

    #[test]
    fn verdict_line_escapes_an_untrusted_verdict() {
        let html =
            verdict_line(Posture::Breach, Some("<img src=x onerror=alert(1)>")).into_string();
        assert!(!html.contains("<img"), "raw tag must not survive: {html}");
        assert!(html.contains("&lt;img"), "verdict HTML-escaped: {html}");
    }

    /// ADR-0019 boundary guard: the detail component takes only its props.
    #[test]
    fn detail_imports_no_engine_domain_type() {
        let _: fn(&DetailProps) -> Markup = detail;
    }
}
