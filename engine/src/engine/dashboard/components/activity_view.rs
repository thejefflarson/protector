//! The Activity (audit) view body (brief §6): the self-reverted-cuts log (a lifted cut + why +
//! age — the safety story, kept visible) and the judgement ring (the verbatim prompt/reply behind
//! each model call, for debugging). The Findings "show model prompt" deep-links here conceptually
//! (brief §4). Honest empty states for both. Pure component; no domain types; all free-text
//! auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    ActivityViewProps, JudgementEntryProps, ReversionProps,
};

/// Render the Activity view: the reversion log, then the judgement ring, each with its honest
/// empty state.
pub fn activity_view(v: &ActivityViewProps) -> Markup {
    html! {
        main.view.view-activity {
            (reversions_block(v))
            (judgements_block(v))
        }
    }
}

/// The self-reverted-cuts log — the safety story (ADR-0016: a cut self-reverts when the breach
/// condition lifts). Toned as the system working, kept visible so a lifted cut is never invisible.
fn reversions_block(v: &ActivityViewProps) -> Markup {
    html! {
        section.activity-section.reversions aria-label="self-reverted cuts" {
            h2.section-h.t-h2 { "self-reverted cuts" }
            p.section-sub.t-body.muted {
                "a cut stands only while the breach condition holds, then self-reverts \u{2014} the \
                 safety story, kept visible."
            }
            @if v.reversions.is_empty() {
                p.activity-empty.t-body.muted {
                    "no cuts have been lifted \u{2014} nothing has been applied-then-reverted yet."
                }
            } @else {
                ul.revert-list {
                    @for r in &v.reversions {
                        (reversion_entry(r))
                    }
                }
            }
        }
    }
}

/// One reversion: the lifted cut signature, why it lifted, and how long ago.
fn reversion_entry(r: &ReversionProps) -> Markup {
    html! {
        li.revert-entry {
            div.revert-head {
                span.revert-tag.t-micro {
                    span.glyph aria-hidden="true" { "\u{21BA}" } "reverted"
                }
                span.revert-age.t-micro.muted { (r.age) " ago" }
            }
            p.revert-cut { code { (r.cut) } }
            p.revert-reason.t-body { (r.reason) }
        }
    }
}

/// The judgement ring — the verbatim prompt/reply per model call, for debugging the model. Each
/// is a collapsed `<details>` (the prompt can be long); honest about an absent prompt/reply.
fn judgements_block(v: &ActivityViewProps) -> Markup {
    html! {
        section.activity-section.judgements aria-label="model judgement ring" {
            h2.section-h.t-h2 { "model judgements" }
            p.section-sub.t-body.muted {
                "the recent calls to the adjudicator \u{2014} the verbatim prompt and reply behind \
                 each verdict, for debugging the model."
            }
            @if v.judgements.is_empty() {
                p.activity-empty.t-body.muted {
                    "no judgements recorded \u{2014} the model has not been asked yet (warming, or no \
                     proven path reached it)."
                }
            } @else {
                ul.judgement-list {
                    @for (i, j) in v.judgements.iter().enumerate() {
                        (judgement_entry(i, j))
                    }
                }
            }
        }
    }
}

/// One judgement: a collapsed disclosure whose summary is the entry + verdict, opening to the
/// verbatim prompt and reply. Honest when the prompt (pre-filter decided) or reply (timeout) is
/// absent.
fn judgement_entry(i: usize, j: &JudgementEntryProps) -> Markup {
    let key = format!("judgement-{i}");
    html! {
        li.judgement-entry {
            details.model-prompt data-prompt=(key) {
                summary.why-toggle role="button" aria-expanded="false" {
                    span.judgement-entry-key.t-data-strong { (j.entry) }
                    span.judgement-entry-meta.t-micro.muted {
                        " \u{00B7} reaches " (j.objectives) " objective"
                        @if j.objectives != 1 { "s" }
                    }
                }
                div.prompt-body {
                    @match &j.verdict {
                        Some(verdict) => p.prompt-verdict.t-data { "final verdict: " span.mono { (verdict) } }
                        None => p.muted.t-data { "no verdict recorded for this call" }
                    }
                    h3.detail-h { "prompt" }
                    @match &j.prompt {
                        Some(p) => pre.prompt-text { (p) }
                        None => p.muted.t-data { "no prompt \u{2014} the deterministic pre-filter decided without asking the model" }
                    }
                    h3.detail-h { "reply" }
                    @match &j.reply {
                        Some(r) => pre.prompt-text { (r) }
                        None => p.muted.t-data { "no reply \u{2014} the model was unavailable (timed out)" }
                    }
                }
            }
        }
    }
}
