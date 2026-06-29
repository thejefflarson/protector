//! The **Action** view body (brief §4/§6) — the engine's whole action story, the merged Trust +
//! Activity tabs, laid out in LIFECYCLE order as three stacked sections:
//!
//! 1. **Proposed cuts** — the lifecycle of a would-be cut: the still-standing would-act proposals
//!    (each classified open / short-lived / coverage-gap) AND the cuts that were applied then
//!    self-reverted (reason + age — the safety story, kept visible). Honest empties: a journal with
//!    no history reads differently from "none in this window"; "no cuts reverted yet" stands on its
//!    own.
//! 2. **Left alone (cleared)** — proven paths the model deliberately cleared (the trust half).
//! 3. **Judgement audit (model debug)** — the verbatim prompt/reply behind each model call, as
//!    collapsed disclosures (where Findings' "show model prompt" conceptually deep-links).
//!
//! Pure component; no domain types; all free-text auto-escaped (invariant #6).

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    ActionViewProps, JudgementEntryProps, LeftAloneProps, ReversionProps, WouldActProps,
};

/// Render the Action view: the headline summary, then the three lifecycle sections in order.
pub fn action_view(v: &ActionViewProps) -> Markup {
    html! {
        main.view.view-action {
            (action_headline(v))
            (proposed_cuts_section(v))
            (left_alone_section(v))
            (judgement_audit_section(v))
        }
    }
}

/// The headline: the window, the proposed-cut count (with the short-lived / coverage-gap / reverted
/// subsets), and the left-alone count — the arm/don't-arm summary at a glance. Counts honest at zero.
fn action_headline(v: &ActionViewProps) -> Markup {
    html! {
        section.trust-summary aria-label="action summary" {
            h2.section-h.t-h2 { "action \u{2014} last " (v.window_human) }
            p.section-sub.t-body.muted {
                "in shadow the engine only proposes; this is the whole action story \u{2014} what it \
                 WOULD have cut (and what self-reverted), what it proved out and left alone, and the \
                 model judgements behind each call."
            }
            div.trust-counts {
                span.count.count-wouldact.t-data-strong {
                    (v.would_act_count) " would have cut"
                }
                @if v.short_lived_count > 0 {
                    span.count.count-shortlived.t-data {
                        (v.short_lived_count) " likely false positive"
                    }
                }
                @if v.coverage_gap_count > 0 {
                    span.count.count-covgap.t-data {
                        (v.coverage_gap_count) " scrutinise first"
                    }
                }
                @if v.reverted_count > 0 {
                    span.count.count-leftalone.t-data {
                        (v.reverted_count) " self-reverted"
                    }
                }
                span.count.count-leftalone.t-data { (v.left_alone_count) " left alone" }
            }
        }
    }
}

/// Section 1 — **Proposed cuts**: the lifecycle of a would-be cut. The still-standing would-act
/// proposals first (sustained-first, each classified), then the cuts that self-reverted. Honest
/// journal-empty state (no history at all) is distinct from "none in this window".
fn proposed_cuts_section(v: &ActionViewProps) -> Markup {
    html! {
        section.activity-section.action-proposed aria-label="proposed cuts" {
            h2.section-h.t-h2 { "proposed cuts" }
            p.section-sub.t-body.muted {
                "the lifecycle of a would-be cut \u{2014} what the engine would sever now, and the \
                 cuts that stood briefly then self-reverted when the breach condition lifted."
            }
            @if v.journal_empty {
                (journal_empty_state())
            } @else {
                (would_act_block(v))
                (reverted_block(v))
            }
        }
    }
}

/// The "would cut" half of section 1 — sustained-first, each entry classified (open / short-lived /
/// coverage-gap). Honest "none in window" when empty (the journal has history, just nothing here).
fn would_act_block(v: &ActionViewProps) -> Markup {
    html! {
        @if v.would_act.is_empty() {
            p.col-empty.t-body.muted {
                "none in the last " (v.window_human)
                " \u{2014} no path reached an exploitable verdict in this window."
            }
        } @else {
            ul.trust-list {
                @for w in &v.would_act {
                    (would_act_entry(w))
                }
            }
        }
    }
}

/// One would-act entry: the entry key, its lifecycle status tags (colour + glyph + word), the
/// frequency/lifetime, and the model's verbatim "why it would have cut".
fn would_act_entry(w: &WouldActProps) -> Markup {
    html! {
        li.trust-entry data-open=(w.open) {
            div.trust-entry-head {
                span.trust-entry-key.t-data-strong { (w.entry) }
                (would_act_tags(w))
            }
            p.trust-entry-meta.t-micro.muted {
                (w.episodes) " episode" @if w.episodes != 1 { "s" }
                " \u{00B7} " (w.would_act_decisions) " affirming decision"
                @if w.would_act_decisions != 1 { "s" }
                " \u{00B7} longest " (w.max_lifetime)
            }
            p.trust-entry-verdict.t-data { (w.last_verdict) }
        }
    }
}

/// The lifecycle status tags for a would-act entry. Each carries colour + glyph + word: would-cut
/// OPEN (still standing — the loud one), short-lived (likely FP — calm), coverage-gap (scrutinise —
/// amber), or sustained (the default worth-a-cut reading).
fn would_act_tags(w: &WouldActProps) -> Markup {
    html! {
        span.trust-tags {
            @if w.open {
                span.trust-tag.tag-open {
                    span.glyph aria-hidden="true" { "\u{2702}" } "would cut \u{00B7} still standing"
                }
            } @else if w.short_lived {
                span.trust-tag.tag-shortlived {
                    span.glyph aria-hidden="true" { "\u{25CB}" } "likely false positive"
                }
            } @else {
                span.trust-tag.tag-sustained {
                    span.glyph aria-hidden="true" { "\u{25B2}" } "sustained"
                }
            }
            @if w.coverage_gap {
                span.trust-tag.tag-covgap title="affirmed exploitability with no CVE/behavioral backing" {
                    span.glyph aria-hidden="true" { "\u{25D0}" } "scrutinise \u{2014} no backing"
                }
            }
        }
    }
}

/// The self-reverted-cuts tail of section 1 — cuts that were applied then self-reverted (ADR-0016:
/// a cut stands only while the breach condition holds). Toned as the system working, kept visible so
/// a lifted cut is never invisible. Honest "no cuts reverted yet" when empty.
fn reverted_block(v: &ActionViewProps) -> Markup {
    html! {
        @if v.reversions.is_empty() {
            p.col-empty.t-body.muted {
                "no cuts reverted yet \u{2014} nothing has been applied-then-self-reverted."
            }
        } @else {
            ul.revert-list {
                @for r in &v.reversions {
                    (reverted_entry(r))
                }
            }
        }
    }
}

/// One self-reverted cut: the lifted cut signature, why it lifted, and how long ago.
fn reverted_entry(r: &ReversionProps) -> Markup {
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

/// Section 2 — **Left alone (cleared)**: proven paths the model deliberately cleared (the trust
/// half). Honest "none in window" when empty.
fn left_alone_section(v: &ActionViewProps) -> Markup {
    html! {
        section.activity-section.action-leftalone aria-label="left alone (cleared)" {
            h2.section-h.t-h2 { "left alone (cleared)" }
            p.section-sub.t-body.muted {
                "proven paths the model judged not exploitable and deliberately left alone \u{2014} \
                 the trust half of the diff."
            }
            @if v.left_alone.is_empty() {
                p.col-empty.t-body.muted {
                    "none in the last " (v.window_human)
                    " \u{2014} no proven path was cleared in this window."
                }
            } @else {
                ul.trust-list {
                    @for l in &v.left_alone {
                        (left_alone_entry(l))
                    }
                }
            }
        }
    }
}

/// One left-alone entry: the cleared entry key + the model's clearing verdict.
fn left_alone_entry(l: &LeftAloneProps) -> Markup {
    html! {
        li.trust-entry.trust-cleared {
            div.trust-entry-head {
                span.trust-tag.tag-cleared {
                    span.glyph aria-hidden="true" { "\u{25CB}" } "cleared"
                }
                span.trust-entry-key.t-data-strong { (l.entry) }
            }
            p.trust-entry-verdict.t-data { (l.verdict) }
        }
    }
}

/// Section 3 — **Judgement audit (model debug)**: the verbatim prompt/reply per model call, as
/// collapsed disclosures (the prompt can be long). Honest about an absent prompt/reply.
fn judgement_audit_section(v: &ActionViewProps) -> Markup {
    html! {
        section.activity-section.judgements aria-label="judgement audit" {
            h2.section-h.t-h2 { "judgement audit" }
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

/// The honest journal-empty state: distinct from "none in this window". No journal history at all
/// means there is nothing to report yet — never read as "all safe".
fn journal_empty_state() -> Markup {
    html! {
        div.empty.trust-empty {
            p.empty-head.t-h2 { "no decisions journaled yet" }
            p.empty-sub.t-body.muted {
                "the durable journal holds no breach decisions \u{2014} the engine has not yet judged \
                 a proven path, or the journal is in-memory only and reset on restart. This is not \
                 an all-clear; enable a durable journal to build would-have-acted history."
            }
        }
    }
}
