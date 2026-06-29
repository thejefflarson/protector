//! The Trust (would-have-acted) view body (brief §6): the arm/don't-arm evidence over the rolling
//! window. Two halves — *would have cut* (sustained-first; `short_lived` = likely FP;
//! `coverage_gap` = affirmed with no CVE backing → scrutinise first; `open` = still standing) vs
//! *left alone* (proven paths the model cleared — the trust half). Honest empty: a journal with no
//! history reads differently from "none in this window". Pure component; no domain types; all
//! free-text auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{LeftAloneProps, TrustViewProps, WouldActProps};

/// Render the Trust view: the headline summary, then the would-cut and left-alone columns, with
/// honest empty states.
pub fn trust_view(v: &TrustViewProps) -> Markup {
    html! {
        main.view.view-trust {
            (trust_headline(v))
            @if v.journal_empty {
                (journal_empty_state())
            } @else {
                div.trust-cols {
                    (would_act_block(v))
                    (left_alone_block(v))
                }
            }
        }
    }
}

/// The headline: the window, the would-cut count (with the short-lived / coverage-gap subsets),
/// and the left-alone count — the arm/don't-arm summary at a glance. Counts are honest at zero.
fn trust_headline(v: &TrustViewProps) -> Markup {
    html! {
        section.trust-summary aria-label="would-have-acted summary" {
            h2.section-h.t-h2 { "would-have-acted \u{2014} last " (v.window_human) }
            p.section-sub.t-body.muted {
                "in shadow the engine only proposes; this is what it WOULD have cut, and what it \
                 proved out and left alone \u{2014} the evidence for whether to arm."
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
                span.count.count-leftalone.t-data { (v.left_alone_count) " left alone" }
            }
        }
    }
}

/// The "would have cut" half — sustained-first, each entry classified (open / short-lived /
/// coverage-gap). Honest "none in window" when empty (the journal has history, just nothing here).
fn would_act_block(v: &TrustViewProps) -> Markup {
    html! {
        section.trust-col.trust-wouldact {
            h3.col-h.t-h2 { "would have cut" }
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
}

/// One would-act entry: the entry key, its classification tags (colour + glyph + word), the
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

/// The classification tags for a would-act entry. Each carries colour + glyph + word: OPEN (still
/// standing — the loud one), short-lived (likely FP — calm), coverage-gap (scrutinise — amber),
/// or sustained (the default worth-a-cut reading).
fn would_act_tags(w: &WouldActProps) -> Markup {
    html! {
        span.trust-tags {
            @if w.open {
                span.trust-tag.tag-open {
                    span.glyph aria-hidden="true" { "\u{25CF}" } "still standing"
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

/// The "left alone" half — proven paths the model cleared (the trust evidence). Honest "none in
/// window" when empty.
fn left_alone_block(v: &TrustViewProps) -> Markup {
    html! {
        section.trust-col.trust-leftalone {
            h3.col-h.t-h2 { "left alone" }
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
