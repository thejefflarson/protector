//! The Findings view body (brief §5): the findings table sorted by urgency, with honest
//! empty / awaiting / blind states. The "all clear" state is rendered ONLY when the model is
//! actively judging (invariant #1) — otherwise an empty list reads as "blind", not "safe".
//! Pure component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::FindingsViewProps;

use super::finding_row::finding_row;

/// Render the Findings view (the table + states). The status strip is composed by `page.rs`;
/// this is the view body under the nav.
pub fn findings_view(v: &FindingsViewProps) -> Markup {
    html! {
        main.view.view-findings {
            @if v.findings.is_empty() {
                (empty_state(v))
            } @else {
                (findings_table(v))
            }
        }
    }
}

/// The findings table. A real `<table>` for keyboard/semantics (accessibility gate §6).
fn findings_table(v: &FindingsViewProps) -> Markup {
    html! {
        table.findings {
            thead {
                tr {
                    th.col-expand scope="col" { span.visually-hidden { "expand" } }
                    th.col-delta scope="col" { "\u{0394}" }
                    th.col-posture scope="col" { "POSTURE" }
                    th.col-entry scope="col" { "ENTRY \u{2192} OBJECTIVE" }
                    th.col-path scope="col" { "PATH" }
                    th.col-evidence scope="col" { "EVIDENCE" }
                    th.col-disposition scope="col" { "DISPOSITION" }
                }
            }
            tbody {
                @for f in &v.findings {
                    (finding_row(f))
                }
            }
        }
    }
}

/// The honest empty state. Crucially, "all clear" is shown ONLY when the model is actively
/// judging; when blind/warming the empty list reads as "we haven't looked", never as safe
/// (the cardinal sin the design exists to prevent — brief §0/§9 invariant #1).
fn empty_state(v: &FindingsViewProps) -> Markup {
    // GREEN all-clear only when the model has affirmatively cleared everything (judging +
    // covered + nothing breach/awaiting/uncertain). An empty list satisfies the count side, so
    // here it turns on whether the model is up AND fully covered (invariant #1).
    if v.strip.all_clear() {
        return html! {
            div.empty.empty-clear {
                p.empty-head { "all clear" }
                p.empty-sub.muted {
                    "no breach-relevant exposed paths \u{2014} the model is judging and found nothing exploitable."
                }
            }
        };
    }
    // Model up but not fully covered (a feed is degraded): the empty list is calm but NOT a green
    // all-clear — the elevated "watching" register (the model isn't fully equipped to clear).
    if v.strip.watching() {
        return html! {
            div.empty.empty-watching {
                p.empty-head { "watching" }
                p.empty-sub.muted {
                    "no breach-relevant exposed paths yet, but a decision feed is degraded \u{2014} \
                     the model is judging but not fully equipped to clear. This is not an all-clear."
                }
            }
        };
    }
    // Model down/warming: an empty list is NOT a clearance. Say so, in the matching non-green
    // amber/slate register.
    let (cls, head, sub) = if v.strip.warming_up {
        (
            "empty empty-warming",
            "warming up",
            "no pass has completed yet \u{2014} verdicts are still loading (slow on a CPU model). \
             This is not an all-clear.",
        )
    } else if !v.strip.model_attached {
        (
            "empty empty-blind",
            "no model configured",
            "nothing is judged exploitable without a model \u{2014} exposed paths are unjudged, not cleared.",
        )
    } else {
        (
            "empty empty-blind",
            "model not answering",
            "the model timed out or is down \u{2014} exposed paths are unjudged, not cleared. \
             This is not an all-clear.",
        )
    };
    html! {
        div class=(cls) {
            p.empty-head { (head) }
            p.empty-sub.muted { (sub) }
        }
    }
}
