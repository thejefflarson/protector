//! The persistent status strip (brief §3/§4): the three honesty axes — decided / judging /
//! covered — carried on EVERY view. Its load-bearing rule (invariant #1): when the model is not
//! judging or is warming up, it renders the honest "blind/warming" banner and NEVER a green
//! all-clear. Pure component: props in, markup out, no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{CoverageChip, StatusStripProps};

/// Render the status strip from its props.
pub fn status_strip(s: &StatusStripProps) -> Markup {
    html! {
        header.strip {
            div.strip-top {
                div.strip-cluster {
                    span.brand { "protector" }
                    span.sep { "\u{25B8}" }
                    span.cluster { (s.cluster) }
                }
                (mode_pill(s.armed))
            }
            div.strip-axes {
                (judging_axis(s))
                (coverage_axes(&s.coverage))
                @if let Some(age) = &s.last_pass {
                    span.axis.freshness { "last pass " (age) }
                } @else {
                    span.axis.freshness.muted { "no pass yet" }
                }
            }
            (headline(s))
        }
    }
}

/// The shadow/enforce mode pill — posture, not a gap (always shown so the operator SEES it).
fn mode_pill(armed: bool) -> Markup {
    let (cls, word, sub) = if armed {
        ("pill mode-enforce", "ENFORCE", "acting")
    } else {
        ("pill mode-shadow", "SHADOW", "proposes, never acts")
    };
    html! {
        span class=(cls) {
            span.pill-word { (word) }
            span.pill-sub { (sub) }
        }
    }
}

/// The decided/judging axis. This is where the honest-calm invariant lives: only a judging,
/// warmed model shows the calm "model judging" reading; otherwise the honest banner.
fn judging_axis(s: &StatusStripProps) -> Markup {
    // The honest-calm invariant (#1): calm only when judging AND not warming.
    if s.calm_is_honest() {
        return html! {
            span.axis.judging.ok {
                span.dot {}
                "model judging"
            }
        };
    }
    // Not honestly calm — render the distinct, NON-green honest banner. The wording tells the
    // operator WHY quiet is not clearance.
    let (cls, glyph, text) = if s.warming_up {
        (
            "axis judging warming",
            "\u{25CC}",
            "warming up \u{2014} exposed paths are unjudged, not cleared",
        )
    } else if !s.model_attached {
        (
            "axis judging blind",
            "\u{25D0}",
            "no model \u{2014} nothing is judged exploitable",
        )
    } else {
        (
            "axis judging blind",
            "\u{25D0}",
            "model not answering \u{2014} exposed paths are unjudged, not cleared",
        )
    };
    html! {
        span class=(cls) {
            span.glyph { (glyph) }
            (text)
        }
    }
}

/// The covered axis: one chip per enrichment feed, each carrying colour + glyph + word.
fn coverage_axes(coverage: &[CoverageChip]) -> Markup {
    html! {
        span.axis.coverage {
            @for chip in coverage {
                (coverage_chip(chip))
            }
        }
    }
}

/// One coverage chip. Present / degraded / absent are visually distinct AND carry a glyph + the
/// feed word — never colour alone.
fn coverage_chip(chip: &CoverageChip) -> Markup {
    let (cls, glyph) = if chip.present {
        ("cov cov-present", "\u{2713}") // ✓
    } else if chip.degraded {
        ("cov cov-degraded", "\u{25D0}") // ◐
    } else {
        ("cov cov-absent", "\u{2014}") // —
    };
    html! {
        span class=(cls) {
            span.cov-label { (chip.label) }
            span.cov-glyph { (glyph) }
        }
    }
}

/// The findings headline line: breach / awaiting / cleared counts + the Δ escalation note. The
/// breach count is the only loud chip; awaiting/cleared are calm. Counts are honest even at
/// zero (never blank).
fn headline(s: &StatusStripProps) -> Markup {
    html! {
        div.headline {
            span.count.count-breach { (s.breach_count) " breach" }
            span.count.count-awaiting { (s.awaiting_count) " awaiting" }
            span.count.count-cleared { (s.cleared_count) " cleared" }
            @if s.escalated_count > 0 {
                span.count.count-escalated {
                    span.glyph { "\u{25B2}" }
                    (s.escalated_count) " escalated since last pass"
                }
            }
        }
    }
}
