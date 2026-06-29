//! The Readiness view body (brief §6): one row per decision input — its honest
//! Present/Absent/Degraded state (colour + glyph + word, never colour alone), the live detail,
//! why it matters, and the env var to enable it. Inputs that WEAKEN decisions when absent float
//! to the top and carry an amber keyline; an absent weakening input shows its "how to enable"
//! instruction prominently (the per-feed enablement surface the operator asked for). Pure
//! component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{ReadinessRowProps, ReadinessViewProps};

/// Render the Readiness view: the coverage rows under the persistent strip (composed by `page`).
pub fn readiness_view(v: &ReadinessViewProps) -> Markup {
    html! {
        main.view.view-readiness {
            section.coverage-detail aria-label="decision-input coverage" {
                h2.section-h.t-h2 { "decision inputs" }
                p.section-sub.t-body.muted {
                    "every input the model leans on to decide \u{2014} its live state, why it matters, \
                     and how to enable it. A weakening input that is absent is shown first."
                }
                ul.cov-rows {
                    @for row in &v.rows {
                        (coverage_row(row))
                    }
                }
            }
        }
    }
}

/// One coverage row. The state chip carries colour + glyph + word; an absent/degraded WEAKENING
/// input gets an amber keyline (style guide: `weakens_decisions` + absent → amber keyline) and
/// surfaces its enablement instruction. The detail is the live, honest line (a count, "last call
/// ok", or "no signals (quiet, or sensor down)").
fn coverage_row(r: &ReadinessRowProps) -> Markup {
    // A weakening input that isn't present is the attention case (amber keyline + how-to-enable).
    let weak_gap = r.weakens_decisions && !r.state.is_present();
    let li_class = if weak_gap {
        "cov-row cov-row-gap"
    } else {
        "cov-row"
    };
    html! {
        li class=(li_class) data-input=(r.id) data-state=(r.state.token()) {
            div.cov-row-head {
                span class={ "cov-state cov-" (r.state.token()) } {
                    span.cov-state-glyph aria-hidden="true" { (r.state.glyph()) }
                    span.cov-state-word { (r.state.word()) }
                }
                span.cov-row-label.t-data-strong { (r.label) }
                @if r.weakens_decisions {
                    span.cov-weakens.t-micro title="absence weakens the model's decision" {
                        "weakens decisions"
                    }
                }
            }
            p.cov-detail.t-data { (r.detail) }
            p.cov-why.t-body.muted { (r.why) }
            // The how-to-enable instruction: always shown when there is an env var/mount, and read
            // as an action ("enable with …") when the input is an absent weakening gap.
            @if !r.enable.is_empty() {
                p class={ "cov-enable t-data" @if weak_gap { " cov-enable-action" } } {
                    span.cov-enable-label.t-micro {
                        @if weak_gap { "enable with" } @else { "configured via" }
                    }
                    " "
                    code.cov-enable-var { (r.enable) }
                }
            }
        }
    }
}
