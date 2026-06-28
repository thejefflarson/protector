//! The ENGINE-INTERNALS renderer (JEF-255): the demoted diagnostics behind the page's one
//! collapsed `<details>` — coverage detail, recent reversions, behavioral-bake counts. Pure
//! `InternalsProps -> Markup`; no `engine::` domain type (ADR-0019). It auto-opens only when a
//! decision-weakening input is unmet, so a blind cluster is never silently calm.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::internals::InternalsProps;

/// Render the internals disclosure. `open` follows `coverage_unmet` — an honest blind cluster
/// surfaces the gap; a covered one keeps the diagnostics tucked away.
pub fn internals(p: &InternalsProps) -> Markup {
    html! {
        details class="internals" open[p.coverage_unmet] {
            summary { h2 class="internals-h" { "Engine internals" } }
            (coverage(p))
            (reversions(p))
            (bake(p))
        }
    }
}

fn coverage(p: &InternalsProps) -> Markup {
    html! {
        section class="cov" {
            h3 { "Coverage " span class="muted" { "(decision inputs)" } }
            table class="cov-table" {
                thead { tr { th { "input" } th { "state" } th { "detail" } th { "enable" } } }
                tbody {
                    @for r in &p.coverage {
                        tr class=(if r.weakens && r.state != "present" { "cov-gap" } else { "" }) {
                            td { (r.label) }
                            td class=(format!("cov-{}", r.state)) { (r.state) }
                            td { (r.detail) span class="muted cov-why" { " — " (r.why) } }
                            td {
                                @if r.enable.is_empty() {
                                    span class="muted" { "—" }
                                } @else {
                                    code { (r.enable) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn reversions(p: &InternalsProps) -> Markup {
    html! {
        section class="rev" {
            h3 { "Recently lifted " span class="muted" { "(self-reverting cuts)" } }
            @if p.reversions.is_empty() {
                p class="muted" { "no cuts lifted yet" }
            } @else {
                ul {
                    @for r in &p.reversions {
                        li {
                            code { (r.cut) } " — " (r.reason)
                            " " span class="muted" { "(" (r.ago) ")" }
                        }
                    }
                }
            }
        }
    }
}

fn bake(p: &InternalsProps) -> Markup {
    html! {
        section class="bake" {
            h3 { "Behavioral bake " span class="muted" { "(this pass, shadow)" } }
            ul class="bake-list" {
                @for b in &p.bake {
                    li { (b.label) ": " b { (b.value) } }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::internals::{BakeRow, CoverageRow, ReversionRow};

    fn props(unmet: bool) -> InternalsProps {
        InternalsProps {
            coverage: vec![CoverageRow {
                label: "Model adjudicator",
                state: "absent",
                why: "decides breach",
                enable: "PROTECTOR_ENGINE_MODEL",
                detail: "no model configured".into(),
                weakens: true,
            }],
            coverage_unmet: unmet,
            reversions: vec![ReversionRow {
                cut: "a -[reaches]-> b".into(),
                reason: "breach cleared".into(),
                ago: "2m ago".into(),
            }],
            bake: vec![BakeRow {
                label: "corroborations this pass",
                value: "2".into(),
            }],
        }
    }

    #[test]
    fn auto_opens_when_unmet() {
        let m = internals(&props(true)).into_string();
        assert!(m.contains("<details class=\"internals\" open"));
        assert!(m.contains("Engine internals"));
        assert!(m.contains("cov-gap"));
    }

    #[test]
    fn stays_closed_when_covered() {
        let m = internals(&props(false)).into_string();
        assert!(!m.contains(" open>"));
    }

    #[test]
    fn shows_coverage_reversions_and_bake() {
        let m = internals(&props(true)).into_string();
        assert!(m.contains("Model adjudicator"));
        // The cut signature's `>` is auto-escaped at the brace.
        assert!(m.contains("a -[reaches]-&gt; b"));
        assert!(m.contains("corroborations this pass"));
        assert!(m.contains("2"));
    }
}
