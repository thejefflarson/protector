//! The instructional first-run checklist (JEF-160), migrated to maud (ADR-0019).
//!
//! PRESENTATION ONLY: this renderer takes its [`FirstRunProps`] and nothing else. It
//! imports NO `engine::` domain type — only its props (from the `view_model`) and maud.
//! Every text value goes through an auto-escaping `( )` brace (ADR-0019). The EXPERT-HONESTY
//! is preserved verbatim in meaning: when the engine has no findings AND inputs are unmet,
//! this REPLACES the empty findings body — it frames itself as a guided start, never a
//! bare/error-looking page; each unmet input is an actionable line linking the one env var
//! / mount to enable it, a met input reads as a done check, and the cold-start note stands.
//!
//! NOTE (ADR-0019, the PreEscaped rule): the legacy panel emitted `to&nbsp;do` as a raw
//! HTML entity. maud auto-escapes every brace and `PreEscaped` is reserved for child
//! `Markup` / `mm()`-sanitized Mermaid only, so we render the non-breaking space as the
//! literal U+00A0 character instead — token-equivalent (it renders as the same
//! non-breaking space) without reaching for the `PreEscaped` allowlist.

use crate::engine::dashboard::view_model::FirstRunProps;
use maud::{Markup, html};

/// The non-breaking space between "to" and "do" — U+00A0 rather than the `&nbsp;` entity,
/// so it stays inside maud's auto-escaped tree (ADR-0019).
const TO_DO: &str = "to\u{a0}do";

/// The instructional first-run checklist: the guided-start preamble, the optional
/// cold-start note, and the per-input checklist (done checks + to-do lines with their
/// enable var). Pure `Props -> Markup`.
pub fn first_run(props: &FirstRunProps) -> Markup {
    html! {
        div class="firstrun" {
            p class="sum" {
                "No findings yet, and some decision inputs aren't configured. protector "
                "degrades quietly when an input is missing — this checklist is the guided "
                "start, not a blank page. Wire each input below to give the model the full "
                "picture."
            }
            @if props.warming_up {
                p class="r-cold" {
                    "warming up — first verdicts can take a few minutes on a CPU model."
                }
            }
            ol class="checklist" {
                @for item in &props.items {
                    @if item.done {
                        li class="r-done" {
                            b { "done" } " — " (item.label) ": " (item.text)
                        }
                    } @else {
                        li class="r-todo" {
                            b { (TO_DO) } " — " (item.label) ": " (item.text)
                            @if let Some(enable) = &item.enable {
                                " — set " code { (enable) }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::legacy::{
        BakeStats, ModelHealth, ReadinessConfig, derive_readiness,
    };
    use crate::engine::dashboard::view_model::first_run_props;
    use std::time::SystemTime;

    /// JEF-160 AC #4: the checklist frames itself as a guided start (never a blank page),
    /// links each unmet input's enable var, and renders to-do lines for unconfigured inputs.
    #[test]
    fn checklist_is_the_guided_start_with_enable_vars() {
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        let panel = first_run(&first_run_props(&r)).into_string();
        assert!(panel.contains("class=\"firstrun\""));
        assert!(panel.contains("ol class=\"checklist\""));
        assert!(panel.contains("guided start, not a blank page"));
        assert!(
            panel.contains("PROTECTOR_ENGINE_MODEL"),
            "model enable linked"
        );
        assert!(
            panel.contains("PROTECTOR_ADVISORY_FILE"),
            "advisory enable linked"
        );
        // The "to do" line carries a non-breaking space (U+00A0), token-equivalent to the
        // legacy `&nbsp;` entity.
        assert!(panel.contains("to\u{a0}do"), "non-breaking 'to do' label");
    }

    /// A met input reads as a done check rather than a to-do.
    #[test]
    fn met_inputs_render_as_done_checks() {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("alert".to_string(), 1);
        bake.signals_by_variant.insert("connection".to_string(), 1);
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 3,
                advisory_count: 3,
                journal_durable: true,
                armed: false,
            },
            ModelHealth::Ok,
            &bake,
            Some(SystemTime::now()),
        );
        let panel = first_run(&first_run_props(&r)).into_string();
        assert!(
            panel.contains("<li class=\"r-done\">"),
            "a met input is a done check"
        );
        assert!(panel.contains("<b>done</b>"));
    }

    /// ADR-0019 boundary guard: the panel takes only its props.
    #[test]
    fn first_run_imports_no_engine_domain_type() {
        let _: fn(&FirstRunProps) -> Markup = first_run;
    }
}
