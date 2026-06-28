//! The readiness / coverage panel (JEF-160), migrated to maud (ADR-0019).
//!
//! PRESENTATION ONLY: this renderer takes its [`ReadinessProps`] and nothing else. It
//! imports NO `engine::` domain type — only its props (from the `view_model`) and maud.
//! Every text value goes through an auto-escaping `( )` brace, so the XSS surface is the
//! brace, not a hand-written `format!` (ADR-0019). The EXPERT-HONESTY is preserved
//! verbatim in meaning: the state WORD is IN TEXT (never glyph-only — accessibility), an
//! absent input that "weakens decisions" carries the explicit tag, the "enable: <var>"
//! hint shows only for an unmet input, and the cold-start note explains the bake window.

use crate::engine::dashboard::view_model::ReadinessProps;
use maud::{Markup, html};

/// The readiness / coverage panel: an ordered `<ol>` of every decision input with its LIVE
/// state in text, the one-line why, the live detail, the "weakens decisions" tag (when
/// applicable), and the enable hint (when unmet). Pure `Props -> Markup`.
pub fn readiness(props: &ReadinessProps) -> Markup {
    html! {
        @if props.warming_up {
            p class="r-cold" {
                "warming up — the first pass hasn't completed; first verdicts can take a few "
                "minutes on a CPU model, so a quiet dashboard right after start is expected."
            }
        }
        ol class="readiness" {
            @for r in &props.rows {
                li class=(format!("r-row r-{}", r.tone)) {
                    span class="r-label" { (r.label) }
                    " "
                    span class=(format!("r-state r-state-{}", r.tone)) { (r.state_word) }
                    @if r.weakens {
                        " " span class="r-weak" { "weakens decisions" }
                    }
                    br;
                    span class="r-why" { (r.why) }
                    " "
                    span class="r-detail" { "— " (r.detail) }
                    @if let Some(enable) = &r.enable {
                        " " span class="r-enable" { "enable: " code { (enable) } }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{BakeStats, ModelHealth, ReadinessConfig};
    use crate::engine::dashboard::view_model::readiness_data::{Readiness, derive_readiness};
    use crate::engine::dashboard::view_model::readiness_props;
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    fn feeds_bake(falco: u64, ebpf: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        if falco > 0 {
            signals_by_variant.insert("alert".to_string(), falco);
        }
        if ebpf > 0 {
            signals_by_variant.insert("connection".to_string(), ebpf);
        }
        BakeStats {
            signals_by_variant,
            ..Default::default()
        }
    }

    fn render(r: &Readiness) -> String {
        readiness(&readiness_props(r)).into_string()
    }

    /// Accessibility: the panel is an ordered list with the state WORD present as text for
    /// every row, the explicit "weakens decisions" tag on an absent weakening input, and
    /// the enable hint for an unmet input (the JEF-160 EXPERT-HONESTY).
    #[test]
    fn states_are_in_text_not_glyph_only() {
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                ..ReadinessConfig::default()
            },
            ModelHealth::Ok,
            &feeds_bake(0, 0),
            Some(SystemTime::now()),
        );
        let panel = render(&r);
        assert!(panel.contains("<ol class=\"readiness\">"));
        assert!(panel.contains(">present<"));
        assert!(panel.contains(">absent<"));
        assert!(panel.contains("weakens decisions"));
        assert!(panel.contains("PROTECTOR_KEV_FILE"));
    }

    #[test]
    fn no_model_says_no_calls_are_made() {
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: false,
                kev_count: 1500,
                journal_durable: true,
                armed: false,
            },
            ModelHealth::Unknown,
            &feeds_bake(1, 1),
            Some(SystemTime::now()),
        );
        let panel = render(&r);
        assert!(panel.contains("no exploitability calls are made"));
    }

    #[test]
    fn cold_start_note_explains_the_bake_window() {
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 1500,
                journal_durable: true,
                armed: false,
            },
            ModelHealth::Unknown,
            &BakeStats::default(),
            None,
        );
        let panel = render(&r);
        assert!(
            panel.contains("warming up") && panel.contains("CPU model"),
            "cold-start note present"
        );
    }

    /// Byte-stability with the legacy `readiness_panel`: a single absent weakening row with
    /// an enable hint must be byte-for-byte the old string-concat output.
    #[test]
    fn readiness_row_is_byte_stable_with_the_legacy_string_concat() {
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        let panel = render(&r);
        // The KEV row, absent + weakening + with its enable hint, byte-for-byte.
        let want = "<li class=\"r-row r-absent\"><span class=\"r-label\">KEV catalogue</span> \
            <span class=\"r-state r-state-absent\">absent</span> \
            <span class=\"r-weak\">weakens decisions</span><br>\
            <span class=\"r-why\">flags known-exploited CVEs so the model weighs active \
            threats first</span> <span class=\"r-detail\">— not loaded — no known-exploited \
            CVE id evidence available</span> <span class=\"r-enable\">enable: \
            <code>PROTECTOR_KEV_FILE</code></span></li>";
        assert!(panel.contains(want), "byte-stable KEV row: {panel}");
        // And the panel is wrapped in the ordered list.
        assert!(panel.contains("<ol class=\"readiness\">"));
    }

    /// ADR-0019 boundary guard: the panel takes only its props.
    #[test]
    fn readiness_imports_no_engine_domain_type() {
        let _: fn(&ReadinessProps) -> Markup = readiness;
    }
}
