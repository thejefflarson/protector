//! The behavioral-bake panel (JEF-48), migrated to maud (ADR-0019).
//!
//! PRESENTATION ONLY: this renderer takes its [`BakeProps`] and nothing else. It imports
//! NO `engine::` domain type — only its props (from the `view_model`) and maud. The variant
//! names go through an auto-escaping `( )` brace (ADR-0019). This is the at-a-glance view of
//! what the behavioral port saw last pass — signal volume by variant, attribution
//! resolved/unresolved (a nonzero unresolved share is highlighted), the live runtime-store
//! size, and corroborations fired. Read-only, shadow-safe.

use crate::engine::dashboard::view_model::BakeProps;
use maud::{Markup, html};

/// The attribution half of the summary line: resolved vs unresolved, with the unresolved
/// share flagged when nonzero (the JEF-48 attribution exit-criterion).
fn attribution(props: &BakeProps) -> Markup {
    html! {
        @if props.unresolved == 0 {
            b { (props.resolved) } " resolved · " span class="muted" { "0 unresolved" }
        } @else {
            b { (props.resolved) } " resolved · "
            span class="flagged" {
                (props.unresolved) " unresolved (" (format!("{:.1}", props.unresolved_pct)) "%)"
            }
        }
    }
}

/// The behavioral-bake panel. When quiet, the honest "nothing observed yet" line; otherwise
/// the summary line plus the per-variant volume table. Pure `Props -> Markup`.
pub fn bake(props: &BakeProps) -> Markup {
    if props.quiet {
        return html! {
            p class="muted" {
                "no behavioral signals observed yet (no sensor reporting, or a quiet cluster)"
            }
        };
    }
    html! {
        div class="sum" {
            "last pass: " b { (props.total) } " signal" (if props.total == 1 { "" } else { "s" })
            " · " (attribution(props))
            " · live store " b { (props.runtime_store) }
            " · corroborations " b { (props.corroborations) }
        }
        table class="vectors" {
            thead { tr { th { "Signal variant" } th { "Count (last pass)" } } }
            tbody {
                @if props.variants.is_empty() {
                    tr { td class="muted" colspan="2" { "no signals this pass" } }
                } @else {
                    @for row in &props.variants {
                        tr { td { code { (row.variant) } } td { (row.count) } }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::legacy::BakeStats;
    use crate::engine::dashboard::view_model::bake_props;
    use std::collections::BTreeMap;

    fn fixture(resolved: u64, unresolved: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        signals_by_variant.insert("connection".to_string(), 12);
        signals_by_variant.insert("secret-read".to_string(), 3);
        signals_by_variant.insert("library-load".to_string(), 5);
        BakeStats {
            signals_by_variant,
            resolved,
            unresolved,
            runtime_store: 7,
            corroborations: 2,
        }
    }

    fn render(b: &BakeStats) -> String {
        bake(&bake_props(b)).into_string()
    }

    #[test]
    fn quiet_when_nothing_observed() {
        let panel = render(&BakeStats::default());
        assert!(panel.contains("no behavioral signals observed yet"));
        // A fully-resolved pass shows no flagged unresolved share.
        let clean = render(&fixture(15, 0));
        assert!(
            !clean.contains("unresolved ("),
            "0 unresolved is not flagged"
        );
    }

    #[test]
    fn renders_volume_attribution_and_corroborations() {
        let panel = render(&fixture(80, 20));
        assert!(panel.contains("connection"));
        assert!(panel.contains("secret-read"));
        assert!(panel.contains("library-load"));
        assert!(panel.contains("80"), "resolved count");
        assert!(panel.contains("class=\"flagged\""), "unresolved is flagged");
        assert!(panel.contains("20.0%"), "unresolved fraction shown");
        assert!(panel.contains("live store"));
        assert!(panel.contains("corroborations"));
    }

    /// Byte-stability with the legacy `bake_panel`: the full panel for a representative pass
    /// must be byte-for-byte the old string-concat output.
    #[test]
    fn bake_output_is_byte_stable_with_the_legacy_string_concat() {
        let got = render(&fixture(80, 20));
        let want = "<div class=\"sum\">last pass: <b>20</b> signals · \
            <b>80</b> resolved · <span class=\"flagged\">20 unresolved (20.0%)</span> · \
            live store <b>7</b> · corroborations <b>2</b></div>\
            <table class=\"vectors\"><thead><tr><th>Signal variant</th>\
            <th>Count (last pass)</th></tr></thead><tbody>\
            <tr><td><code>connection</code></td><td>12</td></tr>\
            <tr><td><code>library-load</code></td><td>5</td></tr>\
            <tr><td><code>secret-read</code></td><td>3</td></tr></tbody></table>";
        assert_eq!(got, want);
    }

    /// ADR-0019 boundary guard: the panel takes only its props.
    #[test]
    fn bake_imports_no_engine_domain_type() {
        let _: fn(&BakeProps) -> Markup = bake;
    }
}
