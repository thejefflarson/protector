//! The persistent nav (JEF-159), migrated to maud as the proof-of-pattern for ADR-0019.
//!
//! PRESENTATION ONLY: this renderer takes its [`NavProps`] and nothing else. It imports
//! NO `engine::` domain type — only its props (from the `view_model`) and maud. That
//! boundary is the whole point of the component split (ADR-0019); the
//! `nav_imports_no_engine_domain_type` test guards it.

use crate::engine::dashboard::view_model::NavProps;
use maud::{Markup, html};

/// The persistent nav shown across the read-only views. The current page carries
/// `aria-current="page"`. Pure `Props -> Markup`; auto-escapes every label.
pub fn nav(props: &NavProps) -> Markup {
    html! {
        nav class="nav" aria-label="views" {
            @for item in &props.items {
                @if item.current {
                    a href=(item.href) aria-current="page" { (item.label) }
                } @else {
                    a href=(item.href) { (item.label) }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::nav_props;

    #[test]
    fn nav_marks_the_current_page_and_lists_the_trimmed_links() {
        let html = nav(&nav_props("/")).into_string();
        // Answer-first trim (JEF-175): dashboard · why · shadow log only.
        assert!(html.contains("<a href=\"/\" aria-current=\"page\">dashboard</a>"));
        assert!(html.contains("<a href=\"/judgements\">why</a>"));
        assert!(html.contains("<a href=\"/report\">shadow log</a>"));
        assert_eq!(html.matches("<a ").count(), 3, "exactly three nav items");
        // De-listed routes never appear in the nav.
        assert!(
            !html.contains("href=\"/reversions\""),
            "reversions de-listed"
        );
        assert!(!html.contains("href=\"/readiness\""), "readiness de-listed");
        assert!(!html.contains("href=\"/bake\""), "bake de-listed");
    }

    #[test]
    fn nav_aria_current_follows_the_active_page() {
        let html = nav(&nav_props("/judgements")).into_string();
        assert!(html.contains("<a href=\"/judgements\" aria-current=\"page\">why</a>"));
        // Only one item is current.
        assert_eq!(html.matches("aria-current").count(), 1);
        assert!(
            html.contains("<a href=\"/\">dashboard</a>"),
            "dashboard not current"
        );
    }

    /// Byte-stability with the pre-maud `nav_bar` output (JEF-204 AC): the migration must
    /// not change a single byte of the rendered nav.
    #[test]
    fn nav_output_is_byte_stable_with_the_legacy_string_concat() {
        let got = nav(&nav_props("/")).into_string();
        let want = "<nav class=\"nav\" aria-label=\"views\">\
                    <a href=\"/\" aria-current=\"page\">dashboard</a>\
                    <a href=\"/judgements\">why</a>\
                    <a href=\"/report\">shadow log</a>\
                    </nav>";
        assert_eq!(got, want);
    }

    /// ADR-0019 boundary: a presentational component imports no `engine::` domain type.
    /// This compile-time guard is a no-op that documents the rule; the real enforcement is
    /// that this file's `use` list names only `view_model` props + maud (see the head).
    #[test]
    fn nav_imports_no_engine_domain_type() {
        // `NavProps` is plain view-model data, not an engine domain type — the component
        // never sees a `Finding`, a `SecurityGraph`, or any `engine::` type.
        let _: fn(&NavProps) -> Markup = nav;
    }
}
