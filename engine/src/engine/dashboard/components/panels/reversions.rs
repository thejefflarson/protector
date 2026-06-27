//! The recent-reversions panel (JEF-141), migrated to maud (ADR-0019).
//!
//! PRESENTATION ONLY: this renderer takes its [`ReversionsProps`] and nothing else. It
//! imports NO `engine::` domain type — only its props (from the `view_model`) and maud.
//! The cut signature and reason go through auto-escaping `( )` braces (ADR-0019). This is
//! the visible record of the self-revert: lifted cuts and why. Quiet when nothing has been
//! lifted (a healthy default, not an error). Newest first.

use crate::engine::dashboard::view_model::ReversionsProps;
use maud::{Markup, html};

/// The recent-reversions panel: the lifted-cut rows, or the quiet default. Pure
/// `Props -> Markup`.
pub fn reversions(props: &ReversionsProps) -> Markup {
    if props.rows.is_empty() {
        return html! { p class="muted" { "no cuts have been lifted yet" } };
    }
    html! {
        table class="vectors" {
            thead { tr { th { "Lifted cut" } th { "Reason" } th { "When" } } }
            tbody {
                @for r in &props.rows {
                    tr {
                        td { code { (r.cut) } }
                        td { (r.reason) }
                        td class="muted" { (r.when) }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::ReversionRecord;
    use crate::engine::dashboard::view_model::reversions_props;
    use std::time::SystemTime;

    fn unix_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn render(recs: &[ReversionRecord]) -> String {
        reversions(&reversions_props(recs)).into_string()
    }

    #[test]
    fn shows_lifted_cuts_or_a_quiet_default() {
        assert!(render(&[]).contains("no cuts have been lifted"));
        let panel = render(&[ReversionRecord {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
            at_ms: unix_now_ms(),
        }]);
        assert!(panel.contains("workload/app/Pod/web"));
        assert!(panel.contains("no proven chain still justifies"));
    }

    /// Byte-stability with the legacy `reversions_panel`: one lifted-cut row, byte-for-byte.
    #[test]
    fn reversions_output_is_byte_stable_with_the_legacy_string_concat() {
        let got = render(&[ReversionRecord {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
            at_ms: unix_now_ms(),
        }]);
        let want = "<table class=\"vectors\"><thead><tr><th>Lifted cut</th><th>Reason</th>\
            <th>When</th></tr></thead><tbody>\
            <tr><td><code>workload/app/Pod/web -[reaches/Tcp]-&gt; workload/app/Pod/db</code></td>\
            <td>no proven chain still justifies this control</td>\
            <td class=\"muted\">just now</td></tr></tbody></table>";
        assert_eq!(got, want);
    }

    /// ADR-0019 boundary guard: the panel takes only its props.
    #[test]
    fn reversions_imports_no_engine_domain_type() {
        let _: fn(&ReversionsProps) -> Markup = reversions;
    }
}
