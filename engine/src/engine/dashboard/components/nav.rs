//! The 5-tab nav shell (brief §4). The nav exists so all five surfaces — Findings, Trust,
//! Readiness, Activity, Admission — are reachable; all five are real views now (phase 2 landed the
//! secondary three; Admission is the webhook-floor peer). Pure component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::Tab;

/// The five top-level tabs, in priority order (default Findings; Admission — the webhook
/// floor — last, alongside the audit-flavoured Activity).
const TABS: [Tab; 5] = [
    Tab::Findings,
    Tab::Trust,
    Tab::Readiness,
    Tab::Activity,
    Tab::Admission,
];

/// Render the tab nav bar, marking the active tab.
pub fn nav_bar(active: Tab) -> Markup {
    html! {
        nav.tabs aria-label="dashboard sections" {
            @for tab in TABS {
                @let is_active = tab == active;
                a.tab href=(tab.path())
                   aria-current=[is_active.then_some("page")]
                   class=(if is_active { "tab tab-active" } else { "tab" }) {
                    (tab.label())
                }
            }
        }
    }
}
