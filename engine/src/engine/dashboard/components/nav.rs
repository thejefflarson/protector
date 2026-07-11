//! The top-level nav shell (brief §4). The nav exists so every surface — Findings, Alerts, Action,
//! Readiness, Admission — is reachable; all are real views (Alerts is the live alarming-now
//! corroboration surface, JEF-323; Action merges the former Trust + Activity tabs into the engine's
//! whole action story; Admission is the webhook-floor peer). Pure component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::Tab;

/// The top-level tabs, in priority order (default Findings; Alerts — the live alarming-now
/// corroboration view — second, next to Findings; Action — the merged would-act + audit story;
/// Admission — the webhook floor — last).
const TABS: [Tab; 5] = [
    Tab::Findings,
    Tab::Alerts,
    Tab::Action,
    Tab::Readiness,
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
