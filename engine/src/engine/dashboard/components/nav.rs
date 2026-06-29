//! The 4-tab nav shell (brief §4). The nav exists so all four surfaces — Findings, Action,
//! Readiness, Admission — are reachable; all four are real views (Action merges the former Trust +
//! Activity tabs into the engine's whole action story; Admission is the webhook-floor peer). Pure
//! component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::Tab;

/// The four top-level tabs, in priority order (default Findings; Action — the merged would-act +
/// audit story — second, in the old Trust slot; Admission — the webhook floor — last).
const TABS: [Tab; 4] = [Tab::Findings, Tab::Action, Tab::Readiness, Tab::Admission];

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
