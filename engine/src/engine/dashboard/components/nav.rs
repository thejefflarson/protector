//! The 4-tab nav shell (brief §4). The nav exists so all four surfaces — Findings, Trust,
//! Readiness, Activity — are reachable; all four are real views now (phase 2 landed the
//! secondary three). Pure component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::Tab;

/// The four top-level tabs, in priority order (default Findings).
const TABS: [Tab; 4] = [Tab::Findings, Tab::Trust, Tab::Readiness, Tab::Activity];

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
