//! The 4-tab nav shell (brief §4) and the phase-2 stub view. The nav exists so all four
//! surfaces are reachable; only Findings is built in phase 1. Pure component; no domain types.

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
                    @if matches!(tab, Tab::Trust | Tab::Readiness | Tab::Activity) {
                        span.tab-phase { "phase 2" }
                    }
                }
            }
        }
    }
}

/// A labelled phase-2 placeholder for the secondary tabs. Honest about what it will hold, so
/// the nav is real rather than a dead link.
pub fn stub_view(tab: Tab, blurb: &str) -> Markup {
    html! {
        main class={ "view view-stub view-" (tab.label()) } {
            div.stub {
                p.stub-head { (tab.label()) }
                span.stub-badge { "phase 2" }
                p.stub-sub.muted { (blurb) }
            }
        }
    }
}
