//! Page composition (ADR-0019): assemble the components into full pages and the `/fragment`
//! live region. This is the only place that knows the document shell (head, asset links, the
//! persistent status strip, the 4-tab nav) and how the live-poll fragment is framed. It imports
//! the components (markup) and the props (data) — never the engine directly.

use maud::{DOCTYPE, Markup, html};

use super::components::{findings_view, nav_bar, status_strip, stub_view};
use super::view_model::props::{FindingsViewProps, StatusStripProps, Tab};

/// The live-region id the JS polls and swaps. The status strip + active view live inside it so
/// a poll re-pulls readiness (a model that just went down flips the banner) and the findings.
pub const LIVE_REGION_ID: &str = "live";

/// The full Findings page: document shell + assets + the live region (strip + nav + findings).
pub fn findings_page(v: &FindingsViewProps) -> Markup {
    document(&v.strip, Tab::Findings, findings_view(v))
}

/// A full phase-2 stub page (Trust / Readiness / Activity): the persistent strip + nav + the
/// labelled placeholder, so the nav is navigable in phase 1.
pub fn stub_page(strip: &StatusStripProps, tab: Tab, blurb: &str) -> Markup {
    document(strip, tab, stub_view(tab, blurb))
}

/// The `/fragment` body for the Findings tab — only the live region's INNER content, for the
/// JS to swap in place (preserving scroll/expansion/filter). No document shell.
pub fn findings_fragment(v: &FindingsViewProps) -> Markup {
    live_region_inner(&v.strip, Tab::Findings, findings_view(v))
}

/// The `/fragment` body for a stub tab.
pub fn stub_fragment(strip: &StatusStripProps, tab: Tab, blurb: &str) -> Markup {
    live_region_inner(strip, tab, stub_view(tab, blurb))
}

/// The document shell: head with same-origin assets (no third-party CSS/JS), then the live
/// region carrying the persistent strip + nav + the view body.
fn document(strip: &StatusStripProps, tab: Tab, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "protector \u{2014} " (strip.cluster) }
                link rel="stylesheet" href="/assets/dashboard.css";
            }
            body {
                div id=(LIVE_REGION_ID) data-tab=(tab.label()) {
                    (live_region_inner(strip, tab, body))
                }
                script src="/assets/dashboard.js" defer {}
            }
        }
    }
}

/// The inner content of the live region — what `/fragment` returns and the JS swaps. The strip
/// and nav are inside it so a poll refreshes coverage/freshness too (brief §7).
fn live_region_inner(strip: &StatusStripProps, tab: Tab, body: Markup) -> Markup {
    html! {
        (status_strip(strip))
        (nav_bar(tab))
        (body)
    }
}
