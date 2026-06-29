//! Page composition (ADR-0019): assemble the components into full pages and the `/fragment`
//! live region. This is the only place that knows the document shell (head, asset links, the
//! persistent status strip, the 4-tab nav) and how the live-poll fragment is framed. It imports
//! the components (markup) and the props (data) — never the engine directly.

use maud::{DOCTYPE, Markup, html};

use super::components::{
    activity_view, findings_view, nav_bar, readiness_view, status_strip, trust_view,
};
use super::view_model::props::{
    ActivityViewProps, FindingsViewProps, ReadinessViewProps, StatusStripProps, Tab, TrustViewProps,
};

/// The live-region id the JS polls and swaps. The status strip + active view live inside it so
/// a poll re-pulls readiness (a model that just went down flips the banner) and the findings.
pub const LIVE_REGION_ID: &str = "live";

/// The full Findings page: document shell + assets + the live region (strip + nav + findings).
pub fn findings_page(v: &FindingsViewProps) -> Markup {
    document(&v.strip, Tab::Findings, findings_view(v))
}

/// The full Trust (would-have-acted) page: the persistent strip + nav + the would-cut/left-alone
/// diff.
pub fn trust_page(v: &TrustViewProps) -> Markup {
    document(&v.strip, Tab::Trust, trust_view(v))
}

/// The full Readiness (coverage) page: the persistent strip + nav + the per-input coverage rows.
pub fn readiness_page(v: &ReadinessViewProps) -> Markup {
    document(&v.strip, Tab::Readiness, readiness_view(v))
}

/// The full Activity (audit) page: the persistent strip + nav + the reversion log + judgement ring.
pub fn activity_page(v: &ActivityViewProps) -> Markup {
    document(&v.strip, Tab::Activity, activity_view(v))
}

/// The `/fragment` body for the Findings tab — only the live region's INNER content, for the
/// JS to swap in place (preserving scroll/expansion/filter). No document shell.
pub fn findings_fragment(v: &FindingsViewProps) -> Markup {
    live_region_inner(&v.strip, Tab::Findings, findings_view(v))
}

/// The `/fragment` body for the Trust tab.
pub fn trust_fragment(v: &TrustViewProps) -> Markup {
    live_region_inner(&v.strip, Tab::Trust, trust_view(v))
}

/// The `/fragment` body for the Readiness tab.
pub fn readiness_fragment(v: &ReadinessViewProps) -> Markup {
    live_region_inner(&v.strip, Tab::Readiness, readiness_view(v))
}

/// The `/fragment` body for the Activity tab.
pub fn activity_fragment(v: &ActivityViewProps) -> Markup {
    live_region_inner(&v.strip, Tab::Activity, activity_view(v))
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
