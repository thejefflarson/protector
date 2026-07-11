//! Page composition (ADR-0019): assemble the components into full pages and the `/fragment`
//! live region. This is the only place that knows the document shell (head, asset links, the
//! persistent status strip, the 4-tab nav) and how the live-poll fragment is framed. It imports
//! the components (markup) and the props (data) — never the engine directly.

use maud::{DOCTYPE, Markup, html};

use super::components::{
    action_view, admission_view, alerts_view, findings_view, nav_bar, readiness_view, status_strip,
};
use super::preact_flags::PreactTabs;
use super::view_model::props::{
    ActionViewProps, AdmissionViewProps, AlertsViewProps, FindingsViewProps, ReadinessViewProps,
    StatusStripProps, Tab,
};

/// The live-region id the JS polls and swaps. The status strip + active view live inside it so
/// a poll re-pulls readiness (a model that just went down flips the banner) and the findings.
pub const LIVE_REGION_ID: &str = "live";

/// The full Findings page: document shell + assets + the live region (strip + nav + findings).
///
/// When `preact.is_preact(Tab::Findings)` is set (ADR-0025 / JEF-397) the findings BODY is replaced
/// by a Preact client mount point (`<div id="dash-root" data-tab="findings">`); the status strip
/// stays server-rendered above it for calm-when-blind first paint. Default OFF ⇒ the maud body,
/// unchanged.
pub fn findings_page(v: &FindingsViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Findings) {
        preact_mount(Tab::Findings, preact)
    } else {
        findings_view(v)
    };
    document(&v.strip, Tab::Findings, body)
}

/// The Preact client mount point for a flagged tab (ADR-0025 / JEF-397, JEF-400): the server strip
/// and nav still frame it (composed by [`document`]); this is only the view BODY the client renders
/// into. The `data-tab` attribute stamps the mounted tab so the client's first paint matches the
/// document, and the `data-preact-tabs` attribute lists every Preact-flagged tab (space-separated)
/// so a client tab-swap is intercepted only among the tabs the server actually client-renders (a
/// swap to a still-maud tab stays a full server navigation, keeping each per-tab flag reversible).
fn preact_mount(tab: Tab, preact: PreactTabs) -> Markup {
    html! {
        div id="dash-root" data-tab=(tab.token()) data-preact-tabs=(preact.enabled_tokens()) {}
    }
}

/// The full Alerts page (JEF-323): the persistent strip + nav + the live "alarming-now"
/// corroboration list. When `alerts` is Preact-flagged (ADR-0025 / JEF-400) the body is the client
/// mount point; default OFF ⇒ the maud body, unchanged.
pub fn alerts_page(v: &AlertsViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Alerts) {
        preact_mount(Tab::Alerts, preact)
    } else {
        alerts_view(v)
    };
    document(&v.strip, Tab::Alerts, body)
}

/// The full Action page: the persistent strip + nav + the merged action story (proposed cuts →
/// left alone → judgement audit). Preact-flaggable (ADR-0025 / JEF-400); default OFF ⇒ maud.
pub fn action_page(v: &ActionViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Action) {
        preact_mount(Tab::Action, preact)
    } else {
        action_view(v)
    };
    document(&v.strip, Tab::Action, body)
}

/// The full Readiness (coverage) page: the persistent strip + nav + the per-input coverage rows.
/// Preact-flaggable (ADR-0025 / JEF-400); default OFF ⇒ maud.
pub fn readiness_page(v: &ReadinessViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Readiness) {
        preact_mount(Tab::Readiness, preact)
    } else {
        readiness_view(v)
    };
    document(&v.strip, Tab::Readiness, body)
}

/// The full Admission/policy (webhook floor) page: the persistent strip + nav + the decision
/// tallies header + the deduped decision rows. Preact-flaggable (ADR-0025 / JEF-400); default OFF ⇒
/// maud.
pub fn admission_page(v: &AdmissionViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Admission) {
        preact_mount(Tab::Admission, preact)
    } else {
        admission_view(v)
    };
    document(&v.strip, Tab::Admission, body)
}

/// The `/fragment` body for the Findings tab — only the live region's INNER content, for the
/// maud JS to swap in place (preserving scroll/expansion/filter). No document shell. When Findings
/// is Preact-flagged (ADR-0025 / JEF-397) the body is the client mount point instead of the maud
/// table — the client reconciles from `/api/findings.json`, not this fragment, but keeping the
/// fragment consistent means a stray `/fragment` poll never re-injects a maud table under the
/// client.
pub fn findings_fragment(v: &FindingsViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Findings) {
        preact_mount(Tab::Findings, preact)
    } else {
        findings_view(v)
    };
    live_region_inner(&v.strip, Tab::Findings, body)
}

/// The `/fragment` body for the Alerts tab (JEF-323) — live-swapped in place so a new alarming-now
/// signal appears (and a cleared one drops) on the next poll without a full reload. Preact-flagged
/// ⇒ the mount point (keeping a stray legacy poll from re-injecting maud under the client), JEF-400.
pub fn alerts_fragment(v: &AlertsViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Alerts) {
        preact_mount(Tab::Alerts, preact)
    } else {
        alerts_view(v)
    };
    live_region_inner(&v.strip, Tab::Alerts, body)
}

/// The `/fragment` body for the Action tab. Preact-flagged ⇒ the mount point (JEF-400).
pub fn action_fragment(v: &ActionViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Action) {
        preact_mount(Tab::Action, preact)
    } else {
        action_view(v)
    };
    live_region_inner(&v.strip, Tab::Action, body)
}

/// The `/fragment` body for the Readiness tab. Preact-flagged ⇒ the mount point (JEF-400).
pub fn readiness_fragment(v: &ReadinessViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Readiness) {
        preact_mount(Tab::Readiness, preact)
    } else {
        readiness_view(v)
    };
    live_region_inner(&v.strip, Tab::Readiness, body)
}

/// The `/fragment` body for the Admission tab. Preact-flagged ⇒ the mount point (JEF-400).
pub fn admission_fragment(v: &AdmissionViewProps, preact: PreactTabs) -> Markup {
    let body = if preact.is_preact(Tab::Admission) {
        preact_mount(Tab::Admission, preact)
    } else {
        admission_view(v)
    };
    live_region_inner(&v.strip, Tab::Admission, body)
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
                // The v4 Preact client (ADR-0025 / JEF-397) mounts into the `#dash-root` node the
                // FINDINGS BODY carries when that tab is Preact-flagged (the mount sits under the
                // server-rendered strip so the calm-when-blind first paint never depends on JS). On
                // a maud tab there is no `#dash-root`, so the bundle is inert. The script loads on
                // every tab (harmless when inert) so a client-flagged tab reached by a full
                // navigation still hydrates.
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
