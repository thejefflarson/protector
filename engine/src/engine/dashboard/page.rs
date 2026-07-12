//! Page composition (ADR-0019 §2, cut over by ADR-0025, and by JEF-408 to a ROOT-ONLY body):
//! assemble the document shell — the `<head>` (title with the cluster label, meta, css link) around
//! the single Preact mount point. This is the only place that knows the document `<head>`.
//!
//! Under JEF-408 (superseding ADR-0025's "strip + nav stay SERVER-RENDERED"): the body is now
//! ROOT-ONLY — just `<div id="dash-root" data-tab=…>` + the deferred bundle `<script>`. EVERY piece
//! of body HTML (the status strip, the tab nav, and every view body) renders in the Preact client
//! reconciling from `/api/{tab}.json`. The honesty contract holds because a blank before the first
//! fetch is honest (absent ≠ green), and the all-clear / watching / judging-state honesty tokens
//! stay SERVER-DERIVED (see `view_model::props::status`) — the client only switches on the token.
//! SSR/hydration of the strip (to close the pre-fetch blank) is a noted follow-up (ADR-0027).

use maud::{DOCTYPE, Markup, html};

use super::view_model::props::Tab;

/// The full page for a tab: the document `<head>` (same-origin assets, the cluster-labelled title)
/// wrapping a ROOT-ONLY body — the Preact `#dash-root` mount point (its `data-tab` tells the client
/// which view to paint first) plus the deferred bundle. Every tab renders the SAME shell; the client
/// reconciles the strip, the nav, and the view body from `/api/{tab}.json`.
///
/// `cluster` is the only body-independent datum the shell needs (the `<title>`); the full
/// `StatusStripProps` is no longer required here — the strip is client-rendered from the JSON.
pub fn page(cluster: &str, tab: Tab) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "protector \u{2014} " (cluster) }
                link rel="stylesheet" href="/assets/dashboard.css";
            }
            body {
                // ROOT-ONLY (JEF-408): the Preact client mounts here and renders ALL body HTML — the
                // status strip, the tab nav, and the view body — reconciling from `/api/{tab}.json`.
                // A blank before the first fetch is honest (absent ≠ green); the honesty tokens stay
                // server-derived in the JSON.
                div id="dash-root" data-tab=(tab.token()) {}
                script src="/assets/dashboard.js" defer {}
            }
        }
    }
}
