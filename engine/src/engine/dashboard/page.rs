//! Page composition (ADR-0019 §2, cut over by ADR-0025 / JEF-398): assemble the SERVER-RENDERED
//! shell — document head, the persistent status strip, and the 5-tab nav — around the Preact client
//! mount point. This is the only place that knows the document shell (head, asset links, the strip,
//! the nav). The maud *body* renderers are gone: every view body is rendered by the Preact client
//! reconciling from `/api/{tab}.json`, so `page.rs` emits, for EVERY tab, the same shell + strip +
//! nav + a `#dash-root` mount point (unconditionally — no flag, no maud fallback).
//!
//! The strip + nav stay SERVER-RENDERED so the calm-when-blind first paint (the honest banner —
//! `!model_judging` / `warming_up` ⇒ never green, ADR-0019 §4) paints before any JS runs and is
//! never subject to a blank-until-hydrated gap. Only the view body under the nav is client-rendered.

use maud::{DOCTYPE, Markup, html};

use super::components::{nav_bar, status_strip};
use super::view_model::props::{StatusStripProps, Tab};

/// The full page for a tab: the document shell (head + same-origin assets) + the SERVER-RENDERED
/// persistent status strip + the 5-tab nav + the Preact `#dash-root` mount point. Every tab renders
/// the SAME structure — the mount's `data-tab` tells the client which view to paint first, and the
/// client reconciles the body from `/api/{tab}.json`. The strip + nav paint before any JS runs
/// (calm-when-blind first paint, ADR-0025); the mount sits under them so first-paint honesty never
/// depends on the bundle. Every tab is client-rendered now (the per-tab flag is gone), so the mount
/// carries no `data-preact-tabs` list — the client intercepts every tab-swap.
pub fn page(strip: &StatusStripProps, tab: Tab) -> Markup {
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
                // Server-rendered so the honest banner paints before any JS runs and never depends
                // on the bundle loading. A JS failure leaves the strip + nav visible, never a stale
                // green.
                (status_strip(strip))
                (nav_bar(tab))
                // The Preact client mounts here and reconciles the view body from `/api/{tab}.json`.
                div id="dash-root" data-tab=(tab.token()) {}
                script src="/assets/dashboard.js" defer {}
            }
        }
    }
}
