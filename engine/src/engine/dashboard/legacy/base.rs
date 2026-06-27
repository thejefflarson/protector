//! Transitional shared base for the still-legacy panels (report / readiness / attack-vector
//! bake), pre-ADR-0019 string-concat rendering.
//!
//! The findings core (cards / rows / mermaid) migrated to the maud `components` +
//! `view_model` layers (JEF-205); this small module keeps the cross-cutting helpers those
//! findings files used to host that the OTHER not-yet-migrated panels still depend on:
//!
//! - [`escape`] — the string-concat HTML escaper (kept until the last legacy caller is gone;
//!   ADR-0019 retires it in the final migration ticket, not here).
//! - the Mermaid graph builder + node-key helpers ([`Mermaid`], [`mm`], [`short`], [`kind`],
//!   [`shape`]), now re-exported from the canonical `components::graph` home so the legacy
//!   `report` graph keeps rendering through the same `mm()`-guarded builder.
//! - the verdict classifiers ([`Posture`], [`flagged`]), re-exported from the canonical
//!   `view_model::findings` data layer so `report` / `readiness` agree with the findings
//!   table on the breach/posture call.
//!
//! New work does NOT add to this; it goes in the maud layers. Every re-export here is
//! transitional plumbing, deleted as the remaining panels migrate.
#![allow(unused_imports)]

// The Mermaid graph builder + node-key helpers now live in the presentation graph component
// (pure over strings; the `mm()` XSS guard backs the `PreEscaped` allowance — ADR-0019).
pub(crate) use crate::engine::dashboard::components::graph::{Mermaid, kind, mm, shape, short};

// The verdict classifiers now live in the findings data layer; the legacy report/readiness
// panels read them through here so they agree with the findings table.
pub(crate) use crate::engine::dashboard::view_model::findings::{Posture, flagged};

/// Minimal HTML escape for the few values that could contain markup-special chars. Retained
/// for the still-legacy panels; ADR-0019 retires it once the last string-concat caller is
/// gone (the final migration ticket), not here.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
