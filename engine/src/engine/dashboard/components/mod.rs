//! The **components** layer (ADR-0019): pure `Props -> Markup` renderers. A component imports
//! ONLY `maud` and the `view_model::props` types — NEVER an `engine::`/`state::` domain type
//! (invariant #4, guard-tested). It is the presentation half of the React-like split: given
//! its props, it renders, escaping all untrusted text via maud's auto-escape (invariant #6).
//!
//! No component emits an inline `<style>`/`style=` attribute (invariant #5) — every visual is
//! driven by a class mapped to a token in `docs/STYLEGUIDE.md` (served as `dashboard.css`).

mod action_view;
mod admission_view;
mod alerts_view;
mod evidence;
mod finding_detail;
mod finding_row;
mod findings_view;
mod nav;
mod readiness_view;
mod status_strip;

pub use action_view::action_view;
pub use admission_view::admission_view;
pub use alerts_view::alerts_view;
pub use findings_view::findings_view;
pub use nav::nav_bar;
pub use readiness_view::readiness_view;
pub use status_strip::status_strip;
