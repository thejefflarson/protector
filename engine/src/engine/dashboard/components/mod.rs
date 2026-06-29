//! The **components** layer (ADR-0019): pure `Props -> Markup` renderers. A component imports
//! ONLY `maud` and the `view_model::props` types — NEVER an `engine::`/`state::` domain type
//! (invariant #4, guard-tested). It is the presentation half of the React-like split: given
//! its props, it renders, escaping all untrusted text via maud's auto-escape (invariant #6).
//!
//! No component emits an inline `<style>`/`style=` attribute (invariant #5) — every visual is
//! driven by a class mapped to a token in `docs/STYLEGUIDE.md` (served as `dashboard.css`).

mod evidence;
mod finding_detail;
mod finding_row;
mod findings_view;
mod nav;
mod status_strip;

pub use findings_view::findings_view;
pub use nav::{nav_bar, stub_view};
pub use status_strip::status_strip;
