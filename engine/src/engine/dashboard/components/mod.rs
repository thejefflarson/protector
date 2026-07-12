//! The **components** layer (ADR-0019 §1, retained by ADR-0025): the SERVER-RENDERED shell parts.
//!
//! Under the v4 cutover (ADR-0025 / JEF-398) the maud *body* renderers are gone — the Preact
//! client renders every view body from the `/api/*.json` snapshots. What stays server-rendered is
//! the calm-when-blind first paint: the persistent **status strip** and the **tab nav**. A JS
//! failure (or the pre-hydration first paint) must never show a stale green, so the strip's honest
//! banner is emitted by the server before any JS runs (ADR-0025: calm-when-blind first paint).
//!
//! These two components are pure `Props -> Markup` renderers importing ONLY `maud` and the
//! `view_model::props` types — never an `engine::`/`state::` domain type (invariant #4,
//! guard-tested) — and emit no inline `<style>`/`style=` (invariant #5, CSP-required).

mod nav;
mod status_strip;

pub use nav::nav_bar;
pub use status_strip::status_strip;
