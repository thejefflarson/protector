//! The dashboard's COMPONENT layer (ADR-0019, JEF-255): pure `Props -> Markup` renderers. A
//! component receives ONLY its `Props` and imports NO `engine::` domain type — the
//! `no_component_imports_an_engine_domain_type` guard test enforces that boundary. Every value
//! is interpolated through a maud `{ }` brace, so all untrusted text is auto-escaped; the only
//! `PreEscaped` are the byte-stable structural/entity constants in [`chips`].
//!
//! The v2 surfaces compose these small renderers (the four kept capabilities as layers of one
//! page): the [`status_line`], the [`breach_queue`], the dense [`endpoints`] table (each row
//! expanding to its [`detail`]: verbatim verdict, rail, [`evidence`] blocks, text [`hops`],
//! what-to-do), the compact [`admission`] strip, and the demoted [`internals`] disclosure.

pub mod admission;
pub mod breach_queue;
pub mod chips;
pub mod detail;
pub mod endpoints;
pub mod evidence;
pub mod hops;
pub mod internals;
pub mod status_line;
