//! The dashboard's VIEW-MODEL layer (ADR-0019, JEF-255): the data shaping that turns the
//! engine's domain state into plain `Props` the pure `components` render. This layer may name
//! `engine::` domain types (it is the boundary); the components below it must not.
//!
//! The v2 single-page IA (JEF-255) shapes one answer — "is anything compromised right now, and
//! if not am I covered or blind?" — into focused prop modules:
//!
//! - [`posture`] — the typed-verdict → [`Posture`] SSOT (derived once, never re-parsed prose).
//! - [`status`] — the one-line status props (breach/endpoints/awaiting/model/coverage).
//! - [`entry`] — the per-endpoint dense-row props and its expanded detail props.
//! - [`evidence`] — the row glyph strip and the expanded evidence blocks.
//! - [`hops`] — the proven attack path as a text hop-list (Mermaid retired).
//! - [`admission`] — the compact admission strip props.
//! - [`internals`] — the demoted engine-internals disclosure props.
//!
//! [`readiness_data`] and [`report_data`] remain the DATA layer: `readiness_data` is the live
//! coverage snapshot the status line + internals read; `report_data` backs the engine's
//! per-pass OTLP would-have-acted mirror ([`super::default_window_report`]).

pub mod admission;
pub mod entry;
pub mod evidence;
pub mod hops;
pub mod internals;
pub mod posture;
pub mod readiness_data;
pub mod report_data;
pub mod status;

pub use posture::Posture;
