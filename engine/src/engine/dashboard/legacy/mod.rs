//! Transitional home for the dashboard's pre-ADR-0019 string-concat rendering.
//!
//! ADR-0019 adopts `maud` and a React-like `view_model` / `components` split. The nav
//! and the status banner are migrated as the proof-of-pattern (JEF-204); the remaining
//! panels (findings cards, report, judgements, readiness) still render via the old
//! `format!`-string helpers and live here until tickets 3–6 migrate them onto the maud
//! components. This module exists ONLY to keep each file under the repo's 1,000-line cap
//! while that migration is in flight — every helper here is slated for deletion.
//!
//! The submodules are split purely by size; they share one namespace (re-exported below)
//! so the in-flight code reads as it did before the split. Cross-module helpers are
//! `pub(crate)` for that reason — not a stable surface, just transitional plumbing.

// Shared imports for every legacy submodule (each does `use super::*;`).
pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::sync::{Arc, Mutex};
pub(crate) use std::time::{Duration, SystemTime};

pub(crate) use serde::{Deserialize, Serialize};

pub(crate) use crate::engine::graph::{Behavior, SecurityGraph, Vulnerability};
pub(crate) use crate::engine::journal::{Decision, EnrichmentCoverage, JournalEntry};
pub(crate) use crate::engine::reason::adjudicate::Verdict;
pub(crate) use crate::engine::reason::proof::ProvenChain;

// The findings core (cards / rows / mermaid) migrated to the maud `components` +
// `view_model` layers (JEF-205); the cross-cutting helpers the remaining panels still need
// live in `base` (re-exporting from the new canonical homes).
mod base;
mod model;
mod panels;
mod readiness;
mod report;

pub(crate) use base::*;
pub use model::*;
pub(crate) use panels::*;
pub use readiness::*;
pub use report::*;

#[cfg(test)]
mod tests;
