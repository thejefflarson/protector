//! Reasoning: the prove / judge core (ADR-0001, 0005, 0013).
//!
//! - [`objective`] — what an attacker would want to reach (the recognized goals).
//! - [`proof`] — deterministic enumeration of proven chains to those objectives. At
//!   this cluster's scale this exhaustive walk finds every structurally-proven chain,
//!   so the engine runs purely on it — there is no model-backed *propose* stage
//!   (ADR-0001, narrowed).
//! - [`adjudicate`] — the model *decides* exploitability of a proven chain.
//! - [`backoff`] — exponential backoff + a global circuit-breaker so an inconclusive
//!   (model-down) adjudication is not re-judged every pass (JEF-234).
//!
//! Proof winnows, the model decides (ADR-0013): only deterministic proof moves
//! privilege; the model judges and promotes, never invents reach.

pub mod adjudicate;
pub mod backoff;
pub mod objective;
pub mod proof;
