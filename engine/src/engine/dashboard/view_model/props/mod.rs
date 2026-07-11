//! The plain presentation **Props** the components render (ADR-0019/ADR-0025). These types are the
//! contract between the `view_model` (which maps engine/`state::` domain types into them) and both
//! the `components` (pure `Props -> Markup` renderers) AND the read-only JSON snapshot the Preact
//! client reconciles from (ADR-0025). They carry NO engine/`state::` domain type — only owned
//! strings, numbers, and small presentation enums — so the component layer can be compiled and
//! guard-tested in isolation from the engine (invariant #4 of the brief).
//!
//! Every string here is treated as UNTRUSTED at render: escaping is a SINGLE render-layer
//! responsibility (maud auto-escape; the Preact client auto-escapes) — the props/JSON carry the raw
//! string, never a pre-escaped one (double-escaping is a bug, ADR-0025). The view_model never makes
//! a decision — these props are a view, never a gate (ADR-0016).
//!
//! ## Wire format (ADR-0025 — serde-props-as-contract)
//!
//! Every view's props derive [`serde::Serialize`] so the JSON snapshot the client consumes IS the
//! serialization of these exact types — there is no parallel DTO. Enums serialize to STABLE string
//! tags (`"breach"`, `"would-fail"`, …) so the wire format is legible and the client switch is
//! exhaustive; a rename breaks the round-trip test, not the client silently. The SERVER-DERIVED
//! honesty tokens ([`StatusStripProps::all_clear`]/[`StatusStripProps::watching`],
//! [`Posture::is_cleared`], the blind-caveat presence) are shipped as DECIDED values — the client
//! performs zero honesty derivation.
//!
//! ## Module layout (CLAUDE.md 1,000-line cap)
//!
//! The props tree is split into one focused submodule per view — [`findings`], [`alerts`],
//! [`readiness`], [`action`], [`admission`] — plus the shared [`status`] strip/tab spine and the
//! pre-existing [`signing`] inventory. Everything is re-exported FLAT here so every consumer's
//! `props::TypeName` path resolves unchanged.

mod action;
mod admission;
mod alerts;
mod findings;
mod readiness;
mod signing;
mod status;

pub use action::{
    ActionViewProps, JudgementEntryProps, LeftAloneProps, ReversionProps, WouldActProps,
};
pub use admission::{AdmissionDecision, AdmissionViewProps, DecisionRowProps, GateStatus};
pub use alerts::{AlertProps, AlertsViewProps};
pub use findings::{
    BehaviorProps, CveProps, DeltaProps, EvidenceProps, EvidenceSummary, FindingProps,
    FindingsViewProps, HopProps, JudgementProps, LiveTag, Posture, ScanProps,
};
pub use readiness::{
    InputStateProps, NodeCoverageStateProps, NodeRowProps, ReadinessRowProps, ReadinessViewProps,
};
pub use signing::{
    ExceptionAcceptedProps, ProvenanceChangeProps, ProvenancePosture, ProvenanceProps,
    RegressionKind, RepoStrength, SignerProps, SigningEnforcement, SigningPosture,
    SigningRegressionProps, SigningRepoProps, SigningRowProps,
};
pub use status::{CoverageChip, StatusStripProps, Tab};

#[cfg(test)]
mod serialize_tests;
