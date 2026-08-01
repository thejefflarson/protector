//! The pre-arm scope-simulation preview props (ADR-0021, ADR-0016): "what fires, and what
//! it severs, if `enforceScope` were this CANDIDATE scope right now" — a pure, read-only
//! projection over the engine's own standing cuts and their already-computed blast radius.
//! Computing or viewing this NEVER applies, arms, or mutates engine state; it is a
//! classification of data the engine already produced this pass.
//!
//! Split out of the parent `props` module to keep every file under the repo's 1,000-line
//! cap (CLAUDE.md); re-exported flat so `props::ScopePreviewViewProps` etc. resolve
//! unchanged.

use super::status::StatusStripProps;

/// One currently-standing cut that WOULD fire under the candidate scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FiringCutProps {
    /// The cut signature (`from -[relation]-> to`), untrusted node keys.
    pub cut: String,
    /// The mechanism this cut would apply (`describe()` prose, untrusted-shaped but
    /// engine-authored — e.g. "add a scoped deny NetworkPolicy/AuthorizationPolicy").
    pub action: String,
    /// Currently-alive peer workloads this cut would sever, other than its own endpoints —
    /// the legitimate traffic that would go dark. Untrusted node keys.
    pub alive_collateral: Vec<String>,
    /// Reachability wasn't fully modeled for this cut this pass — `alive_collateral` may be
    /// under-counted. Rendered as its own "collateral unknown" caveat, never collapsed into
    /// an empty (implied-safe) `alive_collateral`.
    pub collateral_unknown: bool,
}

/// One currently-standing, otherwise-actionable cut the candidate scope does NOT cover — the
/// gate would hold it as a proposal rather than arm it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HeldCutProps {
    pub cut: String,
    pub action: String,
}

/// The whole scope-preview panel's props: the persistent strip, the candidate scope echoed
/// back (so the panel can confirm what it evaluated), and the partitioned result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScopePreviewViewProps {
    pub strip: StatusStripProps,
    /// The candidate namespaces the caller asked to preview, echoed back verbatim.
    pub candidate_namespaces: Vec<String>,
    /// The candidate `key=value` Pod labels the caller asked to preview, echoed back
    /// verbatim, each rendered `"key=value"`.
    pub candidate_labels: Vec<String>,
    /// `true` when the caller supplied neither namespaces nor labels — the honest-empty
    /// case: `would_fire` is empty by construction, not because nothing is standing.
    pub candidate_is_empty: bool,
    /// Cuts that would arm under the candidate scope, with their predicted collateral.
    pub would_fire: Vec<FiringCutProps>,
    /// Currently-standing, otherwise-actionable cuts the candidate scope excludes — the
    /// gate would hold these as proposals.
    pub held_out_of_scope: Vec<HeldCutProps>,
}
