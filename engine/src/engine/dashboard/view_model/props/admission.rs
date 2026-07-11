//! The Admission/policy-view presentation props (the webhook floor, brief §6) — the
//! `DecisionTallies` header (admitted/audited/denied, so a healthy view is never blank) + the
//! per-image signing inventory + deduped decision rows (signature/mesh/decision + the "if
//! enforced" what-if). Split out of the parent `props` module to keep every file under the repo's
//! 1,000-line cap (CLAUDE.md); re-exported flat so `props::AdmissionViewProps` etc. resolve
//! unchanged.
//!
//! The wire format (ADR-0025): these props `serde`-serialize as the read-only Admission JSON. The
//! gate/decision enums serialize to STABLE lowercase string tags (`"verified"`, `"would-fail"`,
//! `"deny"`, …) so the client's switch is exhaustive over a fixed vocabulary. Every string is
//! UNTRUSTED and ships RAW (the render layer escapes; double-escaping is a bug). View-never-a-gate:
//! [`DecisionRowProps::would_admit`] is a DISPLAY-only counterfactual, never a decision the client
//! can act on.

use super::signing::SigningRepoProps;
use super::status::StatusStripProps;

/// A per-gate shadow status (JEF-246) for the admission view — the "was this actually checked?"
/// three-state vocabulary from `ShadowVerdict::status()`: `verified` (in scope, checked, passed),
/// `would-pass` (out of scope, shadow-checked, would pass), `would-fail` (would deny if enforced),
/// or `None` when the gate has no opinion (the field was empty). Carried as colour + glyph + word
/// so meaning never rides on colour alone. Serialized as a STABLE kebab-case string tag — ADR-0025.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateStatus {
    /// In scope, checked, passed.
    Verified,
    /// Out of scope, shadow-checked, would pass if enforced.
    WouldPass,
    /// Would deny if enforced — the attention case.
    WouldFail,
    /// The gate had no opinion (e.g. a non-Pod / out-of-scope object).
    NotApplicable,
}

impl GateStatus {
    /// Parse the engine's coarse shadow status word into the presentation enum. An empty string
    /// (or any unknown legacy word, e.g. the pre-JEF-246 `signed`/`unsigned`) reads as
    /// [`NotApplicable`](Self::NotApplicable) rather than a misleading pass/fail.
    pub fn parse(word: &str) -> GateStatus {
        match word {
            "verified" => GateStatus::Verified,
            "would-pass" => GateStatus::WouldPass,
            "would-fail" => GateStatus::WouldFail,
            _ => GateStatus::NotApplicable,
        }
    }

    /// The CSS token suffix (`--gate-{kind}`) for this status.
    pub fn token(self) -> &'static str {
        match self {
            GateStatus::Verified => "verified",
            GateStatus::WouldPass => "wouldpass",
            GateStatus::WouldFail => "wouldfail",
            GateStatus::NotApplicable => "na",
        }
    }

    /// The glyph carrying the status without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            GateStatus::Verified => "\u{2713}",      // ✓
            GateStatus::WouldPass => "\u{25CB}",     // ○ — would pass (shadow)
            GateStatus::WouldFail => "\u{2715}",     // ✕ — would fail
            GateStatus::NotApplicable => "\u{2014}", // —
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            GateStatus::Verified => "verified",
            GateStatus::WouldPass => "would-pass",
            GateStatus::WouldFail => "would-fail",
            GateStatus::NotApplicable => "n/a",
        }
    }

    /// Whether this gate would deny if enforced — the attention case the row highlights.
    pub fn is_fail(self) -> bool {
        matches!(self, GateStatus::WouldFail)
    }
}

/// The coarse admission decision the webhook resolved — the honest API verdict (never the
/// counterfactual). `allow` = clean admit, `audit` = would-deny-but-allowed (the discovery
/// signal), `deny` = enforced rejection. An unknown legacy word maps to [`Other`](Self::Other).
/// Serialized as a STABLE lowercase string tag — ADR-0025.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionDecision {
    /// A clean admit.
    Allow,
    /// Would-deny-but-allowed (shadow discovery signal).
    Audit,
    /// An enforced rejection.
    Deny,
    /// An unrecognised legacy decision word.
    Other,
}

impl AdmissionDecision {
    /// Parse the engine's coarse decision word.
    pub fn parse(word: &str) -> AdmissionDecision {
        match word {
            "allow" => AdmissionDecision::Allow,
            "audit" => AdmissionDecision::Audit,
            "deny" => AdmissionDecision::Deny,
            _ => AdmissionDecision::Other,
        }
    }

    /// The CSS token suffix (`--decision-{kind}`).
    pub fn token(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "allow",
            AdmissionDecision::Audit => "audit",
            AdmissionDecision::Deny => "deny",
            AdmissionDecision::Other => "other",
        }
    }

    /// The glyph carrying the decision without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "\u{2713}", // ✓
            AdmissionDecision::Audit => "\u{25D0}", // ◐
            AdmissionDecision::Deny => "\u{25CF}",  // ●
            AdmissionDecision::Other => "\u{2014}", // —
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "admitted",
            AdmissionDecision::Audit => "audited",
            AdmissionDecision::Deny => "denied",
            AdmissionDecision::Other => "other",
        }
    }
}

/// One deduped admission decision row for the Admission view. Plain presentation data only — the
/// engine `PolicyDecisionRecord` is mapped into this at the view_model boundary. Every string is
/// UNTRUSTED at render (the image ref / subject / reason can quote attacker-chosen text). No stable
/// id by design — a deduped decision row is keyed by its `(subject, image, decision)` tuple, not a
/// synthetic id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DecisionRowProps {
    /// The coarse decision word (colour + glyph + word).
    pub decision: AdmissionDecision,
    /// The workload subject (`kind/name`), untrusted.
    pub subject: String,
    /// The representative image ref, untrusted. Empty when the decision isn't image-scoped.
    pub image: String,
    /// The request's namespace, untrusted. Empty for a cluster-scoped object.
    pub namespace: String,
    /// The mesh gate's shadow status. (The signature posture now lives in the dedicated signing
    /// inventory — JEF-262 — so the decision log no longer carries a signature *gate* column.)
    pub mesh: GateStatus,
    /// The "if enforced" net counterfactual (JEF-246): would this be admitted if every gate were
    /// enforced? Display-only — the honest API verdict is [`decision`](Self::decision).
    pub would_admit: bool,
    /// The human-actionable reason, untrusted. Empty for a plain admit.
    pub reason: String,
    /// How many times this exact `(subject, image, decision)` was seen (the dedup count).
    pub count: u64,
}

/// The whole Admission/policy view's props (brief §6): the strip + the decision tallies header
/// (so a healthy view is never blank) + the deduped decision rows + the honest-empty framing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AdmissionViewProps {
    pub strip: StatusStripProps,
    /// Clean admits (`allow`) summed over the deduped rows' counts.
    pub admitted: u64,
    /// Would-deny-but-allowed (`audit`).
    pub audited: u64,
    /// Enforced rejections (`deny`).
    pub denied: u64,
    /// Total decisions across all outcomes — drives the honest-empty state when zero.
    pub total: u64,
    /// The per-image signing inventory (JEF-262 / ADR-0020), grouped under its repo — the
    /// observed signing posture of every image, sitting between the tallies header and the
    /// decision log. Empty renders an honest "no images observed yet" (never an all-clear).
    pub signing: Vec<SigningRepoProps>,
    /// The deduped decision rows, newest-first.
    pub rows: Vec<DecisionRowProps>,
}
