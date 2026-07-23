//! The "Access" view presentation props (JEF-490) — the operator's window onto the read-only MCP
//! server's forensic/raw disclosure audit (ADR-0031 §4). Two halves:
//!
//! - **your access** — the caller's OWN tier ([`AccessTier`]) as a chip, over a `cov-rows`-style
//!   list of what each tier reveals vs withholds ([`TierRevealRow`]);
//! - **forensic & raw pulls** — the newest-first audit rows ([`AccessPullRow`]): `when · who · tool
//!   · tier · target-class`, each row's target-class ALREADY redacted to the CALLER's own tier by
//!   the view_model (a lower-tier viewer sees the withheld-workload sentinel, never the crown-jewel
//!   target of a higher-tier pull).
//!
//! Split out of the parent `props` module to keep every file under the repo's 1,000-line cap
//! (CLAUDE.md); re-exported flat so `props::AccessViewProps` etc. resolve unchanged.
//!
//! The wire format (ADR-0025): these props `serde`-serialize as the read-only `/api/access.json`
//! snapshot. [`AccessTier`] serializes to a STABLE lowercase tag (`"redacted"`/`"forensic"`/`"raw"`)
//! so the client's chip switch is exhaustive; every identity/target string is UNTRUSTED and ships
//! RAW (the client auto-escapes — double-escaping is a bug). The tier-aware REDACTION is decided
//! server-side (the target is already the real value or the sentinel), so the client derives nothing.

use crate::engine::dashboard::auth::claims::Tier;
use crate::engine::mcp::EffectiveTier;

use super::status::StatusStripProps;

/// A disclosure tier as the "Access" screen names it — the presentation mirror of the auth [`Tier`]
/// and the MCP [`EffectiveTier`], carried as a stable token so the client renders colour + glyph +
/// WORD (never colour alone). Serialized kebab/lowercase (`"redacted"`/`"forensic"`/`"raw"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessTier {
    /// Safe-by-construction: verdicts, counts, technique IDs, coverage/freshness — nothing
    /// cluster-specific. The floor and the fail-safe default.
    Redacted,
    /// Adds judgement prompt+reply, CVE ids + reachability, proven paths, workload/node names.
    Forensic,
    /// Adds secret NAMES (per-entry only; never secret VALUES — no read path exists). The loud,
    /// scarce posture.
    Raw,
}

impl AccessTier {
    /// Project the caller's verified auth [`Tier`] onto the screen's tier.
    pub fn from_claim(tier: Tier) -> Self {
        match tier {
            Tier::Redacted => AccessTier::Redacted,
            Tier::Forensic => AccessTier::Forensic,
            Tier::Raw => AccessTier::Raw,
        }
    }

    /// Project a pull's clamped [`EffectiveTier`] onto the screen's tier.
    pub fn from_effective(tier: EffectiveTier) -> Self {
        match tier {
            EffectiveTier::Redacted => AccessTier::Redacted,
            EffectiveTier::Forensic => AccessTier::Forensic,
            EffectiveTier::Raw => AccessTier::Raw,
        }
    }
}

/// One row in the "what each tier reveals/withholds" list (Section 1) — a `cov-rows`-style entry
/// describing one tier level and whether the CALLER holds it. Every string is static, operator-facing
/// copy (no cluster data), but ships as data the client renders.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TierRevealRow {
    /// Which tier this row describes.
    pub tier: AccessTier,
    /// What this tier reveals.
    pub reveals: String,
    /// What this tier still withholds.
    pub withholds: String,
    /// Whether the caller's own tier includes this level (`caller_tier >= this`).
    pub held: bool,
}

/// One audit row (Section 2) — a single forensic/raw disclosure, already redacted to the CALLER's
/// own tier. `when · who · tool · tier · target-class`. Untrusted identity/target strings ship RAW
/// (the client escapes). A `raw` pull carries the loud keyline (`raw`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessPullRow {
    /// A compact "N ago" for when the pull happened (server-derived from the record's Unix stamp).
    pub when: String,
    /// The verified human subject that pulled (untrusted — escaped at render).
    pub who: String,
    /// The tool that served the disclosure.
    pub tool: String,
    /// The tier the disclosure was rendered at (the pull's own tier, NOT the caller's).
    pub tier: AccessTier,
    /// The target-class, REDACTED to the caller's own tier: the real workload identity / bulk-scope
    /// label at forensic+, else the withheld-workload sentinel (the SAME string the tool emits).
    pub target: String,
    /// Whether this was a `raw` pull — the loud keyline on the row.
    pub raw: bool,
}

/// The whole "Access" view's props: the persistent strip + the caller's tier chip + the tier-reveal
/// list + the newest-first forensic/raw pulls. `durable` reflects whether the audit sink persists to
/// the PVC — the client picks the honest empty-state sub-line from it (omit "resets on restart" when
/// durable).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessViewProps {
    pub strip: StatusStripProps,
    /// The caller's OWN verified tier — the chip in "your access".
    pub tier: AccessTier,
    /// What each tier reveals/withholds, and which the caller holds (Section 1).
    pub reveals: Vec<TierRevealRow>,
    /// The newest-first forensic/raw pulls, redacted to the caller's own tier (Section 2). The
    /// client reads its length directly for the empty-vs-populated split — no separate count.
    pub pulls: Vec<AccessPullRow>,
    /// Whether the audit sink is durable (PVC-backed). `false` ⇒ in-memory — the empty state then
    /// carries the "this log lives in memory and resets on restart" caveat.
    pub durable: bool,
}
