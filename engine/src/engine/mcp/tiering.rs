//! The tier ceiling + clamp (ADR-0031 §2, JEF-488). The disclosure tier is a **ceiling** derived
//! server-side from the VERIFIED token claim ([`Tier`], JEF-485); a tool argument may only ever
//! NARROW it. The clamp is `min(requested, ceiling)` — the argument is never trusted to WIDEN.
//!
//! [`EffectiveTier`] is deliberately a DISTINCT type from the claim [`Tier`]: a value of this type
//! is the already-clamped result, so a tool cannot accidentally render at the raw ceiling by reading
//! the claim directly. The only way to obtain one is [`EffectiveTier::clamp`].

use serde::{Deserialize, Serialize};

use crate::engine::dashboard::auth::claims::Tier;

/// The tier a response is actually rendered at — the CLAMPED result of `min(requested, ceiling)`.
/// Ordered `Redacted < Forensic < Raw`, mirroring [`Tier`], so a per-tool cap can further lower it.
///
/// Serializes to the SAME low-cardinality label [`as_str`](Self::as_str) returns (`"redacted"` /
/// `"forensic"` / `"raw"`), so the durable access-audit line (JEF-490) persists a stable, legible
/// tier tag that round-trips on replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectiveTier {
    /// Safe-by-construction: verdicts, counts, technique IDs, coverage/freshness — nothing
    /// cluster-specific. The default and the floor.
    Redacted,
    /// Adds judgement prompt+reply, CVE ids + reachability, and paths — but secret NAMES stay
    /// scrubbed. Genuine cluster-data egress (journaled).
    Forensic,
    /// Adds actual secret NAMES (never secret VALUES — no tool has a read path to a value). Genuine
    /// cluster-data egress (journaled); reachable per-entry ONLY (never a bulk dump).
    Raw,
}

impl EffectiveTier {
    /// The stable, low-cardinality label (for the manifest + audit line).
    pub fn as_str(self) -> &'static str {
        match self {
            EffectiveTier::Redacted => "redacted",
            EffectiveTier::Forensic => "forensic",
            EffectiveTier::Raw => "raw",
        }
    }

    /// Whether this tier is above the safe-by-construction floor — i.e. a genuine cluster-data
    /// disclosure that MUST be journaled (ADR-0031 §4).
    pub fn is_disclosure(self) -> bool {
        self > EffectiveTier::Redacted
    }

    /// Project a claim [`Tier`] onto the effective ladder (an unclamped view — used only inside
    /// [`clamp`]).
    fn from_claim(tier: Tier) -> EffectiveTier {
        match tier {
            Tier::Redacted => EffectiveTier::Redacted,
            Tier::Forensic => EffectiveTier::Forensic,
            Tier::Raw => EffectiveTier::Raw,
        }
    }

    /// Clamp a REQUESTED tier to the token's CEILING: `min(requested, ceiling)`. A `None` request
    /// (the tool arg omitted) resolves to the ceiling itself — the caller is served exactly what the
    /// IdP granted, never more. The argument can only NARROW: a `redacted`-ceiling token asking for
    /// `raw` is clamped to `redacted`, because the ceiling is the operator's verified grant, not the
    /// caller's assertion (ADR-0031 §2 — the crux of the whole surface's safety).
    pub fn clamp(requested: Option<Tier>, ceiling: Tier) -> EffectiveTier {
        let ceiling = EffectiveTier::from_claim(ceiling);
        match requested {
            None => ceiling,
            Some(requested) => EffectiveTier::from_claim(requested).min(ceiling),
        }
    }

    /// Apply a per-tool CAP on top of the clamp: the effective tier is further lowered to `cap`.
    /// `list_findings` / `get_coverage` / `signing_inventory` cap at `Forensic` so secret NAMES are
    /// never emitted in a BULK response — raw secret names are reachable ONLY per-entry via
    /// `explain_verdict` (ADR-0031 acceptance: "per-entry only — no dump-all-at-raw path").
    pub fn capped_at(self, cap: EffectiveTier) -> EffectiveTier {
        self.min(cap)
    }
}

/// Parse the optional `tier` tool argument (case-insensitive) into a REQUESTED claim [`Tier`], or
/// `None` when absent/blank. An unrecognized label floors to [`Tier::Redacted`] (the lenient
/// token-facing parse, JEF-485) — it can never widen past the ceiling anyway, so a garbage request
/// resolving to the floor is the safe reading.
pub fn parse_requested_tier(arg: Option<&str>) -> Option<Tier> {
    arg.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(Tier::from_claim_str)
}
