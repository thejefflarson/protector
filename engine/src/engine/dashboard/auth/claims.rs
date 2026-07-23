//! JWT claims: the registered claims protector's verifier reads (subject) plus the
//! **configurable** authorization-tier extraction (ADR-0030 §1).
//!
//! Signature / `iss` / `aud` / `exp` / `nbf` validation is done by `jsonwebtoken` against the
//! [`super::Verifier`]'s pinned [`jsonwebtoken::Validation`]; this module only shapes the
//! decoded claims and maps the tier claim onto the ordered [`Tier`].

use serde::Deserialize;
use serde_json::{Map, Value};

/// The operator's authorization tier — how much of the (already read-only) view a verified
/// identity may see. Ordered **`Redacted < Forensic < Raw`** (least- to most-privileged) so a
/// downstream gate can compare tiers; [`Tier::default`] is the **most-restricted** `Redacted`.
///
/// Per ADR-0030 §6 a missing / empty / unknown tier claim maps to the most-restricted tier —
/// never a permissive default — so the derived `Ord`/`Default` are load-bearing, not cosmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Tier {
    /// The most-restricted tier and the fail-safe default (missing/empty/unknown claim).
    #[default]
    Redacted,
    /// Mid tier.
    Forensic,
    /// The least-restricted tier.
    Raw,
}

impl Tier {
    /// Map a claim string to a tier, case-insensitively. Any unrecognized value maps to the
    /// most-restricted [`Tier::Redacted`] (fail-safe — an unknown label is never permissive).
    pub fn from_claim_str(value: &str) -> Tier {
        match value.trim().to_ascii_lowercase().as_str() {
            "raw" => Tier::Raw,
            "forensic" => Tier::Forensic,
            // "redacted" and everything else (incl. unknown labels) map to the floor.
            _ => Tier::Redacted,
        }
    }

    /// Resolve the tier from a token's claims at a **configurable** claim path. A missing claim,
    /// an empty string, a non-string value, or an unrecognized label all resolve to the
    /// most-restricted [`Tier::Redacted`] (ADR-0030 §6) — never a permissive default.
    pub fn from_claims(claims: &Claims, path: &str) -> Tier {
        match claims.lookup(path).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => Tier::from_claim_str(value),
            _ => Tier::Redacted,
        }
    }
}

/// The decoded token claims the verifier reads: the required `sub`, plus every other claim
/// captured flat in `extra` so the operator-configured tier claim can be looked up from it
/// without this struct having to name the IdP's claim schema (ADR-0030 §1: protector reads the
/// tier claim, it does not define it).
#[derive(Debug, Deserialize)]
pub struct Claims {
    /// The subject — the normalized identity's principal. Required (enforced by the verifier's
    /// `set_required_spec_claims`).
    pub sub: String,
    /// Every non-`sub` claim, flattened, so a configurable tier path resolves against it.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Claims {
    /// Look up a claim by the configured path. First tries `path` as a **literal top-level key**
    /// — so a flat, namespaced claim like `https://protector.example/tier` (dots, slashes and
    /// all) resolves — then falls back to a **dotted traversal** for nested claim objects
    /// (`authz.tier`). This covers both shapes real IdPs emit without a config flag to pick one.
    fn lookup(&self, path: &str) -> Option<&Value> {
        if let Some(value) = self.extra.get(path) {
            return Some(value);
        }
        let mut segments = path.split('.');
        let mut current = self.extra.get(segments.next()?)?;
        for segment in segments {
            current = current.get(segment)?;
        }
        Some(current)
    }
}
