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
    /// Map a *token claim* string to a tier, case-insensitively. Any unrecognized value maps to the
    /// most-restricted [`Tier::Redacted`] (fail-safe — an unknown label in an attacker-influenced
    /// token is never permissive). This leniency is CORRECT for a token claim and WRONG for an
    /// operator config threshold — use [`Tier::parse_config`] for the latter (it fails loud).
    pub fn from_claim_str(value: &str) -> Tier {
        match value.trim().to_ascii_lowercase().as_str() {
            "raw" => Tier::Raw,
            "forensic" => Tier::Forensic,
            // "redacted" and everything else (incl. unknown labels) map to the floor.
            _ => Tier::Redacted,
        }
    }

    /// Strictly parse an OPERATOR-CONFIGURED tier threshold: an exact match on
    /// `redacted`/`forensic`/`raw` (case-insensitive), or `None` for any other value so the caller
    /// FAILS LOUD. This is the deliberate opposite of [`Tier::from_claim_str`]: a mistyped config
    /// threshold (e.g. `raww`, `admin`) must never silently degrade the gate to the least-restrictive
    /// `Redacted` (allow-all) — an operator who typos `raw` must get a loud misconfiguration, not a
    /// dashboard that quietly admits every authenticated identity.
    pub fn parse_config(value: &str) -> Option<Tier> {
        match value.trim().to_ascii_lowercase().as_str() {
            "redacted" => Some(Tier::Redacted),
            "forensic" => Some(Tier::Forensic),
            "raw" => Some(Tier::Raw),
            _ => None,
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

    /// Resolve the CEILING tier for a verified identity (JEF-501), with this precedence:
    ///
    /// 1. An explicit, **recognized** `tier` claim wins — the IdP's own statement is authoritative,
    ///    even over a configured grant (e.g. a claim of `forensic` beats a `raw` grant for the same
    ///    identity: "the IdP's explicit statement wins").
    /// 2. Else, the highest tier the operator's [`TierGrants`] awards this identity, matched by the
    ///    verified `sub` (exact) or a **verified** `email` (case-insensitive) — this is what lets an
    ///    operator grant forensic/raw access when the IdP (e.g. Cloudflare Access over GitHub)
    ///    mints no `tier` claim at all.
    /// 3. Else, the most-restricted [`Tier::Redacted`] floor (ADR-0030 §6 — never a permissive
    ///    default).
    ///
    /// Step 1 uses the STRICT [`Tier::parse_config`], not the lenient [`Tier::from_claim_str`]: an
    /// unrecognized claim value (garbage, not merely absent) is deliberately NOT treated as an
    /// explicit "redacted" statement — it falls through to the grant lookup instead, so a malformed
    /// IdP claim can never shadow a legitimate operator grant.
    ///
    /// Step 2 passes `claims.email_verified` through to [`TierGrants::resolve`]: a signature only
    /// proves the IdP MINTED the token, not that the subject OWNS the `email` claim it carries (a
    /// provider that self-asserts `email` — social login, a self-service directory — lets an
    /// attacker set their account email to a granted operator's address). An email-typed grant is
    /// therefore never a match candidate unless the token asserts `email_verified: true`; `sub`
    /// grants are unaffected (a `sub` is the IdP-assigned principal, not self-asserted).
    pub fn from_claims_with_grants(claims: &Claims, path: &str, grants: &TierGrants) -> Tier {
        if let Some(tier) = Tier::recognized_claim(claims, path) {
            return tier;
        }
        grants.resolve(&claims.sub, claims.email.as_deref(), claims.email_verified)
    }

    /// The claim at `path`, if present, a string, and a RECOGNIZED tier label — `None` for
    /// absent/empty/non-string/unrecognized (see [`Tier::from_claims_with_grants`] for why
    /// "unrecognized" must be `None`, not `Some(Redacted)`, here).
    fn recognized_claim(claims: &Claims, path: &str) -> Option<Tier> {
        let value = claims.lookup(path).and_then(Value::as_str)?;
        Tier::parse_config(value)
    }
}

/// A single grant identifier, TYPED at parse time by how the operator wrote it, so it can only
/// ever match its own field: an identifier containing `@` is an **email** (matched only against a
/// **verified** `email` claim, case-insensitively); one without is a **sub** (matched only against
/// `sub`, exactly). This closes a cross-field collision a single untyped OR would otherwise allow
/// (JEF-501 HIGH fix): without typing, an operator's `raw=alice@example.com` (meant as an email)
/// would ALSO match a token whose opaque `sub` happened to equal that exact string, silently
/// widening the granted set beyond what was configured — and symmetrically for a bare `sub`
/// identifier that happens to collide with someone's `email`. `@`-presence is an unambiguous split
/// (an email always contains `@`; a `sub` — a GitHub id, a UUID, a service-account name — never
/// does in practice), so no identifier is ever ambiguous between the two.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GrantId {
    /// Matched against a **verified** `email` claim only, case-insensitively.
    Email(String),
    /// Matched against `sub` only, exactly.
    Sub(String),
}

impl GrantId {
    fn parse(id: String) -> Self {
        if id.contains('@') {
            GrantId::Email(id)
        } else {
            GrantId::Sub(id)
        }
    }

    /// Whether this identifier matches the verified identity. An [`GrantId::Email`] NEVER matches
    /// unless `email_verified` is `true` (JEF-501 HIGH fix: a self-asserted, unverified `email`
    /// claim proves nothing about ownership — only that the IdP minted *a* token, not that the
    /// subject controls that address).
    fn matches(&self, sub: &str, email: Option<&str>, email_verified: bool) -> bool {
        match self {
            GrantId::Sub(id) => id == sub,
            GrantId::Email(id) => {
                email_verified && email.is_some_and(|email| email.eq_ignore_ascii_case(id))
            }
        }
    }
}

/// Operator-configured identity→tier grants (`PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS`, JEF-501):
/// resolves the tier ceiling from the VERIFIED token identity (`sub`/verified-`email`) when the
/// IdP mints no `tier` claim at all — e.g. Cloudflare Access relaying GitHub, which emits neither.
/// A grant is a CEILING like the claim it stands in for: it can only be READ here, never combined
/// additively, and [`TierGrants::default`] (no entries) reproduces today's behavior (every
/// identity floors to `Redacted` absent a `tier` claim).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierGrants {
    /// Identifiers granted [`Tier::Raw`].
    raw: Vec<GrantId>,
    /// Identifiers granted [`Tier::Forensic`].
    forensic: Vec<GrantId>,
}

impl TierGrants {
    /// Grant `tier` to every identifier in `ids`, each classified as email/sub by
    /// [`GrantId::parse`]. A [`Tier::Redacted`] grant is accepted (the config syntax names a real
    /// tier) but is a documented no-op: `Redacted` is already the floor every identity gets absent
    /// any grant, so there is nothing to record.
    pub fn grant(&mut self, tier: Tier, ids: impl IntoIterator<Item = String>) {
        let ids = ids.into_iter().map(GrantId::parse);
        match tier {
            Tier::Raw => self.raw.extend(ids),
            Tier::Forensic => self.forensic.extend(ids),
            Tier::Redacted => {}
        }
    }

    /// The highest tier granted to a verified identity. `sub` is matched EXACTLY against a
    /// sub-typed grant only; `email` is matched CASE-INSENSITIVELY against an email-typed grant
    /// only, and only when `email_verified` is `true` (JEF-501 — an unverified `email` claim is
    /// never a match candidate). Neither matching ⇒ [`Tier::Redacted`] (an unlisted/absent identity
    /// stays at the floor — a grant never widens beyond what's configured).
    pub fn resolve(&self, sub: &str, email: Option<&str>, email_verified: bool) -> Tier {
        if Self::matches(&self.raw, sub, email, email_verified) {
            Tier::Raw
        } else if Self::matches(&self.forensic, sub, email, email_verified) {
            Tier::Forensic
        } else {
            Tier::Redacted
        }
    }

    fn matches(ids: &[GrantId], sub: &str, email: Option<&str>, email_verified: bool) -> bool {
        ids.iter().any(|id| id.matches(sub, email, email_verified))
    }
}

/// The decoded token claims the verifier reads: the required `sub`, the optional `email` +
/// `email_verified` (JEF-501 — used, together with `sub`, to match an operator-configured tier
/// grant), plus every other claim captured flat in `extra` so the operator-configured tier claim
/// can be looked up from it without this struct having to name the IdP's claim schema (ADR-0030
/// §1: protector reads the tier claim, it does not define it).
#[derive(Debug, Deserialize)]
pub struct Claims {
    /// The subject — the normalized identity's principal. Required (enforced by the verifier's
    /// `set_required_spec_claims`).
    pub sub: String,
    /// The verified token's `email` claim, if the IdP includes one. Optional — many machine
    /// tokens (ID-JAG, service principals) carry no email at all.
    #[serde(default)]
    pub email: Option<String>,
    /// The verified token's `email_verified` claim. **Absent ⇒ `false`** — the safe default
    /// (JEF-501 HIGH fix): a signature only proves the IdP minted the token, never that the
    /// subject owns the `email` it carries, unless the IdP itself asserts it verified that
    /// ownership. An email-typed [`TierGrants`] entry never matches without this being `true`.
    #[serde(default)]
    pub email_verified: bool,
    /// Every non-`sub`/`email`/`email_verified` claim, flattened, so a configurable tier path
    /// resolves against it.
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
