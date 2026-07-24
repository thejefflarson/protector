//! Unit tests for `PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS` (JEF-501): identity→tier grants that
//! resolve the ceiling from a VERIFIED `sub`/`email` when the IdP mints no `tier` claim at all —
//! the Cloudflare-Access-over-GitHub case, verified live, that motivated this ticket. Split out of
//! `tests.rs` to keep both files well under the repo's 1,000-line cap (CLAUDE.md).
//!
//! Also covers the two HIGH findings from the PR #268 security review: an email-typed grant
//! requires `email_verified: true` (a signature only proves the IdP minted the token, never that
//! the subject owns a self-asserted `email`), and a grant identifier is typed (email vs sub) at
//! parse time so it can only ever match its own field — no cross-field collision.

use std::sync::Arc;

use serde_json::json;

use super::claims::{Claims, Tier, TierGrants};
use super::test_support::{
    AUDIENCE, ISSUER, KEY_A_N, KEY_A_PEM, KID_A, TestFetcher, base_claims, jwk_set, sign,
    test_config,
};
use super::{ConfigError, OidcConfig, Verifier};

// ---------------------------------------------------------------------------------------------
// Acceptance: identity→tier grants resolve the ceiling when the IdP mints no `tier` claim.
// ---------------------------------------------------------------------------------------------

/// A grants table with `raw` for one identity-pair and `forensic` for another, used across the
/// claim-level unit tests below.
fn sample_grants() -> TierGrants {
    let mut grants = TierGrants::default();
    grants.grant(
        Tier::Raw,
        ["thejefflarson@gmail.com".to_string(), "raw-sub".to_string()],
    );
    grants.grant(
        Tier::Forensic,
        ["alice@x.com".to_string(), "forensic-sub".to_string()],
    );
    grants
}

#[test]
fn grant_resolves_the_ceiling_by_verified_email_or_sub_when_no_tier_claim_is_present() {
    let grants = sample_grants();
    // No `tier` claim at all — the case this ticket exists for. A VERIFIED email matches.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
        "email_verified": true,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Raw
    );

    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "alice@x.com",
        "email_verified": true,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Forensic,
        "granted forensic, never widened to raw"
    );

    // Not in either list — stays at the floor.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "nobody@x.com",
        "email_verified": true,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted
    );
}

// ---------------------------------------------------------------------------------------------
// HIGH fix 1 (security review, PR #268): an email grant requires `email_verified: true`. A
// signature only proves the IdP MINTED the token, not that the subject OWNS the `email` it
// carries — a provider that self-asserts `email` (social login, a self-service directory) would
// otherwise let an attacker set their account email to a granted operator's address and be
// elevated. `sub` grants are unaffected (a `sub` is IdP-assigned, never self-asserted).
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unverified_email_equal_to_a_grant_does_not_match_a_verified_email_does() {
    let grants = sample_grants();

    // `email_verified` absent ⇒ false (the safe default) ⇒ the grant does NOT apply.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted,
        "an unverified email must NOT elevate, even if it equals a raw grant"
    );

    // `email_verified: false` explicitly ⇒ same denial.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
        "email_verified": false,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted
    );

    // `email_verified: true` ⇒ the SAME email now matches.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
        "email_verified": true,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Raw
    );
}

// ---------------------------------------------------------------------------------------------
// HIGH fix 2 (security review, PR #268): a grant identifier is TYPED (email vs sub) at parse
// time and matches ONLY its own field — no cross-field OR. Without this, an email-shaped grant
// would also match a token whose opaque `sub` happened to equal that string, and vice versa,
// silently widening the granted set past what the operator configured.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_sub_equal_to_a_granted_email_string_does_not_match_no_cross_field() {
    let grants = sample_grants();
    // `sub` == the exact string of the `raw` email grant, but a `sub` is only ever compared
    // against sub-typed grants — an email-typed grant never considers `sub` at all.
    let claims: Claims =
        serde_json::from_value(json!({ "sub": "thejefflarson@gmail.com" })).unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted,
        "a sub matching an email-typed grant string must not match — no cross-field comparison"
    );
}

#[test]
fn an_email_equal_to_a_granted_sub_string_does_not_match_no_cross_field() {
    let grants = sample_grants();
    // `email` (verified) == the exact string of the `raw` sub grant ("raw-sub"), but a sub-typed
    // grant never considers `email` at all.
    let claims: Claims = serde_json::from_value(json!({
        "sub": "irrelevant",
        "email": "raw-sub",
        "email_verified": true,
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted,
        "an email matching a sub-typed grant string must not match — no cross-field comparison"
    );
}

#[test]
fn a_sub_typed_grant_matches_only_sub_exactly() {
    let grants = sample_grants();
    assert_eq!(grants.resolve("raw-sub", None, false), Tier::Raw);
    assert_eq!(
        grants.resolve("RAW-SUB", None, false),
        Tier::Redacted,
        "sub match is exact — a case-differing sub is inert"
    );
}

#[test]
fn an_explicit_recognized_tier_claim_wins_over_a_grant() {
    // The identity has a `raw` grant, but the IdP's own token asserts `forensic` — the explicit
    // claim wins ("the IdP's explicit statement wins"), so the ceiling is forensic, not raw.
    let grants = sample_grants();
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
        "email_verified": true,
        "tier": "forensic",
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Forensic,
        "an explicit recognized claim takes precedence over a grant"
    );
}

#[test]
fn an_unrecognized_tier_claim_falls_through_to_the_grant_not_the_floor() {
    // A garbage claim value (not merely absent) must not shadow a legitimate grant: it is not an
    // "explicit recognized statement", so resolution falls through to the grant lookup.
    let grants = sample_grants();
    let claims: Claims = serde_json::from_value(json!({
        "sub": "someone",
        "email": "thejefflarson@gmail.com",
        "email_verified": true,
        "tier": "superuser",
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Raw
    );
}

#[test]
fn grant_email_match_is_case_insensitive_when_verified() {
    let grants = sample_grants();
    assert_eq!(
        grants.resolve("irrelevant", Some("THEJEFFLARSON@GMAIL.COM"), true),
        Tier::Raw
    );
    // A grant entry matching neither field is inert.
    assert_eq!(
        grants.resolve("someone-else", Some("someone-else@x.com"), true),
        Tier::Redacted
    );
}

#[test]
fn missing_or_empty_email_still_resolves_a_sub_based_grant() {
    let grants = sample_grants();
    assert_eq!(grants.resolve("forensic-sub", None, false), Tier::Forensic);
    assert_eq!(
        grants.resolve("forensic-sub", Some(""), false),
        Tier::Forensic
    );
}

#[tokio::test]
async fn verifier_end_to_end_resolves_raw_and_forensic_grants_from_a_signed_token() {
    // Mints real signed tokens (no `tier` claim) through the JEF-485 scaffolding and drives the
    // FULL verify() path — proving the grant wiring works end to end, not just at the claims layer.
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let config = OidcConfig {
        tier_grants: sample_grants(),
        ..test_config()
    };
    let verifier = Verifier::with_fetcher(config, fetcher);

    // Raw grant, matched by a VERIFIED email; token carries no `tier` claim.
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["email"] = json!("thejefflarson@gmail.com");
    claims["email_verified"] = json!(true);
    let token = sign(KEY_A_PEM, KID_A, &claims);
    let identity = verifier.verify(&token).await.expect("token verifies");
    assert_eq!(identity.tier, Tier::Raw);
    assert_eq!(identity.email.as_deref(), Some("thejefflarson@gmail.com"));

    // The SAME email, UNVERIFIED, must NOT elevate — the end-to-end HIGH fix 1 close.
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["email"] = json!("thejefflarson@gmail.com");
    let token = sign(KEY_A_PEM, KID_A, &claims);
    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Redacted);

    // Forensic grant, matched by sub, unlisted identity stays redacted.
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["sub"] = json!("forensic-sub");
    let token = sign(KEY_A_PEM, KID_A, &claims);
    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Forensic);

    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["sub"] = json!("nobody-in-particular");
    let token = sign(KEY_A_PEM, KID_A, &claims);
    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Redacted);
}

#[tokio::test]
async fn verifier_end_to_end_explicit_claim_still_wins_over_a_raw_grant() {
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let config = OidcConfig {
        tier_grants: sample_grants(),
        ..test_config()
    };
    let verifier = Verifier::with_fetcher(config, fetcher);

    // This identity has a `raw` grant, but the token itself asserts `forensic` — the claim wins.
    let mut claims = base_claims();
    claims["tier"] = json!("forensic");
    claims["email"] = json!("thejefflarson@gmail.com");
    claims["email_verified"] = json!(true);
    let token = sign(KEY_A_PEM, KID_A, &claims);
    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Forensic);
}

// ---------------------------------------------------------------------------------------------
// PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS: strict parsing, fail loud on malformed/unknown.
// ---------------------------------------------------------------------------------------------

#[test]
fn tier_grants_config_parses_multiple_tiers_and_fails_loud_on_malformed_or_unknown() {
    let _env = super::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let clear = || unsafe {
        for key in [
            super::ENV_ISSUER,
            super::ENV_AUDIENCE,
            super::ENV_TIER_GRANTS,
        ] {
            std::env::remove_var(key);
        }
    };
    clear();
    unsafe {
        std::env::set_var(super::ENV_ISSUER, ISSUER);
        std::env::set_var(super::ENV_AUDIENCE, AUDIENCE);
    }

    // A well-formed multi-tier grant list parses and resolves as documented: a VERIFIED email is
    // case-insensitive, `sub` is exact, an unlisted identity floors to Redacted.
    unsafe {
        std::env::set_var(
            super::ENV_TIER_GRANTS,
            "raw=thejefflarson@gmail.com;forensic=alice@x.com,BOB-SUB",
        );
    }
    let config = OidcConfig::from_env().unwrap().unwrap();
    assert_eq!(
        config
            .tier_grants
            .resolve("someone", Some("THEJEFFLARSON@GMAIL.COM"), true),
        Tier::Raw,
        "a verified email matches case-insensitively"
    );
    assert_eq!(
        config
            .tier_grants
            .resolve("someone", Some("thejefflarson@gmail.com"), false),
        Tier::Redacted,
        "the SAME email, unverified, does not match"
    );
    assert_eq!(
        config
            .tier_grants
            .resolve("someone", Some("alice@x.com"), true),
        Tier::Forensic
    );
    assert_eq!(
        config.tier_grants.resolve("BOB-SUB", None, false),
        Tier::Forensic,
        "sub match is exact and works with no email at all"
    );
    assert_eq!(
        config.tier_grants.resolve("bob-sub", None, false),
        Tier::Redacted,
        "sub match is exact — a case-differing sub is inert"
    );
    assert_eq!(
        config
            .tier_grants
            .resolve("nobody", Some("nobody@x.com"), true),
        Tier::Redacted,
        "an identity matching neither list stays at the floor"
    );

    // An unknown tier name (not redacted/forensic/raw) fails loud.
    unsafe { std::env::set_var(super::ENV_TIER_GRANTS, "admin=alice@x.com") };
    assert_eq!(
        OidcConfig::from_env(),
        Err(ConfigError::UnsupportedTierGrant("admin".into()))
    );

    // Malformed syntax (no `=`) fails loud.
    unsafe { std::env::set_var(super::ENV_TIER_GRANTS, "raw-alice@x.com") };
    assert!(matches!(
        OidcConfig::from_env(),
        Err(ConfigError::MalformedTierGrants(_))
    ));

    // An entry with no identifiers fails loud.
    unsafe { std::env::set_var(super::ENV_TIER_GRANTS, "raw=") };
    assert!(matches!(
        OidcConfig::from_env(),
        Err(ConfigError::MalformedTierGrants(_))
    ));

    // A stray `;` (empty entry) fails loud rather than being silently skipped.
    unsafe {
        std::env::set_var(
            super::ENV_TIER_GRANTS,
            "raw=alice@x.com;;forensic=bob@x.com",
        )
    };
    assert!(matches!(
        OidcConfig::from_env(),
        Err(ConfigError::MalformedTierGrants(_))
    ));

    clear();
}
