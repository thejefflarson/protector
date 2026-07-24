//! Unit tests for the OIDC verifier (JEF-485 / ADR-0030).
//!
//! Keys and the in-memory (zero-egress) JWKS fetcher live in [`super::test_support`] — the whole
//! suite mints valid/invalid/rotated tokens through that shared seam without a network fetch.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use super::claims::{Claims, Tier, TierGrants};
use super::jwks::{HttpJwksFetcher, JwksFetcher, JwksStore};
use super::test_support::{
    AUDIENCE, E, ISSUER, KEY_A_N, KEY_A_PEM, KEY_B_N, KEY_B_PEM, KID_A, KID_B, TestFetcher,
    base_claims, jwk_set, now, sign, spawn_oidc_server, test_config, verifier_with_key_a,
};
use super::{
    AuthError, ConfigError, Identity, OidcConfig, SigningAlgorithm, Verifier, require_oidc,
};

// ---------------------------------------------------------------------------------------------
// Acceptance: happy path.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn valid_token_verifies_and_yields_subject_and_tier() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let token = sign(KEY_A_PEM, KID_A, &base_claims());

    let identity = verifier.verify(&token).await.expect("valid token verifies");
    assert_eq!(identity.subject, "user@example.com");
    assert_eq!(identity.tier, Tier::Forensic);
}

// ---------------------------------------------------------------------------------------------
// Acceptance: each rejection is a DISTINCT error variant.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tampered_signature_rejects_distinctly() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let token = sign(KEY_A_PEM, KID_A, &base_claims());

    // Flip the FIRST character of the signature segment — still valid base64url, but it always
    // changes the top bits of the first signature byte (unlike the last char, whose low bits are
    // ignored padding), so the decoded signature bytes always differ → deterministic mismatch.
    let mut segments: Vec<String> = token.split('.').map(String::from).collect();
    let signature = &segments[2];
    let first = signature.chars().next().unwrap();
    let replacement = if first == 'A' { 'B' } else { 'A' };
    segments[2] = format!("{replacement}{}", &signature[1..]);
    let tampered = segments.join(".");

    assert_eq!(
        verifier.verify(&tampered).await.unwrap_err(),
        AuthError::InvalidSignature
    );
}

#[tokio::test]
async fn wrong_issuer_rejects_distinctly() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims["iss"] = json!("https://evil.example");
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(
        verifier.verify(&token).await.unwrap_err(),
        AuthError::InvalidIssuer
    );
}

#[tokio::test]
async fn wrong_audience_rejects_distinctly() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims["aud"] = json!("some-other-service");
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(
        verifier.verify(&token).await.unwrap_err(),
        AuthError::InvalidAudience
    );
}

#[tokio::test]
async fn expired_token_rejects_distinctly() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims["nbf"] = json!(now() - 7200);
    claims["exp"] = json!(now() - 3600);
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(
        verifier.verify(&token).await.unwrap_err(),
        AuthError::Expired
    );
}

#[tokio::test]
async fn not_yet_valid_token_rejects_distinctly() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims["nbf"] = json!(now() + 3600);
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(
        verifier.verify(&token).await.unwrap_err(),
        AuthError::NotYetValid
    );
}

// ---------------------------------------------------------------------------------------------
// Acceptance: alg pinning closes alg-confusion (the load-bearing §1 close).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn alg_confusion_hs256_with_the_public_key_is_rejected() {
    // The classic attack: forge an HS256 token and hope the verifier HMAC-verifies it against the
    // RSA PUBLIC key (which is public). Because the algorithm is pinned to the asymmetric family
    // from config — never read from the token's own header — the header `alg: HS256` is rejected
    // BEFORE any signature check. We hand-build the token so no HMAC backend is even needed.
    let (verifier, _fetcher) = verifier_with_key_a();
    let header = json!({ "alg": "HS256", "typ": "JWT", "kid": KID_A });
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&base_claims()).unwrap()),
        URL_SAFE_NO_PAD.encode(b"not-a-real-signature"),
    );

    assert_eq!(
        verifier.verify(&token).await.unwrap_err(),
        AuthError::InvalidAlgorithm
    );
}

// ---------------------------------------------------------------------------------------------
// Acceptance: JWKS caching, single-flight refresh, and refetch-on-unknown-kid rotation.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn jwks_is_cached_and_refetched_on_unknown_kid_rotation() {
    // End-to-end through the Verifier, over a store with a short refresh interval so a genuine
    // rotation can cross it deterministically (the default interval would throttle the immediate
    // rotation in a fast test).
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let store = JwksStore::with_policy(
        fetcher.clone(),
        Duration::from_secs(300),
        Duration::from_millis(50),
    );
    let verifier = Verifier::with_store(test_config(), store);

    // First verification fetches once and caches.
    let token_a = sign(KEY_A_PEM, KID_A, &base_claims());
    verifier.verify(&token_a).await.expect("key-a verifies");
    assert_eq!(fetcher.call_count(), 1, "first verify fetches the JWKS");

    // A second key-a verification is served entirely from cache — no refetch.
    verifier
        .verify(&token_a)
        .await
        .expect("key-a still verifies");
    assert_eq!(fetcher.call_count(), 1, "a known kid is served from cache");

    // The IdP rotates to key-b. Once the refresh interval has elapsed, a token with the new
    // (unknown) kid triggers exactly one refetch and verifies against the freshly fetched key —
    // all without a process restart.
    fetcher.rotate(jwk_set(&[(KID_B, KEY_B_N)]));
    tokio::time::sleep(Duration::from_millis(60)).await;
    let token_b = sign(KEY_B_PEM, KID_B, &base_claims());
    verifier
        .verify(&token_b)
        .await
        .expect("rotated key-b verifies");
    assert_eq!(
        fetcher.call_count(),
        2,
        "an unknown kid refetches once past the interval"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_kid_burst_is_rate_limited_to_one_fetch_per_interval() {
    // The kid is attacker-controlled (read from the UNSIGNED header before any signature check), so
    // a stream of distinct unknown kids must drive at most ONE network fetch per interval — whether
    // the misses arrive concurrently or sequentially — while a genuine rotation still resolves once
    // the interval elapses. This closes the sequential-miss stampede the single-flight lock alone
    // does not cover.
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let store = Arc::new(JwksStore::with_policy(
        fetcher.clone(),
        Duration::from_secs(300),
        Duration::from_millis(150),
    ));

    // Warm the cache with the real key (one fetch), which also starts the interval clock.
    store
        .decoding_key(Some(KID_A))
        .await
        .expect("key-a resolves");
    assert_eq!(fetcher.call_count(), 1);

    // Sequential unknown-kid spray: each misses the fresh cache, but the throttle denies it
    // without egress — the fetch count does not move.
    for i in 0..20 {
        let kid = format!("attacker-seq-{i}");
        assert_eq!(
            store.decoding_key(Some(&kid)).await.unwrap_err(),
            AuthError::UnknownKey
        );
    }
    assert_eq!(
        fetcher.call_count(),
        1,
        "a sequential unknown-kid burst drives no extra fetch"
    );

    // Concurrent unknown-kid spray: the same guarantee under load.
    let mut handles = Vec::new();
    for i in 0..20 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            let kid = format!("attacker-conc-{i}");
            store.decoding_key(Some(&kid)).await
        }));
    }
    for handle in handles {
        assert_eq!(handle.await.unwrap().unwrap_err(), AuthError::UnknownKey);
    }
    assert_eq!(
        fetcher.call_count(),
        1,
        "a concurrent unknown-kid burst drives no extra fetch"
    );

    // A genuine rotation still resolves once the interval has elapsed — exactly one further fetch.
    fetcher.rotate(jwk_set(&[(KID_B, KEY_B_N)]));
    tokio::time::sleep(Duration::from_millis(170)).await;
    store
        .decoding_key(Some(KID_B))
        .await
        .expect("rotated key-b resolves past the interval");
    assert_eq!(
        fetcher.call_count(),
        2,
        "one fetch per interval: rotation resolves after the wait"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cold_kid_refresh_is_single_flight() {
    // A cold cache under concurrent load must NOT stampede the IdP: all callers coalesce onto one
    // fetch. Fire many verifications against an empty cache and assert exactly one fetch happened.
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let verifier = Arc::new(Verifier::with_fetcher(test_config(), fetcher.clone()));
    let token = Arc::new(sign(KEY_A_PEM, KID_A, &base_claims()));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let verifier = verifier.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            verifier.verify(token.as_str()).await
        }));
    }
    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("each concurrent verify succeeds");
    }
    assert_eq!(
        fetcher.call_count(),
        1,
        "single-flight: a cold kid under load fetches exactly once"
    );
}

// ---------------------------------------------------------------------------------------------
// Acceptance: fail-closed when the JWKS / issuer is unreachable (NEVER a bypass).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn jwks_unreachable_fails_closed() {
    let fetcher = Arc::new(TestFetcher::failing());
    let verifier = Verifier::with_fetcher(test_config(), fetcher);
    let token = sign(KEY_A_PEM, KID_A, &base_claims());

    // An unreachable IdP is an ERROR, never a pass — and it maps to a 503, not an allow.
    let error = verifier.verify(&token).await.unwrap_err();
    assert_eq!(error, AuthError::JwksUnreachable);
    assert_eq!(error.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------------------------
// Acceptance: ID-JAG token (aud=protector, human sub) verifies via the SAME path.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn accepts_id_jag_audience_token_via_the_same_path() {
    // To the resource server an ID-JAG is just a JWT with aud=protector and a human sub — the
    // grant-type marker does not change verification (ADR-0030 §3). Same lane, same checks.
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims["sub"] = json!("alice@corp.example");
    claims["grant_type"] = json!("urn:ietf:params:oauth:grant-type:jwt-bearer");
    claims["tier"] = json!("raw");
    let token = sign(KEY_A_PEM, KID_A, &claims);

    let identity = verifier
        .verify(&token)
        .await
        .expect("ID-JAG token verifies");
    assert_eq!(identity.subject, "alice@corp.example");
    assert_eq!(identity.tier, Tier::Raw);
}

// ---------------------------------------------------------------------------------------------
// Acceptance: tier from a configurable claim path; missing/empty → most-restricted.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tier_extracted_from_configured_claim_path_end_to_end() {
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let config = OidcConfig {
        tier_claim: "authz.tier".into(),
        ..test_config()
    };
    let verifier = Verifier::with_fetcher(config, fetcher);

    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["authz"] = json!({ "tier": "raw" });
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Raw);
}

#[tokio::test]
async fn missing_tier_claim_maps_to_most_restricted_end_to_end() {
    let (verifier, _fetcher) = verifier_with_key_a();
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    let token = sign(KEY_A_PEM, KID_A, &claims);

    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Redacted);
}

#[test]
fn tier_missing_empty_unknown_or_non_string_is_most_restricted() {
    let cases = [
        json!({ "sub": "s" }),                      // absent
        json!({ "sub": "s", "tier": "" }),          // empty
        json!({ "sub": "s", "tier": "   " }),       // whitespace
        json!({ "sub": "s", "tier": "superuser" }), // unknown label
        json!({ "sub": "s", "tier": 42 }),          // non-string
    ];
    for case in cases {
        let claims: Claims = serde_json::from_value(case.clone()).unwrap();
        assert_eq!(
            Tier::from_claims(&claims, "tier"),
            Tier::Redacted,
            "expected most-restricted for {case}"
        );
    }
}

#[test]
fn tier_resolves_literal_flat_and_nested_paths_case_insensitively() {
    // A flat, namespaced claim key (dots and slashes) resolves as a literal key.
    let claims: Claims =
        serde_json::from_value(json!({ "sub": "s", "https://protector.example/tier": "RAW" }))
            .unwrap();
    assert_eq!(
        Tier::from_claims(&claims, "https://protector.example/tier"),
        Tier::Raw
    );

    // A nested claim object resolves by dotted traversal.
    let claims: Claims =
        serde_json::from_value(json!({ "sub": "s", "authz": { "tier": "forensic" } })).unwrap();
    assert_eq!(Tier::from_claims(&claims, "authz.tier"), Tier::Forensic);
}

#[test]
fn tier_ordering_is_redacted_lt_forensic_lt_raw_with_redacted_default() {
    assert!(Tier::Redacted < Tier::Forensic);
    assert!(Tier::Forensic < Tier::Raw);
    assert_eq!(Tier::default(), Tier::Redacted);
}

// ---------------------------------------------------------------------------------------------
// Acceptance (JEF-501): identity→tier grants resolve the ceiling when the IdP mints no `tier`
// claim — the Cloudflare-Access-over-GitHub case, verified live, that motivated this ticket.
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
fn grant_resolves_the_ceiling_by_email_or_sub_when_no_tier_claim_is_present() {
    let grants = sample_grants();
    // No `tier` claim at all — the case this ticket exists for.
    let claims: Claims =
        serde_json::from_value(json!({ "sub": "someone", "email": "thejefflarson@gmail.com" }))
            .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Raw
    );

    let claims: Claims =
        serde_json::from_value(json!({ "sub": "someone", "email": "alice@x.com" })).unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Forensic,
        "granted forensic, never widened to raw"
    );

    // Not in either list — stays at the floor.
    let claims: Claims =
        serde_json::from_value(json!({ "sub": "someone", "email": "nobody@x.com" })).unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Redacted
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
        "tier": "superuser",
    }))
    .unwrap();
    assert_eq!(
        Tier::from_claims_with_grants(&claims, "tier", &grants),
        Tier::Raw
    );
}

#[test]
fn grant_email_match_is_case_insensitive_sub_match_is_exact() {
    let grants = sample_grants();
    // Email: case-insensitive.
    assert_eq!(
        grants.resolve("irrelevant", Some("THEJEFFLARSON@GMAIL.COM")),
        Tier::Raw
    );
    // Sub: exact only — a case-differing sub does not match.
    assert_eq!(grants.resolve("RAW-SUB", None), Tier::Redacted);
    assert_eq!(grants.resolve("raw-sub", None), Tier::Raw);
    // A grant entry matching neither is inert.
    assert_eq!(
        grants.resolve("someone-else", Some("someone-else@x.com")),
        Tier::Redacted
    );
}

#[test]
fn missing_or_empty_email_still_resolves_a_sub_based_grant() {
    let grants = sample_grants();
    assert_eq!(grants.resolve("forensic-sub", None), Tier::Forensic);
    assert_eq!(grants.resolve("forensic-sub", Some("")), Tier::Forensic);
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

    // Raw grant, matched by email; token carries no `tier` claim.
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tier");
    claims["email"] = json!("thejefflarson@gmail.com");
    let token = sign(KEY_A_PEM, KID_A, &claims);
    let identity = verifier.verify(&token).await.expect("token verifies");
    assert_eq!(identity.tier, Tier::Raw);
    assert_eq!(identity.email.as_deref(), Some("thejefflarson@gmail.com"));

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
    let token = sign(KEY_A_PEM, KID_A, &claims);
    assert_eq!(verifier.verify(&token).await.unwrap().tier, Tier::Forensic);
}

// ---------------------------------------------------------------------------------------------
// Acceptance: one path reads a token from BOTH lanes; the mountable layer denies fail-closed.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn layer_reads_token_from_bearer_cf_header_and_cf_cookie() {
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let verifier = Arc::new(Verifier::with_fetcher(test_config(), fetcher));
    let token = sign(KEY_A_PEM, KID_A, &base_claims());

    // The handler echoes the injected identity's subject — proving the layer both authenticated
    // and inserted the normalized Identity into the request extensions.
    async fn echo_subject(Extension(identity): Extension<Identity>) -> String {
        identity.subject
    }
    let app = Router::new()
        .route("/", get(echo_subject))
        .layer(from_fn_with_state(verifier, require_oidc));

    let lanes = [
        (
            axum::http::header::AUTHORIZATION.as_str(),
            format!("Bearer {token}"),
        ),
        ("Cf-Access-Jwt-Assertion", token.clone()),
        (
            axum::http::header::COOKIE.as_str(),
            format!("CF_Authorization={token}; other=1"),
        ),
    ];
    for (name, value) in lanes {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(name, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "lane `{name}` authenticates"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            b"user@example.com",
            "lane `{name}` yields the subject"
        );
    }

    // No token on any lane → 401 (fail closed).
    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn layer_returns_503_when_jwks_unreachable() {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    let fetcher = Arc::new(TestFetcher::failing());
    let verifier = Arc::new(Verifier::with_fetcher(test_config(), fetcher));
    let token = sign(KEY_A_PEM, KID_A, &base_claims());
    let app = Router::new()
        .route("/", get(|| async { "served" }))
        .layer(from_fn_with_state(verifier, require_oidc));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Unreachable IdP → 503, never the served body (fail closed, ADR-0030 §6).
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------------------------
// OidcConfig::from_env models UNCONFIGURED (issuer absent), configured, and misconfiguration.
// ---------------------------------------------------------------------------------------------

#[test]
fn from_env_models_unconfigured_configured_and_errors() {
    // Env is process-global; serialize with the other PROTECTOR_DASHBOARD_OIDC_* env test
    // (`build_dashboard_auth`) via the shared lock, and restore a clean slate at each step.
    let _env = super::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let keys = [
        super::ENV_ISSUER,
        super::ENV_AUDIENCE,
        super::ENV_TIER_CLAIM,
        super::ENV_ALGORITHM,
        super::ENV_TIER_GRANTS,
    ];
    let clear = || unsafe {
        for key in keys {
            std::env::remove_var(key);
        }
    };

    clear();
    // UNCONFIGURED: issuer absent ⇒ Ok(None) — the representable "off" state.
    assert_eq!(OidcConfig::from_env(), Ok(None));

    // Issuer set but audience missing ⇒ loud misconfiguration.
    unsafe { std::env::set_var(super::ENV_ISSUER, ISSUER) };
    assert_eq!(OidcConfig::from_env(), Err(ConfigError::MissingAudience));

    // Issuer + audience ⇒ Some, with the default tier claim and default RS256.
    unsafe { std::env::set_var(super::ENV_AUDIENCE, AUDIENCE) };
    let config = OidcConfig::from_env().unwrap().unwrap();
    assert_eq!(config.issuer, ISSUER);
    assert_eq!(config.audience, AUDIENCE);
    assert_eq!(config.tier_claim, "tier");
    assert_eq!(config.algorithm, SigningAlgorithm::Rs256);
    assert_eq!(
        config.tier_grants,
        super::claims::TierGrants::default(),
        "TIER_GRANTS unset ⇒ no grants (unchanged behavior)"
    );

    // Configurable tier claim + ES256.
    unsafe {
        std::env::set_var(super::ENV_TIER_CLAIM, "authz.tier");
        std::env::set_var(super::ENV_ALGORITHM, "ES256");
    }
    let config = OidcConfig::from_env().unwrap().unwrap();
    assert_eq!(config.tier_claim, "authz.tier");
    assert_eq!(config.algorithm, SigningAlgorithm::Es256);

    // A symmetric / unsupported algorithm is rejected, not pinned.
    unsafe { std::env::set_var(super::ENV_ALGORITHM, "HS256") };
    assert_eq!(
        OidcConfig::from_env(),
        Err(ConfigError::UnsupportedAlgorithm("HS256".into()))
    );

    clear();
}

// ---------------------------------------------------------------------------------------------
// PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS (JEF-501): strict parsing, fail loud on malformed/unknown.
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

    // A well-formed multi-tier grant list parses and resolves as documented: `sub` exact,
    // `email` case-insensitive, an unlisted identity floors to Redacted.
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
            .resolve("someone", Some("THEJEFFLARSON@GMAIL.COM")),
        Tier::Raw,
        "email match is case-insensitive"
    );
    assert_eq!(
        config.tier_grants.resolve("someone", Some("alice@x.com")),
        Tier::Forensic
    );
    assert_eq!(
        config.tier_grants.resolve("BOB-SUB", None),
        Tier::Forensic,
        "sub match is exact and works with no email at all"
    );
    assert_eq!(
        config.tier_grants.resolve("bob-sub", None),
        Tier::Redacted,
        "sub match is exact — a case-differing sub is inert"
    );
    assert_eq!(
        config.tier_grants.resolve("nobody", Some("nobody@x.com")),
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

// ---------------------------------------------------------------------------------------------
// HTTP JWKS fetch: response-body size cap over a loopback OIDC server (no external egress). The
// loopback server helper lives in `super::test_support::spawn_oidc_server`.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oversized_jwks_body_is_rejected_fail_closed() {
    // A 2 MiB JWKS body exceeds the 1 MiB cap → rejected before parse (fail closed), never OOM.
    let (base, _server) = spawn_oidc_server("x".repeat(2 * 1024 * 1024)).await;
    let fetcher = HttpJwksFetcher::new(base);
    assert_eq!(
        fetcher.fetch().await.unwrap_err(),
        AuthError::JwksUnreachable
    );
}

#[tokio::test]
async fn normal_size_jwks_body_parses() {
    let body = json!({
        "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID_A, "n": KEY_A_N, "e": E }]
    })
    .to_string();
    let (base, _server) = spawn_oidc_server(body).await;
    let fetcher = HttpJwksFetcher::new(base);
    let keys = fetcher.fetch().await.expect("a normal-size JWKS parses");
    assert!(keys.find(KID_A).is_some(), "the served key is present");
}
