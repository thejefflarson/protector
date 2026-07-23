//! Unit tests for the OIDC verifier (JEF-485 / ADR-0030).
//!
//! Keys are fixed test RSA keypairs embedded below (the `jsonwebtoken` fixture pattern), and the
//! JWKS is served in-memory by [`TestFetcher`] — so the whole suite runs with ZERO egress: the
//! verifier's [`JwksFetcher`] seam is what lets a test hand it a key set without a network fetch.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use super::claims::{Claims, Tier};
use super::jwks::JwksFetcher;
use super::{
    AuthError, ConfigError, Identity, OidcConfig, SigningAlgorithm, Verifier, require_oidc,
};

const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "protector";
const KID_A: &str = "key-a";
const KID_B: &str = "key-b";
/// RSA public exponent 65537 for every fixture key (base64url of `0x010001`).
const E: &str = "AQAB";

// Two fixed test RSA-2048 keypairs (PKCS#8). Test-only; never used outside this suite.
const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCEU9JVOiw5ixgW\nU8pg41O2YjdX3ycGLXzptlAcnnrZ4B0E5lML7EVpWWzDQ4LkcdMRAYBG+NfqjFUU\n4iGdTxxehE4lkL7na4SkC5AgWknPS7kMwlg5TiPbOGmiO1cHIrKKewba4CKZidbc\n0A/h+4D4UdoHJTfPrFyvLzMDxKCWkevz47D40k+BJK6XuKbJ8nX5+qwLakbRm80y\ne3Ys+c0McRHXagnAKSn4BMCA4qxu1a3/kp0obBhFNR2o5RiLu0d59uaS2uW2qS+q\neCA36ttYtDY/zrSd1LeZynHPUZWLzibiuLJ36KYUtyaRWpmtmUZbtpIw/m9Gq+ER\nJL5FlWdLAgMBAAECggEAQIgAEsADwSwr2veRwh4aPN84zgltJn4YZIEcIFjI4GeC\nv1jzNuVKFE4f1DmgI3e+zpRE0leYNDGrbDu62NQzqYQr9/XWo1Szoqxg5OYjCIyM\n+cPs8kVBBy9DlHILxtcM6quEdEjJlsa5mYV9uV7FTlPcV4+23/fWWzhRUI0bI1Hi\nk1iM4Qj7QT/DM6VzVWHyDkL4Kh9SxnyYZ2MWpH7feCrnr2buuHC3oO2Hc2SaTxwB\niILtLzApFJfmaKMkmfuK3goE886fe3Triw4Db5tod3gTm1S/+T1x782GN+kaba1I\nH5CClZvJXN0a8BeSt6QbkPQBoogh28xO1WekAWcKAQKBgQC4TNbChgVE35w9JCRT\neYnJlTg13Pieq2TZmhfH/Muh1UnU+mEV5JQCfiKz1NOly+P3svpi2XEprtFIciU2\nyF1v55ZjOqOTB0nQdSxrP2Bjs0PBUjkwrJ94751J10naXHHZx5jz18LsQClnkoqD\nwetBACndqqntb7kUrXz1kge7KwKBgQC3ztG4OVaWTsgJ/7ekSeT+SUsHaQRs1CIS\nAF0IKPWN6A81eck1OXboaHnaK2rfAVkBC2OzVsFSYtyZjQ2Rr6D1jHFHMNegA1im\nyS4dLyV5/oGbB0b9pXxpjm8cQ0QDB1AUWzLzkiB6xS/OZaQrEsctwGpF/441S+jH\n49Psg4h0YQKBgBaHNf1DOqOnncaPg208vw4IEn3rC+0BUGuU/XExwoZ+tu60yGdP\nsJP5bS6ERnbOzIf7tcWdhMquluB/K3Nd3KYQLf7lLReM3YYAvLRDY/nr8M1RyrHb\neAbla1maWmm5wST41AaCik4sraL+c7YVXzdr2LJC6VCfxoTzjAHMnutPAoGAaorz\nfXme+xlHUqRrakt69Pq/BtiUvBBqf0y+oFA9pbfxuOmS+8sHZcfJefDYzdMWKEjV\nzcpn3L15aXgdeWj4P9zcfIuPMS0/Yc4TcM83RfOEZLxfJf+akgUB2rwS3D6M6H/E\nlPMK6J8MCvNXqbAEzDxQXaq4X6RUlik1Wk8T9YECgYA/9HsG1gWhym7sOrRjKZuo\ndaCPOThXL4diIz3gjLB4CUeXnuPKB8qMhHBHA3DJTOppa2jznIpwkkTjLBS0IxGE\nTPxpfAAVlyJTwpAzQd5gF024sAjjMXcYqwPyHIdOFeRfqw5b1aPJCNFCmJzKuXDb\nvTzQghpuo/rDAj9SCJ+K1A==\n-----END PRIVATE KEY-----\n";
const KEY_A_N: &str = "hFPSVTosOYsYFlPKYONTtmI3V98nBi186bZQHJ562eAdBOZTC-xFaVlsw0OC5HHTEQGARvjX6oxVFOIhnU8cXoROJZC-52uEpAuQIFpJz0u5DMJYOU4j2zhpojtXByKyinsG2uAimYnW3NAP4fuA-FHaByU3z6xcry8zA8SglpHr8-Ow-NJPgSSul7imyfJ1-fqsC2pG0ZvNMnt2LPnNDHER12oJwCkp-ATAgOKsbtWt_5KdKGwYRTUdqOUYi7tHefbmktrltqkvqnggN-rbWLQ2P860ndS3mcpxz1GVi84m4riyd-imFLcmkVqZrZlGW7aSMP5vRqvhESS-RZVnSw";

const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAswonwmj3aTMZ\nVHjyTeDOt+x+aFggUyIBgjW1+0NEtN9XSk9kqkmghjgHZN/wEscvzp3Ppp1bjS9c\ntCsLpTEajTIFkR0naTYtnxtLCVtOp0jxhL+lvtUu5y2e5mmrvj3IG8TEg+PMu5Fn\nGdgCugzB++3Qa2zQWm+LW5ZtFnKmHeT/KmJjsq7hFYQMaoaJBrGf43vm37k7zfSX\nYw9VAr17YhXeX40g6n2DPdjADl9MBX/dDLXCfkGIPizsV5pGLEwO85mJ+cyS9vpw\nbuhy0bi6l/+yQlQ31difcBBzCcagBDkbGaCnlOHpcC5uOIfyAubN/iKQnjtSQp3K\nSdvG8MmxAgMBAAECggEABvo0ou3qKRM5E3C4lGV3f2SvfoA+uKTp9U4Grdk0PVej\nQqDhMQ7tbY+Olc30QdgcOEHt+ufYiMka7utjJ5/KoGB+cC8p9BReLta1AUmMcdOi\n04PwAIthYrpiL3++UcaorAc9X7Q62l3sTORlquubrKZ3nPVW0lCD+3LMhpSqgBNC\n8lvVSjpto+PDi3WNH7l3dk0ukU52N/neY73mZ9v2TAmlcpvNb97j5SlkirJlxe92\nVCEAckn3ZlPFzr8ZFEaUzZ/iCkzJFF2zrBVkmIJhT09bCNPG/HymbSjmBsDYqNS2\n1xwC2xO8sl1bI+pniQXSN7HiRfKX2ka1fIhui+h/RQKBgQDhXT7TiljtptLFjz1S\n5coalluMXVNIWLMcJopJsZm4Uy8G9AJ6G0x3Tnp0UpaGg/3TDEwXTrQYpHqYXvxY\njCxJzT7FqyrrxCIhJKNVOa0+4VnP0ydRJYGE3pMnAWpPuxKfnmJQA3P3iy+Q4kkw\n6zzI5+/zsFpOINwcgw3UsbTZewKBgQDa5Qui6Hv3kKEXrpNNLO+mtHOrFqcjfV1C\noxZ2siZw7fM/pl86HCEEJpmRFJTQ3sRv6DwUcSfw+dxg0k1b5rL5R8gRBM0A1QET\nW9zDPZF0YVDrx4ACEnn8m0kYhGhmo6LGRsq8ukm3+iI/Hz2cx2jh3I0NxmNy+olg\nPaRW4LETwwKBgQCUU4jMNhw9njTPLm2QKAmS4i8y/SGZVjfcaUlPI4MnHCixjNws\nfdcgFxjlgo3rzue6hjd2h6hlJ6xAqROxO+DSWjHca8H+FsLXyYNuzl1GK4+vByyz\nbdoHF28GlxnfjCK/x8CxJPSokoUl+KlvdwQ0vuLhIsrs7Rex9FegC64aDQKBgGOk\nijSBUhUy8DIAlSs3fmxLjq/eIv1jzvVLmik0FY2os+dQi96++USTcap6TPf7wD4U\n4GyJyh3HD8u/T9m63dPeGjOtFMkBLXkrgwYZW8I3noeGDD5lPMSBx7dyZrf6W1mY\n1ictQeuO4NINHZXlrFfMdyVDHvgzFiAKT2oA5HrTAoGBAN9JyGIqcAHMHxp86VR1\npDEgJd+WvR9/kGxAepqnnkXcpM2o7bsio3XWSmrykGFEJnjX1LfkZ+16n5OdIYYm\n0S7U4ryCaXybsVfoTw4doOOEzXCxCCWR0P/l3BPSkedWyWyqGJSCnvDKkbG59qF5\ny/UYE64QE1FLiOsLb4Xmbmx6\n-----END PRIVATE KEY-----\n";
const KEY_B_N: &str = "wLMKJ8Jo92kzGVR48k3gzrfsfmhYIFMiAYI1tftDRLTfV0pPZKpJoIY4B2Tf8BLHL86dz6adW40vXLQrC6UxGo0yBZEdJ2k2LZ8bSwlbTqdI8YS_pb7VLuctnuZpq749yBvExIPjzLuRZxnYAroMwfvt0Gts0Fpvi1uWbRZyph3k_ypiY7Ku4RWEDGqGiQaxn-N75t-5O830l2MPVQK9e2IV3l-NIOp9gz3YwA5fTAV_3Qy1wn5BiD4s7FeaRixMDvOZifnMkvb6cG7octG4upf_skJUN9XYn3AQcwnGoAQ5Gxmgp5Th6XAubjiH8gLmzf4ikJ47UkKdyknbxvDJsQ";

// ---------------------------------------------------------------------------------------------
// Test helpers: an in-memory JWKS fetcher (no egress) + token signing.
// ---------------------------------------------------------------------------------------------

/// A JWKS fetcher backed by an in-memory set, with a call counter (to prove single-flight) and a
/// `rotate` hook (to prove refetch-on-unknown-kid). It can also be made to always fail, to prove
/// the fail-closed path when the IdP is unreachable.
struct TestFetcher {
    keys: std::sync::Mutex<JwkSet>,
    calls: AtomicUsize,
    fail: bool,
}

impl TestFetcher {
    fn new(set: JwkSet) -> Self {
        Self {
            keys: std::sync::Mutex::new(set),
            calls: AtomicUsize::new(0),
            fail: false,
        }
    }

    /// A fetcher that always errors — the unreachable-IdP condition.
    fn failing() -> Self {
        Self {
            keys: std::sync::Mutex::new(jwk_set(&[])),
            calls: AtomicUsize::new(0),
            fail: true,
        }
    }

    /// Swap the served set — simulates the IdP rotating its signing keys mid-process.
    fn rotate(&self, set: JwkSet) {
        *self.keys.lock().unwrap() = set;
    }

    /// How many times the store actually hit the fetcher.
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JwksFetcher for TestFetcher {
    async fn fetch(&self) -> Result<JwkSet, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(AuthError::JwksUnreachable);
        }
        Ok(self.keys.lock().unwrap().clone())
    }
}

/// Build a JWK set from `(kid, n)` pairs (all RS256, exponent `AQAB`).
fn jwk_set(entries: &[(&str, &str)]) -> JwkSet {
    let keys: Vec<Value> = entries
        .iter()
        .map(|(kid, n)| {
            json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": E })
        })
        .collect();
    serde_json::from_value(json!({ "keys": keys })).expect("valid JWK set")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A valid claim set: correct `iss`/`aud`, a human `sub`, in-window `exp`/`nbf`, tier `forensic`.
fn base_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user@example.com",
        "iat": now() - 10,
        "nbf": now() - 10,
        "exp": now() + 3600,
        "tier": "forensic",
    })
}

/// Sign `claims` as an RS256 JWT with the given `kid`.
fn sign(pem: &str, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("valid RSA PEM");
    encode(&header, claims, &key).expect("sign token")
}

fn test_config() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        tier_claim: "tier".into(),
        algorithm: SigningAlgorithm::Rs256,
    }
}

/// A verifier serving `KEY_A` in-memory, plus the fetcher handle (for call counting / rotation).
fn verifier_with_key_a() -> (Verifier, Arc<TestFetcher>) {
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    (
        Verifier::with_fetcher(test_config(), fetcher.clone()),
        fetcher,
    )
}

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

    // Flip the last character of the signature segment — still valid base64url, wrong signature.
    let mut segments: Vec<String> = token.split('.').map(String::from).collect();
    let signature = &segments[2];
    let last = signature.chars().last().unwrap();
    let replacement = if last == 'A' { 'B' } else { 'A' };
    segments[2] = format!("{}{replacement}", &signature[..signature.len() - 1]);
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
    let (verifier, fetcher) = verifier_with_key_a();

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

    // The IdP rotates to key-b. A token with the new (unknown) kid triggers exactly one refetch,
    // and then verifies against the freshly fetched key — all without a process restart.
    fetcher.rotate(jwk_set(&[(KID_B, KEY_B_N)]));
    let token_b = sign(KEY_B_PEM, KID_B, &base_claims());
    verifier
        .verify(&token_b)
        .await
        .expect("rotated key-b verifies");
    assert_eq!(fetcher.call_count(), 2, "an unknown kid refetches once");
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
    // Env is process-global; keep all mutation inside this one test (no other test reads these
    // vars) and restore a clean slate at each step to avoid cross-assertion bleed.
    let keys = [
        super::ENV_ISSUER,
        super::ENV_AUDIENCE,
        super::ENV_TIER_CLAIM,
        super::ENV_ALGORITHM,
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
