//! Shared, zero-egress test scaffolding for the OIDC auth suites (JEF-485 verifier unit tests +
//! JEF-487 enforcement integration tests). Fixed test RSA keypairs are embedded, and the JWKS is
//! served in-memory by [`TestFetcher`] — so the whole suite runs with NO network: the verifier's
//! [`JwksFetcher`] seam is what lets a test hand it a key set without a fetch. Extracted here so the
//! two suites mint valid/invalid/rotated tokens from ONE source (no fixture duplication).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use super::jwks::JwksFetcher;
use super::{AuthError, OidcConfig, SigningAlgorithm, Verifier};

/// Serializes the tests that mutate the process-global `PROTECTOR_DASHBOARD_OIDC_*` env — the
/// verifier's `from_env` and the dashboard's `build_dashboard_auth` — so cargo's parallel test
/// threads can't interleave their env writes and read each other's half-set state. Acquire it
/// (`ENV_LOCK.lock()...`) at the top of any such test.
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) const ISSUER: &str = "https://issuer.example";
pub(crate) const AUDIENCE: &str = "protector";
pub(crate) const KID_A: &str = "key-a";
pub(crate) const KID_B: &str = "key-b";
/// RSA public exponent 65537 for every fixture key (base64url of `0x010001`).
pub(crate) const E: &str = "AQAB";

// Two fixed test RSA-2048 keypairs (PKCS#8). Test-only; never used outside this suite.
pub(crate) const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCEU9JVOiw5ixgW\nU8pg41O2YjdX3ycGLXzptlAcnnrZ4B0E5lML7EVpWWzDQ4LkcdMRAYBG+NfqjFUU\n4iGdTxxehE4lkL7na4SkC5AgWknPS7kMwlg5TiPbOGmiO1cHIrKKewba4CKZidbc\n0A/h+4D4UdoHJTfPrFyvLzMDxKCWkevz47D40k+BJK6XuKbJ8nX5+qwLakbRm80y\ne3Ys+c0McRHXagnAKSn4BMCA4qxu1a3/kp0obBhFNR2o5RiLu0d59uaS2uW2qS+q\neCA36ttYtDY/zrSd1LeZynHPUZWLzibiuLJ36KYUtyaRWpmtmUZbtpIw/m9Gq+ER\nJL5FlWdLAgMBAAECggEAQIgAEsADwSwr2veRwh4aPN84zgltJn4YZIEcIFjI4GeC\nv1jzNuVKFE4f1DmgI3e+zpRE0leYNDGrbDu62NQzqYQr9/XWo1Szoqxg5OYjCIyM\n+cPs8kVBBy9DlHILxtcM6quEdEjJlsa5mYV9uV7FTlPcV4+23/fWWzhRUI0bI1Hi\nk1iM4Qj7QT/DM6VzVWHyDkL4Kh9SxnyYZ2MWpH7feCrnr2buuHC3oO2Hc2SaTxwB\niILtLzApFJfmaKMkmfuK3goE886fe3Triw4Db5tod3gTm1S/+T1x782GN+kaba1I\nH5CClZvJXN0a8BeSt6QbkPQBoogh28xO1WekAWcKAQKBgQC4TNbChgVE35w9JCRT\neYnJlTg13Pieq2TZmhfH/Muh1UnU+mEV5JQCfiKz1NOly+P3svpi2XEprtFIciU2\nyF1v55ZjOqOTB0nQdSxrP2Bjs0PBUjkwrJ94751J10naXHHZx5jz18LsQClnkoqD\nwetBACndqqntb7kUrXz1kge7KwKBgQC3ztG4OVaWTsgJ/7ekSeT+SUsHaQRs1CIS\nAF0IKPWN6A81eck1OXboaHnaK2rfAVkBC2OzVsFSYtyZjQ2Rr6D1jHFHMNegA1im\nyS4dLyV5/oGbB0b9pXxpjm8cQ0QDB1AUWzLzkiB6xS/OZaQrEsctwGpF/441S+jH\n49Psg4h0YQKBgBaHNf1DOqOnncaPg208vw4IEn3rC+0BUGuU/XExwoZ+tu60yGdP\nsJP5bS6ERnbOzIf7tcWdhMquluB/K3Nd3KYQLf7lLReM3YYAvLRDY/nr8M1RyrHb\neAbla1maWmm5wST41AaCik4sraL+c7YVXzdr2LJC6VCfxoTzjAHMnutPAoGAaorz\nfXme+xlHUqRrakt69Pq/BtiUvBBqf0y+oFA9pbfxuOmS+8sHZcfJefDYzdMWKEjV\nzcpn3L15aXgdeWj4P9zcfIuPMS0/Yc4TcM83RfOEZLxfJf+akgUB2rwS3D6M6H/E\nlPMK6J8MCvNXqbAEzDxQXaq4X6RUlik1Wk8T9YECgYA/9HsG1gWhym7sOrRjKZuo\ndaCPOThXL4diIz3gjLB4CUeXnuPKB8qMhHBHA3DJTOppa2jznIpwkkTjLBS0IxGE\nTPxpfAAVlyJTwpAzQd5gF024sAjjMXcYqwPyHIdOFeRfqw5b1aPJCNFCmJzKuXDb\nvTzQghpuo/rDAj9SCJ+K1A==\n-----END PRIVATE KEY-----\n";
pub(crate) const KEY_A_N: &str = "hFPSVTosOYsYFlPKYONTtmI3V98nBi186bZQHJ562eAdBOZTC-xFaVlsw0OC5HHTEQGARvjX6oxVFOIhnU8cXoROJZC-52uEpAuQIFpJz0u5DMJYOU4j2zhpojtXByKyinsG2uAimYnW3NAP4fuA-FHaByU3z6xcry8zA8SglpHr8-Ow-NJPgSSul7imyfJ1-fqsC2pG0ZvNMnt2LPnNDHER12oJwCkp-ATAgOKsbtWt_5KdKGwYRTUdqOUYi7tHefbmktrltqkvqnggN-rbWLQ2P860ndS3mcpxz1GVi84m4riyd-imFLcmkVqZrZlGW7aSMP5vRqvhESS-RZVnSw";

pub(crate) const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAswonwmj3aTMZ\nVHjyTeDOt+x+aFggUyIBgjW1+0NEtN9XSk9kqkmghjgHZN/wEscvzp3Ppp1bjS9c\ntCsLpTEajTIFkR0naTYtnxtLCVtOp0jxhL+lvtUu5y2e5mmrvj3IG8TEg+PMu5Fn\nGdgCugzB++3Qa2zQWm+LW5ZtFnKmHeT/KmJjsq7hFYQMaoaJBrGf43vm37k7zfSX\nYw9VAr17YhXeX40g6n2DPdjADl9MBX/dDLXCfkGIPizsV5pGLEwO85mJ+cyS9vpw\nbuhy0bi6l/+yQlQ31difcBBzCcagBDkbGaCnlOHpcC5uOIfyAubN/iKQnjtSQp3K\nSdvG8MmxAgMBAAECggEABvo0ou3qKRM5E3C4lGV3f2SvfoA+uKTp9U4Grdk0PVej\nQqDhMQ7tbY+Olc30QdgcOEHt+ufYiMka7utjJ5/KoGB+cC8p9BReLta1AUmMcdOi\n04PwAIthYrpiL3++UcaorAc9X7Q62l3sTORlquubrKZ3nPVW0lCD+3LMhpSqgBNC\n8lvVSjpto+PDi3WNH7l3dk0ukU52N/neY73mZ9v2TAmlcpvNb97j5SlkirJlxe92\nVCEAckn3ZlPFzr8ZFEaUzZ/iCkzJFF2zrBVkmIJhT09bCNPG/HymbSjmBsDYqNS2\n1xwC2xO8sl1bI+pniQXSN7HiRfKX2ka1fIhui+h/RQKBgQDhXT7TiljtptLFjz1S\n5coalluMXVNIWLMcJopJsZm4Uy8G9AJ6G0x3Tnp0UpaGg/3TDEwXTrQYpHqYXvxY\njCxJzT7FqyrrxCIhJKNVOa0+4VnP0ydRJYGE3pMnAWpPuxKfnmJQA3P3iy+Q4kkw\n6zzI5+/zsFpOINwcgw3UsbTZewKBgQDa5Qui6Hv3kKEXrpNNLO+mtHOrFqcjfV1C\noxZ2siZw7fM/pl86HCEEJpmRFJTQ3sRv6DwUcSfw+dxg0k1b5rL5R8gRBM0A1QET\nW9zDPZF0YVDrx4ACEnn8m0kYhGhmo6LGRsq8ukm3+iI/Hz2cx2jh3I0NxmNy+olg\nPaRW4LETwwKBgQCUU4jMNhw9njTPLm2QKAmS4i8y/SGZVjfcaUlPI4MnHCixjNws\nfdcgFxjlgo3rzue6hjd2h6hlJ6xAqROxO+DSWjHca8H+FsLXyYNuzl1GK4+vByyz\nbdoHF28GlxnfjCK/x8CxJPSokoUl+KlvdwQ0vuLhIsrs7Rex9FegC64aDQKBgGOk\nijSBUhUy8DIAlSs3fmxLjq/eIv1jzvVLmik0FY2os+dQi96++USTcap6TPf7wD4U\n4GyJyh3HD8u/T9m63dPeGjOtFMkBLXkrgwYZW8I3noeGDD5lPMSBx7dyZrf6W1mY\n1ictQeuO4NINHZXlrFfMdyVDHvgzFiAKT2oA5HrTAoGBAN9JyGIqcAHMHxp86VR1\npDEgJd+WvR9/kGxAepqnnkXcpM2o7bsio3XWSmrykGFEJnjX1LfkZ+16n5OdIYYm\n0S7U4ryCaXybsVfoTw4doOOEzXCxCCWR0P/l3BPSkedWyWyqGJSCnvDKkbG59qF5\ny/UYE64QE1FLiOsLb4Xmbmx6\n-----END PRIVATE KEY-----\n";
pub(crate) const KEY_B_N: &str = "wLMKJ8Jo92kzGVR48k3gzrfsfmhYIFMiAYI1tftDRLTfV0pPZKpJoIY4B2Tf8BLHL86dz6adW40vXLQrC6UxGo0yBZEdJ2k2LZ8bSwlbTqdI8YS_pb7VLuctnuZpq749yBvExIPjzLuRZxnYAroMwfvt0Gts0Fpvi1uWbRZyph3k_ypiY7Ku4RWEDGqGiQaxn-N75t-5O830l2MPVQK9e2IV3l-NIOp9gz3YwA5fTAV_3Qy1wn5BiD4s7FeaRixMDvOZifnMkvb6cG7octG4upf_skJUN9XYn3AQcwnGoAQ5Gxmgp5Th6XAubjiH8gLmzf4ikJ47UkKdyknbxvDJsQ";

/// A JWKS fetcher backed by an in-memory set, with a call counter (to prove single-flight) and a
/// `rotate` hook (to prove refetch-on-unknown-kid). It can also be made to always fail, to prove
/// the fail-closed path when the IdP is unreachable.
pub(crate) struct TestFetcher {
    keys: std::sync::Mutex<JwkSet>,
    calls: AtomicUsize,
    fail: bool,
}

impl TestFetcher {
    pub(crate) fn new(set: JwkSet) -> Self {
        Self {
            keys: std::sync::Mutex::new(set),
            calls: AtomicUsize::new(0),
            fail: false,
        }
    }

    /// A fetcher that always errors — the unreachable-IdP condition.
    pub(crate) fn failing() -> Self {
        Self {
            keys: std::sync::Mutex::new(jwk_set(&[])),
            calls: AtomicUsize::new(0),
            fail: true,
        }
    }

    /// Swap the served set — simulates the IdP rotating its signing keys mid-process.
    pub(crate) fn rotate(&self, set: JwkSet) {
        *self.keys.lock().unwrap() = set;
    }

    /// How many times the store actually hit the fetcher.
    pub(crate) fn call_count(&self) -> usize {
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
pub(crate) fn jwk_set(entries: &[(&str, &str)]) -> JwkSet {
    let keys: Vec<Value> = entries
        .iter()
        .map(|(kid, n)| {
            json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": E })
        })
        .collect();
    serde_json::from_value(json!({ "keys": keys })).expect("valid JWK set")
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A valid claim set: correct `iss`/`aud`, a human `sub`, in-window `exp`/`nbf`, tier `forensic`.
pub(crate) fn base_claims() -> Value {
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
pub(crate) fn sign(pem: &str, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("valid RSA PEM");
    encode(&header, claims, &key).expect("sign token")
}

pub(crate) fn test_config() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        tier_claim: "tier".into(),
        algorithm: SigningAlgorithm::Rs256,
    }
}

/// A verifier serving `KEY_A` in-memory, plus the fetcher handle (for call counting / rotation).
pub(crate) fn verifier_with_key_a() -> (Verifier, Arc<TestFetcher>) {
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    (
        Verifier::with_fetcher(test_config(), fetcher.clone()),
        fetcher,
    )
}

/// Spin a localhost (loopback-only, no external egress) OIDC discovery + JWKS server serving
/// `jwks_body` at its `jwks_uri`. Returns the issuer base URL and the server task handle.
pub(crate) async fn spawn_oidc_server(jwks_body: String) -> (String, tokio::task::JoinHandle<()>) {
    use axum::Router;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::get;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let discovery = json!({ "jwks_uri": format!("{base}/jwks") }).to_string();
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let discovery = discovery.clone();
                async move { ([(CONTENT_TYPE, "application/json")], discovery) }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let jwks_body = jwks_body.clone();
                async move { ([(CONTENT_TYPE, "application/json")], jwks_body) }
            }),
        );
    let handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (base, handle)
}
