//! The additive, read-only **internal** authentication lane (ADR-0043): accept an in-cluster
//! Kubernetes ServiceAccount-token JWT on the dashboard read surface **alongside** the edge
//! Cloudflare Access path (ADR-0030), so an in-mesh caller (the cluster repo's `fixer`) authorized
//! by its own SA identity can read `/api/*.json` WITHOUT minting an edge Access JWT it structurally
//! cannot obtain in-cluster.
//!
//! This lane is **pure addition**. It never weakens the edge path (which stays exactly as ADR-0030
//! left it), it is **read-only** (it rides the same read-surface gate and touches no mutating /
//! admission path), and it **fails closed**:
//!
//! - An `Authorization: Bearer` token that **verifies** (RS256 against the cluster JWKS, cluster
//!   `iss`, the required internal `aud`, in-window `exp`/`nbf`) **and** whose `sub` is in the
//!   allowlist is admitted — read-only, at the most-restricted [`Tier::Redacted`] (a cluster SA
//!   token carries no `tier` claim).
//! - A token that verifies but whose `sub` is **not** allowlisted is a hard reject
//!   ([`InternalOutcome::NotAllowed`]) — a presented-but-unauthorized identity, never a
//!   fall-through.
//! - A token that does **not** verify is [`InternalOutcome::Unverifiable`]: the caller falls
//!   through to the unchanged edge path. The internal lane itself never fails *open* — an
//!   in-cluster caller sends no `Cf-Access-Jwt-Assertion`, so the edge path then rejects it.
//!
//! The verification primitive is the SAME [`Verifier`] the edge path uses (RS256 pinned — the
//! alg-confusion close of ADR-0030 §1 — with `iss`/`aud`/`exp`/`nbf`/`sub` all required), pointed at
//! the cluster issuer/JWKS via a [`ClusterJwksFetcher`]. Only the key source and the required
//! issuer/audience differ; the fail-closed checks are identical.
//!
//! **Coupling.** The lane rides on [`super::enforce::Enforcer`], which `run_loop` mounts only when
//! the edge OIDC issuer is configured (the dashboard's `Oidc` mode). An edge-trust-only deployment
//! (no issuer) mounts no gate at all, so these env vars are inert there — but that mode already
//! serves the dashboard unauthenticated in-cluster, so there is nothing for the internal lane to
//! add.
//!
//! **Env namespace.** `PROTECTOR_DASHBOARD_INTERNAL_*` — distinct from the edge
//! `PROTECTOR_DASHBOARD_OIDC_*` and from the sigstore `PROTECTOR_OIDC_ISSUER`.

use std::sync::Arc;

use super::claims::TierGrants;
use super::jwks::ClusterJwksFetcher;
use super::{AuthError, Identity, OidcConfig, SigningAlgorithm, Verifier, non_empty_env};

/// `PROTECTOR_DASHBOARD_INTERNAL_AUD` — the audience the cluster SA-token MUST carry. Its PRESENCE
/// (non-empty) is what enables the internal lane; absent ⇒ the lane is off (edge-only), exactly as
/// an unset edge issuer leaves the edge path off.
const ENV_AUD: &str = "PROTECTOR_DASHBOARD_INTERNAL_AUD";
/// `PROTECTOR_DASHBOARD_INTERNAL_ALLOWED_SUBS` — comma-separated EXACT `sub` allowlist, e.g.
/// `system:serviceaccount:fixer:fixer`. Empty ⇒ the lane admits nobody (fail closed; the binary
/// logs loudly and leaves the edge path untouched).
const ENV_ALLOWED_SUBS: &str = "PROTECTOR_DASHBOARD_INTERNAL_ALLOWED_SUBS";
/// `PROTECTOR_DASHBOARD_INTERNAL_ISSUER` — the expected `iss` (the cluster OIDC issuer).
const ENV_ISSUER: &str = "PROTECTOR_DASHBOARD_INTERNAL_ISSUER";
/// `PROTECTOR_DASHBOARD_INTERNAL_JWKS_URL` — the cluster JWKS endpoint (direct, no discovery).
const ENV_JWKS_URL: &str = "PROTECTOR_DASHBOARD_INTERNAL_JWKS_URL";
/// `PROTECTOR_DASHBOARD_INTERNAL_TOKEN_PATH` — this pod's own projected SA token, read fresh per
/// JWKS fetch to authenticate the discovery request.
const ENV_TOKEN_PATH: &str = "PROTECTOR_DASHBOARD_INTERNAL_TOKEN_PATH";
/// `PROTECTOR_DASHBOARD_INTERNAL_CA_PATH` — the cluster CA trusted for the JWKS fetch.
const ENV_CA_PATH: &str = "PROTECTOR_DASHBOARD_INTERNAL_CA_PATH";

/// Defaults matching an in-pod projected SA token at the standard mount.
const DEFAULT_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Configuration for the internal lane, built from the environment via [`InternalConfig::from_env`].
/// `from_env` models the lane's OFF state (audience absent) as `None`, so the binary simply does not
/// attach the lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalConfig {
    /// Expected `iss` — the cluster OIDC issuer.
    pub issuer: String,
    /// The cluster JWKS endpoint the keys are fetched from (authenticated; cluster-CA-signed).
    pub jwks_url: String,
    /// The required `aud` the SA token must carry.
    pub audience: String,
    /// This pod's own projected SA token, read fresh per JWKS fetch.
    pub token_path: String,
    /// The cluster CA trusted for the JWKS fetch.
    pub ca_path: String,
    /// The exact `sub` allowlist. Empty ⇒ the lane admits nobody (fail closed).
    pub allowed_subs: Vec<String>,
}

impl InternalConfig {
    /// Build from the environment, or `None` when `PROTECTOR_DASHBOARD_INTERNAL_AUD` is unset/empty
    /// (the lane is off). The issuer/JWKS/token/CA fall back to the in-pod defaults; the allowlist
    /// is parsed from `PROTECTOR_DASHBOARD_INTERNAL_ALLOWED_SUBS` and MAY be empty here — the binary
    /// treats an empty allowlist as a fail-closed disable (it never admits an un-allowlisted token).
    pub fn from_env() -> Option<InternalConfig> {
        let audience = non_empty_env(ENV_AUD)?;
        let issuer = non_empty_env(ENV_ISSUER).unwrap_or_else(|| DEFAULT_ISSUER.to_string());
        let jwks_url = non_empty_env(ENV_JWKS_URL)
            .unwrap_or_else(|| format!("{}/openid/v1/jwks", issuer.trim_end_matches('/')));
        let token_path =
            non_empty_env(ENV_TOKEN_PATH).unwrap_or_else(|| DEFAULT_TOKEN_PATH.to_string());
        let ca_path = non_empty_env(ENV_CA_PATH).unwrap_or_else(|| DEFAULT_CA_PATH.to_string());
        let allowed_subs = non_empty_env(ENV_ALLOWED_SUBS)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|sub| !sub.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Some(InternalConfig {
            issuer,
            jwks_url,
            audience,
            token_path,
            ca_path,
            allowed_subs,
        })
    }
}

/// The outcome of offering a bearer token to the internal lane. Only [`InternalOutcome::Admit`]
/// authorizes; the other two deny (a hard reject, or a fall-through to the edge path) — there is no
/// "allow / skip" variant.
#[derive(Debug)]
pub enum InternalOutcome {
    /// A verified token with an allowlisted `sub` — admit, read-only, carrying the normalized
    /// [`Identity`] (tier resolves to the floor [`super::claims::Tier::Redacted`], no `tier` claim).
    Admit(Identity),
    /// A verified token whose `sub` is NOT allowlisted — a hard reject (carries the `sub` for the
    /// guard's warn log). Never a fall-through: a presented-but-unauthorized identity is a deny.
    NotAllowed(String),
    /// The token did not verify. The guard falls through to the edge path (the internal lane never
    /// fails *open*); carries the distinct [`AuthError`] for the debug log.
    Unverifiable(AuthError),
}

/// The internal lane: a cluster-pointed [`Verifier`] plus the `sub` allowlist. Cheaply cloneable
/// parts; held by the [`super::enforce::Enforcer`] as an `Option`.
pub struct InternalAuth {
    verifier: Verifier,
    allowed_subs: Arc<Vec<String>>,
}

impl InternalAuth {
    /// Production constructor: a [`Verifier`] over a [`ClusterJwksFetcher`] (trusts `ca_pem`,
    /// presents the pod's SA token). RS256 is pinned and the tier machinery is inert (no `tier`
    /// claim, no grants), so every admitted internal identity is read-only at the floor tier.
    pub fn from_config(config: &InternalConfig, ca_pem: &[u8]) -> Self {
        let fetcher = Arc::new(ClusterJwksFetcher::new(
            config.jwks_url.clone(),
            config.token_path.clone(),
            ca_pem,
        ));
        Self {
            verifier: Verifier::with_fetcher(cluster_oidc_config(config), fetcher),
            allowed_subs: Arc::new(config.allowed_subs.clone()),
        }
    }

    /// Assemble from an explicit [`Verifier`] + allowlist — the seam tests use to inject an
    /// in-memory JWKS (no egress).
    #[cfg(test)]
    pub(crate) fn with_verifier(verifier: Verifier, allowed_subs: Vec<String>) -> Self {
        Self {
            verifier,
            allowed_subs: Arc::new(allowed_subs),
        }
    }

    /// The expected issuer the internal verifier enforces (for the binary's startup log).
    pub fn issuer(&self) -> &str {
        self.verifier.config().issuer.as_str()
    }

    /// The required audience the internal verifier enforces (for the binary's startup log).
    pub fn audience(&self) -> &str {
        self.verifier.config().audience.as_str()
    }

    /// The `sub` allowlist (for the binary's startup log).
    pub fn allowed_subs(&self) -> &[String] {
        &self.allowed_subs
    }

    /// Offer `token` to the internal lane: verify it, then gate on the allowlist. See
    /// [`InternalOutcome`] for the three results.
    pub async fn authorize(&self, token: &str) -> InternalOutcome {
        match self.verifier.verify(token).await {
            Ok(identity) => {
                if self.allowed_subs.iter().any(|sub| sub == &identity.subject) {
                    InternalOutcome::Admit(identity)
                } else {
                    InternalOutcome::NotAllowed(identity.subject)
                }
            }
            Err(error) => InternalOutcome::Unverifiable(error),
        }
    }
}

/// The cluster OIDC config the internal [`Verifier`] enforces: RS256 (cluster SA tokens are RS256),
/// the cluster `iss` + the required internal `aud`, and NO tier claim/grants — a cluster SA token
/// carries no tier, so it resolves to the most-restricted [`super::claims::Tier::Redacted`]
/// (read-only, floor redaction).
fn cluster_oidc_config(config: &InternalConfig) -> OidcConfig {
    OidcConfig {
        issuer: config.issuer.clone(),
        audience: config.audience.clone(),
        tier_claim: super::DEFAULT_TIER_CLAIM.to_string(),
        algorithm: SigningAlgorithm::Rs256,
        tier_grants: TierGrants::default(),
    }
}

#[cfg(test)]
mod tests {
    //! Mirrors watcher's `access_jwt` internal-lane suite, adapted to protector's verifier: an
    //! allowlisted `sub` is admitted; a valid-but-non-allowlisted token is a hard reject; an
    //! unverifiable token falls through; a wrong `aud`/`iss`/alg/expiry rejects; and the lane fails
    //! closed when the JWKS is unreachable. Every token is minted and verified through the in-memory
    //! `test_support` JWKS — zero egress.

    use std::sync::Arc;

    use serde_json::{Value, json};

    use super::super::claims::Tier;
    use super::super::test_support::{
        ENV_LOCK, KEY_A_N, KEY_A_PEM, KID_A, TestFetcher, jwk_set, now, sign,
    };
    use super::super::{AuthError, SigningAlgorithm, Verifier, claims::TierGrants};
    use super::*;

    const CLUSTER_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
    const INTERNAL_AUD: &str = "protector";
    const FIXER_SUB: &str = "system:serviceaccount:fixer:fixer";

    /// The cluster OIDC config a test verifier enforces (RS256, cluster issuer, internal aud).
    fn cluster_config() -> OidcConfig {
        OidcConfig {
            issuer: CLUSTER_ISSUER.into(),
            audience: INTERNAL_AUD.into(),
            tier_claim: "tier".into(),
            algorithm: SigningAlgorithm::Rs256,
            tier_grants: TierGrants::default(),
        }
    }

    /// An internal lane over an in-memory JWKS serving key-A, allowlisting `allowed`.
    fn internal_auth(allowed: &[&str]) -> InternalAuth {
        let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
        let verifier = Verifier::with_fetcher(cluster_config(), fetcher);
        InternalAuth::with_verifier(verifier, allowed.iter().map(|s| s.to_string()).collect())
    }

    /// An internal lane whose JWKS fetch always fails — the unreachable-cluster-JWKS condition.
    fn internal_auth_jwks_down(allowed: &[&str]) -> InternalAuth {
        let verifier = Verifier::with_fetcher(cluster_config(), Arc::new(TestFetcher::failing()));
        InternalAuth::with_verifier(verifier, allowed.iter().map(|s| s.to_string()).collect())
    }

    /// A cluster-SA-token-shaped claim set: cluster issuer, internal aud, in-window exp/nbf, and —
    /// like a real projected token — NO `tier` claim.
    fn cluster_claims(sub: &str) -> Value {
        json!({
            "iss": CLUSTER_ISSUER,
            "aud": INTERNAL_AUD,
            "sub": sub,
            "iat": now() - 10,
            "nbf": now() - 10,
            "exp": now() + 3600,
        })
    }

    #[tokio::test]
    async fn allowlisted_sub_is_admitted_read_only_at_the_floor_tier() {
        let auth = internal_auth(&[FIXER_SUB]);
        let token = sign(KEY_A_PEM, KID_A, &cluster_claims(FIXER_SUB));
        match auth.authorize(&token).await {
            InternalOutcome::Admit(identity) => {
                assert_eq!(identity.subject, FIXER_SUB);
                assert_eq!(
                    identity.tier,
                    Tier::Redacted,
                    "a cluster SA token has no tier claim → floor (read-only redacted)"
                );
            }
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn valid_but_non_allowlisted_sub_is_a_hard_reject() {
        // Verifies fine, but its `sub` is not allowlisted → NotAllowed (a hard reject, never a
        // fall-through). The guard turns this into a 401.
        let auth = internal_auth(&[FIXER_SUB]);
        let token = sign(
            KEY_A_PEM,
            KID_A,
            &cluster_claims("system:serviceaccount:other:intruder"),
        );
        match auth.authorize(&token).await {
            InternalOutcome::NotAllowed(sub) => {
                assert_eq!(sub, "system:serviceaccount:other:intruder")
            }
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_signature_is_unverifiable_falls_through() {
        let auth = internal_auth(&[FIXER_SUB]);
        let token = sign(KEY_A_PEM, KID_A, &cluster_claims(FIXER_SUB));
        let mut segments: Vec<String> = token.split('.').map(String::from).collect();
        let sig = &segments[2];
        let first = sig.chars().next().unwrap();
        segments[2] = format!("{}{}", if first == 'A' { 'B' } else { 'A' }, &sig[1..]);
        let tampered = segments.join(".");
        assert!(matches!(
            auth.authorize(&tampered).await,
            InternalOutcome::Unverifiable(AuthError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn wrong_audience_is_unverifiable() {
        let auth = internal_auth(&[FIXER_SUB]);
        let mut claims = cluster_claims(FIXER_SUB);
        claims["aud"] = json!("not-protector");
        let token = sign(KEY_A_PEM, KID_A, &claims);
        assert!(matches!(
            auth.authorize(&token).await,
            InternalOutcome::Unverifiable(AuthError::InvalidAudience)
        ));
    }

    #[tokio::test]
    async fn wrong_issuer_is_unverifiable() {
        // An edge-issuer token offered on Bearer does NOT verify on the cluster lane → falls through
        // to the edge path (the fall-through the guard relies on to keep the ID-JAG lane working).
        let auth = internal_auth(&[FIXER_SUB]);
        let mut claims = cluster_claims(FIXER_SUB);
        claims["iss"] = json!("https://issuer.example");
        let token = sign(KEY_A_PEM, KID_A, &claims);
        assert!(matches!(
            auth.authorize(&token).await,
            InternalOutcome::Unverifiable(AuthError::InvalidIssuer)
        ));
    }

    #[tokio::test]
    async fn expired_token_is_unverifiable() {
        let auth = internal_auth(&[FIXER_SUB]);
        let mut claims = cluster_claims(FIXER_SUB);
        claims["nbf"] = json!(now() - 7200);
        claims["exp"] = json!(now() - 3600);
        let token = sign(KEY_A_PEM, KID_A, &claims);
        assert!(matches!(
            auth.authorize(&token).await,
            InternalOutcome::Unverifiable(AuthError::Expired)
        ));
    }

    #[tokio::test]
    async fn alg_confusion_hs256_is_unverifiable() {
        // RS256 is pinned from config; a token whose header claims HS256 is rejected BEFORE any
        // signature check — the same alg-confusion close as the edge path.
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let auth = internal_auth(&[FIXER_SUB]);
        let header = json!({ "alg": "HS256", "typ": "JWT", "kid": KID_A });
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cluster_claims(FIXER_SUB)).unwrap()),
            URL_SAFE_NO_PAD.encode(b"not-a-real-signature"),
        );
        assert!(matches!(
            auth.authorize(&token).await,
            InternalOutcome::Unverifiable(AuthError::InvalidAlgorithm)
        ));
    }

    #[tokio::test]
    async fn fails_closed_when_cluster_jwks_unreachable() {
        // An unreachable cluster JWKS is Unverifiable(JwksUnreachable) — never an admit. The guard
        // then falls through to the edge path, which rejects an internal caller (no edge header).
        let auth = internal_auth_jwks_down(&[FIXER_SUB]);
        let token = sign(KEY_A_PEM, KID_A, &cluster_claims(FIXER_SUB));
        assert!(matches!(
            auth.authorize(&token).await,
            InternalOutcome::Unverifiable(AuthError::JwksUnreachable)
        ));
    }

    #[test]
    fn from_env_models_off_defaults_and_allowlist() {
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys = [
            ENV_AUD,
            ENV_ALLOWED_SUBS,
            ENV_ISSUER,
            ENV_JWKS_URL,
            ENV_TOKEN_PATH,
            ENV_CA_PATH,
        ];
        let clear = || unsafe {
            for key in keys {
                std::env::remove_var(key);
            }
        };
        clear();

        // Audience absent ⇒ the lane is off.
        assert_eq!(InternalConfig::from_env(), None);

        // Audience set ⇒ Some, with the in-pod defaults and a parsed (here empty) allowlist.
        unsafe { std::env::set_var(ENV_AUD, "protector") };
        let config = InternalConfig::from_env().expect("audience set ⇒ configured");
        assert_eq!(config.audience, "protector");
        assert_eq!(config.issuer, DEFAULT_ISSUER);
        assert_eq!(
            config.jwks_url,
            "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
        );
        assert_eq!(config.token_path, DEFAULT_TOKEN_PATH);
        assert_eq!(config.ca_path, DEFAULT_CA_PATH);
        assert!(
            config.allowed_subs.is_empty(),
            "an unset allowlist parses empty (the binary fails closed on it)"
        );

        // The allowlist parses + trims; an explicit issuer re-derives the default JWKS URL.
        unsafe {
            std::env::set_var(
                ENV_ALLOWED_SUBS,
                " system:serviceaccount:fixer:fixer , system:serviceaccount:ops:reader ",
            );
            std::env::set_var(ENV_ISSUER, "https://kubernetes.default.svc.cluster.local/");
        }
        let config = InternalConfig::from_env().unwrap();
        assert_eq!(
            config.allowed_subs,
            vec![
                "system:serviceaccount:fixer:fixer".to_string(),
                "system:serviceaccount:ops:reader".to_string(),
            ]
        );
        assert_eq!(
            config.jwks_url, "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
            "a trailing slash on the issuer is trimmed before deriving the JWKS URL"
        );

        clear();
    }
}
