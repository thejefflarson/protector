//! The provider-agnostic OIDC token **verifier** (ADR-0030): the load-bearing security primitive
//! for app-level dashboard auth. Protector is a **resource server** — it verifies presented
//! tokens, it never mints them, runs login flows, or actuates. On a JWT it checks the
//! **signature, `iss`, `aud`, `exp`, `nbf`**, pins the algorithm to the configured **asymmetric**
//! family (never the token's own `alg` header — that structurally excludes alg-confusion), and
//! yields a normalized identity: **subject + [`Tier`]**.
//!
//! A **single** verification path serves every arrival lane — a browser Cloudflare Access
//! assertion (`Cf-Access-Jwt-Assertion` header / `CF_Authorization` cookie) and a machine/agent
//! `Authorization: Bearer` token (incl. ID-JAG, `aud=protector`) — because the verifier only ever
//! sees a JWT, not how it arrived (ADR-0030 §3/§6/§7).
//!
//! **Scope (JEF-485):** this module is the verifier primitive + a mountable middleware layer. The
//! layer is the sibling shape to [`super::security_headers::set_csp`] and CAN be mounted, but it
//! is deliberately **NOT** wired into [`super::router`] here — enforcement wiring and content
//! negotiation (login redirect vs JSON `401`, the loud unconfigured-mode passthrough) are a later
//! ticket (JEF-487). [`OidcConfig::from_env`] merely models the UNCONFIGURED state (issuer absent)
//! so that later ticket can decide the passthrough behavior.

pub mod claims;
pub mod jwks;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};

use claims::{Claims, Tier};
use jwks::{HttpJwksFetcher, JwksFetcher, JwksStore};

/// `PROTECTOR_OIDC_ISSUER` — the configured issuer. Its ABSENCE is what makes the verifier
/// UNCONFIGURED (edge-trust only), the single, loud bypass ADR-0030 §6 names.
const ENV_ISSUER: &str = "PROTECTOR_OIDC_ISSUER";
/// `PROTECTOR_OIDC_AUDIENCE` — required once an issuer is configured.
const ENV_AUDIENCE: &str = "PROTECTOR_OIDC_AUDIENCE";
/// `PROTECTOR_OIDC_TIER_CLAIM` — the configurable claim path the tier is read from.
const ENV_TIER_CLAIM: &str = "PROTECTOR_OIDC_TIER_CLAIM";
/// `PROTECTOR_OIDC_ALGORITHM` — the pinned asymmetric algorithm (`RS256` | `ES256`).
const ENV_ALGORITHM: &str = "PROTECTOR_OIDC_ALGORITHM";

/// The default tier claim path when `PROTECTOR_OIDC_TIER_CLAIM` is unset.
const DEFAULT_TIER_CLAIM: &str = "tier";

/// The Cloudflare Access assertion header — the browser lane (ADR-0030 §7).
const CF_ASSERTION_HEADER: &str = "cf-access-jwt-assertion";
/// The Cloudflare Access cookie name — the browser lane.
const CF_ASSERTION_COOKIE: &str = "CF_Authorization";

/// The pinned asymmetric signing algorithm. Only asymmetric families are accepted; a symmetric
/// algorithm (e.g. `HS256`) is not configurable, because pinning to an asymmetric family is what
/// closes the alg-confusion / HMAC-with-the-public-key attack (ADR-0030 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// ECDSA over P-256 with SHA-256.
    Es256,
}

impl SigningAlgorithm {
    /// Parse a configured algorithm name (case-insensitive). Returns `None` for anything that is
    /// not a supported asymmetric algorithm — notably a symmetric alg is rejected here, not pinned.
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }
}

impl From<SigningAlgorithm> for Algorithm {
    fn from(algorithm: SigningAlgorithm) -> Self {
        match algorithm {
            SigningAlgorithm::Rs256 => Algorithm::RS256,
            SigningAlgorithm::Es256 => Algorithm::ES256,
        }
    }
}

/// The verifier's configuration. Built from the environment via [`OidcConfig::from_env`], which
/// models UNCONFIGURED (issuer absent) as `Ok(None)` — the presence of a config is exactly
/// "app-level auth is configured".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The expected token issuer (`iss`), and the base for OIDC discovery.
    pub issuer: String,
    /// The expected audience (`aud`) — e.g. `protector` (also the ID-JAG audience, ADR-0030 §3).
    pub audience: String,
    /// The claim path the authorization tier is read from (configurable; default `tier`).
    pub tier_claim: String,
    /// The pinned asymmetric algorithm.
    pub algorithm: SigningAlgorithm,
}

/// Why [`OidcConfig::from_env`] could not build a config even though an issuer was present. This
/// is a MISconfiguration (fail loud), distinct from the UNCONFIGURED case (issuer absent → `None`).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// An issuer is set but `PROTECTOR_OIDC_AUDIENCE` is missing — verification needs an audience.
    #[error("{ENV_AUDIENCE} must be set when {ENV_ISSUER} is configured")]
    MissingAudience,
    /// `PROTECTOR_OIDC_ALGORITHM` is set to something other than a supported asymmetric algorithm.
    #[error("{ENV_ALGORITHM} `{0}` is not a supported asymmetric algorithm (RS256, ES256)")]
    UnsupportedAlgorithm(String),
}

impl OidcConfig {
    /// Build from the environment (ADR-0030). `PROTECTOR_OIDC_ISSUER` **absent/empty** ⇒ `Ok(None)`
    /// (UNCONFIGURED — representable so the enforcement ticket can decide loud-log-and-passthrough).
    /// An issuer WITHOUT an audience, or an unsupported algorithm, ⇒ `Err(ConfigError)` (a loud
    /// misconfiguration). Otherwise ⇒ `Ok(Some(config))`.
    pub fn from_env() -> Result<Option<OidcConfig>, ConfigError> {
        let Some(issuer) = non_empty_env(ENV_ISSUER) else {
            return Ok(None); // UNCONFIGURED — issuer absent is the representable "off" state.
        };
        let audience = non_empty_env(ENV_AUDIENCE).ok_or(ConfigError::MissingAudience)?;
        let tier_claim = non_empty_env(ENV_TIER_CLAIM).unwrap_or_else(|| DEFAULT_TIER_CLAIM.into());
        let algorithm = match non_empty_env(ENV_ALGORITHM) {
            Some(name) => {
                SigningAlgorithm::parse(&name).ok_or(ConfigError::UnsupportedAlgorithm(name))?
            }
            None => SigningAlgorithm::Rs256,
        };
        Ok(Some(OidcConfig {
            issuer,
            audience,
            tier_claim,
            algorithm,
        }))
    }
}

/// A trimmed, non-empty environment value, or `None` if unset/blank.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The normalized identity a successful verification yields: the token subject and the resolved
/// authorization tier. Cloneable so the middleware can insert it into the request extensions for a
/// downstream handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The token subject (`sub`) — the principal (a human for a browser/ID-JAG token).
    pub subject: String,
    /// The resolved authorization tier (most-restricted when the claim is absent/empty/unknown).
    pub tier: Tier,
}

/// Every distinct way verification can fail. Each acceptance-critical failure — tampered
/// signature, wrong `iss`, wrong `aud`, expired, not-yet-valid, alg mismatch, unknown key, JWKS
/// unreachable — is a **distinct** variant, and EVERY variant denies (fail closed, ADR-0030 §6).
/// There is deliberately no "allow / skip auth" outcome anywhere in this type.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// No token was presented on any lane.
    #[error("no bearer token presented")]
    MissingToken,
    /// The token is not a well-formed JWT (bad base64/JSON/UTF-8, or a missing required claim).
    #[error("malformed token")]
    MalformedToken,
    /// The token's header algorithm does not match the pinned asymmetric family (alg-confusion).
    #[error("token algorithm does not match the pinned asymmetric family")]
    InvalidAlgorithm,
    /// The signature did not verify against the issuer's key.
    #[error("token signature is invalid")]
    InvalidSignature,
    /// The `iss` claim is not the configured issuer.
    #[error("token issuer does not match the configured issuer")]
    InvalidIssuer,
    /// The `aud` claim is not the configured audience.
    #[error("token audience does not match the configured audience")]
    InvalidAudience,
    /// The token has expired (`exp`).
    #[error("token has expired")]
    Expired,
    /// The token is not yet valid (`nbf`).
    #[error("token is not yet valid")]
    NotYetValid,
    /// No signing key matched the token's `kid`, even after a fresh JWKS fetch.
    #[error("no signing key matched the token key id")]
    UnknownKey,
    /// The issuer's signing keys could not be fetched — we cannot verify, so we do NOT serve
    /// (a `503`, never a bypass; ADR-0030 §6).
    #[error("the issuer signing keys could not be fetched")]
    JwksUnreachable,
    /// Any other verification failure — the catch-all that keeps the error path fail-closed for
    /// conditions not otherwise enumerated (an unexpected error is a deny, never a skip).
    #[error("token verification failed")]
    Other,
}

impl AuthError {
    /// Map a `jsonwebtoken` error to the corresponding distinct variant. Anything not explicitly
    /// enumerated collapses to [`AuthError::Other`] — which still denies (fail closed).
    fn from_jwt(error: &jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match error.kind() {
            ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
            ErrorKind::InvalidAudience => AuthError::InvalidAudience,
            ErrorKind::ExpiredSignature => AuthError::Expired,
            ErrorKind::ImmatureSignature => AuthError::NotYetValid,
            ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
                AuthError::InvalidAlgorithm
            }
            ErrorKind::InvalidToken
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_)
            | ErrorKind::MissingRequiredClaim(_)
            | ErrorKind::InvalidClaimFormat(_) => AuthError::MalformedToken,
            // Any other kind (incl. future ones) fails closed, never bypasses.
            _ => AuthError::Other,
        }
    }

    /// The HTTP status this failure maps to as the fail-closed default. A JWKS-unreachable
    /// condition is a `503` (we could not verify); every other failure is a `401`. The finer
    /// content negotiation (login redirect, JSON body) is JEF-487; this is only the safe default.
    pub fn status(&self) -> StatusCode {
        match self {
            AuthError::JwksUnreachable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Return the status only — the specific variant is for logs/tests, never leaked to the
        // caller (which check failed is not the caller's business). JEF-487 shapes the body.
        self.status().into_response()
    }
}

/// The provider-agnostic OIDC token verifier — the primitive this ticket delivers.
pub struct Verifier {
    config: OidcConfig,
    jwks: JwksStore,
    /// The pinned validation, built once from `config` (algorithm + required `iss`/`aud`/`exp`/
    /// `nbf`/`sub`) so each `verify` reuses it rather than re-allocating it per request.
    validation: Validation,
}

impl Verifier {
    /// Build a verifier that fetches the issuer's keys over HTTPS (discovery → JWKS), with a
    /// bounded-timeout client. This is the production constructor.
    pub fn from_config(config: OidcConfig) -> Self {
        let fetcher = Arc::new(HttpJwksFetcher::new(config.issuer.clone()));
        Self::new(config, JwksStore::new(fetcher))
    }

    /// Build a verifier over an **injected** key source — the seam tests use to serve a JWKS
    /// in-memory (no egress), and the interface the ADR-0030 mounted-JWKS air-gap source can use.
    pub fn with_fetcher(config: OidcConfig, fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self::new(config, JwksStore::new(fetcher))
    }

    /// Assemble the verifier and precompute the pinned [`Validation`] from `config`.
    fn new(config: OidcConfig, jwks: JwksStore) -> Self {
        let validation = build_validation(&config);
        Self {
            config,
            jwks,
            validation,
        }
    }

    /// The configuration this verifier enforces.
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Verify a JWT and yield the normalized [`Identity`]. This is the ONE path for every arrival
    /// lane (§3/§7). Every failure returns an [`AuthError`] (fail closed, §6): nothing here can
    /// return an identity without a valid signature + `iss` + `aud` + `exp` + `nbf`.
    ///
    /// The algorithm is pinned from [`OidcConfig::algorithm`] via [`Validation::new`]; the token's
    /// own `alg` header is **never** used to select the key type. A token whose header algorithm
    /// is outside the pinned family (e.g. `HS256`, `none`) is rejected as
    /// [`AuthError::InvalidAlgorithm`] before any signature check — the alg-confusion close (§1).
    pub async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::MalformedToken)?;
        // Select the DECODING KEY by `kid` only; the ALGORITHM is pinned in `self.validation`. We
        // do NOT read the header's `alg` to choose a key type — that is the alg-confusion vector.
        let key = self.jwks.decoding_key(header.kid.as_deref()).await?;
        let data =
            decode::<Claims>(token, &key, &self.validation).map_err(|e| AuthError::from_jwt(&e))?;
        let tier = Tier::from_claims(&data.claims, &self.config.tier_claim);
        Ok(Identity {
            subject: data.claims.sub,
            tier,
        })
    }
}

/// Build the pinned [`Validation`] from `config`: the algorithm is pinned to the configured
/// asymmetric family (never the token's own `alg`), and `iss`/`aud`/`exp`/`nbf`/`sub` are all
/// required and validated (ADR-0030 §1). Built once per verifier and reused for every request.
fn build_validation(config: &OidcConfig) -> Validation {
    let mut validation = Validation::new(config.algorithm.into());
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "nbf", "sub"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation
}

/// Axum middleware that verifies the presented OIDC token and, on success, inserts the normalized
/// [`Identity`] into the request extensions before passing the request on. On **any** verification
/// failure it DENIES (fail closed, ADR-0030 §6): a JWKS-unreachable condition is a `503`, every
/// other failure a `401`.
///
/// This is the sibling shape to [`super::security_headers::set_csp`] — a mountable layer. It is
/// deliberately **NOT** wired into [`super::router`] in this ticket (JEF-485); enforcement wiring
/// and content negotiation are JEF-487. Mount it with
/// `axum::middleware::from_fn_with_state(Arc<Verifier>, require_oidc)`.
pub async fn require_oidc(
    State(verifier): State<Arc<Verifier>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_token(request.headers()) else {
        return AuthError::MissingToken.into_response();
    };
    match verifier.verify(&token).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(error) => {
            tracing::warn!(%error, "dashboard OIDC verification denied (fail-closed)");
            error.into_response()
        }
    }
}

/// Extract the JWT from a request from EITHER lane, so one verification path serves both machine
/// `Authorization: Bearer` tokens (incl. ID-JAG, `aud=protector`) and browser Cloudflare Access
/// assertions. Priority: `Authorization: Bearer`, then the CF assertion header, then the
/// `CF_Authorization` cookie.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
    {
        return Some(bearer.to_string());
    }
    if let Some(assertion) = headers
        .get(CF_ASSERTION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(assertion.to_string());
    }
    cookie_value(headers, CF_ASSERTION_COOKIE)
}

/// The bearer token from an `Authorization` header value, case-insensitive on the scheme.
fn bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let rest = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!rest.is_empty()).then_some(rest)
}

/// The value of a named cookie from the `Cookie` header, if present and non-empty.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        if let Some((key, value)) = pair.split_once('=')
            && key.trim() == name
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}
