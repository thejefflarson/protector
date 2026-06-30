//! The production signature verifier: keyless cosign verification with sigstore-rs
//! against the public-good sigstore TUF root.
//!
//! [`CosignChecker`] is the one verifier that actually reaches the registry + the
//! transparency log. It serves two callers off the *same* registry round-trip:
//!
//!   * [`observe`](super::posture::SignatureObserver::observe) — reads any image's
//!     signing posture (signed / invalid / not-signed) with NO trusted-identity
//!     config required (ADR-0020 Stage 1: inventory).
//!   * [`is_signed`](super::SignatureChecker::is_signed) — the gated admission check,
//!     which applies the org's identity+issuer constraint to that observation. It is a
//!     thin wrapper over the same layer fetch, so the gated path stays behavior-identical
//!     while sharing the round trip.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use regex::Regex;
use sigstore::cosign::signature_layers::CertificateSubject;
use sigstore::cosign::verification_constraint::VerificationConstraint;
use sigstore::cosign::{ClientBuilder, CosignCapabilities, SignatureLayer, verify_constraints};
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tokio::sync::OnceCell;

use super::SignatureChecker;
use super::posture::{SignatureObserver, Signer, SigningPosture};

/// The production [`SignatureChecker`] / [`SignatureObserver`]: verifies keyless cosign
/// signatures with sigstore-rs against the public-good sigstore TUF root.
pub struct CosignChecker {
    /// Regex the signing cert's SAN identity must match for the GATED check
    /// (start-anchored in [`new`](CosignChecker::new) so it can't match mid-string).
    /// Observation ([`observe`](SignatureObserver::observe)) ignores it entirely — the
    /// Fulcio/Rekor chain is the trust anchor there, not a caller identity.
    identity: Regex,
    /// OIDC issuer expected in the signing cert for the gated check.
    oidc_issuer: String,
    /// Registry credentials, when the gated images are private.
    auth: Auth,
    /// Writable directory for the sigstore TUF cache (an emptyDir in-cluster).
    cache_dir: PathBuf,
    /// Per-image wall-clock budget for the registry/Rekor round trip, so a slow
    /// or hung registry can't stall admission indefinitely.
    verify_timeout: Duration,
    /// The TUF trust root, fetched lazily once (network I/O we don't want to
    /// block webhook startup on). A fresh, cheap cosign `Client` is built from
    /// it per verification — so no shared lock is held across registry I/O and
    /// one slow image can't block unrelated admissions.
    trust_root: OnceCell<SigstoreTrustRoot>,
}

impl CosignChecker {
    pub fn new(
        identity_regexp: &str,
        oidc_issuer: String,
        auth: Auth,
        cache_dir: PathBuf,
        verify_timeout: Duration,
    ) -> Result<Self> {
        // Force a start anchor that binds the *whole* pattern. Wrapping the
        // alternation in a group is essential: a bare `^a|b` parses as
        // `(^a)|(b)`, leaving the second branch unanchored so it matches a
        // trusted prefix mid-string in a cert SAN. Always emit `^(?:…)`,
        // stripping one redundant leading `^` first so a pre-anchored pattern
        // doesn't become `^(?:^…)` (which `regex` rejects).
        let inner = identity_regexp.strip_prefix('^').unwrap_or(identity_regexp);
        let anchored = format!("^(?:{inner})");
        // sigstore-rs reads/writes the TUF trust-root cache in `cache_dir` but does
        // not create it. Under readOnlyRootFilesystem the cache points into a /tmp
        // emptyDir subdir that doesn't exist yet, so without this every verification
        // failed with `No such file or directory (os error 2)` — surfacing as a
        // spurious "signature verification errored" rather than a real verdict.
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating sigstore TUF cache dir {}", cache_dir.display()))?;
        Ok(Self {
            identity: Regex::new(&anchored)?,
            oidc_issuer,
            auth,
            cache_dir,
            verify_timeout,
            trust_root: OnceCell::new(),
        })
    }

    /// Test accessor for the start-anchored identity regex.
    #[cfg(test)]
    pub(super) fn identity_regex(&self) -> &Regex {
        &self.identity
    }

    /// Get (or lazily fetch) the sigstore TUF trust root.
    async fn trust_root(&self) -> Result<&SigstoreTrustRoot> {
        self.trust_root
            .get_or_try_init(|| async {
                anyhow::Ok(SigstoreTrustRoot::new(Some(self.cache_dir.as_path())).await?)
            })
            .await
    }

    /// Fetch the image's signature layers — the one registry + transparency-log round trip
    /// both [`observe`](SignatureObserver::observe) and [`is_signed`](SignatureChecker::is_signed)
    /// share. `trusted_signature_layers` triangulates internally and returns the cosign
    /// signature artifacts attached to the image; a layer's `certificate_signature` is
    /// populated ONLY if its embedded cert chains to the trusted Fulcio root AND its Rekor
    /// bundle verifies — so an attacker-attached, unverifiable layer comes back as a layer
    /// with `certificate_signature: None` rather than being silently dropped. Bounded by
    /// `verify_timeout` so a slow registry can't stall the caller. An `Err` is an
    /// infrastructure failure (registry/Rekor/TUF unreachable), which the caller surfaces as
    /// the transient "checking" state — never as a resting posture, never as a clean verdict.
    async fn fetch_layers(&self, image: &str) -> Result<Vec<SignatureLayer>> {
        let image_ref: OciReference = image.parse()?;
        let trust_root = self.trust_root().await?;
        // A fresh client per call — build() is local (TUF was already fetched),
        // so verifications run concurrently with no shared lock.
        let mut client = ClientBuilder::default()
            .with_trust_repository(trust_root)?
            .build()?;
        let layers = tokio::time::timeout(
            self.verify_timeout,
            client.trusted_signature_layers(&self.auth, &image_ref),
        )
        .await
        .map_err(|_| anyhow::anyhow!("verification timed out after {:?}", self.verify_timeout))??;
        Ok(layers)
    }

    /// Whether the org's identity+issuer constraint is satisfied by `layers` — the GATED
    /// admission question, distinct from observation (here the configured identity regex +
    /// issuer ARE the test). Empty layers (unsigned) yield `Err` from `verify_constraints`,
    /// which we read as "not signed by the trusted identity".
    fn satisfies_org_identity(&self, layers: &[SignatureLayer]) -> bool {
        let constraints: Vec<Box<dyn VerificationConstraint>> = vec![Box::new(IdentityVerifier {
            identity: self.identity.clone(),
            issuer: self.oidc_issuer.clone(),
        })];
        verify_constraints(layers, constraints.iter()).is_ok()
    }
}

#[async_trait]
impl SignatureObserver for CosignChecker {
    async fn observe(&self, image: &str) -> SigningPosture {
        match self.fetch_layers(image).await {
            Ok(layers) => classify(&layers),
            Err(err) => {
                tracing::debug!(%image, error = %err, "signing posture: registry/Rekor unreachable — checking");
                SigningPosture::Checking
            }
        }
    }
}

#[async_trait]
impl SignatureChecker for CosignChecker {
    async fn is_signed(&self, image: &str) -> Result<bool> {
        // Share the ONE registry/Rekor round trip with observation: fetch the layers once,
        // then apply the org constraint. An infra error still propagates as `Err` so a
        // transient blip isn't frozen into a gated verdict (the policy treats it as
        // "couldn't verify", not "unsigned") — behavior-identical to before the split.
        let layers = self.fetch_layers(image).await?;
        Ok(self.satisfies_org_identity(&layers))
    }
}

/// Read a signing posture from fetched signature layers (ADR-0020 Stage 1). Pure
/// classification — no trusted-identity config required, the Fulcio/Rekor chain is the
/// trust anchor:
///   * a layer with a verified `certificate_signature` ⇒ **signed**, capturing the signer
///     (cert subject + OIDC issuer);
///   * one or more layers but NONE verified ⇒ **invalid signature** (a signature artifact is
///     present but does not chain to Fulcio / its Rekor bundle does not verify) — more
///     alarming than, and distinct from, unsigned;
///   * no layers at all ⇒ **not signed**.
///
/// The transient "checking" state is produced by [`observe`](SignatureObserver::observe) on
/// an `Err`, never here. Free of `self` so it is unit-testable against synthesized layers.
pub(super) fn classify(layers: &[SignatureLayer]) -> SigningPosture {
    // Prefer a verified signer: the first layer whose cert chained to Fulcio + verified
    // against Rekor. `CertificateSubject::Email` is a legitimate keyless signer (a human
    // who authenticated via GitHub/Google), recorded as such — observation does not gate
    // (today's org gate rejects Email; the inventory must not).
    for layer in layers {
        if let Some(cert) = layer.certificate_signature.as_ref() {
            let identity = match &cert.subject {
                CertificateSubject::Uri(uri) => uri.clone(),
                CertificateSubject::Email(email) => email.clone(),
            };
            return SigningPosture::Signed(Signer {
                identity,
                issuer: cert.issuer.clone(),
            });
        }
    }
    if layers.is_empty() {
        SigningPosture::NotSigned
    } else {
        // Artifacts present but none verified: the breach-relevant "present but broken"
        // state ADR-0020 distinguishes from a clean unsigned image.
        SigningPosture::InvalidSignature
    }
}

/// A [`VerificationConstraint`] that admits a signing cert whose SAN identity
/// matches a (start-anchored) regex and whose OIDC issuer matches exactly.
/// sigstore-rs ships only an exact-match URL verifier; our identity is a
/// per-repo GitHub Actions workflow URL, so we need the regex (mirroring
/// cosign's `--certificate-identity-regexp`).
#[derive(Debug)]
struct IdentityVerifier {
    identity: Regex,
    issuer: String,
}

impl VerificationConstraint for IdentityVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> sigstore::errors::Result<bool> {
        let Some(cert) = signature_layer.certificate_signature.as_ref() else {
            return Ok(false);
        };
        let issuer_ok = cert.issuer.as_deref() == Some(self.issuer.as_str());
        let identity_ok = match &cert.subject {
            CertificateSubject::Uri(uri) => self.identity.is_match(uri),
            CertificateSubject::Email(_) => false,
        };
        Ok(issuer_ok && identity_ok)
    }
}
