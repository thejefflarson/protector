//! The production signature verifier: keyless cosign verification with sigstore-rs
//! against the public-good sigstore TUF root.
//!
//! [`CosignChecker`] is the one verifier that actually reaches the registry + the
//! transparency log. It serves two callers off the *same* registry round-trip:
//!
//!   * [`observe`](super::posture::SignatureObserver::observe) — reads any image's
//!     signing posture (keyless-verified / signed-key-based / unverifiable-here /
//!     invalid / not-signed) with NO trusted-identity config required (ADR-0020 Stage 1:
//!     inventory; JEF-276 honest, scheme-aware split). Discovery already covers both the
//!     legacy cosign `.sig` tag AND OCI 1.1 referrer-attached signatures — sigstore-rs
//!     `trusted_signature_layers` triangulates both and returns their union.
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
use sigstore::registry::OciReference;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tokio::sync::OnceCell;

use super::SignatureChecker;
use super::auth::RegistryAuth;
use super::posture::{SignatureObserver, Signer, SigningPosture};
use super::provenance::{
    ProvenanceFacts, ProvenanceObserver, ProvenancePosture, classify_provenance,
    is_slsa_predicate_type,
};

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
    /// Per-image registry-auth resolver (JEF-352): the whole mounted dockerconfigjson parsed
    /// once, looked up by each image's registry host at verify time — so a private image on ANY
    /// registry authenticates with its own creds, not one hardcoded registry's.
    auth: RegistryAuth,
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
        auth: RegistryAuth,
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
    ///
    /// Fetch-once-and-stick (JEF-377): `get_or_try_init` caches only a *successful* init — on
    /// `Err` the cell stays empty, so a transient TUF/registry blip is retried on the next call
    /// rather than being frozen, and a success is reused for the process lifetime. There is no
    /// per-verify or interval TUF refresh: the one fetch here (and its one-time tough temp write)
    /// happens on the first verification and never again while it holds, so steady state does no
    /// TUF writes at all. (The tough temp write itself is kept off /tmp via the startup `$TMPDIR`
    /// pin — see `tuf_tmpdir`.)
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
    ///
    /// MIRROR-SERVED IMAGES (JEF-386): sigstore-rs binds a signature to the image by its
    /// **manifest digest** (`triangulate` fetches the pull ref's digest, then verifies each
    /// layer's `simple_signing.critical.image.docker-manifest-digest` — and, on the OCI-1.1
    /// referrer path, the in-toto subject digest — against it). It does NOT compare the
    /// payload's `critical.identity.docker-reference` (nor the subject NAME) to the registry
    /// we pulled from. So an image served from a vanity mirror (e.g. `cr.l5d.io/linkerd/proxy`,
    /// whose signature payload names the signing registry `ghcr.io/linkerd/proxy` for the SAME
    /// digest) verifies here exactly as `cosign verify` does — cert-chain + Rekor + digest, not
    /// registry-name equality. This is safe precisely because the signature is digest-bound: it
    /// cannot be replayed onto a different-digest image, and a digest mismatch or an absent/bad
    /// signature still yields no verified signer (unverifiable / not-signed). The gated identity
    /// check ([`satisfies_org_identity`](Self::satisfies_org_identity)) is unaffected — it still
    /// tests the verified cert's SAN + issuer, never the docker-reference. See `cosign_tests.rs`.
    async fn fetch_layers(&self, image: &str) -> Result<Vec<SignatureLayer>> {
        let image_ref: OciReference = image.parse()?;
        // Resolve auth for THIS image's registry (JEF-352): the mounted dockerconfigjson may carry
        // creds for several registries, so we look up the image's host rather than applying one
        // global credential to every image (which only authenticated ghcr.io and 401ed the rest).
        let auth = self.auth.for_image(image);
        let trust_root = self.trust_root().await?;
        // A fresh client per call — build() is local (TUF was already fetched),
        // so verifications run concurrently with no shared lock.
        let mut client = ClientBuilder::default()
            .with_trust_repository(trust_root)?
            .build()?;
        let layers = tokio::time::timeout(
            self.verify_timeout,
            client.trusted_signature_layers(&auth, &image_ref),
        )
        .await
        // A distinguishable error type (not a bare string) so the observer can tell a spent
        // verification budget apart from a genuine reachability failure via `downcast_ref` —
        // the load-bearing distinction for diagnosing a stuck "checking" posture (JEF-326).
        .map_err(|_| anyhow::Error::new(VerifyTimeout(self.verify_timeout)))??;
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

/// Why an image's signing posture could not be resolved this pass (JEF-326) — the transient
/// [`Checking`](SigningPosture::Checking) split into its two operational causes so the log
/// tells the operator which knob to reach for. Derived from the `fetch_layers` error via
/// [`classify_checking_reason`]; pure and exhaustively unit-testable without a registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CheckingReason {
    /// The per-image verification budget (`PROTECTOR_VERIFY_TIMEOUT`) was exhausted before the
    /// registry/Rekor round trip completed — the slow-path (keyless Fulcio+Rekor+TUF) symptom of
    /// a too-short timeout or a cold TUF cache, NOT unreachability.
    TimedOut(Duration),
    /// The round trip failed outright — registry / transparency log / TUF trust root unreachable
    /// or erroring. Distinct from a spent budget: raising the timeout won't help here.
    Unreachable,
}

impl CheckingReason {
    /// A short, human-facing reason clause for the WARN line (JEF-326).
    fn describe(&self) -> String {
        match self {
            CheckingReason::TimedOut(budget) => {
                format!(
                    "verification timed out after {budget:?} (raise PROTECTOR_VERIFY_TIMEOUT or warm the TUF cache)"
                )
            }
            CheckingReason::Unreachable => "registry/Rekor/TUF unreachable".to_string(),
        }
    }
}

/// Classify a `fetch_layers` error into the operational [`CheckingReason`] (JEF-326): a spent
/// verification budget (a [`VerifyTimeout`] anywhere in the chain) vs a genuine reachability
/// failure. Reads the typed cause via `downcast_ref` rather than matching on message text, so the
/// classification can't silently drift when an error string is reworded.
pub(super) fn classify_checking_reason(err: &anyhow::Error) -> CheckingReason {
    match err.downcast_ref::<VerifyTimeout>() {
        Some(VerifyTimeout(budget)) => CheckingReason::TimedOut(*budget),
        None => CheckingReason::Unreachable,
    }
}

#[async_trait]
impl SignatureObserver for CosignChecker {
    async fn observe(&self, image: &str) -> SigningPosture {
        match self.fetch_layers(image).await {
            Ok(layers) => classify(&layers),
            Err(err) => {
                // WARN, not debug (JEF-326): a stuck "checking" posture was invisible at the default
                // log level, so the perpetual-checking bug was silent. The classified reason names
                // the cause (timeout vs unreachable) so the operator knows which lever to pull.
                let reason = classify_checking_reason(&err);
                tracing::warn!(
                    %image,
                    error = %err,
                    "signing posture unresolved (checking): {}",
                    reason.describe()
                );
                SigningPosture::Checking
            }
        }
    }
}

#[async_trait]
impl ProvenanceObserver for CosignChecker {
    async fn observe_provenance(&self, image: &str) -> ProvenancePosture {
        // Reuse the SAME sanctioned registry/Rekor round trip as signature verification (ADR-0015):
        // `trusted_signature_layers` already returns any attached in-toto/DSSE attestation layer.
        // No second verifier, no new egress path. An infra error is the transient "checking" state.
        match self.fetch_layers(image).await {
            Ok(layers) => classify_provenance(&provenance_facts(&layers)),
            Err(err) => {
                tracing::debug!(%image, error = %err, "build-provenance: registry/Rekor unreachable — checking");
                ProvenancePosture::Checking
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

/// The verification-relevant facts extracted from one fetched [`SignatureLayer`] (JEF-276),
/// decoupled from sigstore's type so [`classify_facts`] is exhaustively unit-testable without
/// synthesising a full Fulcio cert + verification key. Every field reflects what sigstore-rs
/// *already verified* when it built the layer: `certificate_signature` is populated ONLY if the
/// cert chained to the trusted Fulcio root AND its Rekor bundle verified; `bundle` is populated
/// ONLY if the transparency-log inclusion verified; and a layer whose signature genuinely fails
/// (tampered payload, or a Rekor bundle that does not verify) is DROPPED by sigstore-rs before it
/// reaches us, so it never appears here (see the classify note on the reserved `InvalidSignature`).
#[derive(Debug)]
pub(super) struct LayerFacts {
    /// The keyless signer, present only when the Fulcio cert chained + Rekor inclusion verified.
    pub signer: Option<Signer>,
    /// A verified transparency-log (Rekor) bundle is attached — log inclusion held, even when no
    /// Fulcio cert is present (the key-based signing shape).
    pub has_verified_bundle: bool,
    /// A signature artifact is present on the layer at all.
    pub has_signature: bool,
}

impl LayerFacts {
    /// Project the verification-relevant fields off a fetched layer. `CertificateSubject::Email`
    /// is a legitimate keyless signer (a human who authenticated via GitHub/Google), recorded as
    /// such — observation does not gate (the org gate rejects Email; the inventory must not).
    fn from_layer(layer: &SignatureLayer) -> Self {
        let signer = layer.certificate_signature.as_ref().map(|cert| {
            let identity = match &cert.subject {
                CertificateSubject::Uri(uri) => uri.clone(),
                CertificateSubject::Email(email) => email.clone(),
            };
            Signer {
                identity,
                issuer: cert.issuer.clone(),
            }
        });
        LayerFacts {
            signer,
            has_verified_bundle: layer.bundle.is_some(),
            has_signature: layer.signature.is_some(),
        }
    }
}

/// Read a signing posture from fetched signature layers (ADR-0020 Stage 1; JEF-276 honest split).
/// Pure classification — no trusted-identity config required, the Fulcio/Rekor chain is the trust
/// anchor. Delegates to [`classify_facts`] over the per-layer [`LayerFacts`] so the decision table
/// is unit-testable without synthesising real certs. The transient "checking" state is produced by
/// [`observe`](SignatureObserver::observe) on an `Err`, never here.
pub(super) fn classify(layers: &[SignatureLayer]) -> SigningPosture {
    let facts: Vec<LayerFacts> = layers.iter().map(LayerFacts::from_layer).collect();
    classify_facts(&facts)
}

/// The honest posture decision table (JEF-276), in strict precedence — the calmest *supported*
/// evidence wins, and the loud `InvalidSignature` is reserved for a genuine failure:
///   1. any layer with a **verified keyless signer** ⇒ [`Signed`](SigningPosture::Signed) — the one
///      trusted-identity posture (a broken keyless image is dropped by sigstore before it reaches
///      us, so a signer here always chained + log-verified);
///   2. else any layer with a **verified Rekor bundle** but no signer ⇒
///      [`SignedKeyBased`](SigningPosture::SignedKeyBased) — a `cosign sign --key` signature whose
///      log inclusion verified; signer opaque. CALM, never invalid (reproducer 1: cert-manager);
///   3. else any layer with a **signature artifact** but nothing verified against our trust root ⇒
///      [`UnverifiableHere`](SigningPosture::UnverifiableHere) — honest "couldn't verify here", not
///      "forged" (reproducer 2: curl's transparency-log trust-root variance);
///   4. no layers at all ⇒ [`NotSigned`](SigningPosture::NotSigned). A genuinely-failed signature
///      (tampered payload / a cert whose Rekor inclusion doesn't hold) is dropped by sigstore-rs
///      before it reaches us and so lands here too — the SAFE direction: calm and never a false
///      "signed", and still caught loudly as a signing regression on an established repo (JEF-264);
///   5. a degenerate layer with neither signer, verified bundle, nor even a signature ⇒
///      [`InvalidSignature`](SigningPosture::InvalidSignature), the RESERVED loud channel.
///
/// SECURITY: nothing below step 1 is ever read as a trusted signer — key-based and unverifiable are
/// honestly-labelled-but-not-trusted-as-identity, and no calmer-than-actual state is fabricated.
pub(super) fn classify_facts(facts: &[LayerFacts]) -> SigningPosture {
    if let Some(signer) = facts.iter().find_map(|f| f.signer.clone()) {
        return SigningPosture::Signed(signer);
    }
    if facts.iter().any(|f| f.has_verified_bundle) {
        return SigningPosture::SignedKeyBased;
    }
    if facts.iter().any(|f| f.has_signature) {
        return SigningPosture::UnverifiableHere;
    }
    if facts.is_empty() {
        SigningPosture::NotSigned
    } else {
        SigningPosture::InvalidSignature
    }
}

/// Project the SLSA build-provenance facts (JEF-275) off fetched layers: one [`ProvenanceFacts`]
/// per layer whose in-toto predicate type is a SLSA provenance type (a plain signature layer never
/// produces one). `keyless_verified` mirrors the signing axis — sigstore populates
/// `certificate_signature` ONLY when the attestation's cert chained to the trusted Fulcio root AND
/// its Rekor bundle verified, so an attacker-attached, unverifiable attestation comes back with
/// `keyless_verified: false` (which classifies as [`Unverifiable`](ProvenancePosture::Unverifiable),
/// never trusted). The predicate is decoded from the layer's DSSE PAE payload (the in-toto
/// statement), which the classifier reads for the source repo + builder identity.
pub(super) fn provenance_facts(layers: &[SignatureLayer]) -> Vec<ProvenanceFacts> {
    layers
        .iter()
        .filter(|layer| is_slsa_predicate_type(&layer.simple_signing.critical.type_name))
        .map(|layer| ProvenanceFacts {
            predicate_type: layer.simple_signing.critical.type_name.clone(),
            predicate: predicate_from_pae(&layer.raw_data),
            keyless_verified: layer.certificate_signature.is_some(),
        })
        .collect()
}

/// Decode the SLSA `predicate` object out of a layer's DSSE PAE-encoded `raw_data`. sigstore stores
/// the DSSE Pre-Authentication-Encoding (`DSSEv1 <len> <payloadType> <len> <payload>`) in
/// `raw_data`; the `<payload>` is the in-toto Statement JSON, whose `predicate` field carries the
/// SLSA provenance. Returns `None` when the PAE is malformed or the payload isn't the expected
/// in-toto shape — a present-but-opaque attestation (never a fabricated predicate).
fn predicate_from_pae(raw_data: &[u8]) -> Option<serde_json::Value> {
    let payload = pae_payload(raw_data)?;
    let statement: serde_json::Value = serde_json::from_slice(payload).ok()?;
    statement.get("predicate").cloned()
}

/// Extract the `<payload>` bytes from a DSSE PAE header
/// (`DSSEv1 <len(type)> <type> <len(payload)> <payload>`, all lengths ASCII decimal). The type and
/// payload can themselves contain spaces, so this reads by the declared lengths rather than
/// splitting on whitespace. Returns `None` on any malformed field.
fn pae_payload(raw: &[u8]) -> Option<&[u8]> {
    let rest = raw.strip_prefix(b"DSSEv1 ")?;
    // <len(type)> up to the next space.
    let sp = rest.iter().position(|&b| b == b' ')?;
    let type_len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
    let rest = &rest[sp + 1..];
    // Skip the type itself (type_len bytes) then a single space.
    let rest = rest.get(type_len..)?;
    let rest = rest.strip_prefix(b" ")?;
    // <len(payload)> up to the next space.
    let sp = rest.iter().position(|&b| b == b' ')?;
    let payload_len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
    let payload = rest.get(sp + 1..)?;
    // The declared length must match exactly what remains — a defensive check against a truncated
    // or over-long PAE.
    if payload.len() == payload_len {
        Some(payload)
    } else {
        None
    }
}

/// The per-image verification budget was exhausted before the registry/Rekor round trip returned
/// (JEF-326). A typed error (rather than a formatted string) so [`classify_checking_reason`] can
/// tell a spent timeout apart from a reachability failure via `downcast_ref`, robust to message
/// rewording. Carries the budget that elapsed for the operator-facing WARN line.
#[derive(Debug, thiserror::Error)]
#[error("verification timed out after {0:?}")]
pub(super) struct VerifyTimeout(pub(super) Duration);

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

#[cfg(test)]
#[path = "cosign_tests.rs"]
mod cosign_tests;

#[cfg(test)]
mod provenance_pae_tests {
    use super::*;

    /// Build a DSSE PAE the way sigstore's `compute_pae` does, so the extractor is tested against
    /// the exact on-the-wire shape (`DSSEv1 <len> <type> <len> <payload>`).
    fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "DSSEv1 {} {} {} ",
            payload_type.len(),
            payload_type,
            payload.len()
        )
        .into_bytes();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn extracts_predicate_from_a_well_formed_pae() {
        let statement = br#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","predicate":{"runDetails":{"builder":{"id":"https://github.com/org/app/.github/workflows/x.yml@refs/heads/main"}}}}"#;
        let raw = pae("application/vnd.in-toto+json", statement);
        let predicate = predicate_from_pae(&raw).expect("predicate decoded");
        assert_eq!(
            predicate.pointer("/runDetails/builder/id").unwrap(),
            "https://github.com/org/app/.github/workflows/x.yml@refs/heads/main"
        );
    }

    #[test]
    fn payload_with_embedded_spaces_is_read_by_length() {
        // The in-toto statement JSON can contain spaces; the extractor must read by the declared
        // length, not split on whitespace.
        let statement = br#"{ "predicate": { "buildType": "a b c" } }"#;
        let raw = pae("application/vnd.in-toto+json", statement);
        let predicate = predicate_from_pae(&raw).expect("predicate decoded");
        assert_eq!(predicate.pointer("/buildType").unwrap(), "a b c");
    }

    #[test]
    fn malformed_pae_yields_none() {
        assert!(pae_payload(b"not a dsse pae").is_none());
        assert!(predicate_from_pae(b"garbage").is_none());
    }

    #[test]
    fn a_truncated_payload_is_rejected() {
        // Declared length longer than the actual bytes must not silently succeed.
        let raw = b"DSSEv1 4 json 999 {}".to_vec();
        assert!(pae_payload(&raw).is_none());
    }
}

#[cfg(test)]
mod checking_reason_tests {
    use super::*;

    #[test]
    fn a_verify_timeout_error_classifies_as_timed_out_with_its_budget() {
        // The typed timeout — the perpetual-checking symptom on the slow keyless path (JEF-326).
        let err = anyhow::Error::new(VerifyTimeout(Duration::from_secs(20)));
        assert_eq!(
            classify_checking_reason(&err),
            CheckingReason::TimedOut(Duration::from_secs(20))
        );
        // The reason names the knob so the operator isn't left guessing.
        assert!(
            CheckingReason::TimedOut(Duration::from_secs(20))
                .describe()
                .contains("PROTECTOR_VERIFY_TIMEOUT")
        );
    }

    #[test]
    fn a_timeout_wrapped_in_context_still_classifies_as_timed_out() {
        // `downcast_ref` walks the cause chain, so an added context layer doesn't lose the cause.
        let err = anyhow::Error::new(VerifyTimeout(Duration::from_secs(5)))
            .context("observing ghcr.io/org/app:1");
        assert_eq!(
            classify_checking_reason(&err),
            CheckingReason::TimedOut(Duration::from_secs(5))
        );
    }

    #[test]
    fn a_generic_error_classifies_as_unreachable() {
        // Any non-timeout failure (registry 500, Rekor DNS, TUF fetch) is reachability, not budget.
        let err = anyhow::anyhow!("connection refused");
        assert_eq!(classify_checking_reason(&err), CheckingReason::Unreachable);
        assert!(
            CheckingReason::Unreachable
                .describe()
                .contains("unreachable")
        );
    }
}
