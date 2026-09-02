//! Real SLSA build-provenance observation over OCI referrers (ADR-0020 §5).
//!
//! ## Why this is a separate path (not `sigstore`'s cosign layer fetch)
//!
//! The `sigstore` crate (0.14, chainguard) — which the signing axis uses — **cannot observe SLSA
//! build provenance at all**, via either of its public verify paths:
//!   * `trusted_signature_layers` hardcodes the cosign-signature in-toto predicate on its OCI-
//!     referrer path and REJECTS every other predicate, including `https://slsa.dev/provenance/v1`
//!     (what `actions/attest-build-provenance` publishes) — so the attestation is fetched then
//!     dropped; and
//!   * its `bundle::verify::Verifier` recomputes the DSSE envelope hash from a proto round-trip,
//!     which never matches the hash Rekor actually stored (a canonicalization bug), so offline DSSE
//!     verification always fails; its online DSSE path is unimplemented.
//!
//! The net effect was that every image observed [`Absent`](ProvenancePosture::Absent) and the
//! inventory's provenance column was uniformly blank. (These images carry no legacy `.sig` tag
//! either — signature and attestation are BOTH OCI referrers now.)
//!
//! ## What this does
//!
//! Fetch the image's OCI referrers directly, select the SLSA build-provenance bundle(s), and verify
//! each with the `sigstore-verify` crate (prefix-dev) — a maintained verifier that is purpose-built
//! for GitHub artifact attestation and handles the DSSE Rekor-entry consistency **correctly**
//! (payload-hash + signature match, not the broken envelope-hash recompute). Trust material is the
//! crate's built-in `SIGSTORE_PRODUCTION_TRUSTED_ROOT` — no TUF fetch, and verification runs against
//! the bundle's OWN embedded inclusion proof + checkpoint, so it is fully OFFLINE. The verified
//! facts feed the SAME pure [`classify_provenance`] + `parse_slsa_predicate` the signing axis'
//! unit tests already cover, so the four-state precedence (verified / unverifiable / absent /
//! checking) is unchanged; only the *source* of the facts moves to a real referrer fetch.
//!
//! Egress: the SAME sanctioned registry round trip signature verification already makes (ADR-0015),
//! no new destination and no online transparency-log call.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use oci_client::Client;
use oci_client::Reference;
use oci_client::client::ClientConfig;
use oci_client::manifest::{
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
};
use oci_client::secrets::RegistryAuth as OciAuth;
use sigstore_verify::trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_verify::types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};

use super::RegistryAuth;
use super::provenance::{
    ProvenanceFacts, ProvenancePosture, classify_provenance, is_slsa_predicate_type,
};

/// The OCI media type of a Sigstore bundle v0.3 blob — how `actions/attest-build-provenance` (and
/// modern cosign) write both attestations and signatures as OCI referrers.
const SIGSTORE_BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// The manifest media types the top-level fetch must accept to resolve the image's tag object —
/// single-arch manifest OR multi-arch index, whichever the tag points at. Its digest is the SLSA
/// attestation's `subject`, so we hand it to the verifier as the artifact to bind against.
const MANIFEST_MEDIA_TYPES: &[&str] = &[
    OCI_IMAGE_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    IMAGE_MANIFEST_MEDIA_TYPE,
    IMAGE_MANIFEST_LIST_MEDIA_TYPE,
];

/// The built-in sigstore public-good trust root, parsed once. It carries the Fulcio CA, Rekor keys,
/// and CT-log keys `sigstore-verify` needs — so provenance verification does ZERO TUF/network fetch
/// for trust material (the signing axis fetches TUF for its own cosign path; this path does not).
fn trusted_root() -> &'static TrustedRoot {
    static TRUSTED_ROOT: OnceLock<TrustedRoot> = OnceLock::new();
    TRUSTED_ROOT.get_or_init(|| {
        TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
            .expect("built-in sigstore production trusted root must parse")
    })
}

/// Observe `image`'s SLSA build-provenance posture by fetching + verifying its OCI referrers.
///
/// Returns `Err` ONLY on an infrastructure failure (registry unreachable / manifest fetch failed) —
/// the caller maps that to the transient [`Checking`](ProvenancePosture::Checking). A reachable
/// registry with no provenance referrer is [`Absent`](ProvenancePosture::Absent) (an `Ok`), never an
/// error. Verified provenance is [`Verified`](ProvenancePosture::Verified); a present-but-
/// unverifiable attestation is [`Unverifiable`](ProvenancePosture::Unverifiable) — the exact
/// precedence of the shared [`classify_provenance`].
pub(super) async fn observe_provenance(
    auth: &RegistryAuth,
    image: &str,
) -> Result<ProvenancePosture> {
    let image_ref: Reference = image
        .parse()
        .with_context(|| format!("parsing image reference {image}"))?;
    let oci_auth = oci_auth_for(auth, image);
    let client = Client::new(ClientConfig::default());

    // One manifest fetch does double duty: it authenticates the client for the subsequent
    // referrer/blob pulls (token cached), AND yields the tag's manifest digest — the attestation
    // `subject` the verifier binds each DSSE statement against.
    let (_, digest) = client
        .pull_manifest_raw(&image_ref, &oci_auth, MANIFEST_MEDIA_TYPES)
        .await
        .with_context(|| format!("fetching manifest for {image}"))?;
    let subject_ref = Reference::with_digest(
        image_ref.registry().to_string(),
        image_ref.repository().to_string(),
        digest.clone(),
    );

    // The manifest fetch above already proved the registry is reachable + authorized, so a failure
    // to LIST referrers here is not a reachability problem — it means the registry doesn't support
    // the OCI referrers API (many mirrors return an unparseable/empty referrers tag). That is the
    // calm `Absent` (no provenance to show), NOT the transient `Checking` (which would leave every
    // such image stuck showing "checking" forever). Only an unreachable IMAGE is `Checking`.
    let referrers = match client.pull_referrers(&subject_ref, None).await {
        Ok(r) => r,
        Err(err) => {
            tracing::debug!(%image, error = %err, "build-provenance: referrers API unavailable — absent");
            return Ok(ProvenancePosture::Absent);
        }
    };

    let verifier = Verifier::new(trusted_root());
    let mut facts: Vec<ProvenanceFacts> = Vec::new();
    for entry in &referrers.manifests {
        let referrer_ref = Reference::with_digest(
            image_ref.registry().to_string(),
            image_ref.repository().to_string(),
            entry.digest.clone(),
        );
        // A single referrer we can't pull is skipped, not fatal: a hard registry failure already
        // surfaced at the manifest/referrer-list step above (→ Checking). One odd referrer must not
        // mask a real provenance attestation sitting beside it.
        let Ok(data) = client
            .pull(
                &referrer_ref,
                &oci_auth,
                vec![SIGSTORE_BUNDLE_V03_MEDIA_TYPE],
            )
            .await
        else {
            continue;
        };
        for layer in &data.layers {
            if layer.media_type != SIGSTORE_BUNDLE_V03_MEDIA_TYPE {
                continue;
            }
            if let Some(fact) = provenance_fact_from_bundle(&verifier, &layer.data, &digest) {
                facts.push(fact);
            }
        }
    }
    Ok(classify_provenance(&facts))
}

/// Turn one Sigstore-bundle blob into a [`ProvenanceFacts`] IF it is a SLSA build-provenance
/// attestation, else `None` (a signature bundle or any non-SLSA predicate is not provenance).
/// `keyless_verified` reflects whether `sigstore-verify` confirmed the bundle's Fulcio cert chain,
/// SCT, Rekor entry consistency, AND that its in-toto `subject` digest matches this image — the one
/// bit separating a trusted build from a present-but-unverifiable one.
fn provenance_fact_from_bundle(
    verifier: &Verifier,
    bundle_json: &[u8],
    subject_digest: &str,
) -> Option<ProvenanceFacts> {
    let (predicate_type, predicate) = extract_slsa_predicate(bundle_json)?;
    let keyless_verified = verify_bundle(verifier, bundle_json, subject_digest);
    Some(ProvenanceFacts {
        predicate_type,
        predicate: Some(predicate),
        keyless_verified,
    })
}

/// Verify one SLSA bundle blob against the image's `subject_digest` (`sha256:<hex>`) with the
/// permissive observation policy (no configured identity — the Fulcio/Rekor chain is the anchor,
/// ADR-0020 §5; identity is learned, not gated). Any parse/verify failure is a plain `false`
/// (→ `Unverifiable`), never a trusted build.
fn verify_bundle(verifier: &Verifier, bundle_json: &[u8], subject_digest: &str) -> bool {
    let Ok(json) = std::str::from_utf8(bundle_json) else {
        return false;
    };
    let Ok(bundle) = Bundle::from_json(json) else {
        return false;
    };
    let Some(hex) = subject_digest.strip_prefix("sha256:") else {
        return false;
    };
    let Ok(hash) = Sha256Hash::from_hex(hex) else {
        return false;
    };
    // Default policy: verify cert chain + SCT + transparency log, but require NO specific signing
    // identity — observation learns the builder, it does not gate on it.
    verifier
        .verify(hash, &bundle, &VerificationPolicy::default())
        .is_ok()
}

/// Pull `(predicateType, predicate)` out of a Sigstore-bundle v0.3 JSON blob whose content is a DSSE
/// envelope over an in-toto Statement, returning `None` unless the predicate type is a SLSA
/// build-provenance type. Reads the raw JSON (`dsseEnvelope.payload`, base64) rather than the proto
/// types, so it needs no extra proto dependency. Every extracted value is UNTRUSTED third-party text
/// — escaped wherever rendered.
fn extract_slsa_predicate(bundle_json: &[u8]) -> Option<(String, serde_json::Value)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
    let bundle: serde_json::Value = serde_json::from_slice(bundle_json).ok()?;
    let payload_b64 = bundle.pointer("/dsseEnvelope/payload")?.as_str()?;
    let payload = b64.decode(payload_b64).ok()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let predicate_type = statement.get("predicateType")?.as_str()?;
    if !is_slsa_predicate_type(predicate_type) {
        return None;
    }
    let predicate = statement.get("predicate")?.clone();
    Some((predicate_type.to_string(), predicate))
}

/// Map protector's per-image [`RegistryAuth`] resolution onto oci-client's auth enum, so the
/// provenance fetch authenticates private images exactly as the signing sweep does.
fn oci_auth_for(auth: &RegistryAuth, image: &str) -> OciAuth {
    match auth.basic_for_image(image) {
        Some((user, pass)) => OciAuth::Basic(user, pass),
        None => OciAuth::Anonymous,
    }
}

#[cfg(test)]
#[path = "provenance_observer_tests.rs"]
mod tests;
