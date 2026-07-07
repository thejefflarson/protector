//! JEF-386: mirror-served images verify by DIGEST, not by registry name.
//!
//! A cosign signature is digest-bound: its payload pins `docker-manifest-digest`, and sigstore-rs
//! verifies every layer against the digest of the manifest we actually pulled. The payload's
//! `critical.identity.docker-reference` records the registry the signer *published* to — which, for
//! a mirror (e.g. linkerd's `cr.l5d.io/linkerd/proxy`, signed as `ghcr.io/linkerd/proxy` for the
//! SAME digest), differs from the pull registry. These tests pin two guarantees against regression:
//!
//!   1. protector's posture classification NEVER gates on `docker-reference` — a verified signer on
//!      a mirror-referenced layer classifies as `Signed` (matching `cosign verify`'s leniency);
//!   2. the GATED admission identity check stays strict on the verified cert's SAN + issuer, and is
//!      wholly unaffected by the (relaxed) docker-reference — a mirror does NOT smuggle an untrusted
//!      identity past the org gate, and a first-party signer is still admitted regardless of mirror.
//!
//! Built as real [`SignatureLayer`] values (not the decoupled `LayerFacts`) so they exercise the
//! production `classify` path end to end. A live-network reproduction against the exact JEF-386
//! fixture (`cr.l5d.io/linkerd/proxy`) is kept as an `#[ignore]` test below.

use sigstore::cosign::SignatureLayer;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::cosign::payload::simple_signing::{Critical, Identity, Image};
use sigstore::cosign::signature_layers::{CertificateSignature, CertificateSubject};
use sigstore::crypto::{CosignVerificationKey, SigningScheme};

use super::*;

/// The signer identity + issuer on the real linkerd keyless signature (JEF-386 fixture).
const LINKERD_SAN: &str =
    "https://github.com/linkerd/linkerd2/.github/workflows/release.yml@refs/tags/edge-26.6.3";
const GHA_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The digest linkerd's edge-26.6.3 proxy is signed against (matches on both `ghcr.io` and the
/// `cr.l5d.io` mirror — the signature is bound to THIS, never to a registry name).
const DIGEST: &str = "sha256:8d04c5aff5ea67ae053a658f044c1d357d53ab31d02a9d01ccbc6bce4bfa339b";

/// A throwaway verification key. `classify` and the org-identity gate read the cert's SUBJECT +
/// issuer, never this key, so any well-formed P-256 public key stands in for the embedded one.
fn dummy_verification_key() -> CosignVerificationKey {
    const PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4ACeuN3XfivZve92ipTwx7nkgWBu\n\
+mbfq5IHtzbinVL2MOWIYUY6isNPKpCw/06Z+gccB3o8+9JU+y/yKhEqwQ==\n\
-----END PUBLIC KEY-----";
    CosignVerificationKey::from_pem(PEM.as_bytes(), &SigningScheme::ECDSA_P256_SHA256_ASN1)
        .expect("well-formed test P-256 public key")
}

/// A `SimpleSigning` payload whose `docker-reference` names `docker_reference` (the SIGNING
/// registry) and whose manifest digest is `DIGEST` — the shape sigstore-rs returns for a mirror
/// pull, where the reference and the pull registry diverge but the digest is identical.
fn simple_signing(docker_reference: &str) -> SimpleSigning {
    SimpleSigning {
        critical: Critical {
            identity: Identity {
                docker_reference: docker_reference.to_string(),
            },
            image: Image {
                docker_manifest_digest: DIGEST.to_string(),
            },
            type_name: "cosign container image signature".to_string(),
        },
        optional: None,
    }
}

/// A keyless-verified layer: sigstore-rs only populates `certificate_signature` after the embedded
/// cert chained to the trusted Fulcio root AND its Rekor bundle verified. `docker_reference` is the
/// registry the payload names (the mirror case sets it to the signing registry, not the pull one).
fn verified_mirror_layer(docker_reference: &str, san: &str) -> SignatureLayer {
    SignatureLayer {
        simple_signing: simple_signing(docker_reference),
        oci_digest: DIGEST.to_string(),
        certificate_signature: Some(CertificateSignature {
            verification_key: dummy_verification_key(),
            subject: CertificateSubject::Uri(san.to_string()),
            issuer: Some(GHA_ISSUER.to_string()),
            github_workflow_trigger: None,
            github_workflow_sha: None,
            github_workflow_name: None,
            github_workflow_repository: None,
            github_workflow_ref: None,
        }),
        bundle: None,
        signature: Some("MEQCIFPccuwXu5p6+Jexz/x47aQt/d6O68IUVRMGYR4++sXZ".to_string()),
        raw_data: Vec::new(),
    }
}

/// A layer with a signature artifact but nothing verified against our trust root (no cert, no
/// bundle) — the shape sigstore-rs leaves behind when the cert chain / Rekor inclusion / digest
/// binding does NOT hold (it strips the cert + bundle rather than trusting them).
fn unverified_layer(docker_reference: &str) -> SignatureLayer {
    SignatureLayer {
        simple_signing: simple_signing(docker_reference),
        oci_digest: DIGEST.to_string(),
        certificate_signature: None,
        bundle: None,
        signature: Some("MEQCIFPccuwXu5p6+Jexz/x47aQt/d6O68IUVRMGYR4++sXZ".to_string()),
        raw_data: Vec::new(),
    }
}

fn checker_gating(identity_regexp: &str) -> CosignChecker {
    CosignChecker::new(
        identity_regexp,
        GHA_ISSUER.to_string(),
        RegistryAuth::default(),
        std::env::temp_dir().join(format!("protector-cosign-386-{}", std::process::id())),
        std::time::Duration::from_secs(5),
    )
    .expect("checker builds")
}

#[test]
fn mirror_referenced_layer_with_verified_signer_classifies_as_signed() {
    // The JEF-386 core: pulled from the mirror `cr.l5d.io/linkerd/proxy`, but the signature payload
    // names the signing registry `ghcr.io/linkerd/proxy` for the SAME digest. sigstore-rs verified
    // the cert-chain + Rekor + digest and left the signer on the layer; classify must read it as
    // `Signed` — the docker-reference divergence is irrelevant to posture.
    let layer = verified_mirror_layer("ghcr.io/linkerd/proxy", LINKERD_SAN);
    let posture = classify(std::slice::from_ref(&layer));
    assert_eq!(
        posture.status(),
        "signed",
        "mirror-served image must verify"
    );
    let signer = posture.signer().expect("keyless-verified carries a signer");
    assert_eq!(signer.identity, LINKERD_SAN);
    assert_eq!(signer.issuer.as_deref(), Some(GHA_ISSUER));
}

#[test]
fn layer_facts_never_reads_the_docker_reference() {
    // Same verified signer, two wildly different payload references (signing registry vs a bogus
    // one) — classification is byte-for-byte identical, proving posture never consults the
    // docker-reference. If a reference gate were ever added, these would diverge and this fails.
    let signing_registry = classify(&[verified_mirror_layer("ghcr.io/linkerd/proxy", LINKERD_SAN)]);
    let bogus_registry = classify(&[verified_mirror_layer(
        "evil.example/somewhere/else",
        LINKERD_SAN,
    )]);
    assert_eq!(signing_registry, bogus_registry);
    assert_eq!(signing_registry.status(), "signed");
}

#[test]
fn unverified_signature_on_a_mirror_reference_is_not_signed() {
    // The safe direction: a digest mismatch / broken cert-chain / failed Rekor inclusion is stripped
    // by sigstore-rs to a bare signature artifact. That must NOT read as a trusted signer — it is
    // honestly "unverifiable here", never `Signed`, regardless of the (relaxed) docker-reference.
    let posture = classify(&[unverified_layer("ghcr.io/linkerd/proxy")]);
    assert_eq!(posture, SigningPosture::UnverifiableHere);
    assert_eq!(posture.signer(), None);
}

#[test]
fn gated_identity_stays_strict_despite_the_relaxed_reference() {
    // Reference relaxation must NOT weaken the enforcing path. A verified linkerd signer — even
    // though its payload reference matches a legitimate registry — is REJECTED by an org gate scoped
    // to first-party `github.com/thejefflarson/`: the gate tests the cert SAN, never the reference.
    let gate = checker_gating("^https://github\\.com/thejefflarson/");
    let linkerd = verified_mirror_layer("ghcr.io/linkerd/proxy", LINKERD_SAN);
    assert!(
        !gate.satisfies_org_identity(std::slice::from_ref(&linkerd)),
        "a third-party signer must never satisfy the first-party org gate"
    );

    // And a genuine first-party signer is admitted even when its image is pulled from a mirror whose
    // docker-reference names some other registry — identity gating is on the SAN, digest-bound, and
    // reference-agnostic, exactly as the observe path is.
    let first_party = verified_mirror_layer(
        "mirror.internal.example/thejefflarson/protector",
        "https://github.com/thejefflarson/protector/.github/workflows/agent.yml@refs/tags/v0.3.79",
    );
    assert!(
        gate.satisfies_org_identity(std::slice::from_ref(&first_party)),
        "a first-party signer must be admitted regardless of the mirror it was pulled from"
    );
}

#[test]
fn gated_path_rejects_an_unverified_signature() {
    // A stripped, unverifiable signature never satisfies the org gate (no verified signer to match).
    let gate = checker_gating("^https://github\\.com/linkerd/");
    let layer = unverified_layer("ghcr.io/linkerd/proxy");
    assert!(!gate.satisfies_org_identity(std::slice::from_ref(&layer)));
}

/// Live end-to-end reproduction of the exact JEF-386 fixture: the linkerd proxy served from the
/// `cr.l5d.io` vanity mirror, whose signature payload names `ghcr.io/linkerd/proxy`. Reaches the
/// registry + Rekor + the sigstore TUF root, so it is `#[ignore]`d out of the offline per-PR lane;
/// run it deliberately with `cargo test -- --ignored jef_386_mirror_verifies_end_to_end`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "network: hits cr.l5d.io + Rekor + sigstore TUF"]
async fn jef_386_mirror_verifies_end_to_end() {
    let checker = CosignChecker::new(
        "^https://github\\.com/linkerd/",
        GHA_ISSUER.to_string(),
        RegistryAuth::default(),
        std::env::temp_dir().join(format!("protector-cosign-386-live-{}", std::process::id())),
        std::time::Duration::from_secs(60),
    )
    .expect("checker builds");
    let posture = checker.observe("cr.l5d.io/linkerd/proxy:edge-26.6.3").await;
    assert_eq!(
        posture.status(),
        "signed",
        "mirror-served linkerd proxy must verify end to end, got {posture:?}"
    );
    assert_eq!(
        posture.signer().map(|s| s.identity.clone()).as_deref(),
        Some(LINKERD_SAN),
    );
}
