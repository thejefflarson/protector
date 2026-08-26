//! Unit tests for the pure parts of the provenance referrer observer: SLSA predicate extraction
//! out of a Sigstore-bundle v0.3 JSON blob, and the auth mapping. The fetch + cryptographic
//! verification are exercised end-to-end against a live image by the ignored integration test in
//! `engine/tests/` (they need a registry + the sigstore TUF root); here we cover the parsing that
//! decides whether a referrer even IS build provenance.

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};

/// Wrap an in-toto statement JSON in the DSSE-envelope Sigstore-bundle v0.3 shape the extractor
/// reads (`dsseEnvelope.payload` is base64 of the statement).
fn bundle_with_statement(statement: &str) -> Vec<u8> {
    let payload = b64.encode(statement);
    format!(
        r#"{{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",
             "dsseEnvelope":{{"payloadType":"application/vnd.in-toto+json",
                              "payload":"{payload}","signatures":[{{"sig":"AA=="}}]}}}}"#
    )
    .into_bytes()
}

#[test]
fn extracts_a_slsa_v1_predicate() {
    let statement = r#"{"_type":"https://in-toto.io/Statement/v1",
        "predicateType":"https://slsa.dev/provenance/v1",
        "predicate":{"runDetails":{"builder":{"id":"https://github.com/org/app/.github/workflows/x.yml@refs/tags/v1"}}}}"#;
    let (ptype, predicate) =
        extract_slsa_predicate(&bundle_with_statement(statement)).expect("slsa predicate");
    assert_eq!(ptype, "https://slsa.dev/provenance/v1");
    assert_eq!(
        predicate.pointer("/runDetails/builder/id").unwrap(),
        "https://github.com/org/app/.github/workflows/x.yml@refs/tags/v1"
    );
}

#[test]
fn extracts_a_slsa_v02_predicate() {
    let statement = r#"{"predicateType":"https://slsa.dev/provenance/v0.2",
        "predicate":{"builder":{"id":"https://example.com/builder"}}}"#;
    let (ptype, _) =
        extract_slsa_predicate(&bundle_with_statement(statement)).expect("slsa predicate");
    assert_eq!(ptype, "https://slsa.dev/provenance/v0.2");
}

#[test]
fn a_cosign_signature_predicate_is_not_provenance() {
    // The exact predicate sigstore-rs's referrer path accepts and protector's provenance axis must
    // ignore — this is why the axis can't just read every referrer as provenance.
    let statement = r#"{"predicateType":"https://sigstore.dev/cosign/sign/v1","predicate":{}}"#;
    assert!(extract_slsa_predicate(&bundle_with_statement(statement)).is_none());
}

#[test]
fn a_non_dsse_bundle_yields_none() {
    // A message-signature bundle (cosign signature) has no dsseEnvelope — not an attestation.
    let bundle = br#"{"messageSignature":{"signature":"AA=="}}"#;
    assert!(extract_slsa_predicate(bundle).is_none());
}

#[test]
fn garbage_and_bad_base64_yield_none() {
    assert!(extract_slsa_predicate(b"not json").is_none());
    let bad = br#"{"dsseEnvelope":{"payload":"!!!not-base64!!!"}}"#;
    assert!(extract_slsa_predicate(bad).is_none());
}

#[test]
fn a_statement_missing_the_predicate_field_yields_none() {
    // A SLSA predicateType with no predicate object is not usable — never fabricate an empty one.
    let statement = r#"{"predicateType":"https://slsa.dev/provenance/v1"}"#;
    assert!(extract_slsa_predicate(&bundle_with_statement(statement)).is_none());
}

#[test]
fn anonymous_auth_maps_to_oci_anonymous() {
    // The default resolver (no creds) must produce oci-client Anonymous, the safe per-image default.
    let auth = RegistryAuth::default();
    assert!(matches!(
        oci_auth_for(&auth, "ghcr.io/org/app:1"),
        OciAuth::Anonymous
    ));
}
