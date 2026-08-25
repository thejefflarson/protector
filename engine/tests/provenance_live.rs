//! Live end-to-end check of SLSA build-provenance observation (ADR-0020 §5).
//!
//! `#[ignore]`d because it needs network (a real registry + the sigstore trust material) and
//! reaches out to specific public images — so it never runs in CI, but a maintainer can run it to
//! confirm the whole fetch → referrer → `sigstore-verify` chain against real attestations:
//!
//!   cargo test -p protector --test provenance_live -- --ignored --nocapture
//!
//! This test exists because the bug it guards was invisible to unit tests: the provenance path was
//! fully green against synthetic fixtures while returning `Absent` for every real image in
//! production (the `sigstore` crate silently drops SLSA attestations). Only an end-to-end check
//! against a genuinely-attested image catches that class of regression.

use std::time::Duration;

use protector::policies::signature::{
    CosignChecker, ProvenanceObserver, ProvenancePosture, RegistryAuth,
};

fn checker() -> CosignChecker {
    CosignChecker::new(
        ".*",
        "https://token.actions.githubusercontent.com".to_string(),
        RegistryAuth::from_env(),
        std::env::temp_dir().join("protector-tuf-provenance-live"),
        Duration::from_secs(90),
    )
    .expect("build checker")
}

/// protector's own agent image is built with `actions/attest-build-provenance`, so it MUST verify to
/// `Verified` with this repo as the source and its release workflow as the builder — the posture the
/// inventory's provenance column renders. (Override the image via `IMG`.)
#[tokio::test]
#[ignore]
async fn own_image_provenance_verifies() {
    let image = std::env::var("IMG")
        .unwrap_or_else(|_| "ghcr.io/thejefflarson/protector-agent:0.14.1".to_string());
    match checker().observe_provenance(&image).await {
        ProvenancePosture::Verified(p) => {
            assert!(
                p.source_repo.contains("thejefflarson/protector"),
                "unexpected source repo: {}",
                p.source_repo
            );
            assert!(
                p.builder.contains(".github/workflows/"),
                "unexpected builder: {}",
                p.builder
            );
        }
        other => panic!("expected Verified provenance for {image}, got {other:?}"),
    }
}

/// An image with no SLSA attestation on a registry that doesn't support the OCI referrers API must
/// resolve to the calm `Absent`, NOT a perpetual `Checking` — the whole cluster's mirrored base
/// images depend on this staying calm.
#[tokio::test]
#[ignore]
async fn unattested_mirror_image_is_absent() {
    let posture = checker()
        .observe_provenance("mirror.gcr.io/library/redis:7-alpine")
        .await;
    assert_eq!(posture, ProvenancePosture::Absent, "got {posture:?}");
}
