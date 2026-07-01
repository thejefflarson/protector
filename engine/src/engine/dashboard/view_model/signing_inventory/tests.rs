//! Tests for the signing-inventory mapping (JEF-262): the sweep's `Image/<ref>` rows partitioned
//! out of the decision log, each posture resolved to one of the four states (never n/a), the signer
//! label + issuer badge derived from the (untrusted) Fulcio SAN, the image split into repo +
//! digest/tag, and the images grouped under their repo. Escaping of the untrusted identity is a
//! render concern, tested in the Admission render tests.

use super::*;
use crate::engine::policy_log::PolicyDecisionRecord;

/// A signing-sweep observation row, exactly as `engine::signing_sweep` records it: `image-signature`
/// policy, `Image/<ref>` subject, the posture in the `signature` word + the signer prose in `reason`.
fn observed(image: &str, status: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "image-signature",
        "allow",
        format!("Image/{image}"),
        image,
        status,
        "",
        "",
        reason,
    )
}

/// A webhook workload decision row (NOT an inventory row) — used to prove partitioning.
fn workload_decision(subject: &str, image: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "admission",
        "allow",
        subject,
        image,
        "verified",
        "verified",
        "ns",
        "",
    )
}

#[test]
fn signed_github_actions_identity_collapses_to_org_repo_with_a_badge() {
    let rows = vec![observed(
        "ghcr.io/acme/app@sha256:abc",
        "signed",
        "signed by https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1 \
         via https://token.actions.githubusercontent.com",
    )];
    let groups = build(&rows);
    let row = &groups[0].images[0];
    assert_eq!(row.posture, SigningPosture::Signed);
    let signer = row
        .signer
        .as_ref()
        .expect("a signed image carries a signer");
    assert_eq!(signer.identity_short, "acme/app", "GitHub SAN → org/repo");
    assert_eq!(signer.issuer_badge, "github actions");
    assert_eq!(
        signer.identity_full,
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1",
        "the full SAN is preserved for the expand panel + title"
    );
    assert_eq!(
        signer.issuer_full.as_deref(),
        Some("https://token.actions.githubusercontent.com")
    );
}

#[test]
fn signed_email_identity_is_kept_verbatim_with_the_issuer_badge() {
    let rows = vec![observed(
        "ghcr.io/acme/export:3.0.0",
        "signed",
        "signed by releng@acme.example via https://accounts.google.com",
    )];
    let groups = build(&rows);
    let signer = groups[0].images[0].signer.as_ref().unwrap();
    assert_eq!(signer.identity_short, "releng@acme.example");
    assert_eq!(signer.issuer_badge, "google");
}

#[test]
fn signed_without_an_issuer_has_an_empty_badge_and_no_issuer_url() {
    let rows = vec![observed(
        "ghcr.io/acme/app:1",
        "signed",
        "signed by https://github.com/acme/app/.github/workflows/r.yaml@refs/heads/main",
    )];
    let signer = build(&rows)[0].images[0].signer.clone().unwrap();
    assert_eq!(signer.identity_short, "acme/app");
    assert!(signer.issuer_badge.is_empty());
    assert!(signer.issuer_full.is_none());
}

#[test]
fn invalid_posture_maps_and_would_block() {
    let rows = vec![observed(
        "docker.io/library/storefront:latest",
        "invalid-signature",
        "signature present but does not verify (untrusted/tampered chain)",
    )];
    let row = &build(&rows)[0].images[0];
    assert_eq!(row.posture, SigningPosture::Invalid);
    assert!(
        row.signer.is_none(),
        "an invalid signature has no trusted signer"
    );
    assert!(
        !row.posture.would_admit(),
        "invalid would block if enforced"
    );
    assert!(
        !row.detail.is_empty(),
        "the invalid prose is carried for the expand panel"
    );
}

#[test]
fn not_signed_posture_maps_is_calm_and_would_block() {
    let rows = vec![observed("docker.io/library/postgres:16", "not-signed", "")];
    let row = &build(&rows)[0].images[0];
    assert_eq!(row.posture, SigningPosture::NotSigned);
    assert!(row.signer.is_none());
    assert!(
        !row.posture.would_admit(),
        "not signed would block if enforced"
    );
    assert!(row.detail.is_empty(), "not-signed needs no prose");
}

#[test]
fn checking_is_transient_never_a_resting_clean() {
    let rows = vec![observed(
        "registry.k8s.io/pause:3.9",
        "checking",
        "signing posture not yet known (registry/log unreachable)",
    )];
    let row = &build(&rows)[0].images[0];
    assert_eq!(row.posture, SigningPosture::Checking);
    assert!(
        !row.posture.would_admit(),
        "an unverifiable posture is fail-closed (would block), never admitted"
    );
}

#[test]
fn an_unknown_status_word_reads_as_checking_never_a_false_clean() {
    // Defensive: any word that isn't one of the three resting states is the transient checking,
    // never a fabricated resting posture (and never n/a).
    let rows = vec![observed("ghcr.io/acme/mystery:1", "n/a", "")];
    assert_eq!(build(&rows)[0].images[0].posture, SigningPosture::Checking);
}

#[test]
fn only_signed_would_admit() {
    assert!(SigningPosture::Signed.would_admit());
    assert!(!SigningPosture::Invalid.would_admit());
    assert!(!SigningPosture::NotSigned.would_admit());
    assert!(!SigningPosture::Checking.would_admit());
}

#[test]
fn images_are_grouped_under_their_repo() {
    let rows = vec![
        observed("ghcr.io/acme/app@sha256:aa", "not-signed", ""),
        observed("ghcr.io/acme/app@sha256:bb", "signed", "signed by x via y"),
        observed("docker.io/library/postgres:16", "not-signed", ""),
    ];
    let groups = build(&rows);
    assert_eq!(groups.len(), 2, "two distinct repos");
    let acme = groups
        .iter()
        .find(|g| g.repo == "ghcr.io/acme/app")
        .unwrap();
    assert_eq!(acme.images.len(), 2, "both digests fold under the one repo");
    let pg = groups
        .iter()
        .find(|g| g.repo == "docker.io/library/postgres")
        .unwrap();
    assert_eq!(pg.images.len(), 1);
}

#[test]
fn digest_and_tag_and_port_refs_split_correctly() {
    // digest form: repo@sha256:… → the digest is the in-row label.
    let digest = build(&[observed("ghcr.io/acme/app@sha256:abc", "not-signed", "")]);
    assert_eq!(digest[0].repo, "ghcr.io/acme/app");
    assert_eq!(digest[0].images[0].label, "sha256:abc");
    // tag form: repo:tag.
    let tag = build(&[observed("docker.io/library/postgres:16", "not-signed", "")]);
    assert_eq!(tag[0].repo, "docker.io/library/postgres");
    assert_eq!(tag[0].images[0].label, "16");
    // a registry PORT is not a tag — the repo keeps its `:5000`.
    let port = build(&[observed("registry:5000/team/app:2", "not-signed", "")]);
    assert_eq!(port[0].repo, "registry:5000/team/app");
    assert_eq!(port[0].images[0].label, "2");
    // a bare ref with no tag/digest falls back to the full ref as the label.
    let bare = build(&[observed("busybox", "not-signed", "")]);
    assert_eq!(bare[0].repo, "busybox");
    assert_eq!(bare[0].images[0].label, "busybox");
}

#[test]
fn webhook_decision_rows_are_not_in_the_inventory() {
    let rows = vec![
        workload_decision("Pod/web", "ghcr.io/acme/app:1"),
        observed("ghcr.io/acme/app:1", "signed", "signed by x via y"),
    ];
    let groups = build(&rows);
    assert_eq!(
        groups.len(),
        1,
        "only the Image/<ref> observation row is inventoried"
    );
    assert_eq!(groups[0].images.len(), 1);
}

#[test]
fn empty_input_is_an_empty_inventory() {
    assert!(build(&[]).is_empty());
}

#[test]
fn dedup_count_is_carried() {
    let mut r = observed("ghcr.io/acme/app:1", "not-signed", "");
    r.count = 7;
    assert_eq!(build(&[r])[0].images[0].count, 7);
}
