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
fn key_based_posture_maps_calm_carries_no_signer_and_would_block() {
    // JEF-276 reproducer 1 (cert-manager): a key-based signature is CALM (never invalid), carries no
    // trusted signer, and — lacking an identity a gate can vouch for — would block if enforced.
    let rows = vec![observed(
        "quay.io/jetstack/cert-manager-cainjector:v1.20.3",
        "signed-key-based",
        "signed with a key-based cosign signature (verified transparency-log inclusion, no Fulcio \
         identity) \u{2014} signer is opaque to keyless verification",
    )];
    let row = &build(&rows)[0].images[0];
    assert_eq!(row.posture, SigningPosture::SignedKeyBased);
    assert_ne!(
        row.posture,
        SigningPosture::Invalid,
        "a real key-based signature must not be the loud invalid channel"
    );
    assert!(row.signer.is_none(), "key-based is signed-but-opaque");
    assert!(
        !row.posture.would_admit(),
        "no vouchable identity → would block"
    );
    assert!(
        !row.detail.is_empty(),
        "the key-based prose rides the expand panel"
    );
}

#[test]
fn unverifiable_posture_maps_calm_distinct_from_invalid() {
    // JEF-276 reproducer 2 (curl trust-root variance): honest "couldn't verify here", calm-ish, and
    // lexically + structurally distinct from the loud invalid.
    let rows = vec![observed(
        "docker.io/curlimages/curl:latest",
        "unverifiable",
        "signature present but could not be verified against our trust root",
    )];
    let row = &build(&rows)[0].images[0];
    assert_eq!(row.posture, SigningPosture::Unverifiable);
    assert_ne!(row.posture, SigningPosture::Invalid);
    assert!(row.signer.is_none());
    assert!(!row.posture.would_admit());
}

#[test]
fn only_signed_would_admit() {
    assert!(SigningPosture::Signed.would_admit());
    assert!(!SigningPosture::SignedKeyBased.would_admit());
    assert!(!SigningPosture::Unverifiable.would_admit());
    assert!(!SigningPosture::Invalid.would_admit());
    assert!(!SigningPosture::NotSigned.would_admit());
    assert!(!SigningPosture::Checking.would_admit());
}

#[test]
fn posture_tokens_glyphs_and_words_are_distinct_per_state() {
    // Meaning never rides on colour alone, and the loud invalid must read apart from the calm
    // states in token, glyph, AND word (greyscale-safe).
    use std::collections::HashSet;
    let all = [
        SigningPosture::Signed,
        SigningPosture::SignedKeyBased,
        SigningPosture::Unverifiable,
        SigningPosture::Invalid,
        SigningPosture::NotSigned,
        SigningPosture::Checking,
    ];
    let tokens: HashSet<_> = all.iter().map(|p| p.token()).collect();
    let glyphs: HashSet<_> = all.iter().map(|p| p.glyph()).collect();
    let words: HashSet<_> = all.iter().map(|p| p.word()).collect();
    assert_eq!(
        tokens.len(),
        all.len(),
        "every posture has a distinct token"
    );
    assert_eq!(
        glyphs.len(),
        all.len(),
        "every posture has a distinct glyph"
    );
    assert_eq!(words.len(), all.len(), "every posture has a distinct word");
    // The CSS token is fixed `[a-z]` only (safe attribute value, never untrusted text).
    for p in all {
        assert!(p.token().chars().all(|c| c.is_ascii_lowercase()));
    }
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
fn image_rows_carry_a_prefixed_dom_id() {
    let row = &build(&[observed("ghcr.io/acme/app:1", "not-signed", "")])[0].images[0];
    assert!(
        row.dom_id.starts_with("si-"),
        "an image row's id is prefixed to keep its namespace apart from regressions"
    );
    assert!(
        row.dom_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-'),
        "the id is [a-z0-9-] only — a safe id/data-*/aria-controls value"
    );
}

#[test]
fn slug_colliding_images_still_get_distinct_dom_ids() {
    // Two refs that SLUGIFY to the same string (`ghcr-io-a-b-1`) must not share an id — otherwise
    // the whole-row toggle would open the wrong adjacent detail row (the finding_id collision bug).
    // The short hash of the FULL ref is what separates them.
    let rows = vec![
        observed("ghcr.io/a/b:1", "not-signed", ""),
        observed("ghcr.io/a/b-1", "not-signed", ""),
    ];
    let ids: Vec<String> = build(&rows)
        .iter()
        .flat_map(|g| g.images.iter().map(|i| i.dom_id.clone()))
        .collect();
    assert_eq!(ids.len(), 2, "both images are inventoried");
    assert_ne!(ids[0], ids[1], "slug-colliding images get distinct ids");
}

#[test]
fn a_regression_dom_id_never_collides_with_a_bare_image_ref() {
    // A bare image ref can equal its repo string; distinct prefixes (si- vs sr-) keep the image
    // row's id and the repo's regression-row id apart.
    let rows = vec![
        observed("ghcr.io/acme/app", "not-signed", ""),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
    ];
    let g = &build(&rows)[0];
    let image_id = &g.images[0].dom_id;
    let reg_id = &g.regression.as_ref().unwrap().dom_id;
    assert!(image_id.starts_with("si-"));
    assert!(reg_id.starts_with("sr-"));
    assert_ne!(image_id, reg_id, "the two rows never share an id");
}

#[test]
fn images_within_a_group_sort_loud_first() {
    // invalid (loudest) → not signed → checking → signed (calmest, sinks to the bottom).
    let rows = vec![
        observed("ghcr.io/acme/app@sha256:aa", "signed", "signed by x via y"),
        observed("ghcr.io/acme/app@sha256:bb", "checking", "unreachable"),
        observed("ghcr.io/acme/app@sha256:cc", "not-signed", ""),
        observed(
            "ghcr.io/acme/app@sha256:dd",
            "invalid-signature",
            "tampered",
        ),
    ];
    let g = &build(&rows)[0];
    let order: Vec<SigningPosture> = g.images.iter().map(|i| i.posture).collect();
    assert_eq!(
        order,
        vec![
            SigningPosture::Invalid,
            SigningPosture::NotSigned,
            SigningPosture::Checking,
            SigningPosture::Signed,
        ],
        "images sort most-attention-worthy first"
    );
}

#[test]
fn groups_sort_loud_first_and_a_regression_floats_to_the_top() {
    let rows = vec![
        observed("ghcr.io/clean/app:1", "signed", "signed by x via y"),
        observed("docker.io/lib/plain:1", "not-signed", ""),
        observed("docker.io/lib/bad:1", "invalid-signature", "tampered"),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
    ];
    let groups = build(&rows);
    // A standing regression is the loudest — it sorts above every clean/plain/invalid repo.
    assert!(
        groups[0].regression.is_some(),
        "the regressed repo floats to the top"
    );
    // The invalid-image repo outranks the plain and the signed ones.
    let invalid_pos = groups
        .iter()
        .position(|g| {
            g.images
                .iter()
                .any(|i| i.posture == SigningPosture::Invalid)
        })
        .unwrap();
    let signed_pos = groups
        .iter()
        .position(|g| g.images.iter().any(|i| i.posture == SigningPosture::Signed))
        .unwrap();
    assert!(invalid_pos < signed_pos, "invalid outranks signed");
    // The all-signed repo sinks to the bottom.
    assert_eq!(
        groups.last().unwrap().images[0].posture,
        SigningPosture::Signed,
        "the calmest (all-signed) repo sits last"
    );
}

#[test]
fn dedup_count_is_carried() {
    let mut r = observed("ghcr.io/acme/app:1", "not-signed", "");
    r.count = 7;
    assert_eq!(build(&[r])[0].images[0].count, 7);
}

// ---- JEF-264 signing-regression rows -----------------------------------------------------------

/// A signing-regression finding row exactly as `engine::signing_sweep::regression_record` writes it:
/// `SigningRegression/<repo>` subject, the drift token in `signature`, the before→after prose in
/// `reason`, decision `allow` (audit-only).
fn regression(repo: &str, image: &str, signature: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "signing-regression",
        "allow",
        format!("SigningRegression/{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

#[test]
fn unsigned_regression_parses_before_and_after() {
    let rows = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-unsigned-established",
        "now not signed (was signed) | before: https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
    )];
    let group = &build(&rows)[0];
    let reg = group
        .regression
        .as_ref()
        .expect("the repo carries a regression");
    assert_eq!(reg.kind, RegressionKind::Unsigned);
    assert!(
        reg.established,
        "an established-baseline regression is the strong signal"
    );
    assert_eq!(
        reg.before_identities,
        vec!["https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1".to_string()],
        "the before signer is carried in full"
    );
    assert!(reg.after_identity.is_none(), "unsigned has no after signer");
    assert_eq!(reg.image, "ghcr.io/acme/app:2");
}

#[test]
fn identity_change_regression_parses_both_identities_in_full() {
    let rows = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:3",
        "regression-identity-established",
        "signed by https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main via \
         https://token.actions.githubusercontent.com | before: \
         https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
    )];
    let reg = build(&rows)[0].regression.clone().unwrap();
    assert_eq!(reg.kind, RegressionKind::IdentityChange);
    assert_eq!(
        reg.after_identity.as_deref(),
        Some("https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main"),
        "the NEW signer is carried in full"
    );
    assert_eq!(
        reg.after_issuer.as_deref(),
        Some("https://token.actions.githubusercontent.com")
    );
    assert_eq!(
        reg.before_identities,
        vec!["https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1".to_string()],
        "the OLD signer is carried in full alongside the new one"
    );
}

#[test]
fn cold_regression_is_flagged_weak() {
    let rows = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-invalid-cold",
        "now invalid signature (was signed) | before: releng@acme.example",
    )];
    let reg = build(&rows)[0].regression.clone().unwrap();
    assert_eq!(reg.kind, RegressionKind::Invalid);
    assert!(!reg.established, "a cold-baseline regression reads as weak");
}

#[test]
fn regression_attaches_to_its_repo_group_alongside_the_image_rows() {
    let rows = vec![
        observed("ghcr.io/acme/app:2", "not-signed", ""),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-established",
            "now not signed (was signed) | before: releng@acme.example",
        ),
    ];
    let groups = build(&rows);
    assert_eq!(
        groups.len(),
        1,
        "one repo group carries both the image row and the banner"
    );
    assert_eq!(groups[0].images.len(), 1);
    assert!(groups[0].regression.is_some());
}

#[test]
fn regression_for_an_aged_out_image_still_surfaces_its_own_group() {
    // No observation row for the repo (the bad digest aged out of the window), only the regression.
    let rows = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-unsigned-established",
        "now not signed (was signed) | before: releng@acme.example",
    )];
    let groups = build(&rows);
    assert_eq!(groups.len(), 1);
    assert!(
        groups[0].images.is_empty(),
        "no image rows, but the regression still shows"
    );
    assert!(groups[0].regression.is_some());
}

#[test]
fn regression_rows_are_inventory_rows_not_decisions() {
    let r = regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-unsigned-established",
        "now not signed (was signed) | before: releng@acme.example",
    );
    assert!(
        is_inventory_row(&r),
        "a regression row is partitioned out of the webhook decision tallies"
    );
}

#[test]
fn counts_split_established_breach_from_cold_uncertain() {
    let rows = vec![
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
        regression(
            "ghcr.io/acme/other",
            "ghcr.io/acme/other:2",
            "regression-identity-cold",
            "signed by b via c | before: a",
        ),
    ];
    let (established, cold) = counts(&rows);
    assert_eq!(
        established, 1,
        "the established regression counts toward breach"
    );
    assert_eq!(cold, 1, "the cold regression counts toward uncertain");
}

#[test]
fn counts_are_per_repo_not_per_row() {
    // Two regression rows for the SAME repo collapse to one standing regression (newest wins).
    let rows = vec![
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:3",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-invalid-established",
            "now invalid signature (was signed) | before: a",
        ),
    ];
    assert_eq!(counts(&rows), (1, 0), "one repo, one standing regression");
    let groups = build(&rows);
    assert_eq!(groups.len(), 1);
    // Newest-first: the first row (the unsigned one) wins the banner.
    assert_eq!(
        groups[0].regression.as_ref().unwrap().kind,
        RegressionKind::Unsigned
    );
}

// ---- JEF-266: baseline strength badge + registry↔log divergence surfacing ---------------------

/// A per-repo baseline-strength row exactly as `engine::signing_baseline_strength` records it.
fn strength(repo: &str, word: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "signing-strength",
        "allow",
        format!("SigningStrength/{repo}"),
        repo,
        word,
        "",
        "",
        "first_seen:0",
    )
}

#[test]
fn log_corroborated_strength_surfaces_on_the_repo_group() {
    let rows = vec![
        observed("ghcr.io/acme/app@sha256:abc", "signed", "signed by x"),
        strength("ghcr.io/acme/app", "log-corroborated"),
    ];
    let groups = build(&rows);
    assert_eq!(groups[0].strength, RepoStrength::LogCorroborated);
    assert_eq!(groups[0].strength.word(), "log-corroborated");
}

#[test]
fn local_only_strength_is_the_honest_weaker_default() {
    let rows = vec![
        observed("ghcr.io/acme/app@sha256:abc", "signed", "signed by x"),
        strength("ghcr.io/acme/app", "local-only"),
    ];
    let groups = build(&rows);
    assert_eq!(groups[0].strength, RepoStrength::LocalOnly);
    assert_eq!(groups[0].strength.word(), "new baseline (local only)");
}

#[test]
fn a_repo_without_a_strength_row_has_no_badge() {
    let rows = vec![observed(
        "ghcr.io/acme/app@sha256:abc",
        "signed",
        "signed by x",
    )];
    assert_eq!(build(&rows)[0].strength, RepoStrength::Unknown);
}

#[test]
fn strength_rows_are_partitioned_out_of_the_inventory_images() {
    // A strength row must not become a phantom image row under the repo.
    let rows = vec![
        observed("ghcr.io/acme/app@sha256:abc", "signed", "signed by x"),
        strength("ghcr.io/acme/app", "log-corroborated"),
    ];
    let groups = build(&rows);
    assert_eq!(
        groups[0].images.len(),
        1,
        "only the observed image is a row"
    );
}

#[test]
fn divergence_findings_render_through_the_regression_channel() {
    // Both directions ride the SigningRegression channel with a distinct divergence kind + reason.
    let registry_dir = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-divergence-registry-established",
        "registry\u{2194}log divergence: the registry serves a signature the public transparency \
         log has no entry for | before: a",
    )];
    let groups = build(&registry_dir);
    assert_eq!(
        groups[0].regression.as_ref().unwrap().kind,
        RegressionKind::DivergenceRegistrySigned
    );

    let log_dir = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-divergence-log-cold",
        "registry\u{2194}log divergence: the transparency log records a signature the registry now \
         serves unsigned | before: a",
    )];
    let groups = build(&log_dir);
    let reg = groups[0].regression.as_ref().unwrap();
    assert_eq!(reg.kind, RegressionKind::DivergenceLogSigned);
    assert!(
        !reg.established,
        "the cold-strength divergence is a weak lead"
    );
}

#[test]
fn signing_downgrade_findings_render_through_the_regression_channel() {
    // JEF-280: a key-based / unverifiable downgrade rides the SigningRegression channel with a
    // distinct downgrade kind — the view parses the self-describing signature token back.
    let key_based = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-downgrade-key-based-established",
        "now key-based signature, no keyless identity (was keyless-verified) | before: a",
    )];
    let groups = build(&key_based);
    let reg = groups[0].regression.as_ref().unwrap();
    assert_eq!(reg.kind, RegressionKind::DowngradeKeyBased);
    assert!(reg.established, "an established-baseline downgrade is loud");

    let unverifiable = vec![regression(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-downgrade-unverifiable-cold",
        "now unverifiable against our trust root (was keyless-verified) | before: a",
    )];
    let groups = build(&unverifiable);
    let reg = groups[0].regression.as_ref().unwrap();
    assert_eq!(reg.kind, RegressionKind::DowngradeUnverifiable);
    assert!(!reg.established, "a cold-baseline downgrade is a weak lead");
}

// ---- Build-provenance axis (JEF-275) --------------------------------------------------------

/// A provenance observation row, as `engine::provenance_sweep` records it.
fn provenance_observed(image: &str, status: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "build-provenance",
        "allow",
        format!("Provenance/{image}"),
        image,
        status,
        "",
        "",
        reason,
    )
}

/// A provenance-change finding row, as `engine::provenance_sweep::change_record` records it.
fn provenance_change(
    repo: &str,
    image: &str,
    signature: &str,
    reason: &str,
) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "provenance-change",
        "allow",
        format!("ProvenanceChange/{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

#[test]
fn verified_provenance_joins_onto_its_image_row() {
    let rows = vec![
        observed("ghcr.io/acme/app:1", "signed", "signed by x"),
        provenance_observed(
            "ghcr.io/acme/app:1",
            "provenance-verified",
            "built by https://github.com/acme/app/.github/workflows/r.yml@refs/heads/main from github.com/acme/app",
        ),
    ];
    let groups = build(&rows);
    let img = &groups[0].images[0];
    assert_eq!(img.provenance, ProvenancePosture::Verified);
    let info = img.provenance_info.as_ref().expect("verified ⇒ info");
    assert_eq!(info.source_short, "acme/app");
    assert_eq!(info.builder_short, "acme/app");
    assert_eq!(info.source_full, "github.com/acme/app");
}

#[test]
fn image_with_no_provenance_row_defaults_to_absent_never_na() {
    let rows = vec![observed("ghcr.io/acme/app:1", "signed", "signed by x")];
    let groups = build(&rows);
    assert_eq!(groups[0].images[0].provenance, ProvenancePosture::Absent);
    assert!(groups[0].images[0].provenance_info.is_none());
}

#[test]
fn absent_provenance_row_is_calm_absent() {
    let rows = vec![
        observed("ghcr.io/acme/app:1", "signed", "signed by x"),
        provenance_observed("ghcr.io/acme/app:1", "no-provenance", ""),
    ];
    let groups = build(&rows);
    assert_eq!(groups[0].images[0].provenance, ProvenancePosture::Absent);
}

#[test]
fn provenance_change_becomes_the_repo_banner() {
    let rows = vec![
        observed("ghcr.io/acme/app:2", "signed", "signed by x"),
        provenance_change(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "provenance-change-established",
            "built by https://github.com/evil/app/.github/workflows/pwn.yml@refs/heads/main from github.com/evil/app | before: https://github.com/acme/app/.github/workflows/r.yml@refs/heads/main",
        ),
    ];
    let groups = build(&rows);
    let change = groups[0]
        .provenance_change
        .as_ref()
        .expect("provenance change banner");
    assert!(change.established);
    assert_eq!(
        change.after_builder,
        "https://github.com/evil/app/.github/workflows/pwn.yml@refs/heads/main"
    );
    assert_eq!(change.after_source, "github.com/evil/app");
    assert_eq!(
        change.before_builders,
        vec!["https://github.com/acme/app/.github/workflows/r.yml@refs/heads/main".to_string()]
    );
}

#[test]
fn provenance_change_floats_the_group_to_the_top() {
    // A clean repo and a provenance-drifted repo: the drifted one must sort first (loud-first).
    let rows = vec![
        observed("ghcr.io/clean/app:1", "signed", "signed by x"),
        observed("ghcr.io/drift/app:1", "signed", "signed by x"),
        provenance_change(
            "ghcr.io/drift/app",
            "ghcr.io/drift/app:1",
            "provenance-change-established",
            "built by b from s | before: a",
        ),
    ];
    let groups = build(&rows);
    assert_eq!(
        groups[0].repo, "ghcr.io/drift/app",
        "drift floats to the top"
    );
}

#[test]
fn provenance_rows_are_inventory_not_decision_rows() {
    assert!(is_inventory_row(&provenance_observed(
        "ghcr.io/acme/app:1",
        "no-provenance",
        ""
    )));
    assert!(is_inventory_row(&provenance_change(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:1",
        "provenance-change-cold",
        "built by b from s | before: a"
    )));
}
