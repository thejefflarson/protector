//! Tests for the baseline-relative "if enforced" continuity verdict (JEF-297, ADR-0020): the
//! per-image would-admit / would-block / uncertain column is driven by whether a signing-regression
//! stands for that image (the recorded drift verdict a continuity gate enforces), NOT by the raw
//! posture. A calm, consistent posture admits; a genuine regression against an established baseline
//! blocks; a cold-baseline regression reads uncertain; a genuinely-invalid signature blocks
//! outright. Split from `tests.rs` to keep both files under the repo's 1,000-line cap (CLAUDE.md).

use super::*;
use crate::engine::policy_log::PolicyDecisionRecord;

/// A signing-sweep observation row (`Image/<ref>` subject, posture in `signature`, signer prose in
/// `reason`), exactly as `engine::signing_sweep` records it.
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

/// A signing-regression finding row (`SigningRegression/<repo>` subject, the drift token in
/// `signature`, before→after prose in `reason`), as `engine::signing_sweep::regression_record` writes
/// it — the recorded drift verdict this column reads.
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
fn an_established_regression_makes_the_regressed_image_would_block() {
    // signed→unsigned on an ESTABLISHED baseline: the recorded regression drives the regressed
    // image's continuity verdict to would-block (block == regression, matching JEF-265 enforce).
    let rows = vec![
        observed("ghcr.io/acme/app:2", "not-signed", ""),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
    ];
    let img = &build(&rows)[0].images[0];
    assert_eq!(img.posture, SigningPosture::NotSigned);
    assert_eq!(
        img.enforcement,
        SigningEnforcement::WouldBlock,
        "signed\u{2192}unsigned on an established repo would block"
    );
}

#[test]
fn a_downgrade_on_an_established_keyless_repo_would_block() {
    // JEF-280 downgrade: an established-keyless repo now serving key-based is a regression — the
    // downgraded image would block, even though the raw posture (key-based) is individually calm.
    let rows = vec![
        observed("ghcr.io/acme/app:2", "signed-key-based", "key-based cosign"),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-downgrade-key-based-established",
            "now key-based signature, no keyless identity (was keyless-verified) | before: a",
        ),
    ];
    let img = &build(&rows)[0].images[0];
    assert_eq!(img.posture, SigningPosture::SignedKeyBased);
    assert_eq!(img.enforcement, SigningEnforcement::WouldBlock);
}

#[test]
fn an_identity_change_on_an_established_repo_would_block() {
    let rows = vec![
        observed(
            "ghcr.io/acme/app:3",
            "signed",
            "signed by https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main via \
             https://token.actions.githubusercontent.com",
        ),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:3",
            "regression-identity-established",
            "signed by https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main via \
             https://token.actions.githubusercontent.com | before: \
             https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
        ),
    ];
    let img = &build(&rows)[0].images[0];
    assert_eq!(img.posture, SigningPosture::Signed);
    assert_eq!(
        img.enforcement,
        SigningEnforcement::WouldBlock,
        "a new-signer identity change on an established repo would block"
    );
}

#[test]
fn a_cold_baseline_regression_reads_uncertain_not_blocked() {
    // JEF-297 honesty invariant: a regression against a COLD/freshly-learned baseline is a weak lead
    // (JEF-280 cold=uncertain) — non-green, but never a hard block.
    let rows = vec![
        observed("ghcr.io/acme/app:2", "not-signed", ""),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-cold",
            "now not signed (was signed) | before: a",
        ),
    ];
    let img = &build(&rows)[0].images[0];
    assert_eq!(
        img.enforcement,
        SigningEnforcement::Uncertain,
        "a cold-baseline regression is uncertain (non-green), not would-block"
    );
}

#[test]
fn only_the_regressed_image_blocks_calm_siblings_still_admit() {
    // A repo can carry a regression on one digest while its other, continuous digests admit — the
    // per-image lookup keys the verdict to the exact regressed image (not the whole repo).
    let rows = vec![
        observed("ghcr.io/acme/app:2", "not-signed", ""),
        observed(
            "ghcr.io/acme/app:1",
            "signed",
            "signed by https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
        ),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-unsigned-established",
            "now not signed (was signed) | before: a",
        ),
    ];
    let group = &build(&rows)[0];
    let bad = group
        .images
        .iter()
        .find(|i| i.image == "ghcr.io/acme/app:2")
        .unwrap();
    let good = group
        .images
        .iter()
        .find(|i| i.image == "ghcr.io/acme/app:1")
        .unwrap();
    assert_eq!(bad.enforcement, SigningEnforcement::WouldBlock);
    assert_eq!(
        good.enforcement,
        SigningEnforcement::WouldAdmit,
        "the calm, continuous sibling still admits"
    );
}

#[test]
fn invalid_blocks_even_against_a_cold_baseline_no_evasion() {
    // SECURITY: a genuinely-invalid signature is the loud channel and blocks outright — an attacker
    // cannot dodge the would-block by keeping the repo's baseline cold (invalid short-circuits the
    // cold=uncertain path).
    let rows = vec![
        observed("ghcr.io/acme/app:2", "invalid-signature", "tampered chain"),
        regression(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "regression-invalid-cold",
            "now invalid signature (was signed) | before: a",
        ),
    ];
    let groups = build(&rows);
    let img = groups[0]
        .images
        .iter()
        .find(|i| i.image == "ghcr.io/acme/app:2")
        .unwrap();
    assert_eq!(img.enforcement, SigningEnforcement::WouldBlock);
}

#[test]
fn enforcement_verdict_covers_the_continuity_matrix() {
    // The pure verdict function (JEF-297): invalid blocks outright; otherwise the recorded drift
    // verdict drives it — established regression blocks, cold regression is uncertain, no regression
    // admits.
    use SigningEnforcement::*;
    // invalid short-circuits to block regardless of the drift verdict.
    assert_eq!(
        SigningEnforcement::for_image(SigningPosture::Invalid, None),
        WouldBlock
    );
    assert_eq!(
        SigningEnforcement::for_image(SigningPosture::Invalid, Some(false)),
        WouldBlock
    );
    // every calm posture with no regression admits (the homegrown-fleet fix).
    for p in [
        SigningPosture::Signed,
        SigningPosture::SignedKeyBased,
        SigningPosture::Unverifiable,
        SigningPosture::NotSigned,
        SigningPosture::Checking,
    ] {
        assert_eq!(SigningEnforcement::for_image(p, None), WouldAdmit);
        assert_eq!(SigningEnforcement::for_image(p, Some(true)), WouldBlock);
        assert_eq!(SigningEnforcement::for_image(p, Some(false)), Uncertain);
    }
}

/// An "exception accepted" finding row (`SigningException/<repo>` subject, the `exception-<kind>-
/// <strength>` token), as `engine::signing_sweep::exception_record` writes it.
fn exception(repo: &str, image: &str, signature: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "signing-exception",
        "allow",
        format!("SigningException/{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

#[test]
fn an_accepted_exception_renders_calm_distinct_and_uncounted() {
    // JEF-265 render: a regression the operator opted out of shows the DISTINCT "exception accepted"
    // enforcement chip (never would-admit/would-block/green), carries a visible calm banner, and does
    // NOT count toward breach.
    let rows = vec![
        exception(
            "ghcr.io/acme/app",
            "ghcr.io/acme/app:2",
            "exception-unsigned-established",
            "now not signed (was signed) | before: https://github.com/acme/app/.github/workflows/r.yml@refs/tags/v1",
        ),
        observed("ghcr.io/acme/app:2", "not-signed", ""),
    ];
    let groups = build(&rows);
    let group = groups
        .iter()
        .find(|g| g.repo == "ghcr.io/acme/app")
        .expect("the excepted repo group is present (visible)");
    assert!(group.exception.is_some(), "a calm exception banner stands");
    assert!(
        group.regression.is_none(),
        "an accepted exception is NOT the loud regression channel"
    );
    let img = group
        .images
        .iter()
        .find(|i| i.image == "ghcr.io/acme/app:2")
        .expect("the excepted image row is visible");
    assert_eq!(
        img.enforcement,
        SigningEnforcement::ExceptionAccepted,
        "the image's if-enforced chip is the distinct exception-accepted state"
    );
    assert_eq!(
        img.enforcement.word(),
        "exception accepted",
        "the label is a distinct word, never 'signed'/'would admit'"
    );
    // Not counted toward breach (it isn't a regression row).
    assert_eq!(
        counts(&rows),
        (0, 0),
        "an accepted exception never counts toward breach"
    );
}
