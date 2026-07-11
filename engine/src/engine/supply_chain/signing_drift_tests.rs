//! Pure, deterministic tests for the signing-drift classifier (JEF-264). Every case is a total
//! function of `(baseline, posture)` — no clock, no I/O — so the whole rule table is exercised
//! here without reaching a registry, a journal, or a sweep.

use std::collections::BTreeSet;

use super::*;
use crate::engine::state::SigningBaseline;
use crate::policies::signature::{PostureRank, Signer};

/// A baseline that has signed under `identities`, with the given `established` maturity. The
/// timestamps are irrelevant to the classifier (it reads `established`, never the clock), so they
/// are fixed. `rank` is [`PostureRank::Keyless`] — a keyless baseline, matching the store, which
/// only ever learns from a keyless `Signed` posture.
fn baseline(identities: &[&str], established: bool) -> SigningBaseline {
    SigningBaseline {
        identities: identities.iter().map(|s| s.to_string()).collect(),
        issuers: BTreeSet::new(),
        first_seen_ms: 0,
        established,
        log_corroborated: false,
        rank: PostureRank::Keyless,
        provenance_sources: BTreeSet::new(),
        provenance_builders: BTreeSet::new(),
        last_updated_ms: 0,
    }
}

fn signed(identity: &str) -> SigningPosture {
    SigningPosture::Signed(Signer {
        identity: identity.to_string(),
        issuer: Some("https://token.actions.githubusercontent.com".to_string()),
    })
}

const CI: &str = "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1";
const ATTACKER: &str = "https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main";

#[test]
fn signed_to_unsigned_on_established_repo_is_a_regression() {
    let b = baseline(&[CI], true);
    let drift = classify(Some(&b), &SigningPosture::NotSigned);
    assert_eq!(
        drift,
        SigningDrift::Regression {
            kind: RegressionKind::Unsigned,
            established: true,
        }
    );
    assert!(drift.is_regression());
}

#[test]
fn signed_to_invalid_on_established_repo_is_a_regression() {
    let b = baseline(&[CI], true);
    let drift = classify(Some(&b), &SigningPosture::InvalidSignature);
    assert_eq!(
        drift,
        SigningDrift::Regression {
            kind: RegressionKind::Invalid,
            established: true,
        }
    );
}

#[test]
fn new_signer_on_established_repo_is_a_distinct_identity_change_regression() {
    let b = baseline(&[CI], true);
    let drift = classify(Some(&b), &signed(ATTACKER));
    assert_eq!(
        drift,
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange {
                new_identity: ATTACKER.to_string(),
                new_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            },
            established: true,
        },
        "a new signer is a DISTINCT regression from unsigned/invalid, carrying the new identity"
    );
}

#[test]
fn known_identity_new_digest_is_continuous_no_false_positive() {
    // The normal-redeploy rule: a new digest under a known repo, signed by a KNOWN identity, must
    // never surface a finding.
    let b = baseline(&[CI], true);
    let drift = classify(Some(&b), &signed(CI));
    assert_eq!(drift, SigningDrift::Continuous);
    assert!(!drift.is_regression());
}

#[test]
fn one_of_several_known_identities_is_continuous() {
    // A repo with multiple learned signers stays continuous when signed by any one of them.
    let b = baseline(&[CI, ATTACKER], true);
    assert_eq!(classify(Some(&b), &signed(CI)), SigningDrift::Continuous);
    assert_eq!(
        classify(Some(&b), &signed(ATTACKER)),
        SigningDrift::Continuous
    );
}

// ---- JEF-325: tag-agnostic continuity — a new release TAG is not a new signer -------------------

const WF: &str = "https://github.com/thejefflarson/protector/.github/workflows/agent.yml";

#[test]
fn a_new_release_tag_of_the_same_workflow_is_continuous_not_an_identity_change() {
    // THE BUG: two SANs differing ONLY in the release-tag version (same repo/workflow/ref-type) are
    // the SAME continuity identity ⇒ Continuous, never a regression, never a block.
    let b = baseline(&[&format!("{WF}@refs/tags/v0.3.79")], true);
    let drift = classify(Some(&b), &signed(&format!("{WF}@refs/tags/v0.3.80")));
    assert_eq!(
        drift,
        SigningDrift::Continuous,
        "a version bump under the same workflow must not false-positive"
    );
    assert!(!drift.is_regression());
}

#[test]
fn a_new_release_tag_matches_a_canonical_baseline_identity() {
    // The baseline stores the canonical (`@refs/tags/*`) form; a concrete version tag still matches.
    let b = baseline(&[&format!("{WF}@refs/tags/*")], true);
    assert_eq!(
        classify(Some(&b), &signed(&format!("{WF}@refs/tags/v9.9.9"))),
        SigningDrift::Continuous
    );
}

#[test]
fn a_different_workflow_under_the_same_repo_is_still_an_identity_change() {
    // SECURITY: only the tag VALUE is wildcarded — the workflow PATH still discriminates.
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let attacker =
        "https://github.com/thejefflarson/protector/.github/workflows/pwn.yml@refs/tags/v1";
    let drift = classify(Some(&b), &signed(attacker));
    assert_eq!(
        drift,
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange {
                new_identity: attacker.to_string(),
                new_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            },
            established: true,
        },
        "a different workflow is a new signer, even at the same tag"
    );
    assert!(drift.would_block(&signed(attacker)), "and it would block");
}

#[test]
fn a_fork_or_different_repo_is_still_an_identity_change() {
    // SECURITY: the org/repo still discriminates — an attacker's fork is a new identity.
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let fork = "https://github.com/evil/protector/.github/workflows/agent.yml@refs/tags/v1";
    assert!(matches!(
        classify(Some(&b), &signed(fork)),
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange { .. },
            established: true,
        }
    ));
}

#[test]
fn a_branch_ref_is_still_an_identity_change_ref_type_is_never_wildcarded() {
    // SECURITY: ref TYPE stays distinct — a `refs/heads/main` build is NOT a release-tag identity.
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let branch = format!("{WF}@refs/heads/main");
    let drift = classify(Some(&b), &signed(&branch));
    assert!(matches!(
        drift,
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange { .. },
            established: true,
        }
    ));
    assert!(drift.would_block(&signed(&branch)));
}

#[test]
fn a_pull_request_ref_is_still_an_identity_change() {
    // SECURITY: a PR ref is a distinct ref type — not a trusted release identity.
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let pr = format!("{WF}@refs/pull/42/merge");
    assert!(matches!(
        classify(Some(&b), &signed(&pr)),
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange { .. },
            established: true,
        }
    ));
}

#[test]
fn a_wholly_rotated_identity_is_still_an_identity_change() {
    // A rotated signer (different issuer flow / email SAN) has no tag ref to collapse ⇒ still flags.
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let rotated = "attacker@evil.example";
    assert!(matches!(
        classify(Some(&b), &signed(rotated)),
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange { .. },
            established: true,
        }
    ));
}

#[test]
fn identity_change_finding_carries_the_full_raw_san_for_display() {
    // The canonical form is used for COMPARISON only; the finding retains the raw SAN so the render
    // shows exactly which identity signed (including the concrete tag/ref).
    let b = baseline(&[&format!("{WF}@refs/tags/v1")], true);
    let raw = format!("{WF}@refs/heads/main");
    if let SigningDrift::Regression {
        kind: RegressionKind::IdentityChange { new_identity, .. },
        ..
    } = classify(Some(&b), &signed(&raw))
    {
        assert_eq!(new_identity, raw, "the raw SAN is preserved for display");
    } else {
        panic!("expected an IdentityChange regression");
    }
}

#[test]
fn first_sight_of_a_never_seen_signed_repo_is_new_repo_not_a_regression() {
    // Cold start is TOFU: the first signed observation establishes trust, it is never drift.
    let drift = classify(None, &signed(CI));
    assert_eq!(drift, SigningDrift::NewRepo);
    assert!(!drift.is_regression());
}

#[test]
fn never_seen_unsigned_repo_is_continuous_nothing_to_regress_against() {
    // An unsigned image under a repo we have never seen signed has no history to regress against.
    assert_eq!(
        classify(None, &SigningPosture::NotSigned),
        SigningDrift::Continuous
    );
    assert_eq!(
        classify(None, &SigningPosture::InvalidSignature),
        SigningDrift::Continuous
    );
}

#[test]
fn regression_against_a_cold_baseline_is_reduced_not_established() {
    // The reduced-intensity case: a regression against a freshly-learned (cold) baseline is still
    // a regression, but flagged `established: false` — the weak-baseline "treat as a lead" signal.
    let b = baseline(&[CI], false);
    assert_eq!(
        classify(Some(&b), &SigningPosture::NotSigned),
        SigningDrift::Regression {
            kind: RegressionKind::Unsigned,
            established: false,
        }
    );
    assert_eq!(
        classify(Some(&b), &signed(ATTACKER)),
        SigningDrift::Regression {
            kind: RegressionKind::IdentityChange {
                new_identity: ATTACKER.to_string(),
                new_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            },
            established: false,
        }
    );
}

#[test]
fn checking_is_never_a_regression_even_against_an_established_baseline() {
    // A transient registry/log blip must not be read as drift — it resolves next pass.
    let b = baseline(&[CI], true);
    assert_eq!(
        classify(Some(&b), &SigningPosture::Checking),
        SigningDrift::Continuous
    );
}

#[test]
fn key_based_or_unverifiable_downgrade_on_an_established_keyless_repo_is_a_regression() {
    // JEF-280: a key-based / unverifiable posture is individually calm (JEF-276), but on a repo
    // whose established baseline was KEYLESS-verified it is a rank DOWNGRADE — the
    // registry-substitution signal that previously evaded the drift alarm. It fires now.
    let b = baseline(&[CI], true);
    assert_eq!(
        classify(Some(&b), &SigningPosture::SignedKeyBased),
        SigningDrift::Regression {
            kind: RegressionKind::Downgrade {
                to: PostureRank::KeyBased
            },
            established: true,
        }
    );
    assert_eq!(
        classify(Some(&b), &SigningPosture::UnverifiableHere),
        SigningDrift::Regression {
            kind: RegressionKind::Downgrade {
                to: PostureRank::Unverifiable
            },
            established: true,
        }
    );
}

#[test]
fn a_calm_posture_with_no_baseline_stays_continuous() {
    // No keyless baseline to downgrade FROM (an always-key-based cert-manager repo has no learned
    // baseline at all) ⇒ Continuous. This is the JEF-276 false-alarm fix, preserved.
    assert_eq!(
        classify(None, &SigningPosture::SignedKeyBased),
        SigningDrift::Continuous
    );
    assert_eq!(
        classify(None, &SigningPosture::UnverifiableHere),
        SigningDrift::Continuous
    );
}

#[test]
fn a_calm_posture_at_the_baseline_rank_stays_continuous() {
    // A repo whose baseline rank is already key-based (never had a stronger keyless posture) serving
    // key-based is NOT a downgrade — equal rank ⇒ Continuous. Guards the cert-manager win against a
    // future path that learns key-based baselines.
    let mut b = baseline(&[], true);
    b.rank = PostureRank::KeyBased;
    assert_eq!(
        classify(Some(&b), &SigningPosture::SignedKeyBased),
        SigningDrift::Continuous
    );
    // …but unverifiable is still BELOW key-based ⇒ a downgrade even from a key-based baseline.
    assert_eq!(
        classify(Some(&b), &SigningPosture::UnverifiableHere),
        SigningDrift::Regression {
            kind: RegressionKind::Downgrade {
                to: PostureRank::Unverifiable
            },
            established: true,
        }
    );
}

#[test]
fn a_downgrade_against_a_cold_keyless_baseline_is_uncertain_not_silent() {
    // JEF-280 acceptance: a downgrade against a freshly-learned (cold) keyless baseline still FIRES
    // — as a reduced-intensity `established: false` regression (maps to uncertain / non-green), not
    // silence.
    let b = baseline(&[CI], false);
    assert_eq!(
        classify(Some(&b), &SigningPosture::SignedKeyBased),
        SigningDrift::Regression {
            kind: RegressionKind::Downgrade {
                to: PostureRank::KeyBased
            },
            established: false,
        }
    );
}

#[test]
fn classify_is_deterministic() {
    // Same inputs, same class — every time (the property that makes it safe to run per-pass).
    let b = baseline(&[CI], true);
    let first = classify(Some(&b), &SigningPosture::NotSigned);
    for _ in 0..8 {
        assert_eq!(classify(Some(&b), &SigningPosture::NotSigned), first);
    }
}

#[test]
fn regression_kind_words_are_stable_and_distinct() {
    assert_eq!(RegressionKind::Unsigned.word(), "unsigned");
    assert_eq!(RegressionKind::Invalid.word(), "invalid");
    assert_eq!(
        RegressionKind::IdentityChange {
            new_identity: ATTACKER.to_string(),
            new_issuer: None,
        }
        .word(),
        "identity"
    );
    assert_eq!(
        RegressionKind::Downgrade {
            to: PostureRank::KeyBased
        }
        .word(),
        "downgrade-key-based"
    );
    assert_eq!(
        RegressionKind::Downgrade {
            to: PostureRank::Unverifiable
        }
        .word(),
        "downgrade-unverifiable"
    );
}
