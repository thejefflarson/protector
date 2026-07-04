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
