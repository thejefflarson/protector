//! Unit tests for the pure build-provenance drift classifier (JEF-275).

use std::collections::BTreeSet;

use super::*;
use crate::engine::state::SigningBaseline;
use crate::policies::signature::{PostureRank, Provenance, ProvenancePosture};

const CI_BUILDER: &str = "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main";
const ATTACKER_BUILDER: &str =
    "https://github.com/evil/app/.github/workflows/pwn.yml@refs/heads/main";

/// A baseline carrying a learned provenance identity (source `github.com/org/app`, builder
/// `CI_BUILDER`), `established` per the argument.
fn baseline_with_provenance(established: bool) -> SigningBaseline {
    let mut sources = BTreeSet::new();
    sources.insert("github.com/org/app".to_string());
    let mut builders = BTreeSet::new();
    builders.insert(CI_BUILDER.to_string());
    SigningBaseline {
        identities: BTreeSet::new(),
        issuers: BTreeSet::new(),
        first_seen_ms: 0,
        established,
        log_corroborated: false,
        rank: PostureRank::Keyless,
        provenance_sources: sources,
        provenance_builders: builders,
        last_updated_ms: 0,
    }
}

/// A signature-only baseline (no provenance learned yet).
fn baseline_no_provenance() -> SigningBaseline {
    SigningBaseline {
        identities: BTreeSet::new(),
        issuers: BTreeSet::new(),
        first_seen_ms: 0,
        established: true,
        log_corroborated: false,
        rank: PostureRank::Keyless,
        provenance_sources: BTreeSet::new(),
        provenance_builders: BTreeSet::new(),
        last_updated_ms: 0,
    }
}

fn verified(source: &str, builder: &str) -> ProvenancePosture {
    ProvenancePosture::Verified(Provenance {
        source_repo: source.to_string(),
        builder: builder.to_string(),
    })
}

#[test]
fn known_source_and_builder_is_continuous() {
    let b = baseline_with_provenance(true);
    let drift = classify(Some(&b), &verified("github.com/org/app", CI_BUILDER));
    assert_eq!(drift, ProvenanceDrift::Continuous, "a normal rebuild");
}

#[test]
fn new_builder_on_established_repo_is_a_change() {
    let b = baseline_with_provenance(true);
    let drift = classify(Some(&b), &verified("github.com/org/app", ATTACKER_BUILDER));
    match drift {
        ProvenanceDrift::Change {
            new_builder,
            established,
            ..
        } => {
            assert_eq!(new_builder, ATTACKER_BUILDER);
            assert!(established);
        }
        other => panic!("expected Change, got {other:?}"),
    }
}

#[test]
fn new_source_on_established_repo_is_a_change() {
    let b = baseline_with_provenance(true);
    let drift = classify(Some(&b), &verified("github.com/evil/app", CI_BUILDER));
    assert!(drift.is_change());
}

#[test]
fn change_on_a_cold_baseline_is_flagged_weak_not_silent() {
    let b = baseline_with_provenance(false);
    let drift = classify(Some(&b), &verified("github.com/org/app", ATTACKER_BUILDER));
    match drift {
        ProvenanceDrift::Change { established, .. } => assert!(!established, "cold ⇒ weak lead"),
        other => panic!("expected Change, got {other:?}"),
    }
}

#[test]
fn first_verified_provenance_is_new_not_a_change() {
    let b = baseline_no_provenance();
    let drift = classify(Some(&b), &verified("github.com/org/app", CI_BUILDER));
    assert_eq!(
        drift,
        ProvenanceDrift::NewProvenance,
        "cold-start TOFU, not drift"
    );
}

#[test]
fn absent_provenance_is_calm_never_a_change() {
    // SECURITY: absent provenance — the common case — must be calm, never a regression.
    let b = baseline_with_provenance(true);
    assert_eq!(
        classify(Some(&b), &ProvenancePosture::Absent),
        ProvenanceDrift::Continuous
    );
}

#[test]
fn unverifiable_and_checking_are_continuous() {
    let b = baseline_with_provenance(true);
    assert_eq!(
        classify(Some(&b), &ProvenancePosture::Unverifiable),
        ProvenanceDrift::Continuous
    );
    assert_eq!(
        classify(Some(&b), &ProvenancePosture::Checking),
        ProvenanceDrift::Continuous
    );
}

#[test]
fn no_baseline_never_alarms() {
    // A repo with no signing baseline can't anchor a provenance change (augment-only learning).
    assert_eq!(
        classify(None, &verified("github.com/org/app", CI_BUILDER)),
        ProvenanceDrift::Continuous
    );
}
