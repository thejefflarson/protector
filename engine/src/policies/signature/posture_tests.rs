//! Unit tests for the tag-agnostic continuity identity (JEF-325): [`canonical_identity`] and
//! [`Signer::canonical_identity`]. Kept in their own file per the repo's 1,000-line cap (CLAUDE.md).

use super::*;

const WF_SAN: &str = "https://github.com/thejefflarson/protector/.github/workflows/agent.yml";

#[test]
fn canonical_identity_collapses_only_the_release_tag_value() {
    // Two SANs differing only in the tag version collapse to the SAME canonical identity.
    assert_eq!(
        canonical_identity(&format!("{WF_SAN}@refs/tags/v0.3.79")),
        format!("{WF_SAN}@refs/tags/*"),
    );
    assert_eq!(
        canonical_identity(&format!("{WF_SAN}@refs/tags/v0.3.79")),
        canonical_identity(&format!("{WF_SAN}@refs/tags/v0.3.80")),
    );
    // A tag value with slashes (e.g. `release/v1`) is still wholly collapsed.
    assert_eq!(
        canonical_identity(&format!("{WF_SAN}@refs/tags/release/v1")),
        format!("{WF_SAN}@refs/tags/*"),
    );
}

#[test]
fn canonical_identity_keeps_the_discriminating_parts() {
    // Ref TYPE is never wildcarded: a branch/PR ref is returned unchanged (distinct from a tag).
    let branch = format!("{WF_SAN}@refs/heads/main");
    assert_eq!(canonical_identity(&branch), branch);
    let pr = format!("{WF_SAN}@refs/pull/42/merge");
    assert_eq!(canonical_identity(&pr), pr);
    // A different workflow / repo yields a distinct canonical — repo/workflow still discriminate.
    let a = canonical_identity(&format!("{WF_SAN}@refs/tags/v1"));
    let other_wf =
        "https://github.com/thejefflarson/protector/.github/workflows/pwn.yml@refs/tags/v1";
    let other_repo = "https://github.com/evil/protector/.github/workflows/agent.yml@refs/tags/v1";
    assert_ne!(a, canonical_identity(other_wf));
    assert_ne!(a, canonical_identity(other_repo));
    // An email SAN (no tag ref) is returned verbatim.
    assert_eq!(canonical_identity("dev@example.com"), "dev@example.com");
}

#[test]
fn canonical_identity_is_idempotent() {
    for s in [
        format!("{WF_SAN}@refs/tags/v1"),
        format!("{WF_SAN}@refs/tags/*"),
        format!("{WF_SAN}@refs/heads/main"),
        "dev@example.com".to_string(),
    ] {
        let once = canonical_identity(&s);
        assert_eq!(
            canonical_identity(&once),
            once,
            "canonicalization must be idempotent"
        );
    }
}

#[test]
fn signer_canonical_identity_delegates_to_the_helper() {
    let signer = Signer {
        identity: format!("{WF_SAN}@refs/tags/v0.3.80"),
        issuer: Some("https://token.actions.githubusercontent.com".to_string()),
    };
    // The raw SAN is preserved for display; the continuity identity is the collapsed form.
    assert_eq!(signer.identity, format!("{WF_SAN}@refs/tags/v0.3.80"));
    assert_eq!(signer.canonical_identity(), format!("{WF_SAN}@refs/tags/*"));
}

// --- JEF-326: the per-sweep posture summary (the INFO line the sweep logs) ---

#[test]
fn posture_summary_tallies_every_variant() {
    let mut map = PostureMap::new();
    map.record(
        "a",
        SigningPosture::Signed(Signer {
            identity: format!("{WF_SAN}@refs/tags/v1"),
            issuer: None,
        }),
    );
    map.record("b", SigningPosture::SignedKeyBased);
    map.record("c", SigningPosture::UnverifiableHere);
    map.record("d", SigningPosture::InvalidSignature);
    map.record("e", SigningPosture::NotSigned);
    map.record("f", SigningPosture::Checking);
    map.record("g", SigningPosture::Checking);
    let s = map.summary();
    assert_eq!(s.signed, 1);
    assert_eq!(s.signed_key_based, 1);
    assert_eq!(s.unverifiable, 1);
    assert_eq!(s.invalid, 1);
    assert_eq!(s.not_signed, 1);
    assert_eq!(s.checking, 2, "both stuck images are counted");
    assert_eq!(s.total(), 7);
}

#[test]
fn posture_summary_display_is_the_stable_info_line() {
    // The exact shape an operator greps for; `checking=` is present so a stuck fleet is visible.
    let mut map = PostureMap::new();
    map.record("a", SigningPosture::NotSigned);
    map.record("b", SigningPosture::Checking);
    assert_eq!(
        map.summary().to_string(),
        "signed=0 key-based=0 unverifiable=0 invalid=0 not-signed=1 checking=1"
    );
}

#[test]
fn empty_map_summarizes_to_all_zeros() {
    assert_eq!(PostureMap::new().summary(), PostureSummary::default());
    assert_eq!(PostureMap::new().summary().total(), 0);
}
