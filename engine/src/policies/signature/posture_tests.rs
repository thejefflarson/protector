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
