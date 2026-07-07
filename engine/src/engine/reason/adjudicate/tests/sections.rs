//! Adjudicator unit tests, JEF-387: the per-section prompt fingerprints and the chain-shape
//! hash the churn-attribution harness relies on. Kept in its own submodule (like `group_1`..)
//! purely to hold every test file under the 1,000-line cap (repo CLAUDE.md).
#![allow(unused_imports)]

use super::super::*;
use super::graph_with_behaviors;
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{Behavior, NodeKey};
use crate::engine::observe::asn::AsnDb;

/// The per-section fingerprints ISOLATE change. Two prompts that differ ONLY in the
/// observed-runtime section (same entry, no CVEs, no findings, no objectives) must produce a
/// DIFFERENT `runtime` hash but IDENTICAL `cves` / `secrets` / `posture` / `objectives` /
/// `entry` hashes — so the churn harness attributes the re-judge to `runtime` alone, exactly.
#[test]
fn section_hashes_isolate_the_changed_section() {
    let (g_a, entry_a) = graph_with_behaviors(vec![Behavior::ProcessExec {
        path: "/bin/bash".into(),
    }]);
    let (g_b, entry_b) = graph_with_behaviors(vec![Behavior::FileRead {
        path: "/etc/passwd".into(),
    }]);
    // Same synthetic entry key both ways — only the runtime behavior differs.
    assert_eq!(entry_a, entry_b, "fixtures share the entry identity");

    let (_prompt_a, sec_a) =
        build_judgment_prompt_with_sections_asn(&entry_a, &[], &g_a, &AsnDb::empty());
    let (_prompt_b, sec_b) =
        build_judgment_prompt_with_sections_asn(&entry_b, &[], &g_b, &AsnDb::empty());

    assert_ne!(
        sec_a.runtime, sec_b.runtime,
        "the changed runtime section must change the runtime hash"
    );
    assert_eq!(sec_a.cves, sec_b.cves, "cves unchanged ⇒ identical hash");
    assert_eq!(sec_a.secrets, sec_b.secrets, "secrets unchanged");
    assert_eq!(sec_a.posture, sec_b.posture, "posture unchanged");
    assert_eq!(
        sec_a.objectives, sec_b.objectives,
        "objectives unchanged ⇒ identical hash"
    );
    assert_eq!(sec_a.entry, sec_b.entry, "same entry ⇒ identical hash");
}

/// `chain_shape_hash` groups by the objective/technique SET shape — order- and
/// entry-independent — while distinct technique sets hash apart, so the harness can cluster
/// entries that churn on the same chain.
#[test]
fn chain_shape_hash_groups_by_technique_set() {
    let a = NodeKey("secret/app/one".into());
    let b = NodeKey("secret/app/two".into());
    // Same technique set, different objective node keys + order ⇒ same chain shape.
    let set1 = vec![
        (a.clone(), EXPLOIT_PUBLIC_FACING),
        (b.clone(), CREDENTIAL_ACCESS),
    ];
    let set2 = vec![
        (NodeKey("secret/other/x".into()), CREDENTIAL_ACCESS),
        (NodeKey("secret/other/y".into()), EXPLOIT_PUBLIC_FACING),
    ];
    assert_eq!(
        chain_shape_hash(&set1),
        chain_shape_hash(&set2),
        "same technique set ⇒ same chain shape, regardless of entry/order"
    );
    // A different technique set ⇒ a different shape.
    let set3 = vec![(a, EXPLOIT_PUBLIC_FACING)];
    assert_ne!(
        chain_shape_hash(&set1),
        chain_shape_hash(&set3),
        "a different technique set must hash apart"
    );
}
