//! Tests for the durable per-repository signing baseline (JEF-263). Kept in their own file
//! per the repo's 1,000-line cap (CLAUDE.md); tests count toward the limit.

use std::path::{Path, PathBuf};

use super::*;
use crate::policies::signature::{PostureRank, Signer};

/// A unique temp journal path per test (no temp-file crate), mirroring `journal.rs`'s helper.
fn temp_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-baseline-{tag}-{}-{n}.jsonl",
        std::process::id()
    ))
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let mut rolled = path.as_os_str().to_owned();
    rolled.push(".1");
    let _ = std::fs::remove_file(PathBuf::from(rolled));
}

fn signed(identity: &str, issuer: Option<&str>) -> SigningPosture {
    SigningPosture::Signed(Signer {
        identity: identity.to_string(),
        issuer: issuer.map(str::to_string),
    })
}

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[test]
fn observing_a_signed_image_creates_a_repo_keyed_baseline() {
    // Acceptance: a signed image updates the repo baseline (identities/issuers), keyed by
    // registry/repo — not tag/digest.
    let mut store = SigningBaselineStore::new();
    let changed = store.observe(
        "ghcr.io/org/app:1",
        &signed(
            "https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
        ),
        1_000,
    );
    assert_eq!(changed.as_deref(), Some("ghcr.io/org/app"));
    let baseline = store.get("ghcr.io/org/app").expect("baseline learned");
    assert!(
        baseline
            .identities
            .contains("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1")
    );
    assert!(
        baseline
            .issuers
            .contains("https://token.actions.githubusercontent.com")
    );
    assert_eq!(baseline.first_seen_ms, 1_000);
    assert!(
        !baseline.established,
        "first sight is weak, not established"
    );
}

#[test]
fn a_new_tag_or_digest_under_a_known_repo_is_not_a_new_baseline() {
    // Acceptance: a new digest/tag under a repo with an existing baseline does NOT create a
    // new baseline (and, by construction here, is not drift).
    let mut store = SigningBaselineStore::new();
    let id = "https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1";
    store.observe("ghcr.io/org/app:1", &signed(id, None), 1_000);
    // Same signer, different tag AND a digest ref — both fold to ghcr.io/org/app.
    let changed_tag = store.observe("ghcr.io/org/app:2", &signed(id, None), 2_000);
    let changed_digest = store.observe(
        "ghcr.io/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &signed(id, None),
        3_000,
    );
    assert_eq!(
        store.len(),
        1,
        "one baseline for the repo, across tags/digests"
    );
    assert_eq!(changed_tag, None, "same signer, new tag ⇒ nothing changed");
    assert_eq!(
        changed_digest, None,
        "same signer, digest ref ⇒ nothing changed"
    );
    assert_eq!(
        store.get("ghcr.io/org/app").unwrap().first_seen_ms,
        1_000,
        "first_seen is unchanged by later tags"
    );
}

#[test]
fn a_new_signer_under_a_known_repo_widens_the_same_baseline() {
    let mut store = SigningBaselineStore::new();
    store.observe(
        "ghcr.io/org/app:1",
        &signed("id-a", Some("issuer-a")),
        1_000,
    );
    let changed = store.observe(
        "ghcr.io/org/app:1",
        &signed("id-b", Some("issuer-b")),
        2_000,
    );
    assert_eq!(
        changed.as_deref(),
        Some("ghcr.io/org/app"),
        "a new signer is a change"
    );
    let baseline = store.get("ghcr.io/org/app").unwrap();
    assert_eq!(baseline.identities.len(), 2);
    assert_eq!(baseline.issuers.len(), 2);
    assert_eq!(store.len(), 1, "still one repo baseline");
}

#[test]
fn a_freshly_learned_baseline_is_distinguishable_from_an_established_one() {
    // Acceptance: `established` + `first_seen` separate weak (fresh) from strong (matured).
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app:1", &signed("id-a", None), 0);
    assert!(!store.get("ghcr.io/org/app").unwrap().established);
    // Re-observed just past the grace window ⇒ established, first_seen still the original.
    store.observe("ghcr.io/org/app:1", &signed("id-a", None), DAY_MS + 1);
    let baseline = store.get("ghcr.io/org/app").unwrap();
    assert!(baseline.established, "matured past the grace window");
    assert_eq!(
        baseline.first_seen_ms, 0,
        "first_seen is the original observation"
    );
}

#[test]
fn establishment_is_monotonic() {
    // Once established, a later observation (even a clock that appears to go backwards) never
    // un-establishes the baseline.
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app:1", &signed("id-a", None), 0);
    store.observe("ghcr.io/org/app:1", &signed("id-a", None), DAY_MS + 1);
    assert!(store.get("ghcr.io/org/app").unwrap().established);
    store.observe("ghcr.io/org/app:1", &signed("id-a", None), 5);
    assert!(
        store.get("ghcr.io/org/app").unwrap().established,
        "establishment never regresses"
    );
}

#[test]
fn non_signed_postures_never_create_or_touch_a_baseline() {
    // The store only learns from a verifying signature. A not-signed / invalid / checking
    // posture is JEF-264's drift concern and must not create or mutate a baseline here.
    let mut store = SigningBaselineStore::new();
    assert_eq!(
        store.observe("ghcr.io/org/x:1", &SigningPosture::NotSigned, 1),
        None
    );
    assert_eq!(
        store.observe("ghcr.io/org/y:1", &SigningPosture::InvalidSignature, 1),
        None
    );
    assert_eq!(
        store.observe("ghcr.io/org/z:1", &SigningPosture::Checking, 1),
        None
    );
    assert!(
        store.is_empty(),
        "no baseline learned from a non-signed posture"
    );
}

#[test]
fn baseline_survives_an_engine_restart_round_trip() {
    // Acceptance: write + boot-replay. A baseline learned before a "restart" replays after it.
    let path = temp_path("roundtrip");
    {
        let journal = DecisionJournal::open(&path);
        let mut store = SigningBaselineStore::new();
        let repo = store
            .observe(
                "ghcr.io/org/app:1",
                &signed("id-a", Some("issuer-a")),
                1_000,
            )
            .expect("learned");
        store.persist(&journal, &repo);
    }
    // A fresh store on the same journal (the "post-restart" engine) replays it.
    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    let count = restored.restore(&reopened);
    assert_eq!(count, 1);
    let baseline = restored.get("ghcr.io/org/app").expect("restored");
    assert!(baseline.identities.contains("id-a"));
    assert!(baseline.issuers.contains("issuer-a"));
    assert_eq!(baseline.first_seen_ms, 1_000);
    cleanup(&path);
}

#[test]
fn a_learned_baseline_is_keyless_ranked_and_the_rank_survives_a_restart() {
    // JEF-280: the store only learns from a keyless `Signed` posture, so a learned baseline is
    // `Keyless`-ranked — the yardstick downgrade detection compares against — and that rank must
    // survive a journal round-trip so post-restart downgrade detection stays defined.
    let path = temp_path("rank-roundtrip");
    {
        let journal = DecisionJournal::open(&path);
        let mut store = SigningBaselineStore::new();
        let repo = store
            .observe("ghcr.io/org/app:1", &signed("id-a", None), 1_000)
            .expect("learned");
        assert_eq!(
            store.get(&repo).unwrap().rank,
            PostureRank::Keyless,
            "a keyless Signed posture teaches a Keyless-ranked baseline"
        );
        store.persist(&journal, &repo);
    }
    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    restored.restore(&reopened);
    assert_eq!(
        restored.get("ghcr.io/org/app").unwrap().rank,
        PostureRank::Keyless,
        "the learned rank survives a restart"
    );
    cleanup(&path);
}

#[test]
fn a_pre_jef280_line_without_a_rank_replays_as_keyless() {
    // Forward/back-compat: a baseline line written before the `rank` field existed has no `rank`
    // key. `#[serde(default)]` must replay it as `Keyless` — its honest historical value (the store
    // only ever learned from keyless postures), so a persisted keyless baseline still catches a
    // downgrade after an upgrade.
    let path = temp_path("prerank");
    let line = r#"{"at_ms":10,"kind":"signing_baseline","repo":"ghcr.io/org/app","identities":["id-a"],"issuers":[],"first_seen_ms":10,"established":true}"#;
    std::fs::write(&path, format!("{line}\n")).unwrap();
    let journal = DecisionJournal::open(&path);
    let mut store = SigningBaselineStore::new();
    assert_eq!(store.restore(&journal), 1);
    assert_eq!(
        store.get("ghcr.io/org/app").unwrap().rank,
        PostureRank::Keyless,
        "an absent rank replays as Keyless, never a weaker rank that would miss a downgrade"
    );
    cleanup(&path);
}

#[test]
fn log_corroboration_is_set_once_and_survives_a_restart() {
    // JEF-266: marking a repo log-corroborated flips the flag once, and the stronger baseline
    // survives a restart (monotonic — never re-armed to local-only on replay).
    let path = temp_path("corroborate");
    {
        let journal = DecisionJournal::open(&path);
        let mut store = SigningBaselineStore::new();
        let repo = store
            .observe(
                "ghcr.io/org/app:1",
                &signed("id-a", Some("issuer-a")),
                1_000,
            )
            .expect("learned");
        assert!(
            !store.get(&repo).unwrap().log_corroborated,
            "fresh ⇒ local-only"
        );
        assert!(store.mark_corroborated(&repo), "first mark flips the flag");
        assert!(!store.mark_corroborated(&repo), "a second mark is a no-op");
        store.persist(&journal, &repo);
    }
    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    restored.restore(&reopened);
    assert!(
        restored.get("ghcr.io/org/app").unwrap().log_corroborated,
        "corroboration survives a restart"
    );
    assert!(
        !restored.mark_corroborated("ghcr.io/nope"),
        "marking an untracked repo is a no-op"
    );
    cleanup(&path);
}

#[test]
fn last_write_wins_on_replay_across_repeated_lines() {
    // Compaction writes a full-state line each time; replay must keep the LATEST per repo.
    let path = temp_path("lastwrite");
    {
        let journal = DecisionJournal::open(&path);
        let mut store = SigningBaselineStore::new();
        store.observe("ghcr.io/org/app:1", &signed("id-a", None), 1_000);
        store.compact(&journal); // line 1: {id-a}
        store.observe("ghcr.io/org/app:1", &signed("id-b", None), 2_000);
        store.compact(&journal); // line 2: {id-a, id-b}
    }
    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    restored.restore(&reopened);
    let baseline = restored.get("ghcr.io/org/app").unwrap();
    assert_eq!(baseline.identities.len(), 2, "the latest, widest line wins");
    cleanup(&path);
}

#[test]
fn a_baseline_that_matured_while_down_restores_established() {
    // Written fresh (established=false) with an old first_seen; the replay stamp is a day
    // later, so restore recomputes it as established from wall-clock age.
    let path = temp_path("matured");
    let old_line = format!(
        r#"{{"at_ms":{},"kind":"signing_baseline","repo":"ghcr.io/org/app","identities":["id-a"],"issuers":[],"first_seen_ms":0,"established":false}}"#,
        DAY_MS + 5
    );
    std::fs::write(&path, format!("{old_line}\n")).unwrap();
    let journal = DecisionJournal::open(&path);
    let mut store = SigningBaselineStore::new();
    store.restore(&journal);
    assert!(
        store.get("ghcr.io/org/app").unwrap().established,
        "aged past the window by replay time ⇒ established"
    );
    cleanup(&path);
}

#[test]
fn a_forward_compatible_line_with_missing_fields_still_replays() {
    // Forward-compat: every field is #[serde(default)], so a line missing optional fields
    // (here: no issuers, no established) parses rather than breaking the whole replay.
    let path = temp_path("forwardcompat");
    let line = r#"{"at_ms":10,"kind":"signing_baseline","repo":"ghcr.io/org/app","identities":["id-a"],"first_seen_ms":10}"#;
    std::fs::write(&path, format!("{line}\n")).unwrap();
    let journal = DecisionJournal::open(&path);
    let mut store = SigningBaselineStore::new();
    assert_eq!(store.restore(&journal), 1);
    let baseline = store.get("ghcr.io/org/app").unwrap();
    assert!(baseline.identities.contains("id-a"));
    assert!(baseline.issuers.is_empty());
    assert!(!baseline.established);
    cleanup(&path);
}

#[test]
fn compaction_keeps_a_live_established_baseline_across_rotation() {
    // Acceptance: rotation never drops a live repo's established baseline. Establish one repo,
    // then churn the journal past its ~2x rotation window while compacting the store each
    // "pass" — the established baseline must still replay afterwards.
    let path = temp_path("compaction");
    let journal = DecisionJournal::open(&path);
    let mut store = SigningBaselineStore::new();
    // Establish the repo we care about (first_seen old enough to be established).
    store.observe(
        "ghcr.io/org/keep:1",
        &signed("id-keep", Some("issuer-keep")),
        0,
    );
    store.observe(
        "ghcr.io/org/keep:1",
        &signed("id-keep", Some("issuer-keep")),
        DAY_MS + 1,
    );
    assert!(store.get("ghcr.io/org/keep").unwrap().established);

    // Churn the SHARED journal well past its ~2x rotation window with unrelated decisions,
    // compacting the store each pass (the durability discipline the engine loop runs).
    let fat = "z".repeat(1000);
    // MAX_BYTES is 1 MiB; write well past 3x so multiple rotations occur.
    for i in 0..3300 {
        journal.record(Decision::Revert {
            cut: format!("cut-{i}"),
            reason: fat.clone(),
        });
        store.compact(&journal);
    }

    // A post-restart store must still find the established baseline.
    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    restored.restore(&reopened);
    let baseline = restored
        .get("ghcr.io/org/keep")
        .expect("the live established baseline survives rotation via compaction");
    assert!(baseline.established, "and it is still established");
    assert!(baseline.identities.contains("id-keep"));
    cleanup(&path);
}

#[test]
fn without_compaction_a_baseline_can_age_out_of_rotation() {
    // The negative control that proves compaction is load-bearing: the SAME churn, but the
    // baseline line is appended only ONCE (no re-compaction). Rotation ages it out.
    let path = temp_path("nocompaction");
    let journal = DecisionJournal::open(&path);
    let mut store = SigningBaselineStore::new();
    let repo = store
        .observe("ghcr.io/org/keep:1", &signed("id-keep", None), 0)
        .unwrap();
    store.persist(&journal, &repo); // appended once, then never again

    let fat = "z".repeat(1000);
    for i in 0..3300 {
        journal.record(Decision::Revert {
            cut: format!("cut-{i}"),
            reason: fat.clone(),
        });
    }

    let reopened = DecisionJournal::open(&path);
    let mut restored = SigningBaselineStore::new();
    restored.restore(&reopened);
    assert!(
        restored.get("ghcr.io/org/keep").is_none(),
        "without compaction the single baseline line ages out of the rotation window"
    );
    cleanup(&path);
}

#[test]
fn a_disabled_journal_is_in_memory_only_and_resets_on_restart() {
    // Degraded mode is honest: no journal ⇒ the store works in-memory, persist/compact are
    // no-ops, and a fresh store (a "restart") starts empty (re-learns from observation).
    let journal = DecisionJournal::disabled();
    let mut store = SigningBaselineStore::new();
    let repo = store
        .observe("ghcr.io/org/app:1", &signed("id-a", None), 1_000)
        .unwrap();
    store.persist(&journal, &repo);
    store.compact(&journal);
    assert_eq!(store.len(), 1, "in-memory learning still works");

    let mut post_restart = SigningBaselineStore::new();
    assert_eq!(
        post_restart.restore(&journal),
        0,
        "a disabled journal restores nothing — honest cold start"
    );
    assert!(post_restart.is_empty());
}

#[test]
fn the_store_is_bounded_and_evicts_non_established_before_established() {
    // Bounded state + defined eviction: at capacity, a non-established (cheap to re-learn)
    // entry is dropped before an established one.
    let mut store = SigningBaselineStore::with_capacity(2);
    // An established baseline (matured) we want to keep.
    store.observe("ghcr.io/org/keep:1", &signed("id-keep", None), 0);
    store.observe("ghcr.io/org/keep:1", &signed("id-keep", None), DAY_MS + 1);
    assert!(store.get("ghcr.io/org/keep").unwrap().established);
    // A fresh (non-established) baseline fills the second slot.
    store.observe("ghcr.io/org/fresh:1", &signed("id-fresh", None), DAY_MS + 2);
    assert_eq!(store.len(), 2);
    // A third repo forces eviction — the non-established `fresh` goes, `keep` stays.
    store.observe("ghcr.io/org/new:1", &signed("id-new", None), DAY_MS + 3);
    assert_eq!(store.len(), 2, "bounded at capacity");
    assert!(
        store.get("ghcr.io/org/keep").is_some(),
        "established survives eviction"
    );
    assert!(
        store.get("ghcr.io/org/fresh").is_none(),
        "non-established evicted first"
    );
    assert!(
        store.get("ghcr.io/org/new").is_some(),
        "the new repo was admitted"
    );
}

#[test]
fn repo_key_folds_tags_digests_and_host_variants() {
    // The key discipline the whole baseline rests on: host canonicalization + tag/digest strip.
    let mut store = SigningBaselineStore::new();
    let id = "id-a";
    // Uppercase host + tag, and a digest under the same repo, must fold to one key.
    store.observe("GHCR.IO/org/app:1", &signed(id, None), 1);
    store.observe(
        "ghcr.io/org/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        &signed(id, None),
        2,
    );
    assert_eq!(store.len(), 1);
    assert!(store.get("ghcr.io/org/app").is_some());
    // A registry host:port is preserved (only the trailing image tag is stripped).
    store.observe("localhost:5000/team/svc:v2", &signed(id, None), 3);
    assert!(store.get("localhost:5000/team/svc").is_some());
    // A bare Docker Hub shorthand folds to its repo.
    store.observe("postgres:16", &signed(id, None), 4);
    assert!(store.get("postgres").is_some());
}
