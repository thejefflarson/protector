//! Unit tests for the journal's own responsibilities: durable persistence, replay, rotation,
//! and back-compat parsing of every [`Decision`] variant. Split out of `mod.rs` to keep the
//! file under the repo's 1,000-line cap (CLAUDE.md). The engine-orchestration integration
//! tests (journal replay wired into `Engine::process`, including the ADR-0034 D8 double
//! replay-lock's end-to-end behavior) live in the sibling `engine::journal_tests` module.

use super::*;

/// A unique temp path for one test, without pulling in a temp-file crate: the
/// system temp dir plus the test name and a per-call nonce (pid + an atomic counter),
/// so parallel tests never collide. Cleaned up at the end of each test.
fn temp_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-journal-{tag}-{}-{n}.jsonl",
        std::process::id()
    ))
}

/// Remove a journal's files (active + rolled) so a test leaves no residue.
fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(rolled_path(path));
}

#[test]
fn round_trips_decisions_across_a_reopen() {
    // The acceptance criterion: decisions written before a "restart" replay after it.
    let path = temp_path("roundtrip");
    {
        let journal = DecisionJournal::open(&path);
        assert!(journal.is_enabled(), "a writable path enables the journal");
        journal.record(Decision::Breach {
            entry: "workload/app/Pod/web".into(),
            objectives: 3,
            verdict: "exploitable — CVE-2021-44228 reaches the secret".into(),
            coverage: Some(EnrichmentCoverage {
                cves: vec!["CVE-2021-44228".into()],
                behavioral: false,
            }),
            fingerprint: Some("cves=CVE-2021-44228|rt=|objs=secret|findings=".into()),
            verdict_typed: Some(crate::engine::reason::adjudicate::Verdict::Exploitable(
                "CVE-2021-44228 reaches the secret".into(),
            )),
        });
        journal.record(Decision::Apply {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
        });
        journal.record(Decision::Revert {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
        });
    }
    // A fresh journal on the same path (the "post-restart" engine) replays it all.
    let reopened = DecisionJournal::open(&path);
    let entries = reopened.replay();
    assert_eq!(entries.len(), 3, "all three decisions survive the reopen");
    // JEF-301: the breach line carries the evidence fingerprint AND the TYPED decisive
    // verdict across the reopen, so the post-restart engine can re-seed the verdict cache
    // (serve an unchanged entry with no model call) and replay the EXACT prior decision.
    match &entries[0].decision {
        Decision::Breach {
            fingerprint,
            verdict_typed,
            ..
        } => {
            assert_eq!(
                fingerprint.as_deref(),
                Some("cves=CVE-2021-44228|rt=|objs=secret|findings="),
                "the evidence fingerprint (the freshness key) survives the reopen"
            );
            assert_eq!(
                verdict_typed.as_ref(),
                Some(&crate::engine::reason::adjudicate::Verdict::Exploitable(
                    "CVE-2021-44228 reaches the secret".into()
                )),
                "a persisted BREACH replays as the EXACT typed Exploitable, not a downgrade"
            );
        }
        other => panic!("expected a Breach, got {other:?}"),
    }
    assert!(matches!(entries[1].decision, Decision::Apply { .. }));
    match &entries[2].decision {
        Decision::Revert { cut, reason } => {
            assert!(cut.contains("web"));
            assert!(reason.contains("no proven chain"));
        }
        other => panic!("expected a Revert, got {other:?}"),
    }
    // The recorded time is recent (sane wall-clock stamp).
    let age = SystemTime::now()
        .duration_since(entries[0].at())
        .expect("recorded in the past");
    assert!(age.as_secs() < 60, "the stamp is a recent wall-clock time");
    cleanup(&path);
}

/// ADR-0034 D8 (JEF-639) acceptance: an `Incident` line — the model's cut-choice decision,
/// its resolved cut signature(s), and the full-prompt fingerprint it was judged against —
/// round-trips a "restart" byte-for-byte. The replay-lock verification itself (fingerprint +
/// cut-signature re-derivation) is the engine's job, not the journal's — this only proves the
/// journal is a faithful store for the shape it needs to check.
#[test]
fn incident_decision_round_trips_across_a_reopen() {
    let path = temp_path("incident-roundtrip");
    {
        let journal = DecisionJournal::open(&path);
        journal.record(Decision::Incident {
            entry: "workload/app/Pod/web".into(),
            objectives: 2,
            assessment: crate::engine::reason::adjudicate::incident::Assessment::Attack,
            reason: "RCE reaches the secret".into(),
            cuts: vec![
                JournaledCut {
                    node: "workload/app/Pod/web".into(),
                    cut_signature:
                        "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web".into(),
                },
                JournaledCut {
                    node: "workload/app/Pod/store".into(),
                    cut_signature:
                        "workload/app/Pod/store -[quarantine-workload]-> workload/app/Pod/store"
                            .into(),
                },
            ],
            fingerprint: "cves=CVE-2021-44228|rt=|objs=secret|findings=".into(),
        });
    }
    let reopened = DecisionJournal::open(&path);
    let entries = reopened.replay();
    assert_eq!(entries.len(), 1);
    match &entries[0].decision {
        Decision::Incident {
            entry,
            assessment,
            reason,
            cuts,
            fingerprint,
            ..
        } => {
            assert_eq!(entry, "workload/app/Pod/web");
            assert_eq!(
                *assessment,
                crate::engine::reason::adjudicate::incident::Assessment::Attack
            );
            assert_eq!(reason, "RCE reaches the secret");
            assert_eq!(cuts.len(), 2, "both chosen cuts survive the reopen");
            assert_eq!(cuts[0].node, "workload/app/Pod/web");
            assert_eq!(
                fingerprint, "cves=CVE-2021-44228|rt=|objs=secret|findings=",
                "the replay-lock's fingerprint survives byte-for-byte"
            );
        }
        other => panic!("expected an Incident, got {other:?}"),
    }
    cleanup(&path);
}

/// ADR-0035's shadow-bake step: a `CutDivergence` line — the model-vs-deterministic cut
/// comparator's classification for one entry — round-trips a "restart" byte-for-byte, so the
/// bake history a human reads for the arm-readiness review survives across a restart instead of
/// resetting the window.
#[test]
fn cut_divergence_round_trips_across_a_reopen() {
    let path = temp_path("divergence-roundtrip");
    {
        let journal = DecisionJournal::open(&path);
        journal.record(Decision::CutDivergence {
            entry: "workload/shop/Pod/web".into(),
            class: crate::engine::cut_divergence::DivergenceClass::ModelUnderCut,
            model_cuts: vec!["workload/shop/Pod/web".into()],
            deterministic_cuts: vec![
                "workload/shop/Pod/ledger".into(),
                "workload/shop/Pod/payments".into(),
                "workload/shop/Pod/web".into(),
            ],
        });
    }
    let reopened = DecisionJournal::open(&path);
    let entries = reopened.replay();
    assert_eq!(entries.len(), 1);
    match &entries[0].decision {
        Decision::CutDivergence {
            entry,
            class,
            model_cuts,
            deterministic_cuts,
        } => {
            assert_eq!(entry, "workload/shop/Pod/web");
            assert_eq!(
                *class,
                crate::engine::cut_divergence::DivergenceClass::ModelUnderCut
            );
            assert_eq!(model_cuts, &vec!["workload/shop/Pod/web".to_string()]);
            assert_eq!(
                deterministic_cuts.len(),
                3,
                "all three nodes survive the reopen"
            );
        }
        other => panic!("expected a CutDivergence, got {other:?}"),
    }
    cleanup(&path);
}

/// Back-compat: a journal that predates JEF-639 holds ONLY `Breach` lines (no `Incident` line
/// ever existed for this entry) — replay must surface the breach text display-only, exactly as
/// before, with no `Incident` decision to be found (there is nothing to re-arm a cut from; the
/// engine cold-re-judges for cuts, per the `Decision::Incident` type docs).
#[test]
fn a_pre_jef639_journal_holds_no_incident_lines() {
    let path = temp_path("pre-jef639");
    let journal = DecisionJournal::open(&path);
    journal.record(Decision::Breach {
        entry: "workload/app/Pod/web".into(),
        objectives: 1,
        verdict: "exploitable — reaches the secret".into(),
        coverage: None,
        fingerprint: Some("fp-1".into()),
        verdict_typed: Some(crate::engine::reason::adjudicate::Verdict::Exploitable(
            "reaches the secret".into(),
        )),
    });
    let entries = journal.replay();
    assert_eq!(entries.len(), 1);
    assert!(
        !entries
            .iter()
            .any(|e| matches!(e.decision, Decision::Incident { .. })),
        "an old journal has no Incident lines to re-arm a cut from"
    );
    cleanup(&path);
}

#[test]
fn an_unset_path_degrades_to_in_memory_only_and_never_records() {
    // No volume configured ⇒ disabled journal: records are no-ops, replay is empty,
    // and nothing is created on disk. This is the "absent volume = today's behavior".
    let journal = DecisionJournal::disabled();
    assert!(!journal.is_enabled());
    journal.record(Decision::Apply { cut: "x".into() });
    assert!(
        journal.replay().is_empty(),
        "a disabled journal replays nothing"
    );
}

#[test]
fn an_unwritable_path_degrades_gracefully_without_crashing() {
    // A path whose parent can't be created (a file standing in for a directory) is
    // unwritable. `open` must NOT panic — it degrades to disabled.
    let file = temp_path("not-a-dir");
    std::fs::write(&file, b"i am a file, not a directory").unwrap();
    let under_a_file = file.join("journal.jsonl"); // parent is a regular file
    let journal = DecisionJournal::open(&under_a_file);
    assert!(
        !journal.is_enabled(),
        "an unwritable path disables the journal rather than crashing"
    );
    // Recording is a safe no-op on the degraded journal.
    journal.record(Decision::Apply { cut: "y".into() });
    assert!(journal.replay().is_empty());
    cleanup(&file);
}

#[test]
fn write_failure_mid_run_disables_without_crashing() {
    // Open successfully, then delete the file's directory out from under it so the
    // next append fails. The journal must disable itself, not crash.
    let dir = std::env::temp_dir().join(format!(
        "protector-journal-vanish-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("journal.jsonl");
    let journal = DecisionJournal::open(&path);
    assert!(journal.is_enabled());
    journal.record(Decision::Apply {
        cut: "first".into(),
    });
    // The mount "goes away".
    std::fs::remove_dir_all(&dir).unwrap();
    // This append can no longer create the file (parent gone) ⇒ disables, no panic.
    journal.record(Decision::Apply {
        cut: "second".into(),
    });
    assert!(
        !journal.is_enabled(),
        "a write failure disables the journal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotation_bounds_the_journal_and_replay_spans_the_boundary() {
    // Force rotation by writing past MAX_BYTES, then confirm: the active file is
    // bounded, a rolled generation exists, and replay still sees lines from BOTH —
    // i.e. the oldest pre-rotation decision and the newest post-rotation one.
    let path = temp_path("rotation");
    let journal = DecisionJournal::open(&path);
    // A fat reason so each line is ~1 KiB. Write ~1.3× MAX_BYTES so the active file
    // crosses the cap EXACTLY ONCE: the first chunk rolls to `.1` (holding cut-0) and
    // the remainder is the active file (holding the newest cut). With single-generation
    // rotation only the most recent ~2× window is retained — writing well past 2× would
    // legitimately roll cut-0 away — so this stays just over one cap to assert the
    // boundary-spanning replay deterministically.
    let fat = "z".repeat(1000);
    let lines = (MAX_BYTES as usize / 1000) * 13 / 10;
    for i in 0..lines {
        journal.record(Decision::Revert {
            cut: format!("cut-{i}"),
            reason: fat.clone(),
        });
    }
    // The active file is bounded near the cap (a rotation happened).
    let active_len = std::fs::metadata(&path).unwrap().len();
    assert!(
        active_len < MAX_BYTES,
        "the active file is rotated below the cap (was {active_len})"
    );
    assert!(
        std::fs::metadata(rolled_path(&path)).is_ok(),
        "a rolled generation exists after crossing the cap"
    );
    // Replay spans the boundary: it includes the very first cut (in the rolled file)
    // and the very last (in the active file), in order.
    let entries = journal.replay();
    let cuts: Vec<&str> = entries
        .iter()
        .filter_map(|e| match &e.decision {
            Decision::Revert { cut, .. } => Some(cut.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        cuts.contains(&"cut-0"),
        "the oldest decision survives in the roll"
    );
    assert!(
        cuts.contains(&format!("cut-{}", lines - 1).as_str()),
        "the newest decision is in the active file"
    );
    // Total on-disk size stays bounded by ~2× the cap (one rolled generation only).
    let rolled_len = std::fs::metadata(rolled_path(&path)).unwrap().len();
    assert!(
        active_len + rolled_len < 2 * MAX_BYTES + 2000,
        "two generations cap total size at ~2× MAX_BYTES"
    );
    cleanup(&path);
}

#[test]
fn a_pre_jef145_breach_line_deserializes_with_unknown_coverage() {
    // Back-compat (JEF-145): a journal line written before the structured
    // enrichment-coverage field existed has no `coverage` key. `#[serde(default)]`
    // must deserialize it to `None` ("unknown") — NOT a parse failure, and (per the
    // would-have-acted report aggregation) NOT a false coverage gap.
    let line = r#"{"at_ms":1,"kind":"breach","entry":"workload/app/Pod/web","objectives":2,"verdict":"exploitable — reaches the secret"}"#;
    let entry: JournalEntry = serde_json::from_str(line).expect("old line still parses");
    match entry.decision {
        Decision::Breach {
            coverage,
            fingerprint,
            verdict_typed,
            ..
        } => {
            assert!(
                coverage.is_none(),
                "absent coverage degrades to unknown, not a gap"
            );
            // JEF-301 back-compat: a line written before the fingerprint/typed-verdict
            // fields existed has neither key. `#[serde(default)]` must yield `None` for
            // both — the replay then restores it display-only (exactly today's behaviour)
            // and never treats a missing fingerprint as a cache hit against changed
            // evidence.
            assert!(
                fingerprint.is_none(),
                "an absent fingerprint replays as None (display-only, no false cache hit)"
            );
            assert!(
                verdict_typed.is_none(),
                "an absent typed verdict replays as None (display-only restore)"
            );
        }
        other => panic!("expected a Breach, got {other:?}"),
    }
}

#[test]
fn enrichment_coverage_is_backed_when_a_cve_or_behavior_is_present() {
    assert!(
        !EnrichmentCoverage {
            cves: vec![],
            behavioral: false
        }
        .is_backed(),
        "no CVE and no behavior ⇒ unbacked (a gap)"
    );
    assert!(
        EnrichmentCoverage {
            cves: vec!["CVE-2021-44228".into()],
            behavioral: false
        }
        .is_backed(),
        "a CVE backs the decision"
    );
    assert!(
        EnrichmentCoverage {
            cves: vec![],
            behavioral: true
        }
        .is_backed(),
        "a behavioral signal backs the decision"
    );
}

#[test]
fn admission_decisions_round_trip_across_a_reopen() {
    // JEF-237 persistence: an admission record written before a "restart" replays after
    // it, with its dedup count + last-seen intact, so the admission decision log
    // repopulates on boot.
    use crate::engine::policy_log::PolicyDecisionRecord;
    let path = temp_path("admission");
    {
        let journal = DecisionJournal::open(&path);
        let mut record = PolicyDecisionRecord::now(
            "admission",
            "allow",
            "Pod/web",
            "ghcr.io/org/app:1",
            "signed",
            "meshed",
            "default",
            "",
        );
        record.count = 4;
        record.at_ms = 42;
        journal.record(Decision::Admission { record });
    }
    let reopened = DecisionJournal::open(&path);
    let entries = reopened.replay();
    assert_eq!(entries.len(), 1);
    match &entries[0].decision {
        Decision::Admission { record } => {
            assert_eq!(record.subject, "Pod/web");
            assert_eq!(record.image, "ghcr.io/org/app:1");
            assert_eq!(record.signature, "signed");
            assert_eq!(record.mesh, "meshed");
            assert_eq!(record.decision, "allow");
            assert_eq!(record.count, 4, "the dedup count survives the reopen");
            assert_eq!(record.at_ms, 42, "the last-seen survives the reopen");
        }
        other => panic!("expected an Admission, got {other:?}"),
    }
    cleanup(&path);
}

#[test]
fn replay_skips_corrupt_lines() {
    // A crash mid-write can leave a partial trailing line; replay must skip it, not
    // fail, and still return the good lines.
    let path = temp_path("corrupt");
    let journal = DecisionJournal::open(&path);
    journal.record(Decision::Apply { cut: "good".into() });
    // Append a garbage half-line, as a crash would.
    {
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"at_ms\": 1, \"kind\": \"appl").unwrap();
    }
    let entries = journal.replay();
    assert_eq!(
        entries.len(),
        1,
        "the good line survives, the garbage is skipped"
    );
    assert!(matches!(entries[0].decision, Decision::Apply { .. }));
    cleanup(&path);
}
