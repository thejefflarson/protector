//! The decision journal (JEF-141): a durable, append-only record of what the engine
//! decided, so a pod restart doesn't wipe decision history and leave the output state
//! blank for ~20 min while the caches and the CPU model warm.
//!
//! The findings snapshot, the judgement ring, and the mitigation ledger are all in-memory: a
//! restart loses them. The journal closes that gap. Each pass appends its **breach
//! decisions** (the model's per-entry verdict) and its **ledger deltas** (a mitigation
//! applied or a cut reverted, with the [`Reversion`](super::respond::actuator::Reversion)
//! reason) as JSON lines to a file on a mounted volume; on boot the engine replays the
//! tail so the findings snapshot, the judgement record, and the reversion log populate
//! immediately — before a fresh model pass lands.
//!
//! Shape and posture mirror the mounted-snapshot port (`exploit_intel.rs`, the KEV
//! catalogue): the path is a `PROTECTOR_ENGINE_*` env var pointing at an
//! operator-provided PVC or hostPath, and an **absent or unwritable** volume degrades
//! to today's in-memory-only behaviour — it NEVER crashes. Stays in-cluster: this writes
//! to a local mount, no new outbound path.
//!
//! The journal is **bounded by file size** with a single-generation rotation: when the
//! active file exceeds the cap it is rolled to `<path>.1` (replacing any prior roll) and
//! a fresh file is started. Reload reads the rolled generation first, then the active
//! one, so the replayed window spans the rotation boundary. Two files cap total on-disk
//! size at roughly `2 × MAX_BYTES`.
//!
//! Each line is one [`JournalEntry`]; the file format is line-delimited JSON ("JSON
//! lines"), append-friendly and trivially tail-replayable. Parsing is tolerant: a
//! corrupt or truncated line (a crash mid-write) is skipped, never fatal.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Size cap (bytes) for the active journal file before it rotates. ~1 MiB holds many
/// thousands of decision lines — comfortably several restarts' worth of history — while
/// bounding disk use on a small mounted volume. Rotation keeps one prior generation, so
/// total on-disk size is at most ~`2 × MAX_BYTES`.
const MAX_BYTES: u64 = 1024 * 1024;

/// The structured enrichment-coverage behind a breach decision (JEF-145): the SAME
/// CVE/behavioral evidence the model was handed in the adjudication prompt, persisted at
/// journal-append time so the would-have-acted report aggregation can classify an
/// enrichment-coverage gap from FACT
/// rather than grepping the verdict prose for a `CVE-` token (which misclassifies both
/// ways: a prose mention with no real backing reads as covered; a well-enriched verdict
/// that omits the id reads as a gap).
///
/// "Backed" = the model had at least one CVE OR a behavioral signal to weigh. The ABSENCE
/// of this struct on an older journal line (pre-JEF-145) is "unknown" — deliberately NOT
/// a gap (see [`Decision::Breach::coverage`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentCoverage {
    /// The CVE ids in the entry's actual evidence that went into the prompt (the CVE
    /// backing). Empty ⇒ no CVE reached the model for this entry.
    #[serde(default)]
    pub cves: Vec<String>,
    /// Whether any behavioral signal (runtime telemetry, ADR-0014) was present on the
    /// entry when it was judged — the other half of "did the model have evidence".
    #[serde(default)]
    pub behavioral: bool,
}

impl EnrichmentCoverage {
    /// Whether the model had real enrichment to weigh: any CVE evidence OR a behavioral
    /// signal. `false` ⇒ the verdict was reached blind to the vulnerability/runtime data
    /// that would corroborate it — an enrichment-coverage gap.
    pub fn is_backed(&self) -> bool {
        !self.cves.is_empty() || self.behavioral
    }
}

/// What a journal line records — the engine's decision atoms, durable across restarts.
/// Tagged so the JSON line is self-describing and forward-compatible (an unknown future
/// variant is skipped on reload rather than breaking the replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    /// One breach decision: the model's verdict for an internet-facing entry, over the
    /// objectives it reaches. The raw material the findings snapshot and the judgement
    /// record reload after a restart.
    Breach {
        /// The internet-facing entry that was judged.
        entry: String,
        /// How many objectives the entry reaches (the breadth the model weighed).
        objectives: usize,
        /// The model's verdict summary (its own words — both positive and negative).
        verdict: String,
        /// The structured enrichment-coverage behind this decision (JEF-145): the
        /// CVE/behavioral evidence the model was given. `None` on records written before
        /// JEF-145 (via `#[serde(default)]`) — back-compat "unknown", which the
        /// would-have-acted report aggregation treats as NOT a coverage gap rather than a
        /// false positive.
        #[serde(default)]
        coverage: Option<EnrichmentCoverage>,
    },
    /// A mitigation applied (a cut went live), keyed by its cut signature.
    Apply {
        /// The cut's stable signature (`from -[relation]-> to`).
        cut: String,
    },
    /// A mitigation reverted (a cut was lifted), with WHY — the self-revert is the
    /// core safety story (ADR-0016), so the reason is durable, not just logged.
    Revert {
        /// The cut's stable signature that was lifted.
        cut: String,
        /// Why it was lifted (health divergence, posture cleared, …).
        reason: String,
    },
    /// One admission decision the webhook resolved (JEF-237): the deduped per-workload
    /// signature/mesh allow/audit/deny record the admission decision log holds. Persisted so
    /// the admission log survives a restart and repopulates on boot (parallel to how
    /// [`Breach`](Decision::Breach) repopulates the findings snapshot), rather than going
    /// blank. Carries the full [`PolicyDecisionRecord`] (with its dedup `count` + last-seen),
    /// so the replay restores the row verbatim.
    Admission {
        /// The deduped admission-decision record (subject / image / signature / mesh /
        /// decision / reason / count / last-seen). Low-cardinality, no secret values.
        record: crate::engine::policy_log::PolicyDecisionRecord,
    },
    /// A per-repository TOFU signing baseline (JEF-263, ADR-0020): the learned set of
    /// identities/issuers that have signed images under one `registry/repo`, plus when the
    /// repo was first seen signed and whether that history is `established` yet. Written as a
    /// **compacted, full-state** line — the latest line for a repo supersedes every earlier
    /// one on replay (last-write-wins), so re-appending it (on change / per pass) keeps a live
    /// repo's baseline inside the rotation window instead of silently aging out and re-arming
    /// cold-start trust. Every field is `#[serde(default)]` so a future field can be added
    /// without breaking replay of older lines. The identities/issuers are UNTRUSTED Fulcio
    /// cert text — a consumer MUST escape them at render (the zero-egress state never leaves
    /// the cluster).
    SigningBaseline {
        /// The canonical `registry/repo` key (host-normalized, tag/digest stripped).
        #[serde(default)]
        repo: String,
        /// Every signer identity observed signing an image under this repo (sorted, deduped).
        #[serde(default)]
        identities: Vec<String>,
        /// Every OIDC issuer observed signing under this repo (sorted, deduped).
        #[serde(default)]
        issuers: Vec<String>,
        /// When the repo was first observed with a verifying signature, Unix epoch millis.
        #[serde(default)]
        first_seen_ms: u64,
        /// Whether the signed history is `established` (matured past the TOFU grace window) —
        /// `false` is a freshly-learned baseline (weaker evidence).
        #[serde(default)]
        established: bool,
        /// Whether the public Rekor transparency log corroborates this repo's signing history
        /// (JEF-266, ADR-0020 §4) — `true` is real provenance read from the append-only log
        /// (stronger than local-only TOFU). `#[serde(default)]` so lines predating the Rekor lane
        /// replay as local-only (`false`), never a fabricated corroboration.
        #[serde(default)]
        log_corroborated: bool,
    },
}

/// One journal line: a [`Decision`] stamped with when it was recorded. The timestamp is
/// wall-clock (`SystemTime`) so a consumer can render "NNs ago" and the operator has
/// a real audit time; serialized as a Unix-millis integer for a compact, stable line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// When the decision was recorded, Unix epoch milliseconds.
    pub at_ms: u64,
    /// The decision itself.
    #[serde(flatten)]
    pub decision: Decision,
}

impl JournalEntry {
    /// Stamp a decision with the current wall-clock time.
    pub fn now(decision: Decision) -> Self {
        Self {
            at_ms: unix_millis(SystemTime::now()),
            decision,
        }
    }

    /// The recorded time as a `SystemTime` (for relative-time rendering on reload).
    pub fn at(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(self.at_ms)
    }
}

/// `SystemTime` → Unix epoch milliseconds, saturating to 0 for pre-epoch times (which
/// never occur for `SystemTime::now()` but keeps the conversion total).
fn unix_millis(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The durable decision journal. Wraps an optional file path: `Some` when a writable
/// volume is configured (`PROTECTOR_ENGINE_JOURNAL_PATH`), `None` otherwise — in which
/// case every operation is a no-op and the engine runs exactly as it does today
/// (in-memory only). All public methods are infallible from the caller's view: a write
/// error is logged once and the journal disables itself, so a volume that goes away
/// mid-run can never crash the engine.
#[derive(Default)]
pub struct DecisionJournal {
    /// The active file path, or `None` for the disabled (in-memory-only) journal.
    path: Option<PathBuf>,
    /// Set once a write fails, so we stop retrying (and stop spamming the log) on a
    /// persistently-unwritable volume. Behind a `Mutex` to keep `record` `&self`.
    disabled: Mutex<bool>,
}

impl DecisionJournal {
    /// A disabled journal — records nothing, reloads nothing. The honest default when no
    /// volume is configured: behaviour is byte-identical to the pre-JEF-141 engine.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Build from the configured path. A probe write verifies the volume is actually
    /// writable; if it isn't (absent mount, read-only PVC), the journal degrades to
    /// [`disabled`](Self::disabled) with a warning — it NEVER errors. Parent dirs are
    /// created best-effort so a bare hostPath mount works without manual `mkdir`.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            // Best-effort: a failure here surfaces as the probe-write failure below.
            let _ = std::fs::create_dir_all(parent);
        }
        // Probe: open for append (creating if absent). This is the same access pattern
        // every `record` uses, so a success here means records will land.
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(_) => {
                tracing::info!(path = %path.display(), "decision journal enabled (durable)");
                Self {
                    path: Some(path),
                    disabled: Mutex::new(false),
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(), %error,
                    "decision journal volume is not writable; running in-memory only (no crash)"
                );
                Self::disabled()
            }
        }
    }

    /// Build from the `PROTECTOR_ENGINE_JOURNAL_PATH` env var, consistent with the other
    /// `PROTECTOR_ENGINE_*` mounted-file contracts. Unset/empty ⇒ [`disabled`](Self::disabled).
    pub fn from_env() -> Self {
        match std::env::var("PROTECTOR_ENGINE_JOURNAL_PATH") {
            Ok(path) if !path.trim().is_empty() => Self::open(path.trim()),
            _ => Self::disabled(),
        }
    }

    /// Whether the journal is durable (a writable volume is configured). `false` ⇒
    /// in-memory-only mode.
    pub fn is_enabled(&self) -> bool {
        self.path.is_some() && !*self.disabled.lock().expect("journal mutex poisoned")
    }

    /// Append one decision line. Infallible to the caller: a write error disables the
    /// journal (logged once) rather than propagating — a mounted volume that disappears
    /// mid-run degrades to in-memory, never a crash. Rotation is checked before the write
    /// so the active file stays under [`MAX_BYTES`].
    pub fn record(&self, decision: Decision) {
        self.append(JournalEntry::now(decision));
    }

    /// Append several decisions in one go (a pass's batch), each individually stamped.
    pub fn record_all(&self, decisions: impl IntoIterator<Item = Decision>) {
        for decision in decisions {
            self.record(decision);
        }
    }

    fn append(&self, entry: JournalEntry) {
        let Some(path) = &self.path else { return };
        {
            if *self.disabled.lock().expect("journal mutex poisoned") {
                return;
            }
        }
        if let Err(error) = self.try_append(path, &entry) {
            tracing::warn!(
                path = %path.display(), %error,
                "decision journal write failed; disabling journal (in-memory only from here)"
            );
            *self.disabled.lock().expect("journal mutex poisoned") = true;
        }
    }

    fn try_append(&self, path: &Path, entry: &JournalEntry) -> std::io::Result<()> {
        // One JSON line per decision. Serialization of these small, owned structs can't
        // fail in practice, but treat it as an IO-class error rather than panicking.
        let mut line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        rotate_if_needed(path)?;
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Replay the journal's tail, oldest line first, across the rotation boundary: the
    /// rolled generation (`<path>.1`) then the active file. Corrupt/truncated lines are
    /// skipped (a crash mid-write leaves at most one bad trailing line). Returns an
    /// empty vec when the journal is disabled or the files are absent — never an error.
    pub fn replay(&self) -> Vec<JournalEntry> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        let mut entries = Vec::new();
        // Rolled generation first (older), then the active file (newer), so the result
        // is in chronological order.
        for p in [rolled_path(path), path.clone()] {
            if let Ok(contents) = std::fs::read_to_string(&p) {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(entry) = serde_json::from_str::<JournalEntry>(line) {
                        entries.push(entry);
                    }
                    // else: a corrupt/partial line (crash mid-write) — skip it.
                }
            }
        }
        entries
    }
}

/// The rolled-generation path for `path`: `<path>.1`. A single generation keeps total
/// on-disk size bounded (~`2 × MAX_BYTES`) while still spanning the rotation boundary on
/// replay.
fn rolled_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// Rotate the active file when it exceeds [`MAX_BYTES`]: move it to `<path>.1` (replacing
/// any prior roll), leaving the caller to create a fresh active file on the next write.
/// A missing file (nothing written yet) or a size under the cap is a no-op.
fn rotate_if_needed(path: &Path) -> std::io::Result<()> {
    let over_cap = match std::fs::metadata(path) {
        Ok(meta) => meta.len() >= MAX_BYTES,
        Err(_) => false, // not created yet → nothing to rotate
    };
    if over_cap {
        // `rename` replaces an existing destination atomically on the same volume, so the
        // prior `.1` is discarded — we keep exactly one rolled generation.
        std::fs::rename(path, rolled_path(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
        assert!(matches!(entries[0].decision, Decision::Breach { .. }));
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
            Decision::Breach { coverage, .. } => {
                assert!(
                    coverage.is_none(),
                    "absent coverage degrades to unknown, not a gap"
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
}
