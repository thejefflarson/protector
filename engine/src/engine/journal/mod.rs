//! The decision journal (JEF-141): a durable, append-only record of what the engine
//! decided, so a pod restart doesn't wipe decision history and leave the output state
//! blank for ~20 min while the caches and the CPU model warm.
//!
//! The findings snapshot, the judgement ring, and the mitigation ledger are all in-memory: a
//! restart loses them. The journal closes that gap. Each pass appends its **breach
//! decisions** (the model's per-entry verdict), its per-entry **cut-choice decisions**
//! (ADR-0034 D8, JEF-639 — see [`Decision::Incident`]), and its **ledger deltas** (a
//! mitigation applied or a cut reverted, with the
//! [`Reversion`](super::respond::actuator::Reversion) reason) as JSON lines to a file on a
//! mounted volume; on boot the engine replays the tail so the findings snapshot, the
//! judgement record, and the reversion log populate immediately — before a fresh model pass
//! lands.
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
//!
//! Split into a module directory (repo CLAUDE.md's 1,000-line cap): this file is the types +
//! the durable store; [`tests`] holds the file's own unit tests. The engine-orchestration
//! integration tests (journal replay wired into `Engine::process`) live in the sibling
//! `engine::journal_tests` module instead — a different file, a different concern.

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

/// One cut the model chose, durably recorded (ADR-0034 D8, JEF-639) as exactly the two
/// facts the replay-lock checks — the node it named and the mechanism determinism resolved
/// it to AT DECISION TIME. The mechanism/edge (`ProposedAction`/`Link`) are deliberately
/// **not** persisted: on replay they are always RE-DERIVED from the CURRENT menu (never
/// trusted from disk) — see `engine::adj_pass::rearm_restored_decision`. Persisting a copy
/// here would only invite a future caller to skip that re-derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournaledCut {
    /// The node key the model named (verbatim from `contain`, engine-resolved before this
    /// point — never raw model text).
    pub node: String,
    /// The stable cut identity ([`crate::engine::respond::cut_signature`]) determinism
    /// resolved this node to when the decision was made — the replay-lock's second lock
    /// compares this byte-for-byte against a FRESH resolution before re-arming.
    pub cut_signature: String,
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
        /// The evidence FINGERPRINT this decisive verdict was judged against (JEF-301) — the
        /// freshness key. On boot the engine re-seeds the verdict cache from this line, so an
        /// entry whose current fingerprint still MATCHES is served from cache with NO model
        /// call (the big request-volume cut across a protector/Ollama restart); the moment the
        /// fingerprint CHANGES (new CVE / runtime / objective) the cache misses and the entry
        /// re-judges — a stale verdict is never served for changed evidence. `None` on lines
        /// written before JEF-301 (via `#[serde(default)]`): those replay display-only, exactly
        /// today's behaviour, never a cache hit against an unknown fingerprint.
        #[serde(default)]
        fingerprint: Option<String>,
        /// The TYPED decisive verdict (JEF-301), so replay restores the EXACT prior decision
        /// into the verdict cache — a persisted `Exploitable` (a breach) stays `Exploitable`
        /// on boot, never downgraded to a benign or display-only string. Only decisive
        /// verdicts are ever journaled (an `Uncertain`/backed-off timeout never is), so this is
        /// never a persisted "awaiting". `None` on pre-JEF-301 lines (display-only restore).
        #[serde(default)]
        verdict_typed: Option<crate::engine::reason::adjudicate::Verdict>,
    },
    /// One incident cut-choice decision (ADR-0034 D8, JEF-639): the model's per-entry
    /// `IncidentDecision`, durably keyed by the resolved [`JournaledCut::cut_signature`]s it
    /// chose AND the full-prompt `fingerprint` it was judged against. This is the persistence
    /// gap JEF-570 deliberately left open — its Engine-local `decisions` map was in-memory
    /// only, so a restart dropped every standing model-chosen cut to the `containment_for`
    /// human-proposal fallback until re-judged (a real gap under ENFORCE mode: the standing
    /// cut looks retired for the model's cold-start window).
    ///
    /// **On replay, this line re-arms EXACTLY the decision it recorded, or nothing — a
    /// DOUBLE replay-lock** (see `engine::adj_pass::rearm_restored_decision`, run once this
    /// run's own state is available):
    /// 1. `fingerprint` must match the entry's RECOMPUTED full-prompt hash byte-identically
    ///    (the fingerprint ⊇ the menu render, ADR-0034 D4/D9, so a shifted node→mechanism
    ///    mapping already busts it — a fingerprint match alone does NOT re-arm);
    /// 2. AND every cut in `cuts` must re-resolve, byte-identically, to the SAME
    ///    `cut_signature` against the FRESHLY-rebuilt current menu — guards against a
    ///    label/ladder RESOLVER drift between deployed versions that an unchanged fingerprint
    ///    alone can't catch (the prompt hash covers the RENDERED menu text, not the resolver
    ///    code that produced it).
    ///
    /// Either lock failing re-arms **nothing** for this entry — a cold re-judge, never a
    /// partial or best-guess repoint (SECURITY-SENSITIVE: this is the replay/re-arm path for
    /// a possibly-armed cut; an over-eager re-arm could auto-apply a cut the current state no
    /// longer justifies). Old, pre-JEF-639 journals hold no `Incident` lines at all — every
    /// entry cold-re-judges for cuts on first boot after the upgrade (their `Breach` lines
    /// still replay exactly as before, display-only for the verdict text). Only DECISIVE
    /// decisions are ever journaled (mirrors [`Breach`](Self::Breach)); a fresh `Uncertain`
    /// never is (ADR-0034 D7's retirement asymmetry is orthogonal to persistence).
    Incident {
        /// The internet-facing entry this decision was judged for (the ledger's key).
        entry: String,
        /// How many objectives the entry reached when judged (display-only, mirrors
        /// [`Breach::objectives`](Self::Breach)).
        objectives: usize,
        /// The model's 3-value call (ADR-0034 D1).
        assessment: crate::engine::reason::adjudicate::incident::Assessment,
        /// The model's one-sentence reason (display-only; never re-parsed or re-guarded).
        reason: String,
        /// The cuts the model chose, exactly as determinism resolved them AT DECISION TIME —
        /// re-verified, never trusted, on replay (see the type's own docs).
        cuts: Vec<JournaledCut>,
        /// The full-prompt fingerprint this decision was judged against — the replay-lock's
        /// first lock (see the variant docs above).
        fingerprint: String,
    },
    /// One entry's shadow-bake divergence classification (the model-vs-deterministic cut
    /// comparator, `super::cut_divergence`): how the model's chosen cut-set for this entry, this
    /// pass, compared against the deterministic fallback set `respond::containment_for` +
    /// `respond::quarantine_workload_link` would have proposed for the same chains. Durable so
    /// the bake history survives a restart rather than resetting the arm-readiness window (see
    /// `docs/adr/0037-shadow-bake-arm-readiness.md`). Audit only — a consumer reads this to decide
    /// whether the bake has cleared the
    /// exit criterion; nothing re-arms or auto-applies from it (ADR-0016).
    CutDivergence {
        /// The internet-facing entry this classification was computed for.
        entry: String,
        /// How the model's cut-set compared to the deterministic fallback set.
        class: crate::engine::cut_divergence::DivergenceClass,
        /// Node keys the model named this pass (sorted, deduped) — empty for a decisive
        /// `NoAttack`.
        model_cuts: Vec<String>,
        /// Node keys determinism alone would have proposed for the same chains (sorted,
        /// deduped).
        deterministic_cuts: Vec<String>,
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
        /// The strongest signing-posture rank ever learned under this repo (JEF-280) — the yardstick
        /// baseline-relative downgrade detection compares a fresh posture against. `#[serde(default)]`
        /// so a line written before this field existed replays as `Keyless`
        /// ([`PostureRank::default`](crate::policies::signature::PostureRank::default)) — the honest
        /// historical value (the store only ever learned from keyless `Signed` postures), never a
        /// weaker rank that would miss a downgrade.
        #[serde(default)]
        rank: crate::policies::signature::PostureRank,
        /// Every source repository observed in a VERIFIED SLSA build-provenance attestation under
        /// this repo (JEF-275, ADR-0020 §5) — the provenance continuity axis, TOFU-learned like the
        /// signer identities (sorted, deduped). `#[serde(default)]` so lines predating the
        /// provenance axis replay with an empty set (cold provenance), never a fabricated identity.
        /// UNTRUSTED predicate text — escape at render.
        #[serde(default)]
        provenance_sources: Vec<String>,
        /// Every builder identity (SLSA `builder.id`) observed in a VERIFIED provenance attestation
        /// under this repo (JEF-275). `#[serde(default)]` for the same forward-compat reason.
        /// UNTRUSTED — escape at render.
        #[serde(default)]
        provenance_builders: Vec<String>,
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
mod tests;
