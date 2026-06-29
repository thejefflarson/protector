//! The single per-entry verdict store (JEF-157) and the coverage shapes that ride alongside it:
//! the [`VerdictStore`] + its per-entry [`VerdictEntry`], the behavioral-bake [`BakeStats`]
//! snapshot, the [`ModelHealth`] enum, and the [`ReadinessConfig`] presence/absence summary.
//!
//! This is the engine's per-entry verdict memory — the one source of truth for the model's call
//! on each internet-facing entry, collapsing what used to be four separate maps into one record
//! so a verdict written the instant it lands is visible everywhere it is read. Pure data: it
//! holds no rendering.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use crate::engine::reason::adjudicate::Verdict;
use crate::engine::reason::backoff::{CircuitBreaker, EntryBackoff};

use super::recency::{Delta, RecencyInfo, StoredPosture};

/// The behavioral-bake snapshot (JEF-48): what the behavioral port saw in the most
/// recent pass. The same per-pass figures feed the OTLP counters (JEF-100) — this is the
/// in-process mirror. Purely observational: it carries no per-pod payload, only counts and
/// low-cardinality variant labels.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BakeStats {
    /// Signals ingested this pass by [`crate::engine::graph::Behavior::variant_label`]
    /// (connection / secret-read / library-load / exec / priv-change / file-read /
    /// alert), ordered by variant for a stable table.
    pub signals_by_variant: BTreeMap<String, u64>,
    /// Signals this pass the runtime adapter could attribute to a live workload
    /// (a namespace/name attribution, or a cgroup UID matching a pod in the snapshot).
    pub resolved: u64,
    /// Signals this pass whose attribution did NOT resolve (unknown cgroup UID — pod
    /// gone or not yet observed). A sustained nonzero share is the JEF-48 attribution
    /// exit-criterion to watch.
    pub unresolved: u64,
    /// The live (TTL'd) runtime-store cardinality as of this pass — the working set.
    pub runtime_store: u64,
    /// Corroborations that fired this pass: breach-relevant chains a live runtime signal
    /// completed (ADR-0009). In shadow this is the countable "would this have promoted?"
    pub corroborations: u64,
}

impl BakeStats {
    /// Total signals ingested this pass (the sum across variants), the volume figure
    /// for the JEF-48 "signal volume per node is sane" criterion.
    pub fn total_signals(&self) -> u64 {
        self.signals_by_variant.values().copied().sum()
    }

    /// The fraction of attributed signals that did NOT resolve to a live workload, in
    /// `[0, 1]`; `0.0` when nothing was attributed this pass (no signals → no misses).
    /// This is the engine-side resolution rate JEF-48 reads attribution quality from.
    #[allow(dead_code)]
    pub fn unresolved_fraction(&self) -> f64 {
        let total = self.resolved + self.unresolved;
        if total == 0 {
            0.0
        } else {
            self.unresolved as f64 / total as f64
        }
    }
}

/// The LIVE health of the model adjudicator, derived cheaply by piggybacking the LAST
/// adjudication outcome (JEF-160) — NOT a fresh model call. The judging loop stamps this
/// on every fresh call (cache misses): a decisive verdict is [`Ok`](Self::Ok); an
/// inconclusive one ("model unavailable" — a CPU-model timeout / down endpoint) is
/// [`Timeout`](Self::Timeout). [`Unknown`](Self::Unknown) until the model has actually
/// been called this run (cold start, or no model configured — see [`ReadinessConfig`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelHealth {
    /// No fresh model call has landed yet this run (cold start), or no model is
    /// configured at all (the absence is reported via [`ReadinessConfig::model_attached`]).
    #[default]
    Unknown,
    /// The most recent fresh adjudication returned a decisive verdict — the model answered.
    Ok,
    /// The most recent fresh adjudication came back inconclusive ("model unavailable") —
    /// the CPU model timed out or the endpoint is down. The decision still falls through
    /// to the skeptic default, but the model is not currently answering.
    Timeout,
}

impl ModelHealth {
    /// The `u8` wire form for the atomic store on [`super::Findings`] (no extra deps for an
    /// enum atomic). Round-trips through [`from_u8`](Self::from_u8).
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            ModelHealth::Unknown => 0,
            ModelHealth::Ok => 1,
            ModelHealth::Timeout => 2,
        }
    }

    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => ModelHealth::Ok,
            2 => ModelHealth::Timeout,
            _ => ModelHealth::Unknown,
        }
    }
}

/// The engine's **config summary** for the readiness aggregation (JEF-160): presence/absence of
/// each decision input, NOT a config echo. This carries no secret names, no endpoints, no
/// values — only whether an input is wired and (for the file-backed stores) how many
/// entries loaded, which is a non-sensitive coverage figure. Captured once at boot from the
/// same env/handles the engine already reads, and threaded into [`super::derive_readiness`] so
/// the snapshot reports LIVE presence rather than guessing.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadinessConfig {
    /// A model adjudicator is configured (`PROTECTOR_ENGINE_MODEL` set). When false, NO
    /// exploitability calls are made — every breach-relevant chain falls through to the
    /// deterministic skeptic default, the single most load-bearing coverage gap (ADR-0016).
    pub model_attached: bool,
    /// How many KEV CVE ids loaded from the mounted catalogue. `0` ⇒ the store is absent
    /// or empty, so no known-exploited enrichment reaches the model.
    pub kev_count: usize,
    /// How many EPSS scores loaded from the mounted FIRST.org feed (JEF-243). `0` ⇒ the
    /// store is absent or empty, so no exploit-prediction enrichment reaches the model.
    pub epss_count: usize,
    /// The decision journal is durable (a writable `PROTECTOR_ENGINE_JOURNAL_PATH` volume
    /// is mounted). `false` ⇒ in-memory only: verdicts and the would-have-acted aggregation
    /// don't survive a restart.
    pub journal_durable: bool,
    /// Any action class is armed (`engine.enable` non-empty) — enforcing vs shadow. This
    /// is posture, not a gap: shadow is the safe default, reported so the operator can SEE
    /// it rather than infer it.
    pub armed: bool,
}

/// One internet-facing entry's verdict state — the SINGLE source of truth for the
/// model's call on that entry (JEF-157). Collapses what used to be four separate
/// per-entry maps in the engine (`last_verdict` / `verdict_cache` / `restored_verdicts`
/// / `journaled_verdicts`) into one record, so the findings snapshot and the judgement
/// record can never disagree on an entry's verdict and the verdict is visible the instant
/// it lands — not only at end-of-pass.
#[derive(Debug, Clone, Default)]
pub struct VerdictEntry {
    /// The current DISPLAY verdict, typed — the carry-forward + Uncertain-fallback
    /// memory (formerly `last_verdict`). `None` until a live verdict has been displayed
    /// this run; a journal-restored entry carries [`restored`](Self::restored) instead.
    pub display: Option<Verdict>,
    /// A verdict restored from the durable journal on boot (JEF-141), its summary string
    /// — held until a live verdict supersedes it (formerly `restored_verdicts`). Cleared
    /// once `display` lands a live verdict for the entry.
    pub restored: Option<String>,
    /// The cached DECISIVE verdict and the evidence fingerprint it was judged against —
    /// the re-judge gate (formerly `verdict_cache`). Present only for a decisive verdict;
    /// an unchanged fingerprint serves this without calling the (slow CPU) model again.
    pub cached: Option<(String, Verdict)>,
    /// The last verdict summary journaled + notified for this entry — the dedup key
    /// (formerly `journaled_verdicts`), so a steady-state cluster writes/notifies once
    /// per change, not per pass.
    pub journaled: Option<String>,
    /// Exponential-backoff state for INCONCLUSIVE adjudication (JEF-234). An `Uncertain`
    /// verdict (a model timeout / Ollama-down / OOM) is never cached, so without this gate
    /// the entry is re-judged every pass and hammers a struggling model. Each `Uncertain`
    /// grows the retry delay; a decisive verdict resets it. The verdict cache above still
    /// serves decisive verdicts — this only gates the re-judge of failed ones.
    pub backoff: EntryBackoff,
    /// When this entry's key FIRST appeared (JEF-201) — set the first pass the key is seen,
    /// never overwritten after. The Δ column's age is measured from here, NOT from render
    /// time, so it survives repeated reads. A journal-restored entry seeds this with a
    /// synthetic PAST instant (so it never reads as "this pass") via [`restored_recency`].
    ///
    /// [`restored_recency`]: Self::restored_recency
    pub first_seen: Option<Instant>,
    /// The DISPLAY posture this entry carried on the PREVIOUS pass (JEF-201), updated each
    /// pass by diffing the new posture against it. `None` until the first recency update; the
    /// diff against it yields the Δ glyph (escalated / de-escalated / unchanged).
    pub prev_posture: Option<StoredPosture>,
    /// The Δ verdict computed on the LAST recency update (JEF-201) — what changed at the most
    /// recent pass. Held here (not recomputed at render) so a re-read with no new pass shows
    /// the same Δ rather than flickering to NEW. `None` until the first recency update has run
    /// for the entry.
    pub last_delta: Option<Delta>,
    /// Whether this entry was RESTORED from the durable journal on boot (JEF-201, JEF-141) —
    /// it existed before this run, so its first live recency update must read [`Delta::Restored`],
    /// never NEW. Cleared once a live pass re-judges it.
    pub restored_recency: bool,
}

impl VerdictEntry {
    /// The summary string to DISPLAY for this entry: the live display verdict if one
    /// has landed this run, else the journal-restored summary, else nothing. This is
    /// exactly the carry-forward precedence the engine used to apply at publish time —
    /// a live verdict supersedes a restored one — now in one place.
    pub(crate) fn display_summary(&self) -> Option<String> {
        self.display
            .as_ref()
            .map(Verdict::summary)
            .or_else(|| self.restored.clone())
    }

    /// The entry's resolved recency facts at `now` (JEF-201): the stored Δ verdict and the
    /// age since `first_seen`. The Δ is the one computed at the LAST recency update (held in
    /// `last_delta`), so this is stable across repeated reads — `now` only freshens the
    /// human age, never the glyph. A restored entry reports no meaningful age (its first_seen
    /// is synthetic). `None` Δ (no recency update yet) reads as `Unchanged` with no age.
    pub(crate) fn recency_info(&self, now: Instant) -> RecencyInfo {
        let delta = self.last_delta.unwrap_or(Delta::Unchanged);
        // A restored entry's first_seen is synthetic — its age is not a real "seen N ago".
        let age_secs = if self.restored_recency {
            None
        } else {
            self.first_seen
                .map(|fs| now.saturating_duration_since(fs).as_secs())
        };
        RecencyInfo { delta, age_secs }
    }
}

/// The single per-entry verdict store (JEF-157): the one source of truth for the
/// model's verdict per internet-facing entry, shared (`Arc`) between the judging loop (the
/// writer) and the findings snapshot (the reader). Both the findings snapshot (via
/// [`super::Findings::snapshot`]) and the per-pass display derive each finding's verdict by
/// looking its entry up here at read time, so a verdict is visible the moment it is written —
/// there is no end-of-pass re-publish lag. Keyed by the entry's node key.
#[derive(Default)]
pub struct VerdictStore {
    entries: Mutex<BTreeMap<String, VerdictEntry>>,
    /// The GLOBAL inconclusive-adjudication circuit-breaker (JEF-234): when the model
    /// looks fully down (a run of consecutive `Uncertain` calls across all entries), the
    /// whole judging pass skips its model calls for a cooldown, so a fully-down Ollama's
    /// total calls-per-window is bounded regardless of entry count. A decisive success
    /// closes it. Separate lock from `entries` — it is touched once per call, not per entry.
    breaker: Mutex<CircuitBreaker>,
}

/// A stable per-entry seed for the backoff jitter (JEF-234), derived from the entry key
/// so two entries that fail on the same pass spread their retries apart rather than
/// thundering back together. A plain `DefaultHasher` of the key — deterministic per key,
/// no external dependency.
fn jitter_seed(entry: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    entry.hash(&mut h);
    h.finish()
}

impl VerdictStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The display summary for an entry, if any — what a finding from that entry shows
    /// (a live verdict, or a journal-restored one). `None` when the entry has no verdict
    /// yet (the model hasn't reached it).
    pub fn display_summary(&self, entry: &str) -> Option<String> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(VerdictEntry::display_summary)
    }

    /// Apply a mutation to an entry's record (inserting a default first), under one lock.
    /// The engine's writes go through this so each is atomic and visible immediately.
    pub(crate) fn update(&self, entry: &str, f: impl FnOnce(&mut VerdictEntry)) {
        let mut entries = self.entries.lock().expect("verdict store mutex poisoned");
        f(entries.entry(entry.to_string()).or_default());
    }

    /// Seed a journal-restored verdict summary for an entry (JEF-141) — held until a
    /// live verdict supersedes it. Does not touch the cache or the journaled-dedup key.
    ///
    /// JEF-201: a restored entry existed BEFORE this run, so it must never read as NEW in the
    /// Δ column. This marks it `restored_recency` and seeds its `first_seen` with a synthetic
    /// PAST instant (`restored_at`, the journal's last-pass time) so the recency tracker treats
    /// it as pre-existing. The first live pass that re-judges it clears the restored flag.
    pub fn seed_restored(&self, entry: &str, summary: String, restored_at: Instant) {
        self.update(entry, |e| {
            e.restored = Some(summary);
            e.restored_recency = true;
            e.first_seen.get_or_insert(restored_at);
            // A restored entry already has a posture to diff future passes against; until a
            // live pass lands, its Δ reads `Restored` (not `New`).
            e.last_delta.get_or_insert(Delta::Restored);
            e.prev_posture.get_or_insert(StoredPosture::Awaiting);
        });
    }

    /// Record this pass's display POSTURE for an entry and compute its Δ (JEF-201): set
    /// `first_seen` on first sight, diff the new posture against the stored `prev_posture`,
    /// store the resulting [`Delta`], and roll `prev_posture` forward. `now` is injected (the
    /// pass's single `Instant`) so the recency tracking is deterministic in tests and shares
    /// the same clock as the JEF-234 backoff. Pure presentation metadata — never gates a
    /// decision (ADR-0016). A previously-restored entry's first live posture clears the
    /// restored flag and reads as `Restored` for one pass (it existed before this run), then
    /// diffs normally.
    pub fn record_recency(&self, entry: &str, posture: StoredPosture, now: Instant) {
        self.update(entry, |e| {
            let first = e.first_seen.is_none() && !e.restored_recency;
            e.first_seen.get_or_insert(now);
            let delta = if first {
                // Brand-new key this run — NEW regardless of which posture it lands on.
                Delta::New
            } else if e.restored_recency {
                // It was restored from history; its first live pass reads `Restored`, not NEW.
                e.restored_recency = false;
                Delta::Restored
            } else {
                match e.prev_posture {
                    Some(prev) => StoredPosture::delta_from(prev, posture),
                    // No previous posture but already seen (e.g. restored seeded Awaiting and
                    // then cleared): treat as unchanged rather than fabricating an arrow.
                    None => Delta::Unchanged,
                }
            };
            e.last_delta = Some(delta);
            e.prev_posture = Some(posture);
        });
    }

    /// The entry's resolved recency facts at `now` (JEF-201) — the Δ verdict + age the Δ
    /// column renders. `None` when the entry has no record yet (never seen). `now` is injected
    /// for deterministic tests.
    pub fn recency_for(&self, entry: &str, now: Instant) -> Option<RecencyInfo> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .map(|e| e.recency_info(now))
    }

    /// The cached decisive verdict for an entry whose fingerprint matches — the re-judge
    /// gate. `Some(verdict)` serves the cache (no model call); `None` means re-judge.
    pub fn cached_for(&self, entry: &str, fingerprint: &str) -> Option<Verdict> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| match &e.cached {
                Some((fp, v)) if fp == fingerprint => Some(v.clone()),
                _ => None,
            })
    }

    /// Cache a fresh DECISIVE verdict + its fingerprint for the re-judge gate.
    pub fn cache_decisive(&self, entry: &str, fingerprint: String, verdict: Verdict) {
        self.update(entry, |e| e.cached = Some((fingerprint, verdict)));
    }

    /// JEF-234 — whether the judging loop should SKIP the model call for `entry` this pass
    /// because it is in inconclusive-adjudication backoff at `now`. On a cache MISS the loop
    /// checks this BEFORE calling `judge()`: if backing off it keeps the prior display
    /// verdict and does not touch the (struggling) model. `now` is injected for testability.
    pub fn entry_backing_off(&self, entry: &str, now: Instant) -> bool {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .is_some_and(|e| e.backoff.is_backing_off(now))
    }

    /// JEF-234 — record an INCONCLUSIVE (`Uncertain`) adjudication for `entry` at `now`:
    /// grow the entry's exponential backoff AND advance the global breaker's failure run.
    /// The jitter seed is derived from the entry key so distinct entries de-sync their
    /// retries. Does NOT cache the verdict (Uncertain is never decisive) — the backoff is
    /// the gate.
    pub fn record_inconclusive(&self, entry: &str, now: Instant) {
        let seed = jitter_seed(entry);
        self.update(entry, |e| e.backoff.record_failure(now, seed));
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .record_failure(now);
    }

    /// JEF-234 — record a DECISIVE adjudication for `entry`: clear the entry's backoff and
    /// close the global breaker (the model answered). Pairs with [`cache_decisive`], which
    /// the loop still calls to cache the verdict itself.
    ///
    /// [`cache_decisive`]: Self::cache_decisive
    pub fn record_decisive(&self, entry: &str) {
        self.update(entry, |e| e.backoff.record_success());
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .record_success();
    }

    /// JEF-234 — whether the GLOBAL breaker is open at `now`: the whole judging pass should
    /// skip its model calls (the model looks fully down). `now` is injected for testability.
    pub fn breaker_open(&self, now: Instant) -> bool {
        self.breaker
            .lock()
            .expect("verdict store breaker mutex poisoned")
            .is_open(now)
    }

    /// The entry's current typed DISPLAY verdict (the carry-forward + Uncertain-fallback
    /// memory), if a live one has landed this run.
    pub fn display_verdict(&self, entry: &str) -> Option<Verdict> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| e.display.clone())
    }

    /// Record the entry's DISPLAY verdict the instant it is decided — making it visible
    /// on the findings snapshot immediately (the JEF-157 no-lag fix). A live verdict
    /// supersedes any journal-restored one for the entry.
    pub fn set_display(&self, entry: &str, verdict: Verdict) {
        self.update(entry, |e| {
            e.display = Some(verdict);
            e.restored = None;
        });
    }

    /// The last verdict summary journaled/notified for an entry — the dedup key.
    pub fn journaled(&self, entry: &str) -> Option<String> {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .get(entry)
            .and_then(|e| e.journaled.clone())
    }

    /// Record the verdict summary just journaled/notified for an entry (the dedup key).
    pub fn set_journaled(&self, entry: &str, summary: String) {
        self.update(entry, |e| e.journaled = Some(summary));
    }

    /// Drop entries that are no longer present in the live cluster (ephemeral workloads,
    /// removed exposure), so the store tracks the live cluster rather than growing
    /// forever — the prune the engine ran across all four maps each pass.
    pub fn retain_present(&self, present: &std::collections::HashSet<String>) {
        self.entries
            .lock()
            .expect("verdict store mutex poisoned")
            .retain(|entry, _| present.contains(entry));
    }
}
