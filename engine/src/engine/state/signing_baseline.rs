//! The durable, per-repository TOFU signing baseline (JEF-263, ADR-0020 §2).
//!
//! Observation (JEF-261) is a *snapshot*: it says "this image is signed by X right now". It
//! cannot see a **change** in signing posture over time — which is the actual supply-chain
//! attack (a repo that has always shipped signed by one CI identity suddenly ships signed by
//! a different one, or unsigned). This module learns and remembers the missing history: for
//! each **repository** (`registry/repo`, never tag/digest), the set of identities/issuers
//! that have signed images under it, when it was first seen signed, and whether that history
//! is `established` yet (Trust On First Use).
//!
//! ## Durability (same footing as the decision journal)
//!
//! The baseline rides the SAME durable [`DecisionJournal`](crate::engine::journal::DecisionJournal)
//! as every other decision atom — one file, one `PROTECTOR_ENGINE_JOURNAL_PATH`, no second
//! store or env var. On boot the engine [`restore`](SigningBaselineStore::restore)s the
//! journal's tail into memory (exactly how the admission log is repopulated), so a learned
//! baseline survives a restart. A disabled journal ⇒ in-memory only: the store still works,
//! but a restart resets it and it honestly re-learns from observation (all cold-start until
//! re-observed).
//!
//! ## Compaction, NOT rotation-aging
//!
//! The journal is bounded by size with a single-generation rotation that trims old lines. A
//! naive append-once would let an *established* baseline age out of the window on a busy
//! journal and silently re-arm cold-start trust. So each baseline line is **full state**
//! (last-write-wins on replay) and the store [`compact`](SigningBaselineStore::compact)s —
//! re-appends every live repo's baseline each pass — so a live repo's line is always inside
//! the rotation window. In practice a cluster has tens to low-hundreds of distinct repos, so
//! per-pass compaction is a handful of small lines, negligible against the journal cap; the
//! [`DEFAULT_MAX_REPOS`] cap bounds the pathological case.
//!
//! ## Scope (JEF-263)
//!
//! Persistence + in-memory store + boot replay ONLY. Drift *detection*/findings (JEF-264),
//! enforcement (JEF-265), the dashboard render (JEF-262), and Rekor history (JEF-266) consume
//! the baseline this exposes; they are NOT built here. The store only ever *learns* from a
//! `Signed` posture — it never emits a verdict, never gates, and treats a new tag/digest
//! under a known repo as the same baseline (not drift). The identities/issuers are UNTRUSTED
//! Fulcio cert text; a consumer MUST escape them at render (this state never leaves the
//! cluster).

use std::collections::{BTreeSet, HashMap};

use crate::engine::journal::{Decision, DecisionJournal};
use crate::policies::signature::{SigningPosture, repo_key};

/// How long after `first_seen` a baseline is considered [`established`](SigningBaseline::established).
///
/// **Design decision (ADR-0020 addendum, JEF-263): `established` = wall-clock age, not
/// digest-count.** A baseline matures 24h after the repo was first observed signed. Rationale:
/// the whole point of a TOFU baseline is that the FIRST observation is the weakest evidence
/// (it could be the attacker's first signed push), so trust should mature over time rather
/// than on a counter an attacker can inflate by pushing many digests in a burst. Wall-clock
/// age needs no extra durable state (we already persist `first_seen_ms`) and is monotonic —
/// once established, a baseline never un-establishes on a later observation. A digest-count or
/// distinct-day refinement is a future option; `established` + `first_seen` are exposed so
/// JEF-262/JEF-264 can render/weigh the distinction however they choose.
const ESTABLISH_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// Upper bound on distinct repositories tracked in memory. A safety cap for the pathological
/// case (thousands of distinct repos churning through the cluster); a real cluster stays far
/// below it. When inserting a NEW repo would exceed this, one entry is evicted — preferring a
/// non-`established` (cold, cheaply re-learned) entry, oldest-updated first, so a matured
/// baseline is never dropped in favour of churn.
pub const DEFAULT_MAX_REPOS: usize = 4096;

/// One repository's learned signing baseline (JEF-263). Keyed elsewhere by the `registry/repo`
/// string; this is the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningBaseline {
    /// Every signer identity observed signing an image under this repo. A `BTreeSet` so the
    /// set is deduped and deterministically ordered (stable journal lines, stable render).
    /// UNTRUSTED Fulcio cert text — escape at render.
    pub identities: BTreeSet<String>,
    /// Every OIDC issuer observed signing under this repo (deduped, sorted). UNTRUSTED.
    pub issuers: BTreeSet<String>,
    /// When the repo was first observed with a verifying signature, Unix epoch millis.
    pub first_seen_ms: u64,
    /// Whether the signed history has matured past the TOFU grace window (see
    /// [`ESTABLISH_AGE_MS`]). `false` ⇒ a freshly-learned baseline: weaker evidence.
    pub established: bool,
    /// When this baseline was last updated (observed or replayed), Unix epoch millis. In-memory
    /// only (not journaled) — used solely to order eviction. `pub(crate)` so it isn't part of
    /// the public value shape.
    pub(crate) last_updated_ms: u64,
}

impl SigningBaseline {
    /// Serialize this repo's baseline to a full-state journal decision (compaction line).
    fn to_decision(&self, repo: &str) -> Decision {
        Decision::SigningBaseline {
            repo: repo.to_string(),
            identities: self.identities.iter().cloned().collect(),
            issuers: self.issuers.iter().cloned().collect(),
            first_seen_ms: self.first_seen_ms,
            established: self.established,
        }
    }
}

/// The in-memory, per-repository signing-baseline store (JEF-263). Learns from observed
/// `Signed` postures, persists each change to the durable journal as a full-state line, and
/// is [`restore`](Self::restore)d from that journal on boot. Bounded by [`DEFAULT_MAX_REPOS`]
/// with the eviction policy documented there.
#[derive(Debug, Clone)]
pub struct SigningBaselineStore {
    baselines: HashMap<String, SigningBaseline>,
    max_repos: usize,
}

impl Default for SigningBaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningBaselineStore {
    /// A store with the default repo cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_REPOS)
    }

    /// A store with an explicit repo cap (for tests that exercise eviction cheaply).
    pub fn with_capacity(max_repos: usize) -> Self {
        Self {
            baselines: HashMap::new(),
            max_repos: max_repos.max(1),
        }
    }

    /// The learned baseline for a `registry/repo` key, if any.
    pub fn get(&self, repo: &str) -> Option<&SigningBaseline> {
        self.baselines.get(repo)
    }

    /// Number of distinct repositories with a learned baseline.
    pub fn len(&self) -> usize {
        self.baselines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.baselines.is_empty()
    }

    /// All learned `(repo, baseline)` pairs — what JEF-262/JEF-264 read. Order is unspecified.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &SigningBaseline)> {
        self.baselines.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Learn from one observed posture, keyed by the image's `registry/repo`. ONLY a `Signed`
    /// posture updates a baseline (a not-signed / invalid / checking posture is left to the
    /// drift work, JEF-264, and never creates or mutates a baseline here). Returns the repo key
    /// when the baseline was created or changed (new identity/issuer, or `established` flipped),
    /// so the caller can persist just that change; `None` when nothing changed.
    ///
    /// A new tag/digest under a repo with an existing baseline folds to the same key: it does
    /// NOT create a new baseline (and, by construction, is not drift here).
    pub fn observe(
        &mut self,
        image: &str,
        posture: &SigningPosture,
        now_ms: u64,
    ) -> Option<String> {
        let signer = posture.signer()?;
        let repo = repo_key(image);

        if let Some(existing) = self.baselines.get_mut(&repo) {
            let mut changed = false;
            changed |= existing.identities.insert(signer.identity.clone());
            if let Some(issuer) = signer.issuer.as_ref() {
                changed |= existing.issuers.insert(issuer.clone());
            }
            let established = existing.established
                || now_ms.saturating_sub(existing.first_seen_ms) >= ESTABLISH_AGE_MS;
            if established != existing.established {
                existing.established = established;
                changed = true;
            }
            existing.last_updated_ms = now_ms;
            return if changed { Some(repo) } else { None };
        }

        // First time we've seen this repo signed: establish the baseline (cold-start, weak).
        let mut identities = BTreeSet::new();
        identities.insert(signer.identity.clone());
        let mut issuers = BTreeSet::new();
        if let Some(issuer) = signer.issuer.as_ref() {
            issuers.insert(issuer.clone());
        }
        self.evict_if_full();
        self.baselines.insert(
            repo.clone(),
            SigningBaseline {
                identities,
                issuers,
                first_seen_ms: now_ms,
                // First sight is always cold-start (first_seen == now): weakest evidence.
                established: false,
                last_updated_ms: now_ms,
            },
        );
        Some(repo)
    }

    /// Persist one repo's current baseline to the journal as a full-state line. A no-op if the
    /// repo isn't tracked. Infallible from the caller's view (a disabled/unwritable journal is
    /// itself a no-op).
    pub fn persist(&self, journal: &DecisionJournal, repo: &str) {
        if let Some(baseline) = self.baselines.get(repo) {
            journal.record(baseline.to_decision(repo));
        }
    }

    /// Re-append EVERY live repo's baseline as a fresh full-state line (compaction). Called per
    /// pass so a live repo's line stays inside the journal's rotation window and is never aged
    /// out — the durability guarantee that keeps an established baseline from silently
    /// re-arming cold-start trust after enough journal churn. A no-op on an empty store or a
    /// disabled journal.
    pub fn compact(&self, journal: &DecisionJournal) {
        if self.baselines.is_empty() || !journal.is_enabled() {
            return;
        }
        journal.record_all(self.baselines.iter().map(|(repo, b)| b.to_decision(repo)));
    }

    /// Replay the durable journal's [`SigningBaseline`](Decision::SigningBaseline) lines into
    /// the store on boot, folding chronologically so the latest full-state line per repo wins
    /// (compaction semantics). Returns how many distinct repos were restored. A
    /// disabled/empty journal restores nothing. Also refreshes `established` from wall-clock
    /// age at the line's timestamp, so a baseline that matured while the engine was down is
    /// restored established.
    pub fn restore(&mut self, journal: &DecisionJournal) -> usize {
        for entry in journal.replay() {
            if let Decision::SigningBaseline {
                repo,
                identities,
                issuers,
                first_seen_ms,
                established,
            } = entry.decision
            {
                if repo.is_empty() {
                    continue;
                }
                let matured =
                    established || entry.at_ms.saturating_sub(first_seen_ms) >= ESTABLISH_AGE_MS;
                self.upsert(
                    SigningBaseline {
                        identities: identities.into_iter().collect(),
                        issuers: issuers.into_iter().collect(),
                        first_seen_ms,
                        established: matured,
                        last_updated_ms: entry.at_ms,
                    },
                    repo,
                );
            }
        }
        self.baselines.len()
    }

    /// Insert-or-replace one repo's baseline (restore path), respecting the repo cap. An
    /// existing key updates in place (no eviction); a new key over the cap triggers eviction.
    fn upsert(&mut self, baseline: SigningBaseline, repo: String) {
        if !self.baselines.contains_key(&repo) {
            self.evict_if_full();
        }
        self.baselines.insert(repo, baseline);
    }

    /// Evict one entry when the store is at capacity, so a subsequent insert stays bounded.
    /// Prefers a non-`established` entry (cheap to re-learn) over an established one, and among
    /// the eviction candidates drops the least-recently-updated. A no-op below the cap.
    fn evict_if_full(&mut self) {
        if self.baselines.len() < self.max_repos {
            return;
        }
        // Prefer non-established candidates; fall back to all entries only if every baseline
        // is established (a cluster genuinely tracking max_repos matured repos).
        let victim = self
            .baselines
            .iter()
            .filter(|(_, b)| !b.established)
            .min_by_key(|(_, b)| b.last_updated_ms)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                self.baselines
                    .iter()
                    .min_by_key(|(_, b)| b.last_updated_ms)
                    .map(|(k, _)| k.clone())
            });
        if let Some(victim) = victim {
            self.baselines.remove(&victim);
        }
    }
}

#[cfg(test)]
#[path = "signing_baseline_tests.rs"]
mod tests;
