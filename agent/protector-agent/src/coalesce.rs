//! Agent-side debounce/coalescing of behavioral observations before the POST (JEF-296).
//!
//! Follow-on to JEF-294 (which raised the engine's per-batch cap 256→1024 so batches
//! stopped truncating). That stopped the *truncation*, but the real cost is VOLUME: the
//! eBPF observer emits events as they happen, so the engine sees hundreds of near-identical
//! observations per batch — the same workload doing the same coarse thing (repeated cluster
//! egress, repeated execs) — every one of which wakes the engine loop and is only then
//! deduped by the store's TTL (`same_signal` in `engine::observe::runtime`). The POST rate,
//! batch size, and engine-wake churn are all paid *before* that dedup runs.
//!
//! This [`Coalescer`] pre-does the engine's dedup at the source. It buffers mundane
//! observations over a short window and coalesces them by identity — the coarse
//! [`Behavior::fingerprint_key`] (the same notion the engine's verdict cache fingerprints
//! on: `egress:cluster`/`egress:internet`, `exec:<basename>`, `read:<secret>`, …) plus the
//! attribution. Identical signals collapse to the first-seen (its timestamp preserved), so a
//! flood of per-peer connection churn leaves the node as one compact, deduped batch instead
//! of hundreds of rows.
//!
//! ## Alerts are never debounced
//!
//! [`Behavior::is_alert`] observations bypass the buffer entirely and are returned for an
//! IMMEDIATE POST. Alerts are the "something alarming, now" corroboration signal that live
//! containment depends on (JEF-284 condition-2 quarantine, JEF-117) — debouncing them would
//! add window latency to exactly the path that must stay fast. Debouncing is only ever for
//! the high-frequency mundane stream (network / exec / file / library / secret reads).
//!
//! ## Flush triggers (owned by the caller)
//!
//! Two triggers, both bounded: the caller drains the buffer when its window elapses
//! ([`Coalescer::drain`]), and [`Coalescer::offer`] itself drains-and-returns the buffer if
//! admitting a new distinct key would exceed `max_size` — the memory bound, so a burst of
//! genuinely-distinct signals can't grow the buffer without limit.

use std::collections::HashMap;

use protector_behavior::{Attribution, RuntimeObservation};

/// A stable per-workload token for an [`Attribution`], for the coalescing key. Distinct
/// from the behavior fingerprint so two workloads doing the same coarse thing never
/// collapse into one another. The eBPF agent attributes by cgroup pod UID; a Falco-style
/// namespace/name is handled too for completeness (the agent posts UID attributions today).
fn attribution_token(attribution: &Attribution) -> String {
    match attribution {
        Attribution::ByPodUid { pod_uid } => format!("uid:{pod_uid}"),
        Attribution::ByNamespacedName { namespace, pod } => format!("ns:{namespace}/{pod}"),
    }
}

/// The coalescing identity of an observation: `(attribution, coarse behavior fingerprint)`.
/// Two mundane observations sharing this key are the SAME coarse fact — the near-duplicates
/// this buffer collapses. It mirrors [`Behavior::fingerprint_key`] exactly (the engine's
/// verdict-cache notion), so per-peer connection churn (`egress:internet` regardless of the
/// specific peer) and per-path exec churn (`exec:<basename>`) collapse at the node just as
/// they do in the engine — while genuinely distinct facts (a different secret, cluster vs
/// internet egress, a different exec'd binary) keep distinct keys and all survive.
fn coalesce_key(obs: &RuntimeObservation) -> String {
    format!(
        "{}\u{1f}{}",
        attribution_token(&obs.attribution),
        obs.behavior.fingerprint_key()
    )
}

/// Buffers and coalesces mundane behavioral observations before the reporter POSTs them.
///
/// Not `Send`/`Sync`-shared: it lives inside the single flusher task and is driven serially
/// by [`Self::offer`] (on each received observation) and [`Self::drain`] (on the window
/// tick), so it needs no interior locking.
pub struct Coalescer {
    /// The coalesced buffer, keyed by [`coalesce_key`]. The value is the FIRST-seen
    /// observation for that key — later identical ones are dropped, so the first-seen
    /// timestamp (`observed_at_ms`, the freshness stamp) is the one that reaches the engine.
    buffer: HashMap<String, RuntimeObservation>,
    /// Max distinct keys buffered before [`Self::offer`] force-drains. Bounds memory and
    /// keeps a flushed batch at or under this size (well under the engine's 1024 per-batch
    /// cap, so the "behavior batch exceeds the per-batch cap" WARN stays quiet).
    max_size: usize,
}

impl Coalescer {
    /// A coalescer that force-drains once `max_size` distinct keys are buffered.
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: HashMap::new(),
            max_size: max_size.max(1),
        }
    }

    /// Offer one observation. Returns the observations that must be POSTed IMMEDIATELY:
    ///
    /// * an **alert** — never debounced, returned as its own one-element batch so live
    ///   corroboration stays low-latency (it is NOT added to the buffer);
    /// * otherwise, if admitting this new distinct key would exceed `max_size`, the drained
    ///   buffer — the max-size flush that bounds memory (the new observation then starts the
    ///   next window's buffer).
    ///
    /// A mundane observation whose `(attribution, fingerprint)` is already buffered is an
    /// identical near-duplicate and is dropped (the first-seen is kept). The common steady-
    /// state case returns an empty vec — the observation is buffered for the window flush.
    pub fn offer(&mut self, obs: RuntimeObservation) -> Vec<RuntimeObservation> {
        // Alerts bypass the debounce entirely — flush now, never buffer (JEF-296 correctness
        // requirement: live corroboration must not eat the window latency).
        if obs.behavior.is_alert() {
            return vec![obs];
        }
        let key = coalesce_key(&obs);
        if self.buffer.contains_key(&key) {
            // Identical coarse signal already buffered — coalesce (drop), keeping first-seen.
            return Vec::new();
        }
        // A new distinct key. If the buffer is already full, drain it first (the max-size
        // flush) so memory stays bounded, then start the next window with this observation.
        let flushed = if self.buffer.len() >= self.max_size {
            self.drain()
        } else {
            Vec::new()
        };
        self.buffer.insert(key, obs);
        flushed
    }

    /// Drain the coalesced buffer — the window-elapsed flush. Returns one observation per
    /// distinct `(attribution, fingerprint)` seen since the last drain, and empties the
    /// buffer. Order is unspecified (the engine treats a batch as a set).
    pub fn drain(&mut self) -> Vec<RuntimeObservation> {
        self.buffer.drain().map(|(_, obs)| obs).collect()
    }

    /// Whether the buffer holds no coalesced observations (lets the caller skip an empty
    /// window flush without an HTTP round-trip).
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests;
