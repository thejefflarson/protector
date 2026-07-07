//! Stable peer rendering across a transient informer miss (JEF-375).
//!
//! [`IpIndex`] is rebuilt fresh from every pass's [`Snapshot`](crate::engine::observe::Snapshot),
//! so when the informer cache transiently MISSES a pod this pass — it isn't in the
//! reflector store yet, or a resync briefly emptied it — [`IpIndex::resolve`] returns
//! `None` and the peer would drop from its resolved `namespace/name:port (ip)` back to a
//! bare `ip:port`. The peer didn't change; only our rendering flipped. But that flip
//! changes the adjudicator prompt's hash and triggers a spurious verdict-cache re-judge
//! (the ADJ-MISS-DIAG churn this ticket chases).
//!
//! [`PeerResolutionMemo`] remembers the last-known IP→object resolution with a short
//! grace TTL, so a one-pass miss reuses the prior resolution instead of dropping to raw
//! IP — the *same* peer renders the *same* token every pass. It deliberately does NOT
//! reduce which peers appear (that's a security signal — see the ticket's non-goals):
//!   - a genuinely NEW peer that was never resolved still renders raw until the index
//!     resolves it, and re-judges legitimately when it does — the memo never fabricates
//!     a name for an IP it hasn't seen resolved;
//!   - after the grace window a truly departed peer falls back to raw;
//!   - an IP reused by a different object re-resolves on the next index hit (the memo
//!     always overwrites with the freshest confirmed resolution).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{IpIndex, ResolvedPeer, split_ip_port};

/// How long a previously-confirmed IP→object resolution keeps rendering its last-known
/// cluster name while the informer index misses it. Long enough to bridge a transient
/// cache gap across several passes, short enough that a genuinely departed peer reverts
/// to raw within one verdict's lifetime (the verdict fingerprint runs on a comparable
/// window). A miss shorter than this is exactly the churn JEF-375 removes; a miss longer
/// than this is treated as a real change and re-rendered raw.
const GRACE_TTL: Duration = Duration::from_secs(300);

/// A short-lived memo of the last-known IP→cluster-object resolution, used to render a
/// connection peer stably across a transient informer miss. Owned by the
/// [`RuntimeAdapter`](crate::engine::observe::adapter::RuntimeAdapter) and reused across
/// passes; the per-pass [`IpIndex`] is passed in on each call.
#[derive(Debug, Default)]
pub struct PeerResolutionMemo {
    /// IP → (its last confirmed resolution, when it was last confirmed).
    last: HashMap<String, (ResolvedPeer, Instant)>,
}

impl PeerResolutionMemo {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rewrite a `NetworkConnection` peer into its stable resolved form, bridging a
    /// transient informer miss with the last-known resolution.
    ///
    /// Rules mirror the pure per-pass resolution, plus the grace fallback:
    /// - `internet` peers stay raw (external egress — nothing in-cluster to resolve to);
    /// - a peer not in `IP:port` shape stays untouched (we never guess);
    /// - an index HIT renders `namespace/name:port (ip)` and records it as last-known;
    /// - an index MISS reuses the last-known resolution when it's within [`GRACE_TTL`],
    ///   else stays raw `IP:port` (never fabricating a name for an unseen IP).
    ///
    /// `now` is injected so the grace window is deterministic under test.
    pub fn resolve_peer(
        &mut self,
        index: &IpIndex,
        peer: &str,
        internet: bool,
        now: Instant,
    ) -> String {
        if internet {
            // External egress — nothing in-cluster to resolve to; keep it raw.
            return peer.to_string();
        }
        let Some((ip, port)) = split_ip_port(peer) else {
            // Not in `IP:port` shape — leave it untouched rather than guess.
            return peer.to_string();
        };
        match index.resolve(ip) {
            Some(resolved) => {
                // Index hit: this is ground truth — render it and refresh the memo so a
                // later miss (or an IP reused by a new object) reuses the freshest answer.
                let rendered = render(resolved, port, ip);
                self.last.insert(ip.to_string(), (resolved.clone(), now));
                rendered
            }
            None => match self.last.get(ip) {
                // Transient miss within grace: reuse the last-known resolution so the
                // same peer renders the same token (no name<->IP flip).
                Some((resolved, seen)) if now.saturating_duration_since(*seen) <= GRACE_TTL => {
                    render(resolved, port, ip)
                }
                // Never resolved, or the grace window elapsed — stay raw; never fabricate.
                _ => peer.to_string(),
            },
        }
    }

    /// Drop memo entries whose grace window has elapsed. Called once per pass so the memo
    /// can't grow without bound as cluster IPs churn.
    pub fn prune(&mut self, now: Instant) {
        self.last
            .retain(|_, (_, seen)| now.saturating_duration_since(*seen) <= GRACE_TTL);
    }
}

/// Render a resolved peer as `namespace/name:port (raw-ip)` — the raw IP is kept in
/// parens for forensics, exactly as the pure index resolution did.
fn render(resolved: &ResolvedPeer, port: &str, ip: &str) -> String {
    format!("{}:{port} ({ip})", resolved.label())
}

#[cfg(test)]
mod tests;
