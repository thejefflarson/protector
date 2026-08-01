//! The GitOps-independent kill switch (ADR-0021's enforcement gate, fast path): a mounted
//! flag file the engine polls locally. Its presence NARROWS the running posture straight to
//! dry-run for the current pass — it can never widen beyond whatever `mode`/`enforceScope`
//! already armed at boot, so it composes with ADR-0021's single enforcement gate rather than
//! adding a second, independent one. Clearing it (removing the file) restores exactly the
//! arming the process booted with — byte-identical to running without this module at all.
//!
//! Chosen over a local admin HTTP endpoint: a file needs no new listener and no new auth
//! surface to get right under incident pressure, and it keeps working even if the dashboard,
//! mesh, or OIDC path is itself part of the outage — `kubectl` access (already the credential
//! of last resort in any cluster incident) is enough to create or remove it. It is also a pure
//! local read: zero egress, no new outbound call, nothing new to expose.
//!
//! The file's CONTENT is never read or parsed — only its existence is significant — so there
//! is no injection surface: whoever can touch it can only toggle the same narrow disarm any
//! operator can, never anything wider.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

/// The fixed mount path the engine watches by default (mirrors the KEV/EPSS/ASN feed
/// pattern: a fixed path is a deployment essential, not an operator knob — the chart wires
/// the volume once; the flag then toggles per-incident with no chart change and no GitOps
/// sync). `PROTECTOR_BREAK_GLASS_FILE` remains the escape-hatch override.
const DEFAULT_PATH: &str = "/var/lib/protector/break-glass/disarm";

/// How often the background poller checks the flag when nothing else has woken the driving
/// loop — the bound on how fast a quiet cluster notices an engage/clear. Kept short: the
/// check is a single local `stat`, negligible cost even at this cadence.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The break-glass watcher: a path, checked by a plain existence test. Cheap to clone (just
/// the path), so the engine's own copy (consulted every pass) and the background poller's
/// copy (spawned separately to wake the driving loop) read the same file independently — no
/// shared mutable state to get wrong.
#[derive(Debug, Clone)]
pub struct BreakGlass {
    path: PathBuf,
}

impl BreakGlass {
    /// Watch `path`. Exposed for tests and for [`Self::from_env`]'s override; production
    /// wiring should prefer [`Self::from_env`].
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Watch nothing — [`Self::engaged`] is always `false`. The default for an engine built
    /// without an explicit break-glass path (every existing unit test, and any embedding that
    /// doesn't opt in), so this module's mere existence changes nothing for them.
    pub fn disabled() -> Self {
        Self::at(PathBuf::new())
    }

    /// `PROTECTOR_BREAK_GLASS_FILE`, defaulting to the fixed mount path. Always watching —
    /// this is the enforcement gate's own fast path (ADR-0021), not a per-feature detection
    /// toggle, so there is no separate opt-in env var to forget.
    pub fn from_env() -> Self {
        Self::at(
            std::env::var("PROTECTOR_BREAK_GLASS_FILE")
                .unwrap_or_else(|_| DEFAULT_PATH.to_string()),
        )
    }

    /// Whether the flag is present right now — a single local existence check, nothing
    /// parsed. An empty path (`disabled`) never exists, so `disabled()` is always `false`.
    pub fn engaged(&self) -> bool {
        !self.path.as_os_str().is_empty() && self.path.exists()
    }

    /// Background task: wake `tx` on every engage/clear EDGE (not every poll), so the driving
    /// loop reacts within `interval` even on an otherwise-quiet cluster, without adding a
    /// steady drip of wakeups while the flag sits unchanged either way. The caller aborts the
    /// returned handle on shutdown, like the engine's other background tasks (feed reloaders,
    /// the model keep-warm).
    pub fn spawn_poller(self, tx: Sender<()>, interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut engaged = self.engaged();
            loop {
                tokio::time::sleep(interval).await;
                let now = self.engaged();
                if now != engaged {
                    engaged = now;
                    let _ = tx.try_send(());
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
