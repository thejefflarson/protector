//! The DURABLE forensic/raw disclosure audit sink (JEF-490): the durable implementation of the
//! JEF-488 [`AuditSink`](super::audit::AuditSink) seam, plus the read handle the operator "Access"
//! dashboard tab renders from. Every MCP response ABOVE the safe-by-construction `redacted` tier is
//! genuine cluster-data egress (ADR-0031 §4), so it appends ONE append-only record —
//! **subject · entry · tool · tier · time** — bound to the VERIFIED token subject; a `redacted`
//! response never reaches here (the dispatcher gates on `tier.is_disclosure()`).
//!
//! This is a **distinct concern** from the [`DecisionJournal`](crate::engine::journal): a security
//! decision (a breach verdict, an applied cut) is not the same record as a human's disclosure pull,
//! so it lives in its OWN file (`PROTECTOR_MCP_AUDIT_PATH`) with its OWN record type — never
//! overloaded onto the DecisionJournal. It REUSES the journal's proven plumbing PATTERN: an
//! append-only JSON-lines file on the operator-provided PVC, size-bounded with a single-generation
//! rotation, and an **absent/unwritable** volume degrades to in-memory only — it NEVER crashes the
//! read (auditing is best-effort observability, not a gate).
//!
//! It ALSO keeps a bounded in-memory ring (newest-first for the screen), replayed from the durable
//! tail on boot, so the "Access" tab isn't blank after a restart when the volume is durable — and is
//! honestly empty (calm least-privilege) when nothing has been pulled.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::audit::{AuditRecord, AuditSink};
use super::tiering::EffectiveTier;

/// Size cap (bytes) for the active audit file before it rotates. ~1 MiB holds many thousands of
/// disclosure lines while bounding disk use on a small mounted volume; one rolled generation caps
/// total on-disk size at ~`2 × MAX_BYTES`, exactly like the decision journal.
const MAX_BYTES: u64 = 1024 * 1024;

/// The in-memory ring cap — how many of the newest disclosure records the "Access" screen retains
/// for a fast read. Bounded so a long-lived engine can't grow the ring unboundedly; older lines
/// still live on the durable file (they simply age out of the screen's window).
const MAX_RECORDS: usize = 512;

/// One durable forensic/raw disclosure line (ADR-0031 §4) — the owned, serializable mirror of an
/// [`AuditRecord`]. Every field is a low-cardinality fact; NO cluster crown-jewel value rides here
/// (the disclosed data was in the tool response, not the audit line). The `entry` is a workload
/// identity (or the bulk-scope label) — itself a forensic-tier fact, so the "Access" screen redacts
/// it to the VIEWER's own tier before rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    /// The verified human subject (`sub`) the token bound to — WHO saw the cluster fact (with
    /// ID-JAG this is the real human `sub`). Untrusted at render — escaped by the client.
    pub subject: String,
    /// The entry the disclosure was scoped to (a workload identity), or the bulk-scope label for a
    /// bulk listing — WHAT was disclosed. A forensic-tier fact; redacted per-viewer on the screen.
    pub entry: String,
    /// The tool that served it — WHICH read.
    pub tool: String,
    /// The effective (clamped) tier the response was rendered at — HOW MUCH was disclosed.
    pub tier: EffectiveTier,
    /// Emission time, seconds since the Unix epoch — WHEN.
    pub time_unix_secs: u64,
}

impl From<AuditRecord> for AccessRecord {
    fn from(r: AuditRecord) -> Self {
        Self {
            subject: r.subject,
            entry: r.entry,
            tool: r.tool.to_string(),
            tier: r.tier,
            time_unix_secs: r.time_unix_secs,
        }
    }
}

/// The durable forensic/raw disclosure audit sink. Wraps an optional file path on the journal PVC
/// (`Some` when a writable volume is configured, `None` = in-memory-only) plus a bounded in-memory
/// ring the "Access" screen reads. Every public method is infallible from the caller's view: a
/// write error disables the durable file (logged once) and the sink keeps recording in memory, so a
/// volume that vanishes mid-run never crashes the read — auditing is observability, not a gate.
pub struct AccessAuditSink {
    /// The active durable file path, or `None` for the in-memory-only sink.
    path: Option<PathBuf>,
    /// Set once a durable write fails, so we stop retrying (and stop spamming the log) — the sink
    /// then behaves as in-memory-only from that point.
    disabled: Mutex<bool>,
    /// The bounded newest-last ring of disclosure records the "Access" screen snapshots.
    ring: Mutex<VecDeque<AccessRecord>>,
}

impl Default for AccessAuditSink {
    fn default() -> Self {
        Self {
            path: None,
            disabled: Mutex::new(false),
            ring: Mutex::new(VecDeque::new()),
        }
    }
}

impl AccessAuditSink {
    /// An in-memory-only sink — records to the ring, never to disk. The honest default when no
    /// volume is configured; the "Access" screen then shows the "resets on restart" caveat.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Build from the configured path (on the same PVC the decision journal mounts). A probe write
    /// verifies the volume is actually writable; if it isn't (absent mount, read-only PVC) the sink
    /// degrades to [`in_memory`](Self::in_memory) with a warning — it NEVER errors. Parent dirs are
    /// created best-effort so a bare hostPath mount works without a manual `mkdir`. On success the
    /// durable tail is replayed into the ring so the screen isn't blank after a restart.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = std::fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(_) => {
                let mut ring = VecDeque::new();
                for record in replay(&path) {
                    push_bounded(&mut ring, record);
                }
                tracing::info!(path = %path.display(), "mcp access-audit enabled (durable)");
                Self {
                    path: Some(path),
                    disabled: Mutex::new(false),
                    ring: Mutex::new(ring),
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(), %error,
                    "mcp access-audit volume is not writable; recording in-memory only (no crash)"
                );
                Self::in_memory()
            }
        }
    }

    /// Build from `PROTECTOR_MCP_AUDIT_PATH`, consistent with the other `PROTECTOR_*_PATH` mounted
    /// contracts. Unset/empty ⇒ [`in_memory`](Self::in_memory).
    pub fn from_env() -> Self {
        match std::env::var("PROTECTOR_MCP_AUDIT_PATH") {
            Ok(path) if !path.trim().is_empty() => Self::open(path.trim()),
            _ => Self::in_memory(),
        }
    }

    /// Whether the sink persists to a writable volume (durable across a restart). `false` ⇒
    /// in-memory-only — the "Access" screen then carries the honest "resets on restart" caveat so an
    /// empty log is never misread as "nobody ever pulled raw".
    pub fn is_durable(&self) -> bool {
        self.path.is_some() && !*self.disabled.lock().expect("access-audit mutex poisoned")
    }

    /// A NEWEST-FIRST snapshot of the retained disclosure records — what the "Access" screen renders
    /// (Section 2 lists forensic/raw pulls newest-first). Cheap clone of the bounded ring.
    pub fn records(&self) -> Vec<AccessRecord> {
        self.ring
            .lock()
            .expect("access-audit mutex poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Append one already-serializable record: push to the ring (bounded) and, best-effort, to the
    /// durable file. A durable write error disables the file (logged once) but the ring push always
    /// lands — the read never fails.
    fn append(&self, record: AccessRecord) {
        {
            let mut ring = self.ring.lock().expect("access-audit mutex poisoned");
            push_bounded(&mut ring, record.clone());
        }
        let Some(path) = &self.path else { return };
        if *self.disabled.lock().expect("access-audit mutex poisoned") {
            return;
        }
        if let Err(error) = try_append(path, &record) {
            tracing::warn!(
                path = %path.display(), %error,
                "mcp access-audit write failed; disabling durable file (in-memory only from here)"
            );
            *self.disabled.lock().expect("access-audit mutex poisoned") = true;
        }
    }
}

impl AuditSink for AccessAuditSink {
    fn emit(&self, record: AuditRecord) {
        self.append(record.into());
    }
}

/// Push a record onto the newest-last ring, evicting the oldest once the cap is reached so the
/// in-memory window stays bounded.
fn push_bounded(ring: &mut VecDeque<AccessRecord>, record: AccessRecord) {
    if ring.len() >= MAX_RECORDS {
        ring.pop_front();
    }
    ring.push_back(record);
}

/// Append one disclosure line as JSON. Rotation is checked before the write so the active file
/// stays under [`MAX_BYTES`], mirroring the decision journal's single-generation roll.
fn try_append(path: &Path, record: &AccessRecord) -> std::io::Result<()> {
    let mut line = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    rotate_if_needed(path)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Replay the durable tail, oldest line first, across the rotation boundary: the rolled generation
/// (`<path>.1`) then the active file. A corrupt/truncated trailing line (a crash mid-write) is
/// skipped, never fatal — exactly the decision journal's tolerant parse.
fn replay(path: &Path) -> Vec<AccessRecord> {
    let mut records = Vec::new();
    for p in [rolled_path(path), path.to_path_buf()] {
        if let Ok(contents) = std::fs::read_to_string(&p) {
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_str::<AccessRecord>(line) {
                    records.push(record);
                }
            }
        }
    }
    records
}

/// The rolled-generation path for `path`: `<path>.1`.
fn rolled_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// Rotate the active file when it exceeds [`MAX_BYTES`]: move it to `<path>.1` (replacing any prior
/// roll), leaving the caller to create a fresh active file on the next write.
fn rotate_if_needed(path: &Path) -> std::io::Result<()> {
    let over_cap = match std::fs::metadata(path) {
        Ok(meta) => meta.len() >= MAX_BYTES,
        Err(_) => false,
    };
    if over_cap {
        std::fs::rename(path, rolled_path(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
