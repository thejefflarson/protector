//! The audit-emission seam (ADR-0031 §4, JEF-488). Every MCP response ABOVE the safe-by-construction
//! `redacted` tier is genuine cluster-data egress, so it appends a structured audit record —
//! **subject · entry · tool · tier · time** — bound to the VERIFIED token subject. The `redacted`
//! tier discloses nothing cluster-specific and needs no entry-level line.
//!
//! This module is deliberately only the SEAM: a small [`AuditSink`] trait plus a
//! [`TracingAuditSink`] that emits a structured `tracing` event and an in-memory
//! [`RecordingAuditSink`] for tests. The DURABLE sink and the operator "Access" dashboard tab are a
//! SEPARATE ticket (JEF-490); it wires a durable implementation of this same trait in — nothing in
//! the tool/tier code changes, it already emits through the trait object.

use std::sync::Mutex;

use super::tiering::EffectiveTier;

/// One audit line for a forensic/raw disclosure (ADR-0031 §4). The `time` is captured at emission
/// as seconds since the Unix epoch so the record is self-contained (a durable sink — JEF-490 — can
/// re-key it however it likes). Every field is a low-cardinality fact; no cluster crown-jewel value
/// rides here (the disclosed data is in the response, not the audit line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The verified human subject (`sub`) the token bound to — WHO saw the cluster fact.
    pub subject: String,
    /// The entry the disclosure was scoped to (`explain_verdict`), or a scope label for a bulk
    /// forensic listing (`list_findings`/`get_coverage`/`signing_inventory`) — WHAT was disclosed.
    pub entry: String,
    /// The tool that served it — WHICH read.
    pub tool: &'static str,
    /// The effective (clamped) tier the response was rendered at — HOW MUCH was disclosed.
    pub tier: EffectiveTier,
    /// Emission time, seconds since the Unix epoch — WHEN.
    pub time_unix_secs: u64,
}

impl AuditRecord {
    /// Assemble a record, stamping `time` from the wall clock at emission.
    pub fn now(
        subject: impl Into<String>,
        entry: impl Into<String>,
        tool: &'static str,
        tier: EffectiveTier,
    ) -> Self {
        let time_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            subject: subject.into(),
            entry: entry.into(),
            tool,
            tier,
            time_unix_secs,
        }
    }
}

/// The audit seam JEF-490 wires a durable sink into. A `redacted`-tier response never calls this
/// (nothing cluster-specific to record); a `forensic`/`raw` response calls it exactly once per
/// disclosure. Implementations MUST NOT fail the read — auditing is best-effort observability, not
/// a gate — so `emit` returns nothing.
pub trait AuditSink: Send + Sync {
    /// Record one forensic/raw disclosure.
    fn emit(&self, record: AuditRecord);
}

/// The default sink: a structured `tracing` event, so the record lands in the engine's normal
/// observability pipeline until JEF-490 attaches a durable store + the "Access" tab.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn emit(&self, record: AuditRecord) {
        tracing::info!(
            target: "protector::mcp::audit",
            subject = %record.subject,
            entry = %record.entry,
            tool = record.tool,
            tier = record.tier.as_str(),
            time_unix_secs = record.time_unix_secs,
            "mcp forensic/raw disclosure (ADR-0031 §4 audit line)"
        );
    }
}

/// An in-memory sink for tests: it retains every emitted record so a test can assert that a
/// forensic/raw access DID (and a redacted access did NOT) append an audit line.
#[derive(Default)]
pub struct RecordingAuditSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl RecordingAuditSink {
    /// A snapshot of the records emitted so far.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }
}

impl AuditSink for RecordingAuditSink {
    fn emit(&self, record: AuditRecord) {
        self.records
            .lock()
            .expect("audit sink mutex poisoned")
            .push(record);
    }
}
