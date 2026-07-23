//! Tests for the durable forensic/raw disclosure audit sink (JEF-490): a disclosure records ONE
//! line (subject·entry·tool·tier·time) and round-trips across a "restart" when durable; an absent
//! or unwritable volume degrades to in-memory-only without crashing; and the ring reads
//! newest-first. The end-to-end "a forensic/raw pull records exactly one line, a redacted pull
//! records none" is proven through the real trust-core `dispatch` in the sibling `mcp::tests`
//! (which owns the `Finding` fixtures).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::engine::mcp::audit::{AuditRecord, AuditSink};

/// A unique temp path for one test (no temp-file crate): the system temp dir + the test tag + a
/// per-call nonce (pid + an atomic counter), so parallel tests never collide.
fn temp_path(tag: &str) -> PathBuf {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-access-audit-{tag}-{}-{n}.jsonl",
        std::process::id()
    ))
}

/// Remove a sink's files (active + rolled) so a test leaves no residue.
fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(rolled_path(path));
}

fn record(subject: &str, entry: &str, tool: &'static str, tier: EffectiveTier) -> AuditRecord {
    AuditRecord::now(subject, entry, tool, tier)
}

#[test]
fn a_durable_sink_round_trips_disclosures_across_a_reopen() {
    // The acceptance criterion: forensic/raw pulls written before a "restart" replay after it, so
    // the "Access" tab isn't blank on boot when the volume is durable.
    let path = temp_path("roundtrip");
    {
        let sink = AccessAuditSink::open(&path);
        assert!(sink.is_durable(), "a writable path makes the sink durable");
        sink.emit(record(
            "alice@corp.example",
            "workload/app/Pod/web",
            "explain_verdict",
            EffectiveTier::Raw,
        ));
        sink.emit(record(
            "bob@corp.example",
            "(all findings)",
            "list_findings",
            EffectiveTier::Forensic,
        ));
    }
    // A fresh sink on the same path (the "post-restart" engine) replays it all, newest-first.
    let reopened = AccessAuditSink::open(&path);
    let records = reopened.records();
    assert_eq!(records.len(), 2, "both disclosures survive the reopen");
    assert_eq!(records[0].subject, "bob@corp.example", "newest-first");
    assert_eq!(records[0].tier, EffectiveTier::Forensic);
    assert_eq!(records[1].subject, "alice@corp.example");
    assert_eq!(records[1].entry, "workload/app/Pod/web");
    assert_eq!(records[1].tool, "explain_verdict");
    assert_eq!(records[1].tier, EffectiveTier::Raw);
    assert!(records[1].time_unix_secs > 0, "the WHEN stamp is set");
    cleanup(&path);
}

#[test]
fn an_in_memory_sink_records_to_the_ring_but_is_not_durable() {
    let sink = AccessAuditSink::in_memory();
    assert!(
        !sink.is_durable(),
        "no volume ⇒ not durable (resets on restart)"
    );
    sink.emit(record(
        "carol@corp.example",
        "workload/app/Pod/api",
        "explain_verdict",
        EffectiveTier::Raw,
    ));
    let records = sink.records();
    assert_eq!(
        records.len(),
        1,
        "the ring retains the record for the screen"
    );
    assert_eq!(records[0].subject, "carol@corp.example");
}

#[test]
fn an_unwritable_path_degrades_to_in_memory_without_crashing() {
    // A path whose parent is a regular file can't be created — the sink degrades to in-memory,
    // never panics, and still records to the ring.
    let file = temp_path("not-a-dir");
    std::fs::write(&file, b"i am a file, not a directory").unwrap();
    let under_a_file = file.join("audit.jsonl");
    let sink = AccessAuditSink::open(&under_a_file);
    assert!(!sink.is_durable(), "an unwritable path is not durable");
    sink.emit(record("x@e", "y", "list_findings", EffectiveTier::Forensic));
    assert_eq!(sink.records().len(), 1, "recording still lands in memory");
    cleanup(&file);
}
