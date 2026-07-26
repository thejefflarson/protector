//! Tests for the JEF-321 entry-scoped corroboration shape — drop-then-execute — kept in its
//! own `*_tests.rs` file (repo CLAUDE.md: tests count toward the 1,000-line cap).
//! `super` resolves to the proof module, so these exercise the `pub(super)` `corroborate`
//! seam directly, mirroring `corroborate_context_tests.rs`'s cross-tenant-lateral suite.
//!
//! The shape is shadow-gated (it only sets `corroborated`, never actuates) and scoped to a
//! proven internet-facing foothold entry, so the classic "app writes then runs its own /tmp
//! script" pattern on an ordinary pod must NOT corroborate. It is tested BOTH ways —
//! end-to-end through `corroborated_for` (using an objective neither a bare `ProcessExec` nor
//! a benign `FileWrite` blanket-corroborates on its own, so a positive is attributable to the
//! drop-then-execute shape alone) and on `drop_then_execute` directly.

use std::time::{Duration, SystemTime};

use super::corroborate::{DROP_EXEC_WINDOW, EntryContext, corroborated_for, drop_then_execute};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::graph::{Behavior, RuntimeSignal};

/// A base time all `at()` offsets are relative to, so timing is exact regardless of clock.
fn base() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// A `RuntimeSignal` for `behavior` observed `secs` after [`base`].
fn sig(behavior: Behavior, secs: u64) -> RuntimeSignal {
    RuntimeSignal {
        behavior,
        provenance: Provenance::new("test", base() + Duration::from_secs(secs)),
    }
}

fn write(path: &str, secs: u64) -> RuntimeSignal {
    sig(Behavior::FileWrite { path: path.into() }, secs)
}

fn exec(path: &str, secs: u64) -> RuntimeSignal {
    sig(Behavior::ProcessExec { path: path.into() }, secs)
}

/// The entry is a proven internet-facing foothold in namespace `ns`.
fn foothold_entry(ns: &str) -> EntryContext<'_> {
    EntryContext {
        source_ns: ns,
        is_foothold: true,
    }
}

/// The entry is an ordinary (non-foothold) workload in namespace `ns`.
fn ordinary_entry(ns: &str) -> EntryContext<'_> {
    EntryContext {
        source_ns: ns,
        is_foothold: false,
    }
}

/// The objective for the end-to-end `corroborated_for` tests: CREDENTIAL_ACCESS fires (flat
/// arm) only on a `SecretRead`, and these tests carry only `FileWrite`/`ProcessExec` signals,
/// so a positive is attributable to the drop-then-execute shape alone, never the flat arms.
const OBJECTIVE: crate::engine::graph::attack::AttackRef = CREDENTIAL_ACCESS;

// ---- Drop-then-execute — end-to-end through corroborated_for --------------------------

#[test]
fn exec_of_a_recently_written_path_on_the_foothold_entry_corroborates() {
    // /tmp/update.sh is dropped, then run seconds later on the proven foothold entry — the
    // classic drop-then-execute pattern.
    let runtime = [write("/tmp/update.sh", 0), exec("/tmp/update.sh", 5)];
    assert!(corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry("frontend"),
    ));
    assert!(drop_then_execute(&runtime, foothold_entry("frontend")));
}

#[test]
fn exec_with_no_matching_write_does_not_corroborate() {
    // A bare exec with no write of the SAME path anywhere in the window — an ordinary
    // entrypoint exec, the ADR-0011 on-call-engineer false positive.
    let runtime = [exec("/usr/local/bin/app", 0)];
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!drop_then_execute(&runtime, foothold_entry("frontend")));
}

#[test]
fn write_and_exec_of_different_paths_does_not_corroborate() {
    // A write to one path and an exec of a DIFFERENT path — no correlation, just two
    // unrelated mundane behaviors.
    let runtime = [write("/tmp/report.csv", 0), exec("/usr/local/bin/app", 5)];
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!drop_then_execute(&runtime, foothold_entry("frontend")));
}

#[test]
fn drop_then_execute_on_a_non_foothold_entry_does_not_corroborate() {
    // The SAME drop-then-execute pair, but the entry is an ordinary pod, not a proven
    // internet-facing foothold — apps legitimately write-then-run their own /tmp scripts
    // constantly, so this must stay the FP-aware non-corroborating case.
    let runtime = [write("/tmp/update.sh", 0), exec("/tmp/update.sh", 5)];
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!drop_then_execute(&runtime, ordinary_entry("frontend")));
}

#[test]
fn a_write_long_after_the_exec_does_not_corroborate() {
    // The exec happens BEFORE the write of the same path — an unrelated later write (e.g. a
    // log the just-run process itself creates) is not drop-then-execute.
    let runtime = [exec("/tmp/update.sh", 0), write("/tmp/update.sh", 5)];
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!drop_then_execute(&runtime, foothold_entry("frontend")));
}

// ---- Bounded: the DROP_EXEC_WINDOW TTL is exercised at its boundary -------------------

#[test]
fn exec_at_exactly_the_window_boundary_still_corroborates() {
    let window_secs = DROP_EXEC_WINDOW.as_secs();
    let runtime = [
        write("/tmp/update.sh", 0),
        exec("/tmp/update.sh", window_secs),
    ];
    assert!(
        drop_then_execute(&runtime, foothold_entry("frontend")),
        "exec exactly DROP_EXEC_WINDOW after the write is still \"recent\" (<=, not <)"
    );
}

#[test]
fn exec_past_the_window_does_not_corroborate() {
    // The classic "coincidental path reuse hours later" case the ticket's acceptance
    // criteria calls out: a write and an exec of the same path exist in the entry's runtime
    // signal set, but far enough apart that they no longer read as one drop-and-run act.
    let window_secs = DROP_EXEC_WINDOW.as_secs();
    let runtime = [
        write("/tmp/update.sh", 0),
        exec("/tmp/update.sh", window_secs + 1),
    ];
    assert!(
        !corroborated_for(&runtime, &OBJECTIVE, None, foothold_entry("frontend")),
        "outside the drop-exec window must NOT corroborate"
    );
    assert!(!drop_then_execute(&runtime, foothold_entry("frontend")));
}

#[test]
fn bound_is_narrower_than_the_general_runtime_ttl() {
    // The correlation window is deliberately TIGHTER than the general runtime-signal TTL
    // (`observe::runtime::DEFAULT_RUNTIME_WINDOW_SECS`, 30 minutes) — two signals can both
    // still be live in the entry's runtime slice while sitting further apart than a real
    // drop-and-run act would.
    assert!(
        DROP_EXEC_WINDOW
            < Duration::from_secs(crate::engine::observe::runtime::DEFAULT_RUNTIME_WINDOW_SECS),
        "the drop-exec correlation window must be narrower than the general runtime TTL"
    );
}

// ---- Regression guard: don't widen the flat per-behavior predicates -------------------

#[test]
fn an_unpaired_benign_write_and_bare_exec_together_still_do_not_corroborate() {
    // A benign FileWrite (not a sensitive path) and a bare ProcessExec (not shell/pkg-mgr) of
    // DIFFERENT paths on the foothold entry — neither the flat arms nor the drop-then-execute
    // shape should fire; only a matching PATH within the window does.
    let runtime = [write("/data/app.db", 0), exec("/usr/local/bin/worker", 1)];
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry("frontend"),
    ));
}
