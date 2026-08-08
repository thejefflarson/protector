//! Tests for the reverse-shell-on-foothold entry-scoped corroboration shape (ADR-0041),
//! kept in its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the 1,000-line
//! cap; the per-shape convention every sibling shape follows). `super` resolves to the
//! proof module, so these exercise the `pub(super)` `corroborate` seam directly.
//!
//! This shape only became load-bearing once ADR-0041 narrowed the blanket notable-exec arm
//! (`Behavior::ProcessExec => false` in `corroborate.rs`) — before that, any notable exec
//! already corroborated ANY objective, so this narrower exec+egress-timing correlation could
//! never independently flip `corroborated_for` (ADR-0024's redundant-by-construction bar).
//! Every positive test below therefore asserts through `corroborated_for` with an objective
//! the bare exec would NOT corroborate on its own (per `corroborate_objective_tests.rs`'s
//! flip-proof), so a regression back to the blanket arm would NOT be masked here.

use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, corroborated_for, reverse_shell_on_foothold};
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

fn shell_exec() -> Behavior {
    Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: false,
    }
}

fn pkg_mgr_exec() -> Behavior {
    Behavior::ProcessExec {
        path: "/usr/bin/apt".into(),
        exe_anon_inode: false,
    }
}

fn internet_egress(peer: &str) -> Behavior {
    Behavior::NetworkConnection {
        peer: peer.into(),
        internet: true,
    }
}

/// The entry is a proven internet-facing foothold.
fn foothold_entry() -> EntryContext<'static> {
    EntryContext {
        source_ns: "frontend",
        is_foothold: true,
    }
}

/// The entry is an ordinary (non-foothold) workload.
fn ordinary_entry() -> EntryContext<'static> {
    EntryContext {
        source_ns: "frontend",
        is_foothold: false,
    }
}

/// The objective the `corroborated_for` positives below use: CREDENTIAL_ACCESS. The bare
/// (post-ADR-0041) flat arm never fires on a `ProcessExec` or an internet
/// `NetworkConnection` for this tactic, so a `corroborated_for` positive here is
/// attributable to the reverse-shell shape alone — the exact flip-proof ADR-0024 requires.
const OBJECTIVE: crate::engine::graph::attack::AttackRef = CREDENTIAL_ACCESS;

// ---- Shape-positive: shell + in-window egress corroborates where a bare shell would not --

#[test]
fn shell_then_egress_in_window_on_the_foothold_is_a_reverse_shell() {
    let runtime = [
        sig(shell_exec(), 0),
        sig(internet_egress("203.0.113.7:4444"), 5),
    ];
    // Direct predicate.
    assert!(reverse_shell_on_foothold(&runtime, foothold_entry()));
    // End-to-end: flips `corroborated_for` on an objective the bare exec alone would NOT.
    assert!(corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry()
    ));

    // Contrast: the bare shell alone (no egress) does NOT corroborate the same objective —
    // proves the positive above is attributable to the shape, not the exec alone.
    let bare = [sig(shell_exec(), 0)];
    assert!(!reverse_shell_on_foothold(&bare, foothold_entry()));
    assert!(!corroborated_for(&bare, &OBJECTIVE, None, foothold_entry()));
}

// ---- Bare-shell negative ---------------------------------------------------------------

#[test]
fn bare_shell_with_no_egress_anywhere_does_not_corroborate() {
    let runtime = [sig(shell_exec(), 0)];
    assert!(!reverse_shell_on_foothold(&runtime, foothold_entry()));
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry()
    ));
}

// ---- Package-manager negative: excluded from the shape (always egresses) ---------------

#[test]
fn package_manager_exec_then_egress_in_window_does_not_corroborate() {
    // The SAME timing a shell would flip on — but a package-manager exec always egresses
    // (fetching packages), so folding it in would re-create a blanket for that class.
    let runtime = [
        sig(pkg_mgr_exec(), 0),
        sig(internet_egress("203.0.113.7:443"), 5),
    ];
    assert!(!reverse_shell_on_foothold(&runtime, foothold_entry()));
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry()
    ));
}

// ---- Window-expiry negative --------------------------------------------------------------

#[test]
fn shell_and_egress_outside_the_window_do_not_corroborate() {
    // 61s apart — one second past REVERSE_SHELL_WINDOW (60s).
    let runtime = [
        sig(shell_exec(), 0),
        sig(internet_egress("203.0.113.7:4444"), 61),
    ];
    assert!(!reverse_shell_on_foothold(&runtime, foothold_entry()));
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry()
    ));
}

// ---- Non-foothold negative ----------------------------------------------------------------

#[test]
fn shell_then_egress_from_a_non_foothold_entry_does_not_corroborate() {
    let runtime = [
        sig(shell_exec(), 0),
        sig(internet_egress("203.0.113.7:4444"), 5),
    ];
    assert!(!reverse_shell_on_foothold(&runtime, ordinary_entry()));
    assert!(!corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        ordinary_entry()
    ));
}

// ---- Symmetric-window positive: connect-back-then-spawn (egress before the exec) -------

#[test]
fn egress_before_the_exec_in_window_is_also_a_reverse_shell() {
    // The connect-back-then-spawn ordering: the attacker's listener accepts the connection,
    // THEN the shell is spawned into it a moment later. ADR-0041 requires the symmetric
    // window to cover this — the old (withdrawn) asymmetric "exec at-or-before egress" gate
    // would have missed it.
    let runtime = [
        sig(internet_egress("203.0.113.7:4444"), 0),
        sig(shell_exec(), 5),
    ];
    assert!(reverse_shell_on_foothold(&runtime, foothold_entry()));
    assert!(corroborated_for(
        &runtime,
        &OBJECTIVE,
        None,
        foothold_entry()
    ));
}
