//! Tests for the JEF-317 (Route A) entry-scoped corroboration shape — anon-inode exec on
//! the foothold — kept in its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the
//! 1,000-line cap). `super` resolves to the proof module, so these exercise the
//! `pub(super)` `corroborate` seam directly, mirroring `corroborate_privesc_tests.rs`.
//!
//! Route A replaces a WITHDRAWN v1 approach (a security review caught it): v1 classified
//! the exec *path shape* (`/dev/fd/<n>` etc.) and fed it into the flat, blanket
//! `corroborates` gate, forging corroboration on routine `fexecve()`/runc-memfd-reexec
//! behavior. This shape instead reads the real (agent-supplied, kernel-observed)
//! `exe_anon_inode` inode fact, and is scoped BOTH to a proven internet-facing foothold
//! entry AND to an Execution-tactic objective — never the "corroborates any objective"
//! blanket gate a shell/package-manager exec gets.
//!
//! A SECOND security review (still JEF-317) flagged that shipping this LIVE was itself
//! premature: whether the runc CVE-2019-5736 memfd-reexec attributes to the workload
//! cgroup or the host runtime is unmeasured, so the shape now sits behind
//! `PROTECTOR_ANON_EXEC_CORROBORATION` (default OFF). Every case below therefore goes
//! through [`EnvGuard`], mirroring `policies::signature::auth_tests`'s fix for the exact
//! same class of problem (JEF-412): Rust's default test harness runs `#[test]`s as
//! parallel threads in one process, so an unguarded `set_var`/`remove_var` on this
//! process-global var would race sibling tests.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, anon_inode_exec_on_foothold, corroborated_for};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{
    AttackRef, CONTAINER_ADMIN_COMMAND, CREDENTIAL_ACCESS, ESCAPE_TO_HOST,
};
use crate::engine::graph::{Behavior, RuntimeSignal};

const FLAG_VAR: &str = "PROTECTOR_ANON_EXEC_CORROBORATION";

/// Serializes every test that mutates [`FLAG_VAR`] (JEF-412-style race guard).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard giving a test exclusive, restore-on-drop access to [`FLAG_VAR`]. Mirrors
/// `policies::signature::auth_tests::EnvGuard`.
struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Option<String>,
}

impl EnvGuard {
    /// Acquire the lock, snapshot [`FLAG_VAR`], and set it to `Some(value)` or clear it
    /// (`None`) — the shared body for [`set`](Self::set)/[`unset`](Self::unset).
    fn with(value: Option<&str>) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved = std::env::var(FLAG_VAR).ok();
        // SAFETY: the lock guarantees no sibling test reads/writes this var concurrently.
        unsafe {
            match value {
                Some(v) => std::env::set_var(FLAG_VAR, v),
                None => std::env::remove_var(FLAG_VAR),
            }
        }
        Self { _lock: lock, saved }
    }

    /// Turn [`FLAG_VAR`] on for the guarded window.
    fn set(value: &str) -> Self {
        Self::with(Some(value))
    }

    /// Ensure [`FLAG_VAR`] is unset for the guarded window (the default/OFF posture).
    fn unset() -> Self {
        Self::with(None)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: still holding the lock; restore the pre-test value.
        unsafe {
            match &self.saved {
                Some(v) => std::env::set_var(FLAG_VAR, v),
                None => std::env::remove_var(FLAG_VAR),
            }
        }
    }
}

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

fn exec(path: &str, exe_anon_inode: bool, secs: u64) -> RuntimeSignal {
    sig(
        Behavior::ProcessExec {
            path: path.into(),
            exe_anon_inode,
        },
        secs,
    )
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

/// The objective for these tests: an Execution-tactic chain (T1609 Container
/// Administration Command).
fn execution_objective() -> AttackRef {
    CONTAINER_ADMIN_COMMAND
}

// ---- Flag OFF (the shipped default): the shape never corroborates -------------------------

#[test]
fn anon_inode_exec_on_the_foothold_does_not_corroborate_with_the_flag_off() {
    // With PROTECTOR_ANON_EXEC_CORROBORATION unset (the shipped default), this shape must
    // NOT corroborate even on the otherwise-textbook foothold + Execution + anon-inode-exec
    // shape — it stays HELD pending the on-node runc-attribution measurement (JEF-317
    // follow-up: a security review flagged shipping this LIVE ahead of that measurement).
    let _guard = EnvGuard::unset();
    let runtime = [exec("/tmp/payload", true, 0)];
    assert!(!corroborated_for(
        &runtime,
        &execution_objective(),
        None,
        foothold_entry("frontend"),
    ));
    assert!(!anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        foothold_entry("frontend"),
    ));
}

// ---- Positive: anon-inode exec on the foothold entry — end to end (flag ON) ---------------

#[test]
fn anon_inode_exec_on_the_foothold_entry_corroborates_execution() {
    // A memfd/unlinked-backed exec on the proven internet-facing foothold IS the
    // Falco-parity signal (JEF-317): the attacker who owns the front door running a
    // fileless payload on that same workload. Only reachable with the deliberate
    // opt-in flag on (operator running the on-node measurement window).
    let _guard = EnvGuard::set("1");
    let runtime = [exec("/tmp/payload", true, 0)];
    assert!(corroborated_for(
        &runtime,
        &execution_objective(),
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        foothold_entry("frontend"),
    ));
}

// ---- Negative: same exec, non-foothold entry (flag ON) ------------------------------------

#[test]
fn anon_inode_exec_on_a_non_foothold_entry_does_not_corroborate() {
    // The SAME anon-inode exec, but the entry is an ordinary pod — must NOT corroborate
    // (ADR-0011): this is exactly where an unmeasured runc-memfd-reexec false positive
    // would land if it attributed to an arbitrary workload rather than a proven foothold.
    // Flag ON so this exercises the foothold gate specifically, not the flag gate.
    let _guard = EnvGuard::set("1");
    let runtime = [exec("/tmp/payload", true, 0)];
    assert!(!corroborated_for(
        &runtime,
        &execution_objective(),
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        ordinary_entry("frontend"),
    ));
}

// ---- Regression guards: don't widen past exe_anon_inode / past Execution (flag ON) --------

#[test]
fn a_normal_exec_on_the_foothold_does_not_corroborate() {
    // exe_anon_inode: false — an ordinary on-disk exec, even on the proven foothold — is
    // not the fileless-exec signal Falco fires on. Flag ON so this exercises the
    // exe_anon_inode gate specifically, not the flag gate.
    let _guard = EnvGuard::set("1");
    let runtime = [exec("/app/server", false, 0)];
    assert!(!anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        foothold_entry("frontend"),
    ));
}

#[test]
fn anon_inode_exec_on_the_foothold_does_not_corroborate_an_unrelated_objective() {
    // The shape only lights up an Execution-tactic objective — it must not blanket-
    // corroborate a CredentialAccess or PrivilegeEscalation chain just because the entry
    // is a foothold. This is the conservative-scoping guard the withdrawn v1 approach
    // lacked entirely (it corroborated ANY objective). Flag ON so this exercises the
    // tactic gate specifically, not the flag gate.
    let _guard = EnvGuard::set("1");
    let runtime = [exec("/tmp/payload", true, 0)];
    for objective in [CREDENTIAL_ACCESS, ESCAPE_TO_HOST] {
        assert!(
            !corroborated_for(&runtime, &objective, None, foothold_entry("frontend")),
            "{objective:?}"
        );
        assert!(
            !anon_inode_exec_on_foothold(&runtime, &objective, foothold_entry("frontend")),
            "{objective:?}"
        );
    }
}
