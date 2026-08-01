//! Shared `repr(C)` event layouts for protector-agent (ADR-0014).
//!
//! These are written by the eBPF programs (kernel side, `no_std`) and read by the
//! userspace loader. The **byte layout is the contract** — both sides depend on this one
//! crate so they can't drift. All probes write into a single ring buffer; every event
//! begins with [`EventHeader`], whose `kind` tells userspace which body follows. Adding a
//! probe is a new `KIND_*` + body type here, plus a decode arm in the userspace observer.
//!
//! `no_std` (no allocation, no std): usable from the bpf target and from userspace alike.

#![no_std]

/// Event-kind discriminators. Stable wire values; never renumber an existing one.
pub const KIND_CONNECT: u32 = 1;
/// A tmpfs file was opened (fentry on `security_file_open`). Carries the container path;
/// the engine maps it to a SecretRead via the pod's secret volumeMounts, or drops it.
pub const KIND_FILE_OPEN: u32 = 2;
/// An executable file was mmap'd — the dynamic linker loading a shared object / the main
/// binary (fentry on `security_mmap_file`, PROT_EXEC). Carries the path; userspace emits
/// a LibraryLoaded with the basename. Reuses [`FileEvent`] (kind discriminates).
pub const KIND_LIBRARY_LOAD: u32 = 3;
/// A process was exec'd (fentry on `security_bprm_check`). Carries the exec'd binary's
/// path, read from `linux_binprm->filename`, PLUS the anon-inode kernel fact (
/// Route A) read from `bprm->file->f_inode`; userspace emits a `ProcessExec`. Its own
/// [`ExecEvent`] body (not [`FileEvent`]) — the runtime signal for "unexpected process
/// spawned" (ADR-0014).
pub const KIND_EXEC: u32 = 4;
/// A process gained root (fentry on `security_task_fix_setuid`). The eBPF side filters to
/// the escalation case (`new_uid == 0 && old_uid != 0`) so this is always a real
/// privilege gain; the [`PrivEvent`] body carries the old and new real UIDs. Userspace
/// emits a [`Behavior::PrivilegeChange`].
pub const KIND_PRIV_CHANGE: u32 = 5;
/// A file was written (fentry on `security_file_open`, filtered in-kernel to write-intent
/// open flags —). Carries the written file's path (`bpf_d_path`); userspace emits
/// a `Behavior::FileWrite`. The runtime signal for container drift: drop-and-execute /
/// config tampering (ADR-0014). Reuses [`FileEvent`]
/// (the `kind` discriminates it from the read/exec/library file events).
pub const KIND_FILE_WRITE: u32 = 6;
/// A ptrace ATTACH access check (fentry on `security_ptrace_access_check`, filtered
/// in-kernel to `mode & PTRACE_MODE_ATTACH` — Retire-Falco G2). The classic
/// process-injection primitive Falco fires critical on. Carries NO body beyond the shared
/// [`EventHeader`]: the occurrence, attributed by the header's pid/cgroup, IS the fact — the
/// target `task_struct`'s pid is deliberately NOT read (see the eBPF probe's doc comment for
/// why). Userspace emits a `Behavior::PtraceAttach`.
pub const KIND_PTRACE_ATTACH: u32 = 7;
/// A kernel module load (fentry on `security_kernel_load_data`, filtered in-kernel to
/// `id == LOADING_MODULE` — Retire-Falco G2). Falco fires critical on
/// `init_module`/`finit_module`; `load_module()` calls this hook on BOTH syscalls before any
/// parsing, so one probe covers both. Carries NO body beyond [`EventHeader`], same shape as
/// [`KIND_PTRACE_ATTACH`] — the occurrence is the fact. Userspace emits a
/// `Behavior::ModuleLoad`.
pub const KIND_MODULE_LOAD: u32 = 8;

/// Max path bytes carried per [`FileEvent`]. Secret-mount paths are well under this; a
/// longer path is truncated (the secret name still lands). Sized to keep the eBPF stack
/// within budget.
pub const PATH_CAP: usize = 256;

/// One observed file open under a secret mount (kind [`KIND_FILE_OPEN`]). The eBPF side
/// already filtered to secret mounts, so every FileEvent is a secret read.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub header: EventHeader,
    /// Valid bytes in `path` (≤ [`PATH_CAP`]).
    pub len: u32,
    /// The opened file's absolute path (from `bpf_d_path`), not NUL-terminated.
    pub path: [u8; PATH_CAP],
}

/// One observed process exec (kind [`KIND_EXEC`]) — the same `header`/`len`/`path` shape
/// as [`FileEvent`], plus the pure-data anon-inode fact (Route A):
/// [`Self::exe_anon_inode`]. A dedicated struct rather than a [`FileEvent`] field, since
/// this fact is exec-specific — the file-open/library-load/file-write probes have no
/// `bprm` to read it from, so folding it into the shared `FileEvent` would mean carrying a
/// meaningless byte on every OTHER kind's wire event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    /// Valid bytes in `path` (≤ [`PATH_CAP`]).
    pub len: u32,
    /// The exec'd binary's path (`linux_binprm->filename`), not NUL-terminated past `len`.
    pub path: [u8; PATH_CAP],
    /// `1` if the exec'd binary's backing inode is anonymous — memfd/shmem-backed
    /// (`inode->i_sb->s_magic` is the tmpfs/shmem magic) or unlinked (`i_nlink == 0`) —
    /// rather than a normal, linked, on-disk file; `0` otherwise. A `u8`, not `bool`: a
    /// kernel-written byte is not guaranteed a valid Rust `bool` bit pattern, and `no_std`
    /// eBPF code writing this field directly must not rely on that guarantee. A KERNEL-
    /// OBSERVABLE FACT, not a verdict — whether an anon-inode exec is alarming
    /// is engine policy, conservatively scoped (see `engine::observe::exec_class` /
    /// `engine::reason::proof::corroborate`), NOT decided here.
    pub exe_anon_inode: u8,
}

/// The fixed prefix of every event in the ring buffer. `repr(C)`, at offset 0 of each
/// body, so userspace can read `kind` (and `pid`/`cgroup_id`) before it knows which body
/// follows.
///
/// `cgroup_id` is the kernel cgroup id captured AT EVENT TIME via the stable
/// `bpf_get_current_cgroup_id()` helper — the cgroup v2 directory's inode number.
/// Userspace resolves pod attribution from it through a `cgroup_id → pod_uid` table built
/// from `/sys/fs/cgroup`, which fixes the exited-process race: a short-lived in-container
/// exec/shell exits before userspace can read its `/proc/<pid>/cgroup`, so the post-hoc
/// `/proc` read missed it; the in-kernel id is recorded while the process is still live.
/// `pid` is kept too (host-event separation + the `/proc` fallback when the table misses).
///
/// Layout note: adding a `u64` raises the header's alignment to 8, so every `repr(C)`
/// body that embeds it grows by 8 bytes uniformly. The kernel and userspace are built
/// from this one crate and ship together, so the byte layout stays a single contract —
/// `kind` still discriminates the body, and an event shorter than its declared body fails
/// the userspace length check in `decode` (dropped, never misparsed).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub kind: u32,
    pub pid: u32,
    /// The cgroup id (cgroup v2 directory inode) of the task at event time, from
    /// `bpf_get_current_cgroup_id()`. `0` means the kernel couldn't determine it (older
    /// kernel / no cgroup v2) — userspace then falls back to the `/proc/<pid>/cgroup` read.
    pub cgroup_id: u64,
}

/// One observed outbound connection (kind [`KIND_CONNECT`]). `header` first so the
/// shared prefix is at offset 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnEvent {
    pub header: EventHeader,
    /// IPv4 destination, network byte order.
    pub daddr: u32,
    /// Destination port, host byte order.
    pub dport: u16,
}

/// One observed privilege escalation to root (kind [`KIND_PRIV_CHANGE`]). The eBPF side
/// already filtered to the escalation case (`new_uid == 0 && old_uid != 0`), so every
/// PrivEvent is a real gain of root. `header` first so the shared prefix is at offset 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivEvent {
    pub header: EventHeader,
    /// The process's real UID before the change (non-root).
    pub old_uid: u32,
    /// The process's real UID after the change (0 — root).
    pub new_uid: u32,
}

/// In-kernel dedup window for high-frequency repeat events. A connect to the
/// same `(pid, daddr, dport)` seen again within this many nanoseconds is coalesced —
/// suppressed at the source so it never costs a ring-buffer slot. 1s is long enough to
/// collapse a chatty process hammering one destination (the volume problem) yet short
/// enough that a genuinely sustained flow still refreshes its behavioral signal roughly
/// once a second — the additive-evidence model needs presence, not every packet.
pub const DEDUP_WINDOW_NS: u64 = 1_000_000_000;

/// Max entries in an in-kernel dedup map (connect file-write). One slot
/// per live dedup key — `(pid, dest)` for connect, `(pid, inode)` for writes; an LRU map
/// evicts the coldest when full, so a churn of distinct keys can't exhaust it (eviction
/// just means the evicted key re-emits once — safe, never a crash). Sized to cover a busy
/// node's working set while bounding kernel memory (16Ki * a small key+u64 ≈ a few hundred
/// KiB per map).
pub const DEDUP_MAP_CAP: u32 = 16384;

/// Dedup key for the connect probe: the `(pid, destination)` tuple the ticket names.
/// `repr(C)` so the in-kernel BPF-map key layout is fixed (it never crosses to userspace,
/// but keeping it `repr(C)` keeps the in-kernel ABI explicit). `daddr` is the IPv4
/// destination in network byte order, `dport` host order — same as [`ConnEvent`].
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnKey {
    pub pid: u32,
    pub daddr: u32,
    pub dport: u16,
}

impl ConnKey {
    /// Build the dedup key for a connect to `(pid, daddr, dport)`.
    pub fn new(pid: u32, daddr: u32, dport: u16) -> Self {
        Self { pid, daddr, dport }
    }
}

/// Dedup key for the file-write probe: the `(pid, inode)` tuple. Coalescing on
/// the inode collapses the high-frequency case — a process writing the SAME file
/// repeatedly (appending a log, rewriting a state file) — at the source, so a suppressed
/// write never costs a ring-buffer slot. The inode number (not the path) is the cheap
/// in-kernel key: a single `u64` read, no variable-length path hash for the verifier to
/// bound. Userspace/engine coarsen further to the dirname for the verdict-cache
/// fingerprint. `repr(C)` so the in-kernel BPF-map key layout is fixed (it never crosses
/// to userspace, same as [`ConnKey`]).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct WriteKey {
    pub pid: u32,
    pub ino: u64,
}

impl WriteKey {
    /// Build the dedup key for a write by `pid` to the file with inode `ino`.
    pub fn new(pid: u32, ino: u64) -> Self {
        Self { pid, ino }
    }
}

/// Dedup key for the credential-basename read gate (security rework): the
/// `(pid, inode)` tuple, same shape as [`WriteKey`] but a distinct type (its own LRU map,
/// its own gate) so the two dedup domains can't be mixed up at a call site. Bounds a HIGH
/// finding from security review: `try_file_open`'s widening past `is_tmpfs` to a small
/// basename allowlist (`SENSITIVE_CREDENTIAL_BASENAMES` in the eBPF crate) had no dedup, so
/// an attacker with code-exec in any pod could spam reads of a matched basename (e.g.
/// `/etc/shadow`, a `credentials` file) to exhaust the single shared ring buffer and force
/// `record_drop()` to silently drop real exec/priv-change/connect signals node-wide — a
/// sensor-blinding / detection-evasion primitive. Coalescing on `(pid, inode)` collapses
/// exactly that chatty-reader case at the source, same as [`WriteKey`] does for writes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReadKey {
    pub pid: u32,
    pub ino: u64,
}

impl ReadKey {
    /// Build the dedup key for a read by `pid` of the file with inode `ino`.
    pub fn new(pid: u32, ino: u64) -> Self {
        Self { pid, ino }
    }
}

/// Whether a repeat event keyed at `last_ns` should be coalesced (suppressed) at `now_ns`,
/// given the dedup `window_ns`. The single source of truth for the dedup
/// decision, shared verbatim by the kernel probe and the userspace tests so the two can't
/// drift. Returns `true` (coalesce — drop it) when the last emit for this key was strictly
/// within the window. A non-monotonic clock (`now_ns < last_ns`, which `bpf_ktime_get_ns`
/// never produces) is treated as "outside the window" — emit, never wrongly suppress.
#[inline]
pub fn should_coalesce(last_ns: u64, now_ns: u64, window_ns: u64) -> bool {
    now_ns >= last_ns && now_ns.saturating_sub(last_ns) < window_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_a_repeat_inside_the_window() {
        // A second connect 100ms after the first (window 1s) is a repeat — suppress it.
        assert!(should_coalesce(0, 100_000_000, DEDUP_WINDOW_NS));
    }

    #[test]
    fn emits_a_repeat_after_the_window() {
        // Exactly at the window boundary the entry has expired — emit (refresh signal).
        assert!(!should_coalesce(0, DEDUP_WINDOW_NS, DEDUP_WINDOW_NS));
        // Well past the window — emit.
        assert!(!should_coalesce(0, DEDUP_WINDOW_NS + 1, DEDUP_WINDOW_NS));
    }

    #[test]
    fn emits_the_very_first_event_for_a_key() {
        // The first event for a key has no prior timestamp, so the kernel never calls
        // this for it — but a same-tick repeat (now == last == 0) is inside the window.
        assert!(should_coalesce(0, 0, DEDUP_WINDOW_NS));
    }

    #[test]
    fn non_monotonic_clock_does_not_suppress() {
        // Defensive: if now ever reads before last, never wrongly coalesce.
        assert!(!should_coalesce(500, 100, DEDUP_WINDOW_NS));
    }

    #[test]
    fn conn_key_distinguishes_pid_dest_and_port() {
        let base = ConnKey::new(1234, u32::from_ne_bytes([10, 0, 0, 1]), 443);
        assert_eq!(
            base,
            ConnKey::new(1234, u32::from_ne_bytes([10, 0, 0, 1]), 443)
        );
        assert_ne!(
            base,
            ConnKey::new(9999, u32::from_ne_bytes([10, 0, 0, 1]), 443)
        );
        assert_ne!(
            base,
            ConnKey::new(1234, u32::from_ne_bytes([10, 0, 0, 2]), 443)
        );
        assert_ne!(
            base,
            ConnKey::new(1234, u32::from_ne_bytes([10, 0, 0, 1]), 8443)
        );
    }

    #[test]
    fn write_key_distinguishes_pid_and_inode() {
        // The file-write dedup key collapses repeat writes to the SAME (pid,
        // inode) — so it must compare equal for the same pair and differ on either field.
        let base = WriteKey::new(1234, 42);
        assert_eq!(base, WriteKey::new(1234, 42));
        assert_ne!(base, WriteKey::new(9999, 42));
        assert_ne!(base, WriteKey::new(1234, 43));
    }

    #[test]
    fn read_key_distinguishes_pid_and_inode() {
        // The credential-basename-read dedup key (security rework) mirrors
        // WriteKey's equality shape: same (pid, inode) pair compares equal, either field
        // differing does not.
        let base = ReadKey::new(1234, 42);
        assert_eq!(base, ReadKey::new(1234, 42));
        assert_ne!(base, ReadKey::new(9999, 42));
        assert_ne!(base, ReadKey::new(1234, 43));
    }
}
