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

/// The fixed prefix of every event in the ring buffer. `repr(C)`, at offset 0 of each
/// body, so userspace can read `kind` (and `pid`) before it knows which body follows.
/// `pid` is common to every event (userspace maps it via /proc/<pid>/cgroup → pod).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub kind: u32,
    pub pid: u32,
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
