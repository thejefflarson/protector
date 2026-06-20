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
/// A file was opened (fentry on `security_file_open`). Spike phase 1 carries only the
/// header (pid) to confirm the hook attaches/fires; phase 2 adds the path body so the
/// userspace side can recognize secret-mount reads. Next: KIND_LIBRARY_LOAD = 3.
pub const KIND_FILE_OPEN: u32 = 2;

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
