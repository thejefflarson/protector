//! Per-workload ELF static/dynamic **linkage** classification (JEF-407).
//!
//! The engine has no in-cluster access to a workload's entrypoint bytes, so JEF-404's
//! static-linkage reachability sat dormant — `Image::static_binary` was always `None` in
//! prod and a Go / musl-static CVE rendered `not-observed` forever. The node-local agent DOES
//! see the running binary (`/proc/<pid>/exe`), so it is the natural byte source: on an exec it
//! reads only the leading ELF header bytes, classifies linkage with the SAME shared parser the
//! engine uses ([`protector_behavior::elf::elf_static_linkage`] — no `PT_INTERP` ⇒ static), and
//! emits a [`Behavior::ImageLinkage`] over the EXISTING behavioral wire. No new egress (the
//! zero-egress invariant holds), no heavy dependency (the parser is std-only).
//!
//! Split into a pure classifier (injectable read, unit-testable without a real `/proc`) and a
//! thin `/proc` reader (compiled only where it's used), keeping the byte source a separate,
//! testable concern from the ELF logic — the same shape the rest of the agent uses.

use protector_behavior::{Behavior, elf::elf_static_linkage};

/// How many leading bytes of the entrypoint binary to read. The classifier inspects only the
/// ELF header and the program-header table; a `PT_INTERP` (the dynamic-loader marker) is
/// among the very first program headers a linker emits, so 4 KiB comfortably covers the
/// header + the whole program-header table of any real executable while staying a single
/// cheap page-sized read. A binary whose table somehow extends past this simply classifies
/// `None` (unknown) — never a wrong answer (the classifier is conservative by construction).
pub const ELF_HEAD_CAP: usize = 4096;

/// Classify a pid's entrypoint linkage from its ELF header (JEF-407).
///
/// Returns `Some(true)` for a statically linked binary (no `PT_INTERP`), `Some(false)` for a
/// dynamically linked one, and `None` when the linkage is unknown — the exe couldn't be read
/// (process gone / denied) or the bytes don't parse as an ELF we recognize. `None` is dropped
/// by the caller rather than guessed, so the engine keeps its prior `static_binary == None`
/// behavior for that workload — never a false "static".
///
/// `read_head` is injected (a `Fn(u32) -> Option<Vec<u8>>` yielding the leading bytes of
/// `/proc/<pid>/exe`) so this is unit-testable with synthetic ELF fixtures and no real `/proc`.
pub fn classify_linkage(read_head: impl Fn(u32) -> Option<Vec<u8>>, pid: u32) -> Option<bool> {
    elf_static_linkage(&read_head(pid)?)
}

/// The wire signal for a classified linkage: a [`Behavior::ImageLinkage`] carrying the
/// static/dynamic bit. Trivial, but named so the observer's emit path reads clearly and the
/// mapping lives in one place.
pub fn linkage_behavior(static_linkage: bool) -> Behavior {
    Behavior::ImageLinkage { static_linkage }
}

/// Read up to [`ELF_HEAD_CAP`] leading bytes of a pid's entrypoint binary via
/// `/proc/<pid>/exe`. `None` if the process is gone or the exe is unreadable (a kernel thread,
/// a denied read) — the linkage is then unknown and the caller drops it, never fatal. Reads
/// only the header prefix, not the whole (possibly huge) binary.
pub fn read_exe_head(pid: u32) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(format!("/proc/{pid}/exe")).ok()?;
    let mut buf = Vec::with_capacity(ELF_HEAD_CAP);
    // `take` bounds the read to the header prefix regardless of the binary's real size.
    file.take(ELF_HEAD_CAP as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 64-bit little-endian ELF header + program-header table over `p_types`
    /// (mirrors the shared classifier's own fixtures — the smallest bytes that classify).
    fn elf64_le(p_types: &[u32]) -> Vec<u8> {
        const EHDR64: usize = 0x40;
        const PHENT64: usize = 0x38;
        let phnum = p_types.len();
        let phoff = EHDR64;
        let mut buf = vec![0u8; EHDR64 + phnum * PHENT64];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        buf[0x36..0x38].copy_from_slice(&(PHENT64 as u16).to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(phnum as u16).to_le_bytes());
        for (i, &p_type) in p_types.iter().enumerate() {
            let at = phoff + i * PHENT64;
            buf[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
        }
        buf
    }

    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;

    #[test]
    fn static_entrypoint_classifies_static() {
        // A Go / musl-static entrypoint: LOAD segments, no PT_INTERP → Some(true).
        let bytes = elf64_le(&[PT_LOAD, PT_LOAD]);
        assert_eq!(classify_linkage(|_| Some(bytes.clone()), 42), Some(true));
    }

    #[test]
    fn dynamic_entrypoint_classifies_dynamic() {
        // A glibc dynamically linked entrypoint: a PT_INTERP among the LOADs → Some(false).
        let bytes = elf64_le(&[PT_LOAD, PT_INTERP]);
        assert_eq!(classify_linkage(|_| Some(bytes.clone()), 42), Some(false));
    }

    #[test]
    fn unreadable_exe_is_unknown() {
        // The process is gone / the exe is unreadable → None (dropped, never guessed).
        assert_eq!(classify_linkage(|_| None, 42), None);
    }

    #[test]
    fn non_elf_bytes_are_unknown() {
        // A script interpreter or garbage prefix → None, not a wrong classification.
        assert_eq!(
            classify_linkage(|_| Some(b"#!/bin/sh\n".to_vec()), 42),
            None
        );
    }

    #[test]
    fn read_exe_head_reads_at_most_the_cap_and_never_panics() {
        // `/proc/self/exe` exists on Linux (where the agent runs); reading it must return the
        // leading header bytes bounded by the cap, and must never read the whole binary. On a
        // non-Linux dev box `/proc` is absent → None (the same honest "unknown" the classifier
        // drops). Either way the read must not panic.
        if let Some(head) = read_exe_head(std::process::id()) {
            assert!(head.len() <= ELF_HEAD_CAP, "read is bounded by the cap");
            assert!(!head.is_empty(), "a real binary has a header");
        }
    }

    #[test]
    fn linkage_behavior_carries_the_bit() {
        assert_eq!(
            linkage_behavior(true),
            Behavior::ImageLinkage {
                static_linkage: true
            }
        );
        assert_eq!(
            linkage_behavior(false),
            Behavior::ImageLinkage {
                static_linkage: false
            }
        );
    }
}
