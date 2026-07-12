//! Minimal ELF static-linkage classification (JEF-404).
//!
//! Reachability is proven by correlating a CVE's package against runtime
//! [`Behavior::LibraryLoaded`](protector_behavior::Behavior::LibraryLoaded) events: a
//! `.so` the kernel loads names the vulnerable package. **Statically linked binaries have
//! no per-library `.so` loads** — Go compiles everything into one executable, a
//! CGO-disabled / musl-static build does the same — so `LibraryLoaded` never names the
//! package and every CVE renders `not-observed` even when the vulnerable code is genuinely
//! on a hot path. That absence must not read as evidence-of-absence (see
//! [`Reachability::PresentStaticBinary`](crate::engine::graph::Reachability)).
//!
//! The cheapest reliable signal that a binary is static is its ELF header: a dynamically
//! linked executable carries a `PT_INTERP` program header naming its dynamic loader
//! (`/lib64/ld-linux-x86-64.so.2`, …); a fully static one does **not**. This module reads
//! ONLY the ELF header and the program-header table — no sections, no symbols, no dynamic
//! table — so it is a tiny, well-scoped parser rather than a heavyweight ELF dependency
//! (zero new heavy crate; the graph stays zero-egress — this only ever inspects bytes the
//! engine was already handed).
//!
//! It is byte-only and pure: give it the leading bytes of a binary, get back whether it is
//! statically linked. That keeps it fully unit-testable with tiny synthetic fixtures and
//! keeps *where the bytes come from* a separate plumbing concern.

/// The four-byte ELF magic (`0x7f 'E' 'L' 'F'`) every ELF file starts with.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// `e_ident[EI_CLASS]` values: 32-bit vs 64-bit. Their layouts differ only in field widths.
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

/// `e_ident[EI_DATA]` values: little- vs big-endian. We honor the file's own byte order so
/// a cross-compiled (e.g. big-endian) binary classifies correctly.
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

/// Program-header type `PT_INTERP` — names the dynamic loader. Its presence is the
/// definitive "this binary is dynamically linked" signal; its absence (in an otherwise
/// valid executable) means static linkage.
const PT_INTERP: u32 = 3;

/// Classify a binary's ELF header as statically vs dynamically linked (JEF-404).
///
/// Returns:
/// - `Some(true)`  — a valid ELF with **no** `PT_INTERP` program header: statically linked.
/// - `Some(false)` — a valid ELF that carries a `PT_INTERP` header: dynamically linked.
/// - `None`        — not an ELF, truncated, or a header we can't parse: linkage unknown, so
///   the caller must fall back to the pre-existing behavior (never guess "static").
///
/// Deliberately conservative: any malformed or unrecognized field yields `None` rather than
/// a wrong classification — a false "static" would mislabel a `not-observed` CVE as
/// indeterminate, and a false "dynamic" would do the reverse, so an honest "unknown" is the
/// only safe answer when the bytes don't parse cleanly.
///
/// Only the ELF header (`e_phoff`, `e_phentsize`, `e_phnum`) and the program-header table
/// (each entry's `p_type`) are read — bounded, allocation-free, and it stops at the first
/// `PT_INTERP` it finds.
pub fn elf_static_linkage(bytes: &[u8]) -> Option<bool> {
    // e_ident is 16 bytes; the smallest header we parse (32-bit) is 52 bytes. Reject
    // anything too short to hold even the fields we read.
    if bytes.len() < 20 || bytes[..4] != ELF_MAGIC {
        return None;
    }
    let class = bytes[4];
    let data = bytes[5];
    let le = match data {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return None,
    };

    // Field offsets/sizes differ between the 32- and 64-bit ELF header layouts. We need
    // e_phoff (program-header table file offset), e_phentsize (per-entry size), and e_phnum
    // (entry count) — plus, per entry, the p_type at the entry's start.
    let (phoff_off, phentsize_off, phnum_off) = match class {
        ELFCLASS64 => (0x20usize, 0x36usize, 0x38usize),
        ELFCLASS32 => (0x1Cusize, 0x2Ausize, 0x2Cusize),
        _ => return None,
    };

    let phoff = match class {
        ELFCLASS64 => read_u64(bytes, phoff_off, le)? as usize,
        _ => read_u32(bytes, phoff_off, le)? as usize,
    };
    let phentsize = read_u16(bytes, phentsize_off, le)? as usize;
    let phnum = read_u16(bytes, phnum_off, le)? as usize;

    // No program headers at all (e.g. a relocatable object, or e_phoff == 0): we cannot see
    // an interpreter, so we cannot assert static linkage — report unknown.
    if phoff == 0 || phnum == 0 || phentsize < 4 {
        return None;
    }

    // p_type is the FIRST 4 bytes of every program-header entry in both ELF classes, so we
    // only ever read those 4 bytes per entry regardless of 32/64-bit width.
    for i in 0..phnum {
        let entry = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let p_type = read_u32(bytes, entry, le)?;
        if p_type == PT_INTERP {
            // A dynamic loader is named → dynamically linked.
            return Some(false);
        }
    }
    // A valid ELF whose program headers name no interpreter → statically linked.
    Some(true)
}

fn read_u16(bytes: &[u8], off: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = bytes.get(off..off + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn read_u32(bytes: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

fn read_u64(bytes: &[u8], off: usize, le: bool) -> Option<u64> {
    let b: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    })
}

#[cfg(test)]
mod tests;
