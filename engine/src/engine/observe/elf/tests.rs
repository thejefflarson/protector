//! Unit tests for the ELF static-linkage classifier (JEF-404). Fixtures are built as the
//! smallest representative ELF byte layouts — a 64-bit little-endian header plus a program
//! header table — so a `PT_INTERP` entry (dynamic) and its absence (static) classify
//! differently WITHOUT shipping a real multi-megabyte binary. The classifier reads only the
//! header and the program-header table, so these minimal fixtures exercise the whole path.

use super::*;

/// ELF header size for the 64-bit layout (`Elf64_Ehdr`).
const EHDR64: usize = 0x40;
/// Program-header entry size for the 64-bit layout (`Elf64_Phdr`).
const PHENT64: usize = 0x38;

/// Build a minimal 64-bit little-endian ELF: a valid header pointing at a program-header
/// table of `p_types`, one entry per type. Only the fields the classifier reads
/// (magic, class, data, e_phoff, e_phentsize, e_phnum, and each entry's p_type) are set;
/// everything else is zero — that is all the classifier inspects.
fn elf64_le(p_types: &[u32]) -> Vec<u8> {
    let phnum = p_types.len();
    let phoff = EHDR64;
    let mut buf = vec![0u8; EHDR64 + phnum * PHENT64];
    // e_ident
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    // e_phoff (u64 @ 0x20)
    buf[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
    // e_phentsize (u16 @ 0x36), e_phnum (u16 @ 0x38)
    buf[0x36..0x38].copy_from_slice(&(PHENT64 as u16).to_le_bytes());
    buf[0x38..0x3A].copy_from_slice(&(phnum as u16).to_le_bytes());
    // program headers: p_type is the first u32 of each entry
    for (i, &p_type) in p_types.iter().enumerate() {
        let at = phoff + i * PHENT64;
        buf[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
    }
    buf
}

/// Build a minimal 32-bit little-endian ELF (`Elf32_Ehdr` = 0x34, `Elf32_Phdr` = 0x20),
/// to confirm the class-dependent offsets are handled, not just the 64-bit path.
fn elf32_le(p_types: &[u32]) -> Vec<u8> {
    const EHDR32: usize = 0x34;
    const PHENT32: usize = 0x20;
    let phnum = p_types.len();
    let phoff = EHDR32;
    let mut buf = vec![0u8; EHDR32 + phnum * PHENT32];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 1; // ELFCLASS32
    buf[5] = 1; // ELFDATA2LSB
    buf[0x1C..0x20].copy_from_slice(&(phoff as u32).to_le_bytes()); // e_phoff (u32)
    buf[0x2A..0x2C].copy_from_slice(&(PHENT32 as u16).to_le_bytes()); // e_phentsize
    buf[0x2C..0x2E].copy_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum
    for (i, &p_type) in p_types.iter().enumerate() {
        let at = phoff + i * PHENT32;
        buf[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
    }
    buf
}

const PT_LOAD: u32 = 1;
const PT_INTERP_T: u32 = 3;

#[test]
fn static_elf_has_no_interp_program_header() {
    // A Go / musl-static binary: LOAD segments, but no PT_INTERP naming a dynamic loader.
    let bytes = elf64_le(&[PT_LOAD, PT_LOAD]);
    assert_eq!(
        elf_static_linkage(&bytes),
        Some(true),
        "an ELF with no PT_INTERP is statically linked"
    );
}

#[test]
fn dynamic_elf_carries_an_interp_program_header() {
    // A normal glibc dynamically-linked executable: a PT_INTERP segment among its LOADs.
    let bytes = elf64_le(&[PT_LOAD, PT_INTERP_T, PT_LOAD]);
    assert_eq!(
        elf_static_linkage(&bytes),
        Some(false),
        "an ELF with a PT_INTERP is dynamically linked"
    );
}

#[test]
fn static_vs_dynamic_classify_differently() {
    // The core JEF-404 distinction: the same shape with vs without PT_INTERP must differ.
    let stat = elf64_le(&[PT_LOAD]);
    let dynm = elf64_le(&[PT_LOAD, PT_INTERP_T]);
    assert_ne!(elf_static_linkage(&stat), elf_static_linkage(&dynm));
    assert_eq!(elf_static_linkage(&stat), Some(true));
    assert_eq!(elf_static_linkage(&dynm), Some(false));
}

#[test]
fn thirty_two_bit_elf_is_classified_with_class_specific_offsets() {
    // The 32-bit layout has different header offsets; both static and dynamic must classify.
    assert_eq!(elf_static_linkage(&elf32_le(&[PT_LOAD])), Some(true));
    assert_eq!(elf_static_linkage(&elf32_le(&[PT_INTERP_T])), Some(false));
}

#[test]
fn big_endian_byte_order_is_honored() {
    // A big-endian (ELFDATA2MSB) 64-bit ELF: fields must be read big-endian, else e_phnum
    // would read as a huge number and mis-parse. Build it by hand in BE.
    let phnum = 1usize;
    let mut buf = vec![0u8; EHDR64 + phnum * PHENT64];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 2; // ELFDATA2MSB
    buf[0x20..0x28].copy_from_slice(&(EHDR64 as u64).to_be_bytes());
    buf[0x36..0x38].copy_from_slice(&(PHENT64 as u16).to_be_bytes());
    buf[0x38..0x3A].copy_from_slice(&(phnum as u16).to_be_bytes());
    buf[EHDR64..EHDR64 + 4].copy_from_slice(&PT_LOAD.to_be_bytes());
    assert_eq!(elf_static_linkage(&buf), Some(true));
}

#[test]
fn non_elf_and_truncated_input_is_unknown() {
    // Not an ELF at all → unknown (never guess).
    assert_eq!(elf_static_linkage(b"#!/bin/sh\n"), None);
    // ELF magic but truncated before the header fields → unknown.
    assert_eq!(elf_static_linkage(&[0x7f, b'E', b'L', b'F']), None);
    // Empty → unknown.
    assert_eq!(elf_static_linkage(&[]), None);
}

#[test]
fn unrecognized_class_or_data_is_unknown() {
    // Valid magic but a bogus EI_CLASS / EI_DATA → unknown, not a wrong classification.
    let mut bad_class = elf64_le(&[PT_LOAD]);
    bad_class[4] = 9; // not ELFCLASS32/64
    assert_eq!(elf_static_linkage(&bad_class), None);
    let mut bad_data = elf64_le(&[PT_LOAD]);
    bad_data[5] = 9; // not LSB/MSB
    assert_eq!(elf_static_linkage(&bad_data), None);
}

#[test]
fn no_program_headers_is_unknown_not_static() {
    // A relocatable object (e_phnum == 0): we cannot see an interpreter, so we must NOT
    // assert static linkage — an honest unknown.
    let bytes = elf64_le(&[]);
    assert_eq!(elf_static_linkage(&bytes), None);
}

#[test]
fn out_of_range_program_header_table_is_unknown() {
    // e_phoff points past the end of the buffer → the per-entry read fails → unknown,
    // never a panic and never a wrong classification.
    let mut bytes = elf64_le(&[PT_LOAD]);
    bytes[0x20..0x28].copy_from_slice(&(0xFFFF_FFFFu64).to_le_bytes());
    assert_eq!(elf_static_linkage(&bytes), None);
}
