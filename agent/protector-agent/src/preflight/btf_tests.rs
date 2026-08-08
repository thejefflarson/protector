use super::*;
use crate::preflight::fixture::BtfBuilder;

#[test]
fn rejects_data_shorter_than_a_header() {
    assert!(matches!(
        RawBtf::parse(&[0u8; 4]),
        Err(BtfParseError::TooShort)
    ));
}

#[test]
fn rejects_bad_magic() {
    let mut blob = vec![0u8; 24];
    blob[0] = 0xaa;
    blob[1] = 0xbb;
    assert!(matches!(RawBtf::parse(&blob), Err(BtfParseError::BadMagic)));
}

#[test]
fn rejects_a_type_section_that_overruns_the_blob() {
    // A well-formed header claiming a type_len far larger than the actual data.
    let mut blob = vec![0u8; 24];
    blob[0..2].copy_from_slice(&0xeb9fu16.to_le_bytes());
    blob[4..8].copy_from_slice(&24u32.to_le_bytes()); // hdr_len
    blob[12..16].copy_from_slice(&999u32.to_le_bytes()); // type_len — way past EOF
    assert!(matches!(
        RawBtf::parse(&blob),
        Err(BtfParseError::Truncated)
    ));
}

#[test]
fn endian_u32_and_i32_are_total_on_a_too_short_slice() {
    // Regression for the ADR-0014 never-panic contract: `Endian::u32`/`i32` used to
    // `.expect()` a 4-byte slice. Every current caller happens to pass one, but a
    // wrong-sized caller (or a future one) must fail closed with `Truncated`, not panic.
    assert!(matches!(
        Endian::Little.u32(&[1, 2, 3]),
        Err(BtfParseError::Truncated)
    ));
    assert!(matches!(
        Endian::Big.u32(&[]),
        Err(BtfParseError::Truncated)
    ));
    assert!(matches!(
        Endian::Little.i32(&[0u8; 2]),
        Err(BtfParseError::Truncated)
    ));
}

#[test]
fn a_blob_truncated_mid_integer_fails_closed_without_panicking() {
    // A well-formed blob (built by the same fixture builder the other tests use), then
    // cut short a couple of bytes into its type section — the truncation lands
    // mid-integer, inside the last member's byte_offset word, not on a type boundary.
    // The parser must fail closed (Truncated), never panic, on this malformed input.
    let mut b = BtfBuilder::new();
    b.add_struct("demo_file", false, &[("f_flags", 0, 40), ("f_path", 0, 64)]);
    let mut blob = b.build();
    blob.truncate(blob.len() - 2);
    assert!(matches!(
        RawBtf::parse(&blob),
        Err(BtfParseError::Truncated)
    ));
}

#[test]
fn finds_a_plain_struct_field_offset() {
    let mut b = BtfBuilder::new();
    b.add_struct("demo_file", false, &[("f_flags", 0, 40), ("f_path", 0, 64)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("demo_file", "f_flags"), Some(40));
    assert_eq!(btf.struct_field_offset("demo_file", "f_path"), Some(64));
}

#[test]
fn unknown_struct_or_field_is_none() {
    let mut b = BtfBuilder::new();
    b.add_struct("demo_file", false, &[("f_flags", 0, 40)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("no_such_struct", "f_flags"), None);
    assert_eq!(btf.struct_field_offset("demo_file", "no_such_field"), None);
}

#[test]
fn recurses_into_an_anonymous_union_member() {
    // Mirrors `struct inode`: i_ino at +64, then an anonymous union (itself starting at
    // +72) whose first member is i_nlink — the parser must add the union member's own
    // offset (+72) to i_nlink's offset WITHIN the union (0) to land on +72.
    let mut b = BtfBuilder::new();
    let union_id = b.add_struct("", true, &[("i_nlink", 0, 0), ("__i_nlink", 0, 0)]);
    b.add_struct("demo_inode", false, &[("i_ino", 0, 64), ("", union_id, 72)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("demo_inode", "i_ino"), Some(64));
    assert_eq!(btf.struct_field_offset("demo_inode", "i_nlink"), Some(72));
    assert_eq!(btf.struct_field_offset("demo_inode", "__i_nlink"), Some(72));
}

#[test]
fn recurses_through_a_typedef_wrapping_the_anonymous_members_type() {
    // A pathological but legal shape: the anonymous member's type is a typedef of the
    // union, not the union directly. The walk must see through it.
    let mut b = BtfBuilder::new();
    let union_id = b.add_struct("", true, &[("val", 0, 0)]);
    let typedef_id = b.add_typedef("kuid_t", union_id);
    b.add_struct("demo_cred", false, &[("", typedef_id, 8)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("demo_cred", "val"), Some(8));
}

#[test]
fn finds_an_enum_variant_value() {
    let mut b = BtfBuilder::new();
    b.add_enum(
        "demo_kernel_load_data_id",
        &[
            ("LOADING_UNKNOWN", 0),
            ("LOADING_FIRMWARE", 1),
            ("LOADING_MODULE", 2),
        ],
    );
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(
        btf.enum_value("demo_kernel_load_data_id", "LOADING_MODULE"),
        Some(2)
    );
    assert_eq!(
        btf.enum_value("demo_kernel_load_data_id", "LOADING_FIRMWARE"),
        Some(1)
    );
    assert_eq!(
        btf.enum_value("demo_kernel_load_data_id", "NOT_A_VARIANT"),
        None
    );
}

#[test]
fn anonymous_member_recursion_terminates_on_a_self_referential_type() {
    // A malformed/adversarial BTF blob could encode a struct whose anonymous member
    // points back at itself (or a longer cycle) — the walk must terminate (a bounded
    // "not found", never a stack overflow that would crash the agent outright rather
    // than degrade gracefully, ADR-0014).
    let mut b = BtfBuilder::new();
    let self_id = b.next_id();
    b.add_struct("cyclic", false, &[("", self_id, 0)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("cyclic", "anything"), None);
}

#[test]
fn a_second_struct_of_the_same_name_does_not_confuse_the_first_lookup() {
    // BTF is append-only per compilation unit; a real vmlinux blob has thousands of
    // types. Confirm the scan returns the FIRST struct match, not a later unrelated one.
    let mut b = BtfBuilder::new();
    b.add_struct("file", false, &[("f_flags", 0, 40)]);
    b.add_struct("other", false, &[("f_flags", 0, 999)]);
    let btf = RawBtf::parse(&b.build()).unwrap();
    assert_eq!(btf.struct_field_offset("file", "f_flags"), Some(40));
}

#[test]
fn parses_a_big_endian_header() {
    // A minimal, valid BTF header + one empty string table, every multi-byte field
    // encoded BIG-endian — confirms `RawBtf::parse` detects endianness from the magic
    // bytes rather than assuming the host's (the fixture builder above only ever
    // produces little-endian blobs, matching a real `bpfel`-target node).
    let mut blob = Vec::new();
    blob.extend_from_slice(&0xeb9fu16.to_be_bytes()); // magic
    blob.push(1); // version
    blob.push(0); // flags
    blob.extend_from_slice(&24u32.to_be_bytes()); // hdr_len
    blob.extend_from_slice(&0u32.to_be_bytes()); // type_off
    blob.extend_from_slice(&0u32.to_be_bytes()); // type_len (no types)
    blob.extend_from_slice(&0u32.to_be_bytes()); // str_off
    blob.extend_from_slice(&1u32.to_be_bytes()); // str_len (just the leading NUL)
    blob.push(0); // the string table's leading NUL byte
    let btf = RawBtf::parse(&blob).unwrap();
    assert_eq!(btf.struct_field_offset("anything", "anything"), None);
}
