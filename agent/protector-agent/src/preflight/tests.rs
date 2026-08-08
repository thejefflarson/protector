//! End-to-end preflight tests: [`super::check`]/[`super::check_bytes`] against a fixture
//! BTF blob ([`crate::preflight::fixture::BtfBuilder`]) that mirrors the real
//! `FIELD_OFFSETS` table field-for-field, so these exercise the exact same lookups the
//! agent runs against a node's live BTF — just against a hand-built "kernel" instead.

use super::fixture::BtfBuilder;
use super::*;

/// Build a fixture whose struct layout matches every [`FIELD_OFFSETS`] entry. Each
/// parameter lets a caller deliberately vary the one field a test is targeting while
/// every other field stays correct — the shared shape both `golden()` (all correct) and
/// every mismatch test build from, so a fixture's correct fields never drift out of sync
/// between tests.
///
/// `f_path_offset`: `file.f_path`'s offset (varied to simulate a kernel-upgrade-moved
/// offset). `inode_union_offset`: the anonymous union holding `i_nlink`/`__i_nlink`'s own
/// offset within `inode` (varied to prove the anon-union recursion actually adds it in,
/// rather than ignoring it). `loading_module_value`: the `LOADING_MODULE` enum variant's
/// value. `include_linux_binprm`: omit the struct entirely to simulate a field BTF has no
/// record of at all (`actual: None`, not just a moved offset).
fn build_fixture(
    f_path_offset: u32,
    inode_union_offset: u32,
    loading_module_value: i32,
    include_linux_binprm: bool,
) -> Vec<u8> {
    let mut b = BtfBuilder::new();
    b.add_struct(
        "file",
        false,
        &[
            ("f_inode", 0, 32),
            ("f_flags", 0, 40),
            ("f_path", 0, f_path_offset),
        ],
    );
    b.add_struct("path", false, &[("dentry", 0, 8)]);
    b.add_struct("dentry", false, &[("d_name", 0, 32)]);
    b.add_struct("qstr", false, &[("name", 0, 8)]);
    // inode.i_nlink lives in an anonymous union immediately after i_ino — the same shape
    // the real kernel struct has (see vmlinux.rs's module doc).
    let union_id = b.add_struct("", true, &[("i_nlink", 0, 0), ("__i_nlink", 0, 0)]);
    b.add_struct(
        "inode",
        false,
        &[
            ("i_sb", 0, 40),
            ("i_ino", 0, 64),
            ("", union_id, inode_union_offset),
        ],
    );
    b.add_struct("super_block", false, &[("s_magic", 0, 96)]);
    b.add_struct("cred", false, &[("uid", 0, 8)]);
    b.add_struct("kuid_t", false, &[("val", 0, 0)]);
    if include_linux_binprm {
        b.add_struct(
            "linux_binprm",
            false,
            &[("file", 0, 64), ("filename", 0, 96)],
        );
    }
    b.add_enum(
        "kernel_load_data_id",
        &[
            ("LOADING_UNKNOWN", 0),
            ("LOADING_FIRMWARE", 1),
            ("LOADING_MODULE", loading_module_value),
        ],
    );
    b.build()
}

fn golden() -> Vec<u8> {
    build_fixture(64, 72, 2, true)
}

#[test]
fn correct_offsets_and_enum_pass_clean() {
    let report = check_bytes(&golden());
    assert!(report.is_clean(), "{report:?}");
    assert!(report.field_mismatches.is_empty());
    assert!(report.enum_mismatch.is_none());
}

#[test]
fn a_moved_offset_is_flagged_with_expected_and_actual() {
    // Simulate the 6.8→6.11 struct file reorg the module doc describes: f_path moves
    // from +64 to +72.
    let report = check_bytes(&build_fixture(72, 72, 2, true));
    assert_eq!(
        report.field_mismatches,
        vec![FieldMismatch {
            kernel_struct: "file",
            field: "f_path",
            expected: 64,
            actual: Some(72),
        }]
    );
    assert!(!report.struct_ok("file"));
    // Every OTHER struct's fields were untouched — only `file` fails.
    assert!(report.struct_ok("inode"));
    assert!(report.struct_ok("linux_binprm"));
    assert!(report.enum_mismatch.is_none());
}

#[test]
fn anon_union_recursion_resolves_i_nlink_correctly() {
    // A dedicated, independent check that the anon-union recursion the module doc calls
    // out (`inode.i_nlink`) is exactly the field the full-table check relies on: placing
    // the union itself at the WRONG offset (+80 instead of +72) must surface as exactly
    // one `inode.i_nlink` mismatch (72 expected, 80 actual), proving the recursion
    // actually adds the anon member's own offset in rather than ignoring it.
    let report = check_bytes(&build_fixture(64, 80, 2, true));
    assert_eq!(
        report.field_mismatches,
        vec![FieldMismatch {
            kernel_struct: "inode",
            field: "i_nlink",
            expected: 72,
            actual: Some(80),
        }]
    );
    assert!(!report.struct_ok("inode"));
}

#[test]
fn enum_value_mismatch_is_flagged_independently_of_field_offsets() {
    let report = check_bytes(&build_fixture(64, 72, 5, true));
    assert!(report.field_mismatches.is_empty());
    assert_eq!(
        report.enum_mismatch,
        Some(EnumMismatch {
            enum_name: "kernel_load_data_id",
            variant: "LOADING_MODULE",
            expected: 2,
            actual: Some(5),
        })
    );
}

#[test]
fn a_struct_missing_from_btf_entirely_flags_every_field_with_no_actual() {
    let report = check_bytes(&build_fixture(64, 72, 2, false));
    let mut binprm: Vec<_> = report
        .field_mismatches
        .iter()
        .filter(|m| m.kernel_struct == "linux_binprm")
        .collect();
    binprm.sort_by_key(|m| m.field);
    assert_eq!(binprm.len(), 2);
    assert_eq!(binprm[0].field, "file");
    assert_eq!(binprm[0].actual, None);
    assert_eq!(binprm[1].field, "filename");
    assert_eq!(binprm[1].actual, None);
    assert!(!report.struct_ok("linux_binprm"));
    assert!(report.struct_ok("file")); // unrelated structs stay clean
}

#[test]
fn unparseable_btf_fails_closed_on_every_table_entry() {
    let report = check_bytes(b"not a btf blob");
    assert_eq!(report, PreflightReport::fail_closed());
    assert_eq!(report.field_mismatches.len(), FIELD_OFFSETS.len());
    assert!(
        FIELD_OFFSETS
            .iter()
            .all(|e| !report.struct_ok(e.kernel_struct))
    );
    assert!(report.enum_mismatch.is_some());
}
