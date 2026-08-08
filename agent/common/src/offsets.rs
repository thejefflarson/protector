//! The offset/enum table both the eBPF crate's compile-time guard and the userspace
//! loader's load-time BTF preflight read (ADR-0014 amendment). See the module doc in
//! `lib.rs` for why this exists: one number, checked twice (compile time against the
//! hand-laid bindings, load time against the running kernel's live BTF), never hand-kept
//! in sync between the two.

/// One `(struct, field, expected byte offset)` entry — a field the eBPF probes read via a
/// baked offset (`agent/protector-agent-ebpf/src/vmlinux.rs`). `kernel_struct` is the
/// struct's name as it appears in kernel BTF (e.g. `"file"`, not a Rust type path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldOffset {
    pub kernel_struct: &'static str,
    pub field: &'static str,
    /// Verified byte offset on the fleet's kernel (7.0.0 — see `vmlinux.rs`'s module doc
    /// for the derivation of each field below).
    pub offset: u32,
}

impl FieldOffset {
    const fn new(kernel_struct: &'static str, field: &'static str, offset: u32) -> Self {
        Self {
            kernel_struct,
            field,
            offset,
        }
    }
}

/// Every field offset a probe bakes in. Order mirrors `vmlinux.rs`'s struct declarations
/// (`file` → `path` → `dentry` → `qstr` → `inode` → `super_block` → `cred`/`kuid_t` →
/// `linux_binprm`), so a diff against that file's `offset_of!` block reads in the same
/// order.
pub const FIELD_OFFSETS: &[FieldOffset] = &[
    FieldOffset::new("file", "f_inode", 32),
    FieldOffset::new("file", "f_flags", 40),
    FieldOffset::new("file", "f_path", 64),
    FieldOffset::new("path", "dentry", 8),
    FieldOffset::new("dentry", "d_name", 32),
    FieldOffset::new("qstr", "name", 8),
    FieldOffset::new("inode", "i_sb", 40),
    FieldOffset::new("inode", "i_ino", 64),
    // Lives in an anonymous union immediately after i_ino (`union { const unsigned int
    // i_nlink; unsigned int __i_nlink; }`) — both the compile-time `offset_of!` (a plain
    // Rust field access through the flattened binding) and the load-time BTF walk (which
    // must recurse into the anonymous union to find it) land on the SAME byte offset, +72.
    FieldOffset::new("inode", "i_nlink", 72),
    FieldOffset::new("super_block", "s_magic", 96),
    FieldOffset::new("cred", "uid", 8),
    FieldOffset::new("kuid_t", "val", 0),
    FieldOffset::new("linux_binprm", "file", 64),
    FieldOffset::new("linux_binprm", "filename", 96),
];

/// The BTF enum the module-load probe's `LOADING_MODULE` constant must match
/// (`agent/protector-agent-ebpf/src/main.rs`; `include/linux/kernel_read_file.h`'s `enum
/// kernel_load_data_id`). Unlike a struct offset this is never verifier-checked — a wrong
/// value is a plain integer compare that misclassifies silently rather than failing loud
/// — which is why the preflight checks it explicitly (ADR-0014 amendment).
pub const LOADING_MODULE_ENUM: &str = "kernel_load_data_id";
pub const LOADING_MODULE_VARIANT: &str = "LOADING_MODULE";
pub const LOADING_MODULE_VALUE: u32 = 2;

/// Look up `kernel_struct.field`'s expected byte offset in [`FIELD_OFFSETS`]. `const fn`
/// so the eBPF crate's `offset_of!` guard can assert `bindings == table` at compile time —
/// the identical lookup the userspace preflight performs against live BTF at load time.
/// Panics (a compile error in the `const` context it's used from) if the pair isn't in the
/// table — a coding mistake to fix by adding the entry, not a runtime condition.
pub const fn offset_of_table(kernel_struct: &str, field: &str) -> u32 {
    let mut i = 0;
    while i < FIELD_OFFSETS.len() {
        let entry = FIELD_OFFSETS[i];
        if str_eq(entry.kernel_struct, kernel_struct) && str_eq(entry.field, field) {
            return entry.offset;
        }
        i += 1;
    }
    panic!("offset_of_table: no FIELD_OFFSETS entry for this (struct, field) — add it there first")
}

/// `const fn` byte-wise string equality — `&str`'s `PartialEq` isn't `const`, so
/// [`offset_of_table`] (evaluated at compile time by the eBPF crate's `offset_of!` guard)
/// needs its own.
const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_of_table_matches_the_declared_entries() {
        for entry in FIELD_OFFSETS {
            assert_eq!(
                offset_of_table(entry.kernel_struct, entry.field),
                entry.offset
            );
        }
    }

    #[test]
    #[should_panic(expected = "no FIELD_OFFSETS entry")]
    fn offset_of_table_panics_on_an_unknown_pair() {
        offset_of_table("file", "not_a_real_field");
    }

    #[test]
    fn str_eq_distinguishes_length_and_content() {
        assert!(str_eq("file", "file"));
        assert!(!str_eq("file", "files"));
        assert!(!str_eq("file", "path"));
        assert!(str_eq("", ""));
    }
}
