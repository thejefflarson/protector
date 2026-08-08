//! Which kernel structs each struct-reading fentry probe depends on, and the load-time
//! BTF preflight wiring that turns that dependency table into an attach/skip decision
//! (ADR-0014 amendment). Split out of `observer.rs` to keep it under the repo's 1,000-line
//! file cap. `crate::preflight` does the actual BTF walk this module consumes; this file
//! is only the probe-classification policy and its logging.

use crate::preflight::PreflightReport;

/// Which kernel structs (by `protector_agent_common::offsets::FIELD_OFFSETS` struct name)
/// each fentry probe's kernel-side code (`protector-agent-ebpf/src/main.rs`) reads
/// through. The preflight disables a probe here if ANY field of ANY struct it depends on
/// diverged from live BTF — fail-closed, at struct granularity: a moved field can shift
/// every other pointer chase through that same struct, so a probe reading `inode` at all
/// is untrusted the moment ONE `inode` field diverges, not just the one that moved. A
/// probe absent from this table reads no vmlinux struct offset at all (only scalar
/// arguments and the shared `EventHeader`) and always attaches regardless of the
/// preflight.
const STRUCT_DEPS: &[(&str, &[&str])] = &[
    // file_open: is_tmpfs (file→f_inode→inode→i_sb→super_block) + the sensitive-
    // credential-basename check (file→f_path→path→dentry→d_name→qstr) + emit_file_path
    // (file.f_path itself, for bpf_d_path).
    (
        "file_open",
        &["file", "inode", "super_block", "path", "dentry", "qstr"],
    ),
    // file_write: the write-intent filter (file.f_flags) + inode_ino (file→f_inode→
    // inode.i_ino, the dedup key) + emit_file_path (file.f_path).
    ("file_write", &["file", "inode", "path"]),
    // mmap_file: emit_lib_name (file→f_path→path→dentry→d_name→qstr).
    ("mmap_file", &["file", "path", "dentry", "qstr"]),
    // fix_setuid: cred→uid (kuid_t.val).
    ("fix_setuid", &["cred", "kuid_t"]),
    // bprm_check: linux_binprm.file/.filename, plus exe_is_anon_inode's
    // file→f_inode→inode→i_sb→super_block chase.
    (
        "bprm_check",
        &["linux_binprm", "file", "inode", "super_block"],
    ),
    // ptrace_access_check / kernel_load_data read only scalar arguments (`mode`, `id`)
    // plus the shared EventHeader — no vmlinux struct offset — so they're absent here
    // and always attach (an enum-value mismatch on kernel_load_data is still logged, but
    // fail-OPENS: see `load_preflight` below).
];

/// The kernel structs `probe` depends on, per [`STRUCT_DEPS`] — `&[]` (always attaches)
/// if the probe isn't listed.
pub(super) fn struct_deps(probe: &str) -> &'static [&'static str] {
    STRUCT_DEPS
        .iter()
        .find(|(name, _)| *name == probe)
        .map(|(_, deps)| *deps)
        .unwrap_or(&[])
}

/// Read and parse `/sys/kernel/btf/vmlinux` (independently of the `aya::Btf` the observer
/// also loads for fentry attach — `aya`/`aya-obj`'s public API can't answer offset/enum
/// questions, see `preflight/btf.rs`'s module doc) and check it against the shared
/// offset/enum table, logging every divergence found — the expected-vs-actual data an
/// operator needs to regenerate `vmlinux.rs`'s bindings. A read failure (missing BTF — an
/// older kernel, or the DaemonSet's `/sys/kernel/btf` mount missing) fails closed the same
/// way a parse failure does ([`PreflightReport::fail_closed`]).
pub(super) fn load_preflight() -> PreflightReport {
    let report = match std::fs::read("/sys/kernel/btf/vmlinux") {
        Ok(bytes) => crate::preflight::check_bytes(&bytes),
        Err(error) => {
            tracing::warn!(
                %error,
                "BTF preflight: could not read node BTF; every struct-reading probe disabled"
            );
            PreflightReport::fail_closed()
        }
    };
    for mismatch in &report.field_mismatches {
        tracing::warn!(
            kernel_struct = mismatch.kernel_struct,
            field = mismatch.field,
            expected = mismatch.expected,
            actual = ?mismatch.actual,
            "BTF preflight: field offset mismatch — update agent/common's FIELD_OFFSETS \
             (and vmlinux.rs) from this line"
        );
    }
    if let Some(mismatch) = &report.enum_mismatch {
        tracing::warn!(
            enum_name = mismatch.enum_name,
            variant = mismatch.variant,
            expected = mismatch.expected,
            actual = ?mismatch.actual,
            "BTF preflight: LOADING_MODULE enum value mismatch — the module-load probe \
             may misclassify (still attached: not verifier-checked, fail-open)"
        );
    }
    if report.is_clean() {
        tracing::info!(
            "BTF preflight: every baked field offset and the LOADING_MODULE enum value \
             match this node's live BTF"
        );
    }
    report
}
