//! Load-time BTF preflight (ADR-0014 amendment): before any probe attaches, re-verify
//! every field offset the eBPF crate bakes in (`agent/protector-agent-ebpf/src/
//! vmlinux.rs`, guarded at compile time against the shared table in
//! `protector-agent-common`) against THIS node's live BTF, plus the `LOADING_MODULE`
//! enum value the module-load probe compares against.
//!
//! The eBPF crate has no CO-RE field relocation (rustc emits no BTF field relocations —
//! see `vmlinux.rs`'s module doc): every `(*ptr).field` is baked in as a constant offset
//! at compile time, verified once against the fleet kernel that existed at the time. A
//! kernel upgrade can silently move a field; the compile-time `offset_of!` guard can't
//! catch that (it only proves the bindings are internally consistent with themselves, not
//! with a NEW kernel). This module is the guard that DOES catch it, on every node, at
//! every agent start — the observer (`crate::observer`) calls [`check_bytes`] before
//! attaching any probe and disables the probes whose reads it can no longer trust.
//!
//! This module is deliberately independent of the `ebpf` feature (unlike the observer
//! that calls it): it's plain, off-fleet-testable userspace Rust — see `preflight/
//! btf_tests.rs` and `preflight/tests.rs`, both exercised against hand-built fixture BTF
//! blobs (`preflight/fixture.rs`), no live kernel or bpf toolchain required.

mod btf;
#[cfg(test)]
mod fixture;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use protector_agent_common::offsets::{
    FIELD_OFFSETS, LOADING_MODULE_ENUM, LOADING_MODULE_VALUE, LOADING_MODULE_VARIANT,
};

pub use btf::RawBtf;

/// One field whose live-BTF offset diverges from what `agent/common`'s table (and the
/// eBPF crate's `offset_of!` guard) expect — the regeneration data an operator needs:
/// which field, what the bindings expect, what the kernel actually has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMismatch {
    pub kernel_struct: &'static str,
    pub field: &'static str,
    pub expected: u32,
    /// `None` when the struct/field isn't found in BTF at all (a bigger divergence than a
    /// moved offset — a renamed/removed field, or BTF that couldn't be read/parsed).
    pub actual: Option<u32>,
}

/// The `LOADING_MODULE` enum-value mismatch, if any. Unlike a struct offset this is NOT
/// verifier-checked — `try_kernel_load_data` compares it as a plain integer — so a wrong
/// value would silently misclassify rather than fail loud, which is why the preflight
/// checks it explicitly rather than trusting the compile-time constant alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumMismatch {
    pub enum_name: &'static str,
    pub variant: &'static str,
    pub expected: i64,
    pub actual: Option<i64>,
}

/// The result of walking a node's live BTF against [`FIELD_OFFSETS`] and
/// [`LOADING_MODULE_ENUM`]. Built once at agent startup, before any probe attaches.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub field_mismatches: Vec<FieldMismatch>,
    pub enum_mismatch: Option<EnumMismatch>,
}

impl PreflightReport {
    /// Whether every [`FIELD_OFFSETS`] entry for this `kernel_struct` name matched live
    /// BTF. Fail-closed at struct granularity, not field granularity: if any field of a
    /// struct a probe reads diverged, every other pointer chase through that same struct
    /// is untrusted too (a moved field can shift everything after it) — see the
    /// `STRUCT_DEPS` table in `observer.rs` that decides which probes this gates.
    pub fn struct_ok(&self, kernel_struct: &str) -> bool {
        !self
            .field_mismatches
            .iter()
            .any(|m| m.kernel_struct == kernel_struct)
    }

    /// True if nothing diverged and the enum matched — the common, healthy case.
    pub fn is_clean(&self) -> bool {
        self.field_mismatches.is_empty() && self.enum_mismatch.is_none()
    }

    /// Every table entry marked mismatched (`actual` unknown) — the fail-closed report
    /// for when BTF can't even be read (e.g. `/sys/kernel/btf/vmlinux` missing, an older
    /// kernel with no exported BTF). Every struct-reading probe is then disabled via
    /// [`Self::struct_ok`]; the struct-free probes (connect, ptrace-attach, module-load)
    /// still attach — degrade-gracefully, never crash-loop (ADR-0014).
    pub fn fail_closed() -> Self {
        let field_mismatches = FIELD_OFFSETS
            .iter()
            .map(|entry| FieldMismatch {
                kernel_struct: entry.kernel_struct,
                field: entry.field,
                expected: entry.offset,
                actual: None,
            })
            .collect();
        Self {
            field_mismatches,
            enum_mismatch: Some(EnumMismatch {
                enum_name: LOADING_MODULE_ENUM,
                variant: LOADING_MODULE_VARIANT,
                expected: LOADING_MODULE_VALUE as i64,
                actual: None,
            }),
        }
    }
}

/// Walk `btf` against the shared offset/enum table, producing every divergence found.
/// Pure (no I/O, no logging) so it's directly unit-testable; the caller (`observer.rs`)
/// owns turning the result into log lines and probe-attach decisions.
pub fn check(btf: &RawBtf) -> PreflightReport {
    let field_mismatches = FIELD_OFFSETS
        .iter()
        .filter_map(|entry| {
            let actual = btf.struct_field_offset(entry.kernel_struct, entry.field);
            (actual != Some(entry.offset)).then_some(FieldMismatch {
                kernel_struct: entry.kernel_struct,
                field: entry.field,
                expected: entry.offset,
                actual,
            })
        })
        .collect();

    let actual_enum = btf.enum_value(LOADING_MODULE_ENUM, LOADING_MODULE_VARIANT);
    let enum_mismatch =
        (actual_enum != Some(LOADING_MODULE_VALUE as i64)).then_some(EnumMismatch {
            enum_name: LOADING_MODULE_ENUM,
            variant: LOADING_MODULE_VARIANT,
            expected: LOADING_MODULE_VALUE as i64,
            actual: actual_enum,
        });

    PreflightReport {
        field_mismatches,
        enum_mismatch,
    }
}

/// Parse `bytes` as BTF and run [`check`] against it. A parse failure (missing/corrupt
/// `/sys/kernel/btf/vmlinux`) folds into [`PreflightReport::fail_closed`] — the caller has
/// one fail-closed path to handle, not a separate parse-error case.
pub fn check_bytes(bytes: &[u8]) -> PreflightReport {
    match RawBtf::parse(bytes) {
        Ok(btf) => check(&btf),
        Err(_) => PreflightReport::fail_closed(),
    }
}
