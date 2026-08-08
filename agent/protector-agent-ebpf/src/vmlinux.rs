//! Minimal kernel struct bindings for the eBPF probes (ADR-0014).
//!
//! These are NOT the full `aya-tool`-generated `vmlinux.rs` (that was ~60k lines — well
//! over the repo's 1,000-line file cap — and, being a static snapshot, silently rots on
//! every kernel upgrade). Instead this hand-written module declares ONLY the structs the
//! probes touch, laid out so each field the code reads sits at the byte offset it has in
//! the fleet's running kernel. Reads never copy a whole struct, so a trailing prefix is
//! all that's needed — every struct here is a truthful prefix of the real kernel struct.
//!
//! # Why offsets, not names, are the contract
//!
//! aya has no CO-RE field relocation here: the bpf object bakes each `(*ptr).field` as a
//! constant offset at compile time (see agent/protector-agent-ebpf/.cargo/config.toml —
//! plain `bpfel-unknown-none`, no `preserve_access_index`). So the offset below is what
//! ends up in the verified program; it MUST match the kernel. `bpf_d_path(&file->f_path)`
//! in particular is verifier-checked against the kernel's BTF: the 7.0.0 verifier walks
//! the kernel `struct file` at the baked offset and requires it to land on a `struct path`
//! (else: "R1 is of type file but path is expected"). With `f_path` at the correct offset
//! the walk resolves to `path` and the helper is accepted.
//!
//! # Offsets (verified 2026-07-05 against BOTH fleet arches' live BTF)
//!
//! Dumped `/sys/kernel/btf/vmlinux` from `7.0.0-27-generic` (amd64, cluster-node-3) and
//! `7.0.0-1014-raspi` (arm64, cluster-node-0). Every field read below is at an IDENTICAL
//! offset on both arches (the only arm64/amd64 `super_block` divergence is `s_vop` at
//! +192, long past `s_magic` at +96), so this single static layout is correct fleet-wide.
//!
//! Linux 6.11 reorganized `struct file`: `f_path` moved +168 -> +64, `f_inode`
//! -> +32, `f_flags` -> +40. The previous 6.8-generated bindings put `f_path` at +168,
//! which on 7.0.0 lands in the `f_wb_err`/`f_ep` region — the verifier rejection that
//! degraded the two `bpf_d_path` probes (secret-read `file_open` + `file_write`) to
//! loaded=4/6 fleet-wide. Regenerate (re-verify the offsets) on any kernel struct change.
//!
//! # `linux_binprm.file` / `inode.i_nlink` — verified continuously, not just once
//!
//! Two fields added for the fileless-exec (anon-inode) probe were derived from kernel
//! *source* layout, not dumped from live BTF like everything else above: `linux_binprm.file`
//! (+64) and `inode.i_nlink` (+72). Each carries its own derivation in its struct's doc
//! comment. Unlike the offsets above (dumped once from live BTF on both fleet arches),
//! these two were never manually confirmed against `bpftool btf dump` — but they don't
//! need to be, ONE-TIME, by hand: the userspace loader's load-time BTF preflight
//! (`agent/protector-agent/src/preflight`, ADR-0014 amendment) re-derives every field in
//! this module — these two included — against each node's live BTF before any probe
//! attaches, every time the agent starts. A wrong offset here fails the SAME way a wrong
//! `f_path` offset would have: either a verifier rejection (probe degrades, loud in the
//! heartbeat) or, worse, a silently wrong bool if the misread pointer happens to still
//! verify — which is why the preflight disables the struct-reading probes on a mismatch
//! (fail-closed) rather than trusting a compile-time assertion alone.

// Padding fields (and `mnt`, present only to place `dentry` at +8) are never read — they
// exist solely to position the fields the probes DO read at the right byte offset.
#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_void};

/// `struct path` — `{ mnt, dentry }`. `bpf_d_path` takes `&file->f_path`; the library-load
/// probe reads `f_path.dentry`. `mnt` is only here to place `dentry` at +8.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct path {
    pub mnt: *mut c_void,    // +0  struct vfsmount *
    pub dentry: *mut dentry, // +8
}

/// `struct file` — prefix through `f_path` (+64). `f_inode` (+32) and `f_flags` (+40) feed
/// the tmpfs filter and the write-intent filter; `f_path` (+64) feeds `bpf_d_path`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct file {
    _pad0: [u8; 32],
    pub f_inode: *mut inode, // +32
    pub f_flags: u32,        // +40
    _pad1: [u8; 20],
    pub f_path: path, // +64
}

/// `struct dentry` — prefix through `d_name` (+32). The library-load probe reads
/// `dentry->d_name.name` (the leaf basename byte pointer).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dentry {
    _pad0: [u8; 32],
    pub d_name: qstr, // +32
}

/// `struct qstr` — the leaf name pointer at +8 (the `hash_len` union occupies +0).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qstr {
    _pad0: [u8; 8],
    pub name: *const u8, // +8  const unsigned char *
}

/// `struct inode` — prefix through `i_nlink` (+72). `i_sb` (+40) reaches the superblock
/// (tmpfs magic); `i_ino` (+64) is the file-write dedup key; `i_nlink` (+72) is
/// the anon-inode discriminator — `0` for an unlinked inode (a memfd, or any file `rm`'d
/// while still executing), non-zero for a normal directory-linked file.
///
/// `i_nlink`'s offset was derived from kernel source, not dumped from live BTF like the
/// fields above it. `i_nlink` is the first field of an anonymous union (`union { const
/// unsigned int i_nlink; unsigned int __i_nlink; }`) immediately after `i_ino` in `struct
/// inode` — no padding needed since `i_ino` (an 8-byte `unsigned long`) already leaves the
/// next field 8-aligned. +72 = +64 (`i_ino`'s offset) + 8 (`i_ino`'s size). The load-time
/// BTF preflight re-derives this offset on every node at every agent start — including
/// recursing into the anonymous union — so a derivation error here is caught continuously,
/// not just once (see the module doc above and `agent/protector-agent/src/preflight`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct inode {
    _pad0: [u8; 40],
    pub i_sb: *mut super_block, // +40
    _pad1: [u8; 16],
    pub i_ino: u64,   // +64  unsigned long
    pub i_nlink: u32, // +72 — verified at every load, not just once (see doc above)
}

/// `struct super_block` — prefix through `s_magic` (+96), the tmpfs filter's discriminator.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct super_block {
    _pad0: [u8; 96],
    pub s_magic: u64, // +96  unsigned long
}

/// `kuid_t { val }` — the u32 uid the privilege-change probe compares against 0.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kuid_t {
    pub val: u32,
}

/// `struct cred` — prefix through `uid` (+8). The privilege-change probe reads
/// `cred->uid.val` for `new` and `old`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct cred {
    _pad0: [u8; 8],
    pub uid: kuid_t, // +8
}

/// `struct linux_binprm` — prefix through `filename` (+96), the resolved exec path
/// (`char *`) the process-exec probe emits. `file` (+64) is the ALREADY-OPENED
/// executable's `struct file*` — by the time `security_bprm_check` fires, `bprm_execve()`
/// (fs/exec.c) has already opened it (`do_open_execat`/`bprm->file = …`), before
/// `exec_binprm()` → `search_binary_handler()` → `security_bprm_check()` is reached — so
/// this read is safe at this hook, no ordering hazard.
///
/// **ON-NODE BTF VERIFICATION PENDING for `file`:** derived from kernel source
/// layout (`struct linux_binprm` in linux/binfmts.h), not dumped from live BTF like
/// `filename` below (already verified on-node). Derivation: `vma`(+0) +
/// `vma_pages`(+8) + `mm`(+16) + `p`(+24) + `argmin`(+32) + the four-bit `unsigned int`
/// bitfield (+40, padded to +48 for the next pointer's alignment) + `executable`(+48) +
/// `interpreter`(+56) + `file`(+64) + `cred`(+72) + `unsafe`(+80) + `per_clear`(+84) +
/// `argc`(+88) + `envc`(+92) = `filename` at +96 — which matches the INDEPENDENTLY
/// on-node-verified `filename` offset below exactly, a strong (but not certain) signal
/// this derivation tracks the real fleet layout. Like `inode.i_nlink` above, the
/// load-time BTF preflight re-derives this offset from live BTF on every node at every
/// agent start, so this derivation is checked continuously rather than trusted once — see
/// the module doc above and `agent/protector-agent/src/preflight`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct linux_binprm {
    _pad0: [u8; 64],
    pub file: *mut file, // +64 — verified at every load, not just once (see doc above)
    _pad1: [u8; 24],
    pub filename: *const c_char, // +96
}

// Compile-time guard: pin every read field to the SHARED offset table in
// `protector-agent-common` (ADR-0014 amendment) — `bindings == table`, asserted here, plus
// the userspace loader's load-time preflight asserting `table == node-BTF`
// (agent/protector-agent/src/preflight), transitively proves `bindings == kernel` on every
// node at every start, not just at this compile. These are the offsets the compiler bakes
// into `bpf_d_path` and the `bpf_probe_read_kernel` chases; if a future edit (padding
// slip, a reverted binding, a kernel struct change) moves one without updating the shared
// table too, the eBPF crate fails to BUILD here — loud at CI time rather than a silent
// misread or a verifier rejection only visible on a live node. `offset_of!` and
// `offset_of_table` are both const, so this costs nothing at runtime.
const _: () = {
    use core::mem::offset_of;
    // `offset_of!` yields `usize`; the shared table stores `u32` (plenty for any struct
    // offset in these bindings) so it can be `no_std`-friendly without pulling in a
    // pointer-width-specific type — cast at the comparison, not in the table.
    const fn tbl(kernel_struct: &str, field: &str) -> usize {
        protector_agent_common::offsets::offset_of_table(kernel_struct, field) as usize
    }
    assert!(offset_of!(file, f_inode) == tbl("file", "f_inode"));
    assert!(offset_of!(file, f_flags) == tbl("file", "f_flags"));
    assert!(offset_of!(file, f_path) == tbl("file", "f_path"));
    assert!(offset_of!(path, dentry) == tbl("path", "dentry"));
    assert!(offset_of!(dentry, d_name) == tbl("dentry", "d_name"));
    assert!(offset_of!(qstr, name) == tbl("qstr", "name"));
    assert!(offset_of!(inode, i_sb) == tbl("inode", "i_sb"));
    assert!(offset_of!(inode, i_ino) == tbl("inode", "i_ino"));
    assert!(offset_of!(inode, i_nlink) == tbl("inode", "i_nlink"));
    assert!(offset_of!(super_block, s_magic) == tbl("super_block", "s_magic"));
    assert!(offset_of!(cred, uid) == tbl("cred", "uid"));
    assert!(offset_of!(kuid_t, val) == tbl("kuid_t", "val"));
    assert!(offset_of!(linux_binprm, file) == tbl("linux_binprm", "file"));
    assert!(offset_of!(linux_binprm, filename) == tbl("linux_binprm", "filename"));
};
