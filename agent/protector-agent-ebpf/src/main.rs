//! eBPF programs for protector-agent (ADR-0014). `no_std`, built for the bpf target
//! with bpf-linker (see agent/README.md / the Dockerfile `ebpf` stage).
//!
//! All probes write into one ring buffer ([`EVENTS`]); every event begins with an
//! [`EventHeader`] whose `kind` discriminates the body, so userspace can drain a
//! single ring and dispatch by type. Adding a probe (secret-read, library-load) is a
//! new `KIND_*`, a new body type, and a new userspace decode arm — not a new ring or a
//! second drain loop.
//!
//! Phase-2 first probe: outbound connections. A kprobe on `security_socket_connect`
//! (an LSM hook stable across kernels) reads the IPv4 destination and emits a
//! [`ConnEvent`] (kind [`KIND_CONNECT`]). Observe-only; fail safe (a bad read drops the
//! event, never errors the probe).

#![no_std]
#![no_main]

// Kernel struct bindings (struct file/path/…), generated from the node BTF — needed so
// bpf_d_path receives a BTF-typed `&file->f_path`. See docs/ebpf-testing-on-nodes.md.
mod vmlinux;

use aya_ebpf::{
    helpers::gen::{bpf_d_path, bpf_probe_read_kernel, bpf_probe_read_kernel_str},
    macros::{fentry, kprobe, map},
    maps::{PerCpuArray, RingBuf},
    programs::{FEntryContext, ProbeContext},
};
// The event layouts + kind discriminators are shared verbatim with the userspace loader
// via this one crate, so the kernel↔userspace byte contract can't drift (ADR-0014).
use protector_agent_common::{
    ConnEvent, EventHeader, FileEvent, KIND_CONNECT, KIND_FILE_OPEN, KIND_LIBRARY_LOAD, PATH_CAP,
};

/// Ring buffer of behavioral events (all kinds) drained by userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Count of events the kernel had to drop because [`EVENTS`] was full (a
/// `reserve` returning `None`). Ring-buffer loss is otherwise silent — this makes
/// it observable so userspace can surface it in the heartbeat (JEF-58). A
/// `PerCpuArray` with one slot: each CPU bumps its own counter with no atomics or
/// contention; userspace sums across CPUs for the cumulative total. Incremented
/// only at the two `EVENTS.reserve` failure sites via [`record_drop`].
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Bump the per-CPU drop counter (slot 0). Called at every [`EVENTS`] reserve
/// failure. Verifier-safe: a single bounded array lookup + in-place increment, no
/// loops. A missing slot (can't happen for a 1-entry array) is a silent no-op.
fn record_drop() {
    if let Some(slot) = DROPS.get_ptr_mut(0) {
        unsafe { *slot += 1 };
    }
}

// Minimal kernel sockaddr layout for the IPv4 case. We only touch the family and the
// `sockaddr_in` address/port; reads are bounds-checked by `bpf_probe_read_kernel`.
const AF_INET: u16 = 2;

#[repr(C)]
struct SockAddr {
    sa_family: u16,
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
}

/// kprobe on `security_socket_connect(struct socket *, struct sockaddr *address, int)`.
#[kprobe]
pub fn connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx);
    0 // always 0 — observe-only, never perturb the syscall
}

fn try_connect(ctx: &ProbeContext) -> Result<(), i64> {
    // 2nd arg is `struct sockaddr *address`.
    let addr: *const SockAddr = ctx.arg(1).ok_or(1i64)?;

    let mut family: u16 = 0;
    let rc = unsafe {
        bpf_probe_read_kernel(
            &mut family as *mut u16 as *mut core::ffi::c_void,
            core::mem::size_of::<u16>() as u32,
            &(*addr).sa_family as *const u16 as *const core::ffi::c_void,
        )
    };
    if rc != 0 || family != AF_INET {
        return Ok(());
    }

    let sin = addr as *const SockAddrIn;
    let mut daddr: u32 = 0;
    let mut dport: u16 = 0;
    unsafe {
        bpf_probe_read_kernel(
            &mut daddr as *mut u32 as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
            &(*sin).sin_addr as *const u32 as *const core::ffi::c_void,
        );
        bpf_probe_read_kernel(
            &mut dport as *mut u16 as *mut core::ffi::c_void,
            core::mem::size_of::<u16>() as u32,
            &(*sin).sin_port as *const u16 as *const core::ffi::c_void,
        );
    }

    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(mut slot) = EVENTS.reserve::<ConnEvent>(0) {
        slot.write(ConnEvent {
            header: EventHeader {
                kind: KIND_CONNECT,
                pid,
            },
            daddr,
            dport: u16::from_be(dport),
        });
        slot.submit(0);
    } else {
        record_drop(); // ring full — count the loss instead of silently skipping
    }
    Ok(())
}

/// tmpfs superblock magic. Kubernetes Secret / ConfigMap / projected volumes are all
/// tmpfs, so this is the in-kernel filter. It's broad (also /tmp, /dev/shm, emptyDir-
/// memory, SA tokens) but tmpfs *opens* are moderate volume — far below the full
/// file-open firehose — and the ENGINE narrows to real Secret mounts. We can't filter to
/// secrets precisely in-kernel: bpf_d_path returns the container-relative path, which has
/// no universal secret marker (see docs/ebpf-testing-on-nodes.md).
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// `PROT_EXEC` — an executable memory mapping. The dynamic linker mmaps shared objects
/// (and the main binary) executable, so this distinguishes a code load from a data mmap.
const PROT_EXEC: u64 = 0x4;

/// fentry on `security_file_open(struct file *file)` — the secret-read probe (ADR-0014).
/// For a tmpfs read, emits a [`FileEvent`] with the container-relative path via
/// `bpf_d_path`; the engine maps it to a SecretRead (or drops it). Filtering to tmpfs
/// in-kernel keeps the (very high) file-open volume off the ring buffer. Observe-only.
#[fentry(function = "security_file_open")]
pub fn file_open(ctx: FEntryContext) -> u32 {
    let _ = try_file_open(&ctx);
    0
}

fn try_file_open(ctx: &FEntryContext) -> Result<(), i64> {
    // security_file_open's first argument is `struct file *file`.
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    if file.is_null() || !is_tmpfs(file) {
        return Ok(());
    }
    emit_file_path(file, KIND_FILE_OPEN);
    Ok(())
}

/// fentry on `security_mmap_file(struct file *file, unsigned long prot, unsigned long
/// flags)` — the library-load probe (ADR-0014). An executable mmap of a file is the
/// dynamic linker loading a shared object (or the main binary); emit its name so
/// userspace can name the loaded library. Anonymous/non-exec mmaps are skipped.
#[fentry(function = "security_mmap_file")]
pub fn mmap_file(ctx: FEntryContext) -> u32 {
    let _ = try_mmap_file(&ctx);
    0
}

fn try_mmap_file(ctx: &FEntryContext) -> Result<(), i64> {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    if file.is_null() {
        return Ok(()); // anonymous mapping — not a file/code load
    }
    let prot: u64 = unsafe { ctx.arg(1) };
    if prot & PROT_EXEC == 0 {
        return Ok(()); // not executable — a data mapping, not a code load
    }
    // NOT emit_file_path: bpf_d_path is rejected by the verifier in security_mmap_file
    // (security_mmap_file isn't on the kernel's d_path allowlist, unlike
    // security_file_open — JEF-68). Userspace only needs the library *name*, which is the
    // leaf basename, so read the dentry's d_name directly with bpf_probe_read_kernel.
    emit_lib_name(file);
    Ok(())
}

/// bpf_d_path the file's path into a [`FileEvent`] of `kind` and submit it. Shared by the
/// secret-read (file_open) probe — it needs the full path so the engine can match it to a
/// Secret mount. (Library-load uses [`emit_lib_name`]: bpf_d_path is disallowed in its hook.)
fn emit_file_path(file: *const vmlinux::file, kind: u32) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let mut ev = FileEvent {
        header: EventHeader { kind, pid },
        len: 0,
        path: [0u8; PATH_CAP],
    };
    // &file->f_path as a BTF-typed `struct path *` — what bpf_d_path requires.
    let path_ptr = unsafe { core::ptr::addr_of!((*file).f_path) };
    let n = unsafe {
        bpf_d_path(
            path_ptr as *mut _,
            ev.path.as_mut_ptr() as *mut _,
            PATH_CAP as u32,
        )
    };
    if n <= 0 {
        return;
    }
    ev.len = if (n as usize) < PATH_CAP {
        n as u32
    } else {
        PATH_CAP as u32
    };
    if let Some(mut slot) = EVENTS.reserve::<FileEvent>(0) {
        slot.write(ev);
        slot.submit(0);
    } else {
        record_drop(); // ring full — count the loss instead of silently skipping
    }
}

/// Emit the library *name* (leaf basename) of `file` as a [`KIND_LIBRARY_LOAD`] event.
/// The library-load probe can't use `bpf_d_path` (the verifier rejects it in the
/// security_mmap_file hook — not on the kernel's d_path allowlist; JEF-68). Userspace only
/// needs the basename to name the library, which is the leaf dentry's `d_name`, so read it
/// directly with bpf_probe_read_kernel(_str) — allowed in any program type.
fn emit_lib_name(file: *const vmlinux::file) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let mut ev = FileEvent {
        header: EventHeader {
            kind: KIND_LIBRARY_LOAD,
            pid,
        },
        len: 0,
        path: [0u8; PATH_CAP],
    };
    // file->f_path.dentry, then dentry->d_name.name (the basename byte pointer).
    let mut dentry: *mut vmlinux::dentry = core::ptr::null_mut();
    let mut name_ptr: *const u8 = core::ptr::null();
    unsafe {
        if read_kernel(&mut dentry, core::ptr::addr_of!((*file).f_path.dentry)) != 0
            || dentry.is_null()
        {
            return;
        }
        if read_kernel(
            &mut name_ptr,
            core::ptr::addr_of!((*dentry).d_name.name).cast(),
        ) != 0
            || name_ptr.is_null()
        {
            return;
        }
    }
    // Copy the NUL-terminated basename into the event buffer (returns bytes incl. NUL).
    let n = unsafe {
        bpf_probe_read_kernel_str(
            ev.path.as_mut_ptr() as *mut core::ffi::c_void,
            PATH_CAP as u32,
            name_ptr as *const core::ffi::c_void,
        )
    };
    if n <= 0 {
        return;
    }
    ev.len = if (n as usize) < PATH_CAP {
        n as u32
    } else {
        PATH_CAP as u32
    };
    if let Some(mut slot) = EVENTS.reserve::<FileEvent>(0) {
        slot.write(ev);
        slot.submit(0);
    } else {
        record_drop();
    }
}

/// Whether `file` lives on a tmpfs — `file->f_inode->i_sb->s_magic == TMPFS_MAGIC`. The
/// pointer chase uses bpf_probe_read_kernel (fixed offsets from the node-BTF vmlinux),
/// the same safe pattern as the connect probe. A failed read = "not tmpfs" (drop).
fn is_tmpfs(file: *const vmlinux::file) -> bool {
    unsafe {
        let mut inode: *mut vmlinux::inode = core::ptr::null_mut();
        if read_kernel(&mut inode, core::ptr::addr_of!((*file).f_inode)) != 0 || inode.is_null() {
            return false;
        }
        let mut sb: *mut vmlinux::super_block = core::ptr::null_mut();
        if read_kernel(&mut sb, core::ptr::addr_of!((*inode).i_sb)) != 0 || sb.is_null() {
            return false;
        }
        let mut magic: u64 = 0;
        if read_kernel(&mut magic, core::ptr::addr_of!((*sb).s_magic).cast()) != 0 {
            return false;
        }
        magic == TMPFS_MAGIC
    }
}

/// bpf_probe_read_kernel a `T` from kernel address `src` into `dst`. Returns 0 on success.
unsafe fn read_kernel<T>(dst: &mut T, src: *const T) -> i64 {
    unsafe {
        bpf_probe_read_kernel(
            dst as *mut T as *mut core::ffi::c_void,
            core::mem::size_of::<T>() as u32,
            src as *const core::ffi::c_void,
        )
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
