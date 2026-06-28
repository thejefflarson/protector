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
    helpers::bpf_ktime_get_ns,
    helpers::gen::{
        bpf_d_path, bpf_get_current_cgroup_id, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
    },
    macros::{fentry, kprobe, map},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, ProbeContext},
};
// The event layouts + kind discriminators are shared verbatim with the userspace loader
// via this one crate, so the kernel↔userspace byte contract can't drift (ADR-0014). The
// dedup key/window/decision (JEF-65) live here too so the kernel probe and the userspace
// tests share one definition and can't drift.
use protector_agent_common::{
    should_coalesce, ConnEvent, ConnKey, EventHeader, FileEvent, PrivEvent, DEDUP_MAP_CAP,
    DEDUP_WINDOW_NS, KIND_CONNECT, KIND_EXEC, KIND_FILE_OPEN, KIND_LIBRARY_LOAD, KIND_PRIV_CHANGE,
    PATH_CAP,
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

/// Build the [`EventHeader`] common to every emitted event: the kind plus the current
/// task's pid and cgroup id, both captured AT EVENT TIME (JEF-158). The cgroup id comes
/// from the stable `bpf_get_current_cgroup_id()` helper (the cgroup v2 directory inode),
/// recorded while the process is still live so userspace can attribute it to a pod even
/// after the (often short-lived) process has exited — the exited-process race the
/// post-hoc `/proc/<pid>/cgroup` read can't win. Both calls are stable helpers usable in
/// kprobe and fentry programs alike. Verifier-safe: two helper calls, no loops, no reads.
fn make_header(kind: u32) -> EventHeader {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: `bpf_get_current_cgroup_id` is a stable helper with no arguments and no
    // pointer use; it returns 0 if the current task has no cgroup v2 id (handled in
    // userspace by falling back to the `/proc` read).
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    EventHeader {
        kind,
        pid,
        cgroup_id,
    }
}

/// In-kernel connect dedup map (JEF-65): `(pid, daddr, dport)` → last-emit time (ns).
/// Coalesces high-frequency *repeats* — a chatty process hammering the same destination —
/// at the source, so a suppressed connect never costs a ring-buffer slot (the volume
/// problem JEF-58's drop counter measures). LRU so a churn of distinct destinations can't
/// exhaust it: the coldest key is evicted and simply re-emits once. Connect is the
/// firehose probe; the other probes are already volume-bounded (in-kernel filtered to rare
/// events), so dedup is applied to connect only — the per-(pid, dest) case the ticket names.
#[map]
static CONN_SEEN: LruHashMap<ConnKey, u64> = LruHashMap::with_max_entries(DEDUP_MAP_CAP, 0);

/// Count of connect events coalesced (suppressed in-kernel) by [`CONN_SEEN`] dedup
/// (JEF-65). Same per-CPU, one-slot shape as [`DROPS`]: each CPU bumps its own slot, no
/// atomics; userspace sums across CPUs and surfaces the cumulative total in the heartbeat,
/// so the volume cut is observable rather than invisible. Bumped only in [`record_coalesced`].
#[map]
static COALESCED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Bump the per-CPU coalesced counter (slot 0). Called whenever the connect dedup map
/// suppresses a repeat. Verifier-safe: one bounded lookup + in-place increment, no loops.
fn record_coalesced() {
    if let Some(slot) = COALESCED.get_ptr_mut(0) {
        unsafe { *slot += 1 };
    }
}

/// The connect dedup gate (JEF-65). Returns `true` if this connect to `key` should be
/// emitted, `false` if it's a repeat inside [`DEDUP_WINDOW_NS`] and was coalesced (the
/// counter is bumped here). On emit, stamps `now` so the next repeat is measured from it.
/// LRU insert can't fail meaningfully — if it ever did we fall through to emit (fail open:
/// never silently lose a real signal to a bookkeeping error). The first sighting of a key
/// (no entry) always emits.
fn allow_connect(key: &ConnKey) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(last) = CONN_SEEN.get_ptr_mut(key) {
        // SAFETY: `last` points at this key's live slot; we read then overwrite it.
        let last_ns = unsafe { *last };
        if should_coalesce(last_ns, now, DEDUP_WINDOW_NS) {
            record_coalesced();
            return false;
        }
        unsafe { *last = now };
        return true;
    }
    // First time we've seen this key (or it was LRU-evicted): record and emit.
    let _ = CONN_SEEN.insert(key, &now, 0);
    true
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
    let dport = u16::from_be(dport);
    // JEF-65: coalesce high-frequency repeats in-kernel. A connect to the same
    // (pid, daddr, dport) seen again within DEDUP_WINDOW_NS is suppressed here — it never
    // reaches the ring buffer — cutting volume at the source rather than draining + dropping
    // duplicates in userspace. The first sighting (and one per window thereafter) emits.
    if !allow_connect(&ConnKey::new(pid, daddr, dport)) {
        return Ok(());
    }
    if let Some(mut slot) = EVENTS.reserve::<ConnEvent>(0) {
        slot.write(ConnEvent {
            header: make_header(KIND_CONNECT),
            daddr,
            dport,
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

/// fentry on `security_task_fix_setuid(struct cred *new, const struct cred *old, int flags)`
/// — the privilege-change probe (ADR-0014, Falco privilege-escalation parity). This LSM hook
/// runs on every credential change (setuid/setresuid/…), so we filter IN-KERNEL to the only
/// case worth a signal: a process *gaining* root (`new->uid.val == 0 && old->uid.val != 0`).
/// That keeps ring volume tiny and the signal meaningful — a non-root process becoming root.
/// Reads the cred `uid.val` fields with `bpf_probe_read_kernel` (never bpf_d_path — JEF-68).
/// Observe-only; a failed read drops the event, never errors the probe.
#[fentry(function = "security_task_fix_setuid")]
pub fn fix_setuid(ctx: FEntryContext) -> u32 {
    let _ = try_fix_setuid(&ctx);
    0
}

fn try_fix_setuid(ctx: &FEntryContext) -> Result<(), i64> {
    // arg0 = `struct cred *new`, arg1 = `const struct cred *old`.
    let new: *const vmlinux::cred = unsafe { ctx.arg(0) };
    let old: *const vmlinux::cred = unsafe { ctx.arg(1) };
    if new.is_null() || old.is_null() {
        return Ok(());
    }
    // cred->uid is a kuid_t { val: u32 } — chase to the u32 with bpf_probe_read_kernel.
    let mut new_uid: u32 = 0;
    let mut old_uid: u32 = 0;
    unsafe {
        if read_kernel(&mut new_uid, core::ptr::addr_of!((*new).uid.val)) != 0 {
            return Ok(());
        }
        if read_kernel(&mut old_uid, core::ptr::addr_of!((*old).uid.val)) != 0 {
            return Ok(());
        }
    }
    // Emit ONLY on escalation to root: a non-root process becoming root. Lateral or
    // de-escalating credential changes (the bulk of setuid traffic) are dropped here.
    if !(new_uid == 0 && old_uid != 0) {
        return Ok(());
    }
    if let Some(mut slot) = EVENTS.reserve::<PrivEvent>(0) {
        slot.write(PrivEvent {
            header: make_header(KIND_PRIV_CHANGE),
            old_uid,
            new_uid,
        });
        slot.submit(0);
    } else {
        record_drop(); // ring full — count the loss instead of silently skipping
    }
    Ok(())
}

/// fentry on `security_bprm_check(struct linux_binprm *bprm)` — the process-exec probe
/// (ADR-0014, JEF-53). This LSM hook fires on every `execve` once the new binary is
/// resolved, so `bprm->filename` is the path the kernel is about to exec. Emits a
/// [`FileEvent`] (kind [`KIND_EXEC`]) carrying that path; userspace turns it into a
/// `ProcessExec`. Observe-only. NOTE: the attach point is `security_bprm_check` (the
/// exported LSM call, in BTF — like the other `security_*` probes); the un-prefixed
/// `bprm_check_security` is NOT a BTF function on 6.8 (verified on-node: JEF-53 deploy).
#[fentry(function = "security_bprm_check")]
pub fn bprm_check(ctx: FEntryContext) -> u32 {
    let _ = try_bprm_check(&ctx);
    0
}

fn try_bprm_check(ctx: &FEntryContext) -> Result<(), i64> {
    // security_bprm_check's first argument is `struct linux_binprm *bprm`.
    let bprm: *const vmlinux::linux_binprm = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return Ok(());
    }
    emit_exec_path(bprm);
    Ok(())
}

/// Emit the exec'd binary's path as a [`KIND_EXEC`] event. `bprm->filename` is a kernel
/// `char *` (the resolved exec path), so — like the library-load probe — read the string
/// directly with `bpf_probe_read_kernel_str`. NOT `bpf_d_path`: `security_bprm_check`
/// isn't on the kernel's d_path allowlist, so the verifier would reject it (JEF-68).
fn emit_exec_path(bprm: *const vmlinux::linux_binprm) {
    let mut ev = FileEvent {
        header: make_header(KIND_EXEC),
        len: 0,
        path: [0u8; PATH_CAP],
    };
    // Read the `char *filename` pointer out of the binprm, then the string it points to.
    let mut name_ptr: *const u8 = core::ptr::null();
    unsafe {
        if read_kernel(&mut name_ptr, core::ptr::addr_of!((*bprm).filename).cast()) != 0
            || name_ptr.is_null()
        {
            return;
        }
    }
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
        record_drop(); // ring full — count the loss instead of silently skipping
    }
}

/// bpf_d_path the file's path into a [`FileEvent`] of `kind` and submit it. Shared by the
/// secret-read (file_open) probe — it needs the full path so the engine can match it to a
/// Secret mount. (Library-load uses [`emit_lib_name`]: bpf_d_path is disallowed in its hook.)
fn emit_file_path(file: *const vmlinux::file, kind: u32) {
    let mut ev = FileEvent {
        header: make_header(kind),
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
    let mut ev = FileEvent {
        header: make_header(KIND_LIBRARY_LOAD),
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
