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
    helpers::gen::{bpf_d_path, bpf_probe_read_kernel},
    macros::{fentry, kprobe, map},
    maps::RingBuf,
    programs::{FEntryContext, ProbeContext},
};
// The event layouts + kind discriminators are shared verbatim with the userspace loader
// via this one crate, so the kernel↔userspace byte contract can't drift (ADR-0014).
use protector_agent_common::{
    ConnEvent, EventHeader, FileEvent, KIND_CONNECT, KIND_FILE_OPEN, PATH_CAP,
};

/// Ring buffer of behavioral events (all kinds) drained by userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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
    }
    Ok(())
}

/// `…/kubernetes.io~secret/…` is how the kubelet mounts a Secret volume; this marker in
/// the opened path means the workload is reading a mounted secret.
// DIAGNOSTIC (temporary): match the canary so the userspace capture log prints the raw
// path bpf_d_path returns, to confirm whether it's the container-relative or host path.
// Reverts to "kubernetes.io~secret" (or a tmpfs filter) once the path format is known.
const SECRET_MARKER: [u8; 6] = *b"canary";

/// fentry on `security_file_open(struct file *file)` — the secret-read probe (ADR-0014).
/// Reads the opened file's path via `bpf_d_path` and, **only if** it's under a secret
/// mount, emits a [`FileEvent`] with the path. Filtering in-kernel keeps the (very high)
/// file-open volume off the ring buffer. Observe-only; a bad read drops the event.
#[fentry(function = "security_file_open")]
pub fn file_open(ctx: FEntryContext) -> u32 {
    let _ = try_file_open(&ctx);
    0
}

fn try_file_open(ctx: &FEntryContext) -> Result<(), i64> {
    // security_file_open's first argument is `struct file *file`.
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    if file.is_null() {
        return Ok(());
    }
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let mut ev = FileEvent {
        header: EventHeader {
            kind: KIND_FILE_OPEN,
            pid,
        },
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
        return Ok(());
    }
    let len = if (n as usize) < PATH_CAP {
        n as usize
    } else {
        PATH_CAP
    };
    if !has_secret_marker(&ev.path, len) {
        return Ok(());
    }
    ev.len = len as u32;
    if let Some(mut slot) = EVENTS.reserve::<FileEvent>(0) {
        slot.write(ev);
        slot.submit(0);
    }
    Ok(())
}

/// Bounded substring search for [`SECRET_MARKER`] in `buf[..len]`. Indices are masked to
/// `PATH_CAP` so the verifier sees every access provably in-bounds.
fn has_secret_marker(buf: &[u8; PATH_CAP], len: usize) -> bool {
    let n = if len > PATH_CAP { PATH_CAP } else { len };
    let mut i = 0usize;
    while i + SECRET_MARKER.len() <= n {
        let mut j = 0usize;
        let mut hit = true;
        while j < SECRET_MARKER.len() {
            let idx = (i + j) & (PATH_CAP - 1);
            // SAFETY: idx is masked < PATH_CAP; j < SECRET_MARKER.len().
            if unsafe { *buf.get_unchecked(idx) != *SECRET_MARKER.get_unchecked(j) } {
                hit = false;
                break;
            }
            j += 1;
        }
        if hit {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
