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

use aya_ebpf::{
    helpers::gen::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
// The event layouts + kind discriminators are shared verbatim with the userspace loader
// via this one crate, so the kernel↔userspace byte contract can't drift (ADR-0014).
use protector_agent_common::{ConnEvent, EventHeader, KIND_CONNECT};

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
