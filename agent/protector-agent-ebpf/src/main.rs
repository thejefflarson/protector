//! eBPF programs for protector-agent (ADR-0014). NODE-BUILT: `no_std`, compiled for
//! the bpf target with bpf-linker (see agent/README.md), not by the userspace build.
//!
//! Phase-2 first probe: outbound connections. A kprobe on `security_socket_connect`
//! (an LSM hook present across kernels — stable, unlike raw syscall ABIs) reads the
//! destination and emits a [`ConnEvent`] to a ring buffer the userspace agent drains,
//! resolves to a pod, and turns into a `NetworkConnection` behavior. Secret-read
//! (`security_file_open` under secret mounts) and library-load probes follow.
//!
//! Design constraints (ADR-0014): observe only (never modify), aggregate cheaply, fail
//! safe (a missing hook = fewer signals, never a crash).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};

/// One observed connection. `repr(C)` so the userspace agent reads the same layout.
#[repr(C)]
pub struct ConnEvent {
    /// Origin pid — userspace maps it via /proc/<pid>/cgroup → pod (see `pod.rs`).
    pub pid: u32,
    /// IPv4 destination (network byte order); 0 for non-IPv4 (skipped userspace-side).
    pub daddr: u32,
    /// Destination port (host byte order).
    pub dport: u16,
}

/// Ring buffer of connection events drained by userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// kprobe on `security_socket_connect(struct socket*, struct sockaddr*, int)`.
#[kprobe]
pub fn connect(ctx: ProbeContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0, // fail safe — drop this event, never error the probe
    }
}

fn try_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // NODE-BUILT: read the destination from the sockaddr (2nd arg) with CO-RE
    // bpf_probe_read on `sockaddr_in.sin_addr` / `sin_port`, guarding `sin_family ==
    // AF_INET`. Sketched here; completed + verified on a kernel.
    //   let addr: *const sockaddr = ctx.arg(1).ok_or(1)?;
    //   let family = bpf_probe_read_kernel(&(*addr).sa_family)?;
    //   if family != AF_INET { return Ok(()); }
    //   let sin: *const sockaddr_in = addr.cast();
    //   let daddr = bpf_probe_read_kernel(&(*sin).sin_addr.s_addr)?;
    //   let dport = u16::from_be(bpf_probe_read_kernel(&(*sin).sin_port)?);
    let (daddr, dport) = (0u32, 0u16);

    if let Some(mut slot) = EVENTS.reserve::<ConnEvent>(0) {
        slot.write(ConnEvent { pid, daddr, dport });
        slot.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
