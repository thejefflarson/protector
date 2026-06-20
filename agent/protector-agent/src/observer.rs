//! The observer: the source of behavioral observations.
//!
//! Two builds. The default (no `ebpf` feature) is a no-op so the userspace skeleton —
//! the report path, batching, pod resolution, the wire contract — compiles and unit-
//! tests without a kernel or bpf-linker. With `--features ebpf` (built on a node) the
//! [`EbpfObserver`] loads the real probes. Both drive the same `Sender<Observation>`.

use tokio::sync::mpsc::Sender;

use crate::behavior::Observation;

/// Default observer: collects nothing. The real collection is the eBPF probes; this
/// keeps the binary runnable (healthy DaemonSet, exercisable report path) when built
/// without them, and says how to turn them on.
pub struct NoopObserver;

impl NoopObserver {
    pub async fn run(self, _tx: Sender<Observation>) {
        tracing::warn!(
            "built without the `ebpf` feature — no behavioral collection. Rebuild with \
             `--features ebpf` on a node (needs bpf-linker) to load the probes."
        );
        // Stay up so the DaemonSet stays Ready; the report path/batcher still run.
        std::future::pending::<()>().await
    }
}

/// The real, eBPF-backed observer. Feature-gated: only built on a node with the bpf
/// toolchain, where it can be compiled and load-tested. It loads the compiled eBPF
/// object (from the `protector-agent-ebpf` crate), attaches the connection probe,
/// drains the ring buffer, resolves each event's cgroup→pod, and emits a
/// `NetworkConnection` observation. Secret-read and library-load probes layer in next.
#[cfg(feature = "ebpf")]
pub use ebpf::EbpfObserver;

#[cfg(feature = "ebpf")]
mod ebpf {
    use std::net::Ipv4Addr;

    use aya::Ebpf;
    use aya::maps::RingBuf;
    use aya::programs::KProbe;
    use tokio::io::unix::AsyncFd;

    use super::*;
    use crate::behavior::Behavior;
    use crate::pod::{PodResolver, parse_pod_uid};

    /// Mirror of the eBPF crate's `ConnEvent` (same `repr(C)` layout).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ConnEvent {
        pid: u32,
        daddr: u32, // network byte order
        dport: u16, // host byte order
    }

    pub struct EbpfObserver {
        resolver: PodResolver,
    }

    impl EbpfObserver {
        pub fn new(resolver: PodResolver) -> Self {
            Self { resolver }
        }

        pub async fn run(self, tx: Sender<Observation>) -> anyhow::Result<()> {
            // The BPF object is compiled + embedded by build.rs under the `ebpf` feature.
            let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/protector-agent.bpf.o"
            )))?;
            let program: &mut KProbe = ebpf
                .program_mut("connect")
                .ok_or_else(|| anyhow::anyhow!("connect program missing from object"))?
                .try_into()?;
            program.load()?;
            program.attach("security_socket_connect", 0)?;
            tracing::info!("attached connect probe; draining events");

            let ring = RingBuf::try_from(
                ebpf.take_map("EVENTS")
                    .ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?,
            )?;
            let mut async_fd = AsyncFd::new(ring)?;
            loop {
                let mut guard = async_fd.readable_mut().await?;
                {
                    let ring = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        let data: &[u8] = &item;
                        if data.len() < std::mem::size_of::<ConnEvent>() {
                            continue;
                        }
                        // SAFETY: the kernel wrote a ConnEvent of exactly this layout.
                        let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<ConnEvent>()) };
                        if let Some(obs) = self.observe(&ev)
                            && tx.send(obs).await.is_err()
                        {
                            return Ok(()); // receiver gone — shut down
                        }
                    }
                }
                guard.clear_ready();
            }
        }

        /// Map a raw event to an attributed observation, or drop it (mis-attribution is
        /// worse than a missing signal — ADR-0014).
        fn observe(&self, ev: &ConnEvent) -> Option<Observation> {
            let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", ev.pid)).ok()?;
            let uid = parse_pod_uid(&cgroup)?;
            let pod = self.resolver.resolve(&uid)?;
            // daddr's bytes are the network-order octets; to_ne_bytes on LE gives them
            // in [a,b,c,d] order, which is what Ipv4Addr::from([u8;4]) wants.
            let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
            Some(Observation {
                namespace: pod.namespace.clone(),
                pod: pod.name.clone(),
                behavior: Behavior::NetworkConnection {
                    peer: format!("{ip}:{}", ev.dport),
                    internet: !(ip.is_private() || ip.is_loopback() || ip.is_link_local()),
                },
            })
        }
    }
}
