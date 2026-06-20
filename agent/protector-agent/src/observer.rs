//! The observer: the source of behavioral observations.
//!
//! Two builds. The default (no `ebpf` feature) is a no-op so the userspace skeleton —
//! the report path, batching, pod resolution, the wire contract — compiles and unit-
//! tests without a kernel or bpf-linker. With `--features ebpf` (built on a node) the
//! [`EbpfObserver`] loads the real probes. Both drive the same
//! `Sender<RuntimeObservation>`.

use protector_behavior::RuntimeObservation;
use tokio::sync::mpsc::Sender;

/// Default observer: collects nothing. The real collection is the eBPF probes; this
/// keeps the binary runnable (healthy DaemonSet, exercisable report path) when built
/// without them, and says how to turn them on.
pub struct NoopObserver;

impl NoopObserver {
    pub async fn run(self, _tx: Sender<RuntimeObservation>) {
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use aya::Ebpf;
    use aya::maps::RingBuf;
    use aya::programs::KProbe;
    use tokio::io::unix::AsyncFd;

    use super::*;
    use crate::pod::parse_pod_uid;
    // The repr(C) event layouts are shared with the eBPF crate via this one crate, so the
    // kernel↔userspace byte contract can't drift (ADR-0014).
    use protector_agent_common::{ConnEvent, EventHeader, KIND_CONNECT};
    use protector_behavior::Behavior;

    /// This sensor's identity, carried into each observation's provenance so the engine
    /// can tell agent signals from Falco's (ADR-0003 corroboration).
    const SOURCE: &str = "protector-agent";

    /// The probes to load and attach: (program name in the object, kernel hook). Adding
    /// a probe is one row here plus a decode arm in `decode` — no new control flow.
    const PROBES: &[(&str, &str)] = &[("connect", "security_socket_connect")];

    pub struct EbpfObserver;

    impl EbpfObserver {
        pub async fn run(self, tx: Sender<RuntimeObservation>) -> anyhow::Result<()> {
            // The BPF object is compiled + embedded by build.rs under the `ebpf` feature.
            let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/protector-agent.bpf.o"
            )))?;
            for (name, hook) in PROBES {
                let program: &mut KProbe = ebpf
                    .program_mut(name)
                    .ok_or_else(|| anyhow::anyhow!("{name} program missing from object"))?
                    .try_into()?;
                program.load()?;
                program.attach(*hook, 0)?;
                tracing::info!(probe = *name, hook = *hook, "attached probe");
            }
            tracing::info!("draining events");

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
                        if let Some(obs) = Self::decode(&item)
                            && tx.send(obs).await.is_err()
                        {
                            return Ok(()); // receiver gone — shut down
                        }
                    }
                }
                guard.clear_ready();
            }
        }

        /// Read an event's header, dispatch on its kind, and turn it into an observation.
        /// Returns `None` for a truncated event, an unknown kind, or a pid that doesn't
        /// resolve to a pod (host process) — all dropped, never fatal.
        fn decode(data: &[u8]) -> Option<RuntimeObservation> {
            if data.len() < std::mem::size_of::<EventHeader>() {
                return None;
            }
            // SAFETY: every event begins with an EventHeader (offset 0, repr(C)).
            let header = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<EventHeader>()) };
            match header.kind {
                KIND_CONNECT => {
                    if data.len() < std::mem::size_of::<ConnEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a ConnEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<ConnEvent>()) };
                    Self::connect(&ev)
                }
                _ => None, // unknown kind (older/newer probe set) — skip
            }
        }

        /// Map a connect event to an observation attributed by pod UID (the engine
        /// resolves UID → namespace/pod, so namespace/pod are left empty here). Drops
        /// events whose cgroup isn't a pod.
        fn connect(ev: &ConnEvent) -> Option<RuntimeObservation> {
            let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", ev.header.pid)).ok()?;
            let uid = parse_pod_uid(&cgroup)?;
            // daddr's bytes are the network-order octets; to_ne_bytes on LE gives them
            // in [a,b,c,d] order, which is what Ipv4Addr::from([u8;4]) wants.
            let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
            Some(RuntimeObservation {
                namespace: String::new(),
                pod: String::new(),
                pod_uid: Some(uid),
                source: Some(SOURCE.into()),
                observed_at_ms: now_ms(),
                behavior: Behavior::NetworkConnection {
                    peer: format!("{ip}:{}", ev.dport),
                    internet: !(ip.is_private() || ip.is_loopback() || ip.is_link_local()),
                },
            })
        }
    }

    /// Wall-clock now as Unix epoch millis, for the observation's freshness stamp. `None`
    /// only if the clock is before the epoch (never, in practice) — the engine then
    /// falls back to ingest time.
    fn now_ms() -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as u64)
    }
}
