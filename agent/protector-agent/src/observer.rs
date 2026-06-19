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
    use super::*;
    use crate::pod::PodResolver;

    pub struct EbpfObserver {
        resolver: PodResolver,
    }

    impl EbpfObserver {
        pub fn new(resolver: PodResolver) -> Self {
            Self { resolver }
        }

        pub async fn run(self, tx: Sender<Observation>) -> anyhow::Result<()> {
            // NODE-BUILT skeleton. The concrete aya wiring is completed and load-tested
            // on a kernel (it can't be exercised in the engine's CI), but the shape is:
            //
            //   1. let mut ebpf = aya::Ebpf::load(EBPF_OBJECT)?;          // include_bytes! the built object
            //   2. let prog: &mut aya::programs::KProbe =
            //          ebpf.program_mut("connect").unwrap().try_into()?;
            //      prog.load()?; prog.attach("security_socket_connect", 0)?;
            //   3. let mut ring = aya::maps::RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
            //   4. loop { for event in ring.next() { -> ConnEvent { cgroup_id/pid, daddr, dport } }
            //         let uid = resolve cgroup -> pod uid (read /proc/<pid>/cgroup, parse_pod_uid)
            //         if let Some(pod) = self.resolver.resolve(&uid) {
            //             let internet = !is_cluster_cidr(daddr);
            //             tx.send(Observation { namespace, pod, behavior:
            //                 Behavior::NetworkConnection { peer: fmt(daddr,dport), internet } }).await?;
            //         } }
            //
            // Until that lands, fail loudly rather than silently pretend to observe.
            let _ = (&self.resolver, &tx);
            anyhow::bail!("EbpfObserver loader not yet wired — complete on a node (see agent/README.md)")
        }
    }
}
