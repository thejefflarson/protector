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
/// without them, and says how to turn them on. Gated to the non-`ebpf` build — its only
/// user (main.rs picks `EbpfObserver` under `--features ebpf`) — so the shipping ebpf
/// image doesn't carry it as dead code.
#[cfg(not(feature = "ebpf"))]
pub struct NoopObserver;

#[cfg(not(feature = "ebpf"))]
impl NoopObserver {
    pub async fn run(
        self,
        _tx: Sender<RuntimeObservation>,
        probes: std::sync::Arc<crate::ProbeStatus>,
    ) {
        // No collection ⇒ zero probes attached: the liveness beacon (JEF-308) then honestly reports
        // this node BLIND (probes_loaded == 0), never a false healthy.
        probes.set(0, 0);
        tracing::warn!(
            "built without the `ebpf` feature — no behavioral collection. Rebuild with \
             `--features ebpf` on a node (needs bpf-linker) to load the probes."
        );
        // Stay up so the DaemonSet stays Ready; the report path/batcher still run.
        std::future::pending::<()>().await
    }
}

/// Signals-per-second over a heartbeat interval: the count of successfully attributed
/// and forwarded observations divided by the elapsed wall-clock seconds (JEF-101). Pure
/// and kernel-free so it's unit-testable in the default build. Guards a zero/sub-tick
/// elapsed (returns 0.0 rather than dividing by ~0 and reporting a nonsense spike).
///
/// Only the `ebpf` build's heartbeat calls this; gate it to that build (plus `test`,
/// which exercises it directly) so the default no-op build doesn't warn it unused.
#[cfg(any(feature = "ebpf", test))]
fn signal_rate(delta_signals: u64, elapsed: std::time::Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    delta_signals as f64 / secs
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
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use aya::maps::{PerCpuArray, RingBuf};
    use aya::programs::{FEntry, KProbe};
    use aya::{Btf, Ebpf};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    use super::*;
    use crate::pod::{CgroupTable, PodAttribution, resolve_attribution, scan_cgroupfs};
    // The repr(C) event layouts are shared with the eBPF crate via this one crate, so the
    // kernel↔userspace byte contract can't drift (ADR-0014).
    use protector_agent_common::{
        ConnEvent, EventHeader, FileEvent, KIND_CONNECT, KIND_EXEC, KIND_FILE_OPEN,
        KIND_FILE_WRITE, KIND_LIBRARY_LOAD, KIND_PRIV_CHANGE, PATH_CAP, PrivEvent,
    };
    use protector_behavior::{Attribution, Behavior};

    /// This sensor's identity, carried into each observation's provenance so the engine
    /// can tell agent signals from Falco's (ADR-0003 corroboration).
    const SOURCE: &str = "protector-agent";

    /// The probes to load and attach: (program name in the object, kernel hook). Adding
    /// a probe is one row here plus a decode arm in `decode` — no new control flow.
    const PROBES: &[(&str, &str)] = &[("connect", "security_socket_connect")];

    /// How often to read the kernel drop counter and (if it moved) log a heartbeat.
    /// Drops are silent loss from a full ring; 30s keeps the signal visible without
    /// spamming the log (JEF-58).
    const HEARTBEAT: Duration = Duration::from_secs(30);

    /// Depth of the drain→attribution hand-off channel. The drain parses ring bytes
    /// (cheap) and pushes a [`RawEvent`] here; the attribution worker drains it doing the
    /// blocking `/proc/<pid>/cgroup` read (slow). The buffer absorbs short bursts so a
    /// momentarily-slow `/proc` doesn't immediately stall the ring drain. Sized to a few
    /// thousand events: large enough to ride out a spike, small enough to bound memory.
    const ATTRIB_QUEUE: usize = 4096;

    /// Cap on the pid→pod_uid attribution cache. Repeated events from the same pid (the
    /// common case — a chatty process) skip the `/proc` read entirely. pids are recycled
    /// by the kernel, so an entry can go stale; the cache is best-effort and bounded, and
    /// a wrong-but-same-pod attribution under recycling is harmless to the additive model.
    /// When full we clear it wholesale (cheap, rare) rather than track per-entry LRU.
    const PID_CACHE_CAP: usize = 8192;

    /// How often the attribution worker rescans `/sys/fs/cgroup` to refresh the
    /// `cgroup_id → pod_uid` table (JEF-158). The agent has no pod watch (no cluster
    /// credentials, ADR-0014), so a periodic rescan is how it tracks pods coming and going.
    /// 10s is well under a pod's lifetime: a pod created between scans simply attributes via
    /// the `/proc` fallback until the next scan, then via the table — never a lost signal.
    /// The scan is a cheap shallow walk of the kubepods hierarchy (a few dozen directories).
    const CGROUP_RESCAN: Duration = Duration::from_secs(10);

    /// The cgroup v2 mount root the table is scanned from. The DaemonSet mounts the host's
    /// `/sys/fs/cgroup` read-only.
    fn cgroup_root() -> &'static std::path::Path {
        std::path::Path::new("/sys/fs/cgroup")
    }

    /// A ring event parsed into typed fields but **not yet attributed** to a pod. This is
    /// the unit handed across the drain→worker boundary (JEF-64): the cheap `repr(C)`
    /// decode stays on the drain, the expensive cgroup read happens in the worker. One
    /// variant per probe — mirrors the `decode` dispatch.
    enum RawEvent {
        /// Outbound connect: destination IPv4 (network order) + port (host order).
        Connect {
            attr: EventAttr,
            daddr: u32,
            dport: u16,
        },
        /// tmpfs file open: the (already-truncated, NUL-trimmed) container path.
        FileRead { attr: EventAttr, path: String },
        /// Executable mmap: the library basename (e.g. `libssl.so.3`).
        LibraryLoad { attr: EventAttr, name: String },
        /// Privilege escalation to root: the pre/post real UIDs (the eBPF side already
        /// filtered to `new_uid == 0 && old_uid != 0`).
        PrivChange {
            attr: EventAttr,
            old_uid: u32,
            new_uid: u32,
        },
        /// Process exec: the exec'd binary path (e.g. `/usr/bin/bash`), NUL-trimmed.
        Exec { attr: EventAttr, path: String },
        /// File write: the written file's path (e.g. `/etc/cron.d/x`), NUL-trimmed. The
        /// eBPF side already filtered to write-intent opens and deduped repeats to the same
        /// `(pid, inode)`; this just carries the path through (JEF-306).
        FileWrite { attr: EventAttr, path: String },
    }

    /// The pair of identities every event carries for attribution (JEF-158): the in-kernel
    /// `cgroup_id` (the hot path — resolved via the [`CgroupTable`], works after the process
    /// exits) and the `pid` (the `/proc/<pid>/cgroup` fallback when the table misses).
    #[derive(Clone, Copy)]
    struct EventAttr {
        pid: u32,
        cgroup_id: u64,
    }

    impl EventAttr {
        /// Lift the shared header's identities into an [`EventAttr`].
        fn from_header(header: &EventHeader) -> Self {
            Self {
                pid: header.pid,
                cgroup_id: header.cgroup_id,
            }
        }
    }

    impl RawEvent {
        /// The (cgroup_id, pid) identities this event is attributed by.
        fn attr(&self) -> EventAttr {
            match self {
                RawEvent::Connect { attr, .. }
                | RawEvent::FileRead { attr, .. }
                | RawEvent::LibraryLoad { attr, .. }
                | RawEvent::PrivChange { attr, .. }
                | RawEvent::Exec { attr, .. }
                | RawEvent::FileWrite { attr, .. } => *attr,
            }
        }

        /// Build the behavior body for this event. Pure (no I/O) — the pod_uid is supplied
        /// by the caller after attribution.
        fn into_behavior(self) -> Behavior {
            match self {
                RawEvent::Connect { daddr, dport, .. } => {
                    // daddr's bytes are the network-order octets; to_ne_bytes on LE gives
                    // them in [a,b,c,d] order, which is what Ipv4Addr::from([u8;4]) wants.
                    let ip = Ipv4Addr::from(daddr.to_ne_bytes());
                    Behavior::NetworkConnection {
                        peer: format!("{ip}:{dport}"),
                        internet: !(ip.is_private() || ip.is_loopback() || ip.is_link_local()),
                    }
                }
                RawEvent::FileRead { path, .. } => Behavior::FileRead { path },
                RawEvent::LibraryLoad { name, .. } => Behavior::LibraryLoaded { name },
                RawEvent::PrivChange {
                    old_uid, new_uid, ..
                } => Behavior::PrivilegeChange {
                    from_uid: old_uid,
                    to_uid: new_uid,
                },
                RawEvent::Exec { path, .. } => Behavior::ProcessExec { path },
                RawEvent::FileWrite { path, .. } => Behavior::FileWrite { path },
            }
        }
    }

    pub struct EbpfObserver;

    impl EbpfObserver {
        pub async fn run(
            self,
            tx: Sender<RuntimeObservation>,
            probes: Arc<crate::ProbeStatus>,
        ) -> anyhow::Result<()> {
            // The BPF object is compiled + embedded by build.rs under the `ebpf` feature.
            let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/protector-agent.bpf.o"
            )))?;
            let mut loaded: u32 = 0;
            for (name, hook) in PROBES {
                let program: &mut KProbe = ebpf
                    .program_mut(name)
                    .ok_or_else(|| anyhow::anyhow!("{name} program missing from object"))?
                    .try_into()?;
                program.load()?;
                program.attach(*hook, 0)?;
                loaded += 1;
                tracing::info!(probe = *name, hook = *hook, "attached probe");
            }
            // Best-effort fentry probes (secret-read, library-load). NOT fatal — a probe
            // that fails to load/attach (no BTF/fentry, verifier reject) is logged and
            // skipped, leaving the others (and the connect kprobe) running.
            let (fentry_loaded, fentry_total) = Self::attach_fentry(&mut ebpf);
            loaded += fentry_loaded;
            // Publish probe-attach status (JEF-308): the liveness beacon reads it so a Ready agent
            // whose probes failed to attach (loaded == 0) reads BLIND, and a partial load reads
            // degraded — signal-flow liveness, not pod-Ready.
            let total = PROBES.len() as u32 + fentry_total;
            probes.set(loaded, total);
            tracing::info!(loaded, total, "eBPF probes attached (JEF-308 liveness)");
            tracing::info!("draining events");

            let ring = RingBuf::try_from(
                ebpf.take_map("EVENTS")
                    .ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?,
            )?;
            // The kernel's cumulative drop counter (per-CPU, one slot). Taken like
            // EVENTS so we own a stable handle for the heartbeat reads (JEF-58).
            let drops: PerCpuArray<_, u64> = PerCpuArray::try_from(
                ebpf.take_map("DROPS")
                    .ok_or_else(|| anyhow::anyhow!("DROPS map missing"))?,
            )?;
            // The kernel's cumulative in-kernel-coalesced counter (per-CPU, one slot),
            // taken like DROPS so the heartbeat can surface how many connect repeats the
            // dedup map suppressed at the source (JEF-65).
            let coalesced: PerCpuArray<_, u64> = PerCpuArray::try_from(
                ebpf.take_map("COALESCED")
                    .ok_or_else(|| anyhow::anyhow!("COALESCED map missing"))?,
            )?;
            let mut async_fd = AsyncFd::new(ring)?;
            // Heartbeat ticker for the drop counter. The first tick fires immediately;
            // skip it so the first *logged* heartbeat reflects a real interval.
            let mut heartbeat = tokio::time::interval(HEARTBEAT);
            heartbeat.tick().await;
            let mut last_drops: u64 = 0;

            // JEF-64: attribution is OFF the drain path. The drain only parses ring bytes
            // into `RawEvent`s (cheap) and hands them to this bounded channel; a separate
            // worker task does the blocking `/proc/<pid>/cgroup` read, builds the
            // `RuntimeObservation`, and forwards it to `tx`. A slow `/proc` can no longer
            // back the ring up — at worst the channel fills and we drop new raw events
            // (see `try_send` below), which the additive-evidence model tolerates.
            //
            // JEF-65: in-kernel event aggregation now coalesces high-frequency connect
            // repeats at the source — a per-(pid, dest) LRU dedup map in the connect probe
            // suppresses a repeat seen within the dedup window so it never costs a ring slot
            // (cutting volume before the drain, not draining + dropping duplicates here). The
            // suppressed count surfaces as `coalesced` in the heartbeat below.
            let (raw_tx, raw_rx) = mpsc::channel::<RawEvent>(ATTRIB_QUEUE);
            // Per-node counters shared with the attribution worker (JEF-101). All are
            // cumulative; the heartbeat snapshots them to surface the numbers JEF-48's
            // exit criteria need measurable per node: ring-buffer drops, the signal rate,
            // and attribution quality. `Relaxed` is fine — these are monotonic counters
            // read for observability, not a synchronization gate.
            //
            // JEF-115: `unresolved` now counts ONLY genuine misses (pid gone / cgroup
            // unreadable), matching the engine-side ~1.4%. The host-process firehose the
            // node-wide kprobe sees — readable cgroups that simply aren't pods — is the
            // EXPECTED case and is counted separately in `host_events`, not as a failure.
            let unresolved = Arc::new(AtomicU64::new(0));
            let host_events = Arc::new(AtomicU64::new(0));
            let signals = Arc::new(AtomicU64::new(0));
            let worker = tokio::spawn(Self::attribution_worker(
                raw_rx,
                tx,
                Arc::clone(&unresolved),
                Arc::clone(&host_events),
                Arc::clone(&signals),
            ));
            // Snapshots from the previous heartbeat, for the per-interval rate.
            let mut last_signals: u64 = 0;
            let mut last_tick = Instant::now();

            let result = loop {
                tokio::select! {
                    guard = async_fd.readable_mut() => {
                        let mut guard = match guard {
                            Ok(guard) => guard,
                            Err(error) => break Err(error.into()),
                        };
                        {
                            let ring = guard.get_inner_mut();
                            while let Some(item) = ring.next() {
                                let Some(raw) = Self::decode(&item) else { continue };
                                // Bounded, non-blocking hand-off. `try_send` returns
                                // immediately so draining stays fast: a full queue means
                                // attribution is behind, and we deliberately drop this
                                // raw event rather than block the drain (which would
                                // re-introduce the very ring-buffer backpressure JEF-64
                                // removes). A closed channel means the worker exited
                                // (receiver gone) — shut the drain down too.
                                match raw_tx.try_send(raw) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {}
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        break;
                                    }
                                }
                            }
                        }
                        guard.clear_ready();
                        // If the worker is gone, stop draining (clean shutdown).
                        if raw_tx.is_closed() {
                            break Ok(());
                        }
                    }
                    _ = heartbeat.tick() => {
                        let total = Self::sum_percpu(&drops);
                        // Only log the loud drop warning when there's loss and it's
                        // changed since last tick — a quiet ring stays silent.
                        if total > 0 && total != last_drops {
                            tracing::info!(
                                drops = total,
                                "eBPF ring buffer dropped events (cumulative); buffer is full"
                            );
                        }
                        last_drops = total;

                        // JEF-101: emit the per-node numbers JEF-48 needs measurable —
                        // cumulative ring drops, the signal rate over this interval, and
                        // attribution quality — as a structured stat line (greppable/
                        // scrapeable per node, no new deps, wire payload unchanged). Unlike
                        // the drop warning above this fires every tick so "zero drops" is
                        // observable as a present-and-zero datapoint.
                        //
                        // JEF-115: `attribution_unresolved` is now genuine misses only
                        // (should be near-zero, matching the engine's ~1.4%); the expected
                        // host-process firehose is reported separately as `host_events` so
                        // it's visible without masquerading as attribution failure.
                        let unresolved_total = unresolved.load(Ordering::Relaxed);
                        let host_total = host_events.load(Ordering::Relaxed);
                        let signals_total = signals.load(Ordering::Relaxed);
                        // JEF-65: connect repeats coalesced in-kernel (cumulative). A
                        // rising `coalesced` against a flat/low `ring_drops` is the dedup
                        // working — volume cut at the source before it can pressure the ring.
                        let coalesced_total = Self::sum_percpu(&coalesced);
                        let now = Instant::now();
                        let rate = signal_rate(
                            signals_total.saturating_sub(last_signals),
                            now.duration_since(last_tick),
                        );
                        last_signals = signals_total;
                        last_tick = now;
                        tracing::info!(
                            ring_drops = total,
                            coalesced = coalesced_total,
                            attribution_unresolved = unresolved_total,
                            host_events = host_total,
                            signals_per_s = rate,
                            "agent stats"
                        );
                    }
                }
            };
            // Drop our sender so the worker's `recv` returns `None` and it exits, then
            // wait for it so attribution-in-flight isn't cut off mid-send on shutdown.
            drop(raw_tx);
            let _ = worker.await;
            result
        }

        /// The attribution worker: the slow half of the split, off the drain path
        /// (JEF-64). Receives parsed-but-unattributed [`RawEvent`]s, resolves each to a pod
        /// UID, builds the `RuntimeObservation`, and forwards it to `tx`. Exits when the
        /// drain drops its sender (`recv` → `None`) or the report receiver is gone
        /// (`tx.send` errors) — either way a clean shutdown.
        ///
        /// JEF-158: attribution now resolves the event's in-kernel `cgroup_id` against a
        /// [`CgroupTable`] built from `/sys/fs/cgroup` FIRST. A table hit needs no `/proc`
        /// read, so a short-lived in-container exec/shell that has already exited still
        /// attributes — the exited-process race the post-hoc `/proc/<pid>/cgroup` read keeps
        /// losing. The `/proc` read stays as the fallback for a table miss (a host process,
        /// or a pod cgroup created since the last scan). The table is refreshed on an
        /// interval ([`CGROUP_RESCAN`]) — the agent has no cluster credentials and no pod
        /// watch (ADR-0014), so a periodic rescan of the cgroup hierarchy is how it tracks
        /// pods coming and going.
        ///
        /// JEF-115 (unchanged): three outcomes. A pod is forwarded; a readable non-pod
        /// cgroup (the host-process firehose) is dropped and counted as a `host_event`
        /// (EXPECTED, not a failure); an unreadable cgroup (pid gone) is the only case
        /// counted as `unresolved` — a genuine miss.
        async fn attribution_worker(
            mut raw_rx: mpsc::Receiver<RawEvent>,
            tx: Sender<RuntimeObservation>,
            unresolved: Arc<AtomicU64>,
            host_events: Arc<AtomicU64>,
            signals: Arc<AtomicU64>,
        ) {
            // The hot-path table (cgroup_id → pod_uid), rescanned from /sys/fs/cgroup on an
            // interval. Built once up front so the very first events can resolve.
            let mut table = scan_cgroupfs(cgroup_root());
            tracing::info!(
                pods = table.len(),
                "cgroup attribution table built (JEF-158)"
            );
            let mut rescan = tokio::time::interval(CGROUP_RESCAN);
            rescan.tick().await; // consume the immediate first tick
            // Per-pid cache for the FALLBACK `/proc` read only — a table miss from a chatty
            // host pid shouldn't re-read `/proc` per event. Bounded; cleared wholesale at cap.
            let mut fallback_cache: HashMap<u32, PodAttribution> = HashMap::new();
            loop {
                let raw = tokio::select! {
                    recv = raw_rx.recv() => match recv {
                        Some(raw) => raw,
                        None => return, // drain gone — clean shutdown
                    },
                    _ = rescan.tick() => {
                        // Refresh the table to pick up pods added/removed since the last scan.
                        table = scan_cgroupfs(cgroup_root());
                        tracing::debug!(pods = table.len(), "cgroup attribution table rescanned");
                        continue;
                    }
                };
                let attr = raw.attr();
                let uid = match Self::resolve(&table, &mut fallback_cache, attr) {
                    PodAttribution::Pod(uid) => uid,
                    PodAttribution::NotAPod => {
                        // The node-wide kprobe's expected host firehose — dropped (never
                        // fatal). Counted apart from misses so it doesn't masquerade as
                        // attribution failure (JEF-115).
                        host_events.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    PodAttribution::Unreadable => {
                        // pid gone / cgroup unreadable — a genuine miss. This is what
                        // JEF-48's "low unresolved attribution" measures per node.
                        unresolved.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let obs = RuntimeObservation {
                    attribution: Attribution::by_pod_uid(uid),
                    source: Some(SOURCE.into()),
                    observed_at_ms: now_ms(),
                    // The agent's node (JEF-308) is stamped by the flusher in `main` from `K8S_NODE`
                    // — kept in one place, so the ebpf worker leaves it unset here.
                    node: None,
                    behavior: raw.into_behavior(),
                };
                if tx.send(obs).await.is_err() {
                    return; // report receiver gone — shut down
                }
                // A signal successfully attributed and forwarded — the rate numerator.
                signals.fetch_add(1, Ordering::Relaxed);
            }
        }

        /// Resolve one event's [`EventAttr`] to a [`PodAttribution`] (JEF-158): the in-kernel
        /// `cgroup_id` against `table` first (no `/proc` — the exited-process-safe hot path),
        /// then the `/proc/<pid>/cgroup` fallback on a miss, memoized in `cache` so a flood
        /// from one pid doesn't re-read `/proc`. Every fallback outcome (pod, host non-pod,
        /// unreadable) is cached. Bounded: at [`PID_CACHE_CAP`] the cache is cleared wholesale
        /// (cheap, rare; pids churn anyway). A table hit is NOT cached — the table is already
        /// an in-memory map.
        fn resolve(
            table: &CgroupTable,
            cache: &mut HashMap<u32, PodAttribution>,
            attr: EventAttr,
        ) -> PodAttribution {
            if let Some(uid) = table.lookup(attr.cgroup_id) {
                return PodAttribution::Pod(uid.to_string());
            }
            if let Some(cached) = cache.get(&attr.pid) {
                return cached.clone();
            }
            let attribution = resolve_attribution(table, attr.cgroup_id, attr.pid, read_cgroup);
            if cache.len() >= PID_CACHE_CAP {
                cache.clear();
            }
            cache.insert(attr.pid, attribution.clone());
            attribution
        }

        /// Sum a single-slot per-CPU `u64` counter across all CPUs into its cumulative
        /// total. Shared by the ring-drop counter (JEF-58) and the in-kernel-coalesced
        /// counter (JEF-65) — both are the same one-slot `PerCpuArray<u64>` shape. A
        /// per-CPU read failure is treated as 0 for that read (best-effort observability —
        /// never errors the drain).
        fn sum_percpu(
            counter: &PerCpuArray<impl std::borrow::Borrow<aya::maps::MapData>, u64>,
        ) -> u64 {
            match counter.get(&0, 0) {
                Ok(values) => values.iter().copied().sum(),
                Err(_) => 0,
            }
        }

        /// Attach the fentry probes, each best-effort (a failure is logged, not fatal).
        /// (program name in the object, kernel function it hooks). fentry attaches via
        /// BTF, so it's separate from the kprobe table; the BTF is loaded once. Returns
        /// `(attached, attempted)` so the caller can publish the probe-attach status the
        /// per-node liveness beacon reads (JEF-308) — a partial load reads degraded.
        fn attach_fentry(ebpf: &mut Ebpf) -> (u32, u32) {
            const FENTRY_PROBES: &[(&str, &str)] = &[
                ("file_open", "security_file_open"),
                ("file_write", "security_file_open"),
                ("mmap_file", "security_mmap_file"),
                ("fix_setuid", "security_task_fix_setuid"),
                ("bprm_check", "security_bprm_check"),
            ];
            let attempted = FENTRY_PROBES.len() as u32;
            let btf = match Btf::from_sys_fs() {
                Ok(btf) => btf,
                Err(error) => {
                    tracing::warn!(%error, "kernel BTF unavailable; fentry probes off");
                    return (0, attempted);
                }
            };
            let mut attached = 0u32;
            for (name, func) in FENTRY_PROBES {
                match Self::attach_one_fentry(ebpf, &btf, name, func) {
                    Ok(()) => {
                        attached += 1;
                        tracing::info!(probe = *name, func = *func, "attached fentry");
                    }
                    Err(error) => {
                        tracing::warn!(%error, probe = *name, "fentry did not attach; continuing")
                    }
                }
            }
            (attached, attempted)
        }

        fn attach_one_fentry(
            ebpf: &mut Ebpf,
            btf: &Btf,
            name: &str,
            func: &str,
        ) -> anyhow::Result<()> {
            let program: &mut FEntry = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("{name} program missing from object"))?
                .try_into()?;
            program.load(func, btf)?;
            program.attach()?;
            Ok(())
        }

        /// Read an event's header, dispatch on its kind, and parse it into a typed but
        /// **unattributed** [`RawEvent`]. This is the cheap half, and it stays on the
        /// drain path: only the `repr(C)` byte parse (no `/proc`, no allocation beyond the
        /// path string). Returns `None` for a truncated event, an unknown kind, or an
        /// empty path — all dropped, never fatal. Attribution (the cgroup read) happens
        /// later in the worker (JEF-64).
        fn decode(data: &[u8]) -> Option<RawEvent> {
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
                KIND_FILE_OPEN => {
                    if data.len() < std::mem::size_of::<FileEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a FileEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<FileEvent>()) };
                    Self::file_read(&ev)
                }
                KIND_LIBRARY_LOAD => {
                    if data.len() < std::mem::size_of::<FileEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a FileEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<FileEvent>()) };
                    Self::library_load(&ev)
                }
                KIND_PRIV_CHANGE => {
                    if data.len() < std::mem::size_of::<PrivEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a PrivEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<PrivEvent>()) };
                    Self::priv_change(&ev)
                }
                KIND_EXEC => {
                    if data.len() < std::mem::size_of::<FileEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a FileEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<FileEvent>()) };
                    Self::exec(&ev)
                }
                KIND_FILE_WRITE => {
                    if data.len() < std::mem::size_of::<FileEvent>() {
                        return None;
                    }
                    // SAFETY: kind says this is a FileEvent of exactly this layout.
                    let ev = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<FileEvent>()) };
                    Self::file_write(&ev)
                }
                _ => None, // unknown kind (older/newer probe set) — skip
            }
        }

        /// Parse a connect event into a [`RawEvent`]. Pure (no `/proc`) — the engine
        /// resolves UID → namespace/pod later, after the worker attributes the pid.
        fn connect(ev: &ConnEvent) -> Option<RawEvent> {
            Some(RawEvent::Connect {
                attr: EventAttr::from_header(&ev.header),
                daddr: ev.daddr,
                dport: ev.dport,
            })
        }

        /// Parse a tmpfs file open into a raw FileRead. The agent can't tell if it's a
        /// secret (bpf_d_path gives only the container path); the engine refines
        /// FileRead → SecretRead via the pod's secret volumeMounts, or drops it. Drops
        /// events with an empty path. Pure (no `/proc`).
        fn file_read(ev: &FileEvent) -> Option<RawEvent> {
            let len = (ev.len as usize).min(PATH_CAP);
            let path = String::from_utf8_lossy(&ev.path[..len])
                .trim_end_matches('\0')
                .to_string();
            if path.is_empty() {
                return None;
            }
            Some(RawEvent::FileRead {
                attr: EventAttr::from_header(&ev.header),
                path,
            })
        }

        /// Parse an executable mmap into a LibraryLoad. The library name is the path
        /// basename (e.g. `libssl.so.3`) — the container path is fine here, the engine
        /// reasons about the loaded library by name. Drops empty names. Pure (no `/proc`).
        fn library_load(ev: &FileEvent) -> Option<RawEvent> {
            let len = (ev.len as usize).min(PATH_CAP);
            let path = String::from_utf8_lossy(&ev.path[..len]);
            let name = path.trim_end_matches('\0').rsplit('/').next().unwrap_or("");
            if name.is_empty() {
                return None;
            }
            Some(RawEvent::LibraryLoad {
                attr: EventAttr::from_header(&ev.header),
                name: name.to_string(),
            })
        }

        /// Parse a privilege-change event into a raw PrivChange. The eBPF side already
        /// filtered to the escalation-to-root case (`new_uid == 0 && old_uid != 0`), so
        /// this just carries the UIDs through. Pure (no `/proc`).
        fn priv_change(ev: &PrivEvent) -> Option<RawEvent> {
            Some(RawEvent::PrivChange {
                attr: EventAttr::from_header(&ev.header),
                old_uid: ev.old_uid,
                new_uid: ev.new_uid,
            })
        }

        /// Parse a process-exec event into a raw Exec. `path` is the exec'd binary path as
        /// the kernel saw it (`linux_binprm->filename`), NUL-trimmed; the behavior crate
        /// coarsens it to the basename for the fingerprint. Drops empty paths. Pure (no
        /// `/proc`).
        fn exec(ev: &FileEvent) -> Option<RawEvent> {
            let len = (ev.len as usize).min(PATH_CAP);
            let path = String::from_utf8_lossy(&ev.path[..len])
                .trim_end_matches('\0')
                .to_string();
            if path.is_empty() {
                return None;
            }
            Some(RawEvent::Exec {
                attr: EventAttr::from_header(&ev.header),
                path,
            })
        }

        /// Parse a file-write event into a raw FileWrite. `path` is the written file's path
        /// as the kernel saw it (`bpf_d_path`), NUL-trimmed; the behavior crate coarsens it
        /// to the dirname for the fingerprint. The eBPF side already filtered to write-intent
        /// opens and deduped repeats to the same `(pid, inode)`, so this just carries the
        /// path through. Drops empty paths. Pure (no `/proc`). PURE DATA (JEF-306): the
        /// container-drift / tamper *classification* is engine policy (F3), not done here.
        fn file_write(ev: &FileEvent) -> Option<RawEvent> {
            let len = (ev.len as usize).min(PATH_CAP);
            let path = String::from_utf8_lossy(&ev.path[..len])
                .trim_end_matches('\0')
                .to_string();
            if path.is_empty() {
                return None;
            }
            Some(RawEvent::FileWrite {
                attr: EventAttr::from_header(&ev.header),
                path,
            })
        }
    }

    /// Read a pid's cgroup membership text (`/proc/<pid>/cgroup`). The blocking read kept
    /// off the drain path (JEF-64): called only from the attribution worker. `None` if the
    /// process is gone or unreadable (a host process or an exited pid) — the event is then
    /// dropped, never fatal.
    fn read_cgroup(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
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

    #[cfg(test)]
    #[path = "observer_ebpf_tests.rs"]
    mod tests;
}

#[cfg(test)]
mod rate_tests {
    use std::time::Duration;

    use super::signal_rate;

    #[test]
    fn computes_per_second_over_the_interval() {
        // 300 signals over a 30s heartbeat → 10/s.
        assert_eq!(signal_rate(300, Duration::from_secs(30)), 10.0);
    }

    #[test]
    fn fractional_rate() {
        // 15 signals over 30s → 0.5/s.
        assert_eq!(signal_rate(15, Duration::from_secs(30)), 0.5);
    }

    #[test]
    fn zero_signals_is_zero_rate() {
        // A quiet interval must report 0.0, not absence — present-and-zero is the
        // "no drops / no traffic" datapoint JEF-48 needs.
        assert_eq!(signal_rate(0, Duration::from_secs(30)), 0.0);
    }

    #[test]
    fn zero_elapsed_does_not_divide_by_zero() {
        // A coincident / sub-tick interval must not produce a nonsense spike.
        assert_eq!(signal_rate(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn sub_second_interval_scales_up() {
        // 5 signals over 500ms → 10/s (rate is normalized, not raw count).
        assert_eq!(signal_rate(5, Duration::from_millis(500)), 10.0);
    }
}
