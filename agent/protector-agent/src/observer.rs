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
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use aya::maps::{PerCpuArray, RingBuf};
    use aya::programs::{FEntry, KProbe};
    use aya::{Btf, Ebpf};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    use super::*;
    use crate::pod::parse_pod_uid;
    // The repr(C) event layouts are shared with the eBPF crate via this one crate, so the
    // kernel↔userspace byte contract can't drift (ADR-0014).
    use protector_agent_common::{
        ConnEvent, EventHeader, FileEvent, KIND_CONNECT, KIND_EXEC, KIND_FILE_OPEN,
        KIND_LIBRARY_LOAD, KIND_PRIV_CHANGE, PATH_CAP, PrivEvent,
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

    /// A ring event parsed into typed fields but **not yet attributed** to a pod. This is
    /// the unit handed across the drain→worker boundary (JEF-64): the cheap `repr(C)`
    /// decode stays on the drain, the expensive cgroup read happens in the worker. One
    /// variant per probe — mirrors the `decode` dispatch.
    enum RawEvent {
        /// Outbound connect: destination IPv4 (network order) + port (host order).
        Connect { pid: u32, daddr: u32, dport: u16 },
        /// tmpfs file open: the (already-truncated, NUL-trimmed) container path.
        FileRead { pid: u32, path: String },
        /// Executable mmap: the library basename (e.g. `libssl.so.3`).
        LibraryLoad { pid: u32, name: String },
        /// Privilege escalation to root: the pre/post real UIDs (the eBPF side already
        /// filtered to `new_uid == 0 && old_uid != 0`).
        PrivChange {
            pid: u32,
            old_uid: u32,
            new_uid: u32,
        },
        /// Process exec: the exec'd binary path (e.g. `/usr/bin/bash`), NUL-trimmed.
        Exec { pid: u32, path: String },
    }

    impl RawEvent {
        /// The pid this event is attributed by — the key for the cgroup read and cache.
        fn pid(&self) -> u32 {
            match self {
                RawEvent::Connect { pid, .. }
                | RawEvent::FileRead { pid, .. }
                | RawEvent::LibraryLoad { pid, .. }
                | RawEvent::PrivChange { pid, .. }
                | RawEvent::Exec { pid, .. } => *pid,
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
            }
        }
    }

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
            // Best-effort fentry probes (secret-read, library-load). NOT fatal — a probe
            // that fails to load/attach (no BTF/fentry, verifier reject) is logged and
            // skipped, leaving the others (and the connect kprobe) running.
            Self::attach_fentry(&mut ebpf);
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
            // JEF-58 follow-up: in-kernel event aggregation (BPF-map dedup of
            // high-frequency repeats) is still not done — out of scope here, see JEF-64.
            let (raw_tx, raw_rx) = mpsc::channel::<RawEvent>(ATTRIB_QUEUE);
            let worker = tokio::spawn(Self::attribution_worker(raw_rx, tx));

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
                        let total = Self::read_drops(&drops);
                        // Only log when there's loss and it's changed since last tick —
                        // a quiet ring stays silent.
                        if total > 0 && total != last_drops {
                            tracing::info!(
                                drops = total,
                                "eBPF ring buffer dropped events (cumulative); buffer is full"
                            );
                        }
                        last_drops = total;
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
        /// (JEF-64). Receives parsed-but-unattributed [`RawEvent`]s, resolves each pid to
        /// a pod UID via `/proc/<pid>/cgroup` (cached by pid), builds the
        /// `RuntimeObservation`, and forwards it to `tx`. Exits when the drain drops its
        /// sender (`recv` → `None`) or the report receiver is gone (`tx.send` errors) —
        /// either way a clean shutdown.
        async fn attribution_worker(
            mut raw_rx: mpsc::Receiver<RawEvent>,
            tx: Sender<RuntimeObservation>,
        ) {
            let mut cache: HashMap<u32, Option<String>> = HashMap::new();
            while let Some(raw) = raw_rx.recv().await {
                let Some(uid) = Self::attribute(&mut cache, raw.pid(), read_cgroup) else {
                    continue; // host process / unreadable cgroup — drop, never fatal
                };
                let obs = RuntimeObservation {
                    attribution: Attribution::by_pod_uid(uid),
                    source: Some(SOURCE.into()),
                    observed_at_ms: now_ms(),
                    behavior: raw.into_behavior(),
                };
                if tx.send(obs).await.is_err() {
                    return; // report receiver gone — shut down
                }
            }
        }

        /// Resolve a pid to its pod UID, memoized in `cache` so repeated events from the
        /// same pid skip the `/proc` read. The `read` closure yields the pid's cgroup text
        /// (injected so this is unit-testable without a real `/proc`). A `None` result
        /// (host process / unreadable) is cached too, so a flood from one host pid doesn't
        /// re-read `/proc` per event. Bounded: at `PID_CACHE_CAP` entries the cache is
        /// cleared wholesale before inserting (cheap, rare; pids churn anyway).
        fn attribute(
            cache: &mut HashMap<u32, Option<String>>,
            pid: u32,
            read: impl Fn(u32) -> Option<String>,
        ) -> Option<String> {
            if let Some(cached) = cache.get(&pid) {
                return cached.clone();
            }
            let uid = read(pid).as_deref().and_then(parse_pod_uid);
            if cache.len() >= PID_CACHE_CAP {
                cache.clear();
            }
            cache.insert(pid, uid.clone());
            uid
        }

        /// Sum the per-CPU drop counter across all CPUs into the cumulative total.
        /// A per-CPU read failure is treated as 0 for that read (best-effort
        /// observability — never errors the drain).
        fn read_drops(
            drops: &PerCpuArray<impl std::borrow::Borrow<aya::maps::MapData>, u64>,
        ) -> u64 {
            match drops.get(&0, 0) {
                Ok(values) => values.iter().copied().sum(),
                Err(_) => 0,
            }
        }

        /// Attach the fentry probes, each best-effort (a failure is logged, not fatal).
        /// (program name in the object, kernel function it hooks). fentry attaches via
        /// BTF, so it's separate from the kprobe table; the BTF is loaded once.
        fn attach_fentry(ebpf: &mut Ebpf) {
            const FENTRY_PROBES: &[(&str, &str)] = &[
                ("file_open", "security_file_open"),
                ("mmap_file", "security_mmap_file"),
                ("fix_setuid", "security_task_fix_setuid"),
                ("bprm_check", "security_bprm_check"),
            ];
            let btf = match Btf::from_sys_fs() {
                Ok(btf) => btf,
                Err(error) => {
                    tracing::warn!(%error, "kernel BTF unavailable; fentry probes off");
                    return;
                }
            };
            for (name, func) in FENTRY_PROBES {
                match Self::attach_one_fentry(ebpf, &btf, name, func) {
                    Ok(()) => tracing::info!(probe = *name, func = *func, "attached fentry"),
                    Err(error) => {
                        tracing::warn!(%error, probe = *name, "fentry did not attach; continuing")
                    }
                }
            }
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
                _ => None, // unknown kind (older/newer probe set) — skip
            }
        }

        /// Parse a connect event into a [`RawEvent`]. Pure (no `/proc`) — the engine
        /// resolves UID → namespace/pod later, after the worker attributes the pid.
        fn connect(ev: &ConnEvent) -> Option<RawEvent> {
            Some(RawEvent::Connect {
                pid: ev.header.pid,
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
                pid: ev.header.pid,
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
                pid: ev.header.pid,
                name: name.to_string(),
            })
        }

        /// Parse a privilege-change event into a raw PrivChange. The eBPF side already
        /// filtered to the escalation-to-root case (`new_uid == 0 && old_uid != 0`), so
        /// this just carries the UIDs through. Pure (no `/proc`).
        fn priv_change(ev: &PrivEvent) -> Option<RawEvent> {
            Some(RawEvent::PrivChange {
                pid: ev.header.pid,
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
                pid: ev.header.pid,
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
    mod tests {
        use std::cell::Cell;

        use super::*;

        const POD_CGROUP: &str =
            "/kubepods/besteffort/pod3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b/abc123";

        #[test]
        fn attribute_resolves_and_memoizes_by_pid() {
            let mut cache = HashMap::new();
            let reads = Cell::new(0);
            let read = |_pid: u32| {
                reads.set(reads.get() + 1);
                Some(POD_CGROUP.to_string())
            };

            let first = EbpfObserver::attribute(&mut cache, 42, &read);
            let second = EbpfObserver::attribute(&mut cache, 42, &read);

            assert_eq!(
                first.as_deref(),
                Some("3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b")
            );
            assert_eq!(first, second);
            // The second call must hit the cache, not re-read `/proc`.
            assert_eq!(reads.get(), 1, "repeated pid should skip the cgroup read");
        }

        #[test]
        fn attribute_caches_negative_result() {
            let mut cache = HashMap::new();
            let reads = Cell::new(0);
            // A host process: readable cgroup, but not a pod's.
            let read = |_pid: u32| {
                reads.set(reads.get() + 1);
                Some("/system.slice/sshd.service".to_string())
            };

            assert_eq!(EbpfObserver::attribute(&mut cache, 7, &read), None);
            assert_eq!(EbpfObserver::attribute(&mut cache, 7, &read), None);
            // A flood from one host pid must not re-read `/proc` per event.
            assert_eq!(reads.get(), 1, "negative result should be cached too");
        }

        #[test]
        fn attribute_caches_unreadable_cgroup() {
            let mut cache = HashMap::new();
            // An exited / unreadable pid yields `None` from the reader.
            let read = |_pid: u32| None;
            assert_eq!(EbpfObserver::attribute(&mut cache, 99, &read), None);
            assert!(cache.contains_key(&99), "missing cgroup should be cached");
        }

        #[test]
        fn attribute_clears_cache_at_cap() {
            let mut cache = HashMap::new();
            let read = |_pid: u32| Some(POD_CGROUP.to_string());
            // Fill to capacity, then one more insert trips the wholesale clear.
            for pid in 0..PID_CACHE_CAP as u32 {
                EbpfObserver::attribute(&mut cache, pid, &read);
            }
            assert_eq!(cache.len(), PID_CACHE_CAP);
            EbpfObserver::attribute(&mut cache, PID_CACHE_CAP as u32, &read);
            assert_eq!(cache.len(), 1, "cache should clear wholesale at the cap");
        }

        #[test]
        fn decode_connect_parses_without_proc() {
            let ev = ConnEvent {
                header: EventHeader {
                    kind: KIND_CONNECT,
                    pid: 1234,
                },
                daddr: u32::from_ne_bytes([8, 8, 8, 8]),
                dport: 443,
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&ev as *const ConnEvent).cast::<u8>(),
                    std::mem::size_of::<ConnEvent>(),
                )
            };
            match EbpfObserver::decode(bytes) {
                Some(RawEvent::Connect { pid, daddr, dport }) => {
                    assert_eq!(pid, 1234);
                    assert_eq!(daddr, ev.daddr);
                    assert_eq!(dport, 443);
                }
                other => panic!("expected Connect, got something else: {}", other.is_none()),
            }
        }

        #[test]
        fn decode_priv_change_parses_uids() {
            let ev = PrivEvent {
                header: EventHeader {
                    kind: KIND_PRIV_CHANGE,
                    pid: 4321,
                },
                old_uid: 1000,
                new_uid: 0,
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&ev as *const PrivEvent).cast::<u8>(),
                    std::mem::size_of::<PrivEvent>(),
                )
            };
            match EbpfObserver::decode(bytes) {
                Some(RawEvent::PrivChange {
                    pid,
                    old_uid,
                    new_uid,
                }) => {
                    assert_eq!(pid, 4321);
                    assert_eq!(old_uid, 1000);
                    assert_eq!(new_uid, 0);
                }
                _ => panic!("expected PrivChange"),
            }
            // And the raw event maps to the PrivilegeChange behavior with from/to uids.
            let raw = EbpfObserver::decode(bytes).unwrap();
            assert_eq!(
                raw.into_behavior(),
                Behavior::PrivilegeChange {
                    from_uid: 1000,
                    to_uid: 0,
                }
            );
        }

        #[test]
        fn decode_exec_parses_path_and_maps_to_process_exec() {
            // A KIND_EXEC FileEvent carrying a NUL-terminated exec path must decode to a
            // RawEvent::Exec, and into_behavior must map it to Behavior::ProcessExec whose
            // fingerprint coarsens to the basename (JEF-53).
            let mut path = [0u8; PATH_CAP];
            let bin = b"/usr/bin/bash\0";
            path[..bin.len()].copy_from_slice(bin);
            let ev = FileEvent {
                header: EventHeader {
                    kind: KIND_EXEC,
                    pid: 4321,
                },
                len: bin.len() as u32,
                path,
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&ev as *const FileEvent).cast::<u8>(),
                    std::mem::size_of::<FileEvent>(),
                )
            };
            let raw = EbpfObserver::decode(bytes).expect("KIND_EXEC should decode");
            match &raw {
                RawEvent::Exec { pid, path } => {
                    assert_eq!(*pid, 4321);
                    assert_eq!(path, "/usr/bin/bash");
                }
                _ => panic!("expected RawEvent::Exec"),
            }
            assert_eq!(raw.pid(), 4321);
            match raw.into_behavior() {
                Behavior::ProcessExec { path } => {
                    assert_eq!(path, "/usr/bin/bash");
                    assert_eq!(
                        Behavior::ProcessExec { path }.fingerprint_key(),
                        "exec:bash"
                    );
                }
                other => panic!("expected ProcessExec, got {other:?}"),
            }
        }
    }
}
