//! cgroup → pod UID attribution.
//!
//! An eBPF event carries a kernel identity, not a pod. There are two ways to recover the
//! pod UID, and this module owns both:
//!
//! - **In-kernel cgroup id (JEF-158, the hot path).** The probe stamps each event with
//!   `bpf_get_current_cgroup_id()` — the cgroup v2 directory inode — captured while the
//!   process is still live. Userspace keeps a [`CgroupTable`] mapping that id to the pod
//!   UID, built by scanning `/sys/fs/cgroup` (each kubepods cgroup directory's inode is
//!   exactly that id). Looking the event's id up in the table needs no `/proc` read, so a
//!   short-lived in-container exec/shell that has already exited still attributes — the
//!   exited-process race the post-hoc `/proc/<pid>/cgroup` read keeps losing.
//! - **`/proc/<pid>/cgroup` text (the fallback).** When the table misses (a host process,
//!   or a brand-new pod cgroup not yet scanned), [`classify_cgroup`] parses the pid's
//!   cgroup text the old way.
//!
//! Either way the agent extracts only the pod **UID**; the **engine** maps that UID to a
//! namespace/pod from its pod watch (so the agent needs no cluster credentials, ADR-0014).
//! A cgroup that isn't a pod's (a host process) yields `None` and the event is dropped —
//! a missing signal beats a mis-attributed one.

/// The outcome of resolving a pid to a pod (JEF-115). The node-wide kprobe sees the
/// whole host firehose, so most events are *expected* non-pods, not failures. Keeping
/// the two apart is what lets the agent's `attribution_unresolved` stat mean a GENUINE
/// miss (matching the engine's ~1.4%) rather than the host-process noise floor:
///
/// - [`Pod`](PodAttribution::Pod): a readable cgroup that *is* a pod — forward it.
/// - [`NotAPod`](PodAttribution::NotAPod): a readable cgroup that isn't a pod's (a host
///   daemon, kube-system on a host cgroup) — EXPECTED, dropped, not a failure.
/// - [`Unreadable`](PodAttribution::Unreadable): the pid's cgroup couldn't be read (the
///   process is gone, or `/proc` denied us) — a real attribution miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodAttribution {
    /// Resolved to a pod UID (canonical, dashes normalized).
    Pod(String),
    /// Readable cgroup, but a host process — not a pod. Expected, not a miss.
    NotAPod,
    /// The cgroup was unreadable (pid gone / denied) — a genuine miss.
    Unreadable,
}

/// Classify a pid's cgroup read into the three [`PodAttribution`] outcomes. `cgroup` is
/// the `/proc/<pid>/cgroup` text, or `None` if the read failed (process gone /
/// unreadable). A readable-but-non-pod cgroup is [`NotAPod`](PodAttribution::NotAPod),
/// NOT a miss — see the enum docs.
pub fn classify_cgroup(cgroup: Option<&str>) -> PodAttribution {
    match cgroup {
        None => PodAttribution::Unreadable,
        Some(text) => match parse_pod_uid(text) {
            Some(uid) => PodAttribution::Pod(uid),
            None => PodAttribution::NotAPod,
        },
    }
}

/// Extract the pod UID from a cgroup path. Handles the two common layouts:
///
/// - systemd (cgroup v2): `…/kubepods-besteffort-pod<uid>.slice/…` where the UID's
///   dashes are rendered as underscores (`pod3f5e_..._a1.slice`).
/// - cgroupfs: `…/kubepods/besteffort/pod<uid>/<container-id>`.
///
/// Returns the canonical UID (underscores normalized back to dashes) or `None` if the
/// path isn't a pod cgroup.
pub fn parse_pod_uid(cgroup_path: &str) -> Option<String> {
    for seg in cgroup_path.split('/') {
        // systemd slice: `kubepods-<qos>-pod<uid>.slice` or `kubepods-pod<uid>.slice`.
        // Anchor on `-pod` so we don't match the `pod` inside `kubepods` itself.
        if let Some(rest) = seg.strip_suffix(".slice")
            && let Some(idx) = rest.find("-pod")
        {
            let uid = &rest[idx + 4..];
            if !uid.is_empty() {
                return Some(uid.replace('_', "-"));
            }
        }
        // cgroupfs: a bare `pod<uid>` segment
        if let Some(uid) = seg.strip_prefix("pod")
            && !uid.is_empty()
            && uid.contains('-')
        {
            return Some(uid.to_string());
        }
    }
    None
}

/// A snapshot of `cgroup_id → pod_uid`, the in-kernel attribution table (JEF-158).
///
/// The eBPF probe stamps each event with `bpf_get_current_cgroup_id()` (the cgroup v2
/// directory inode). This table maps that id straight to the pod UID, so a hot-path event
/// is attributed with a single map lookup and no `/proc/<pid>/cgroup` read — which is what
/// lets a short-lived in-container process attribute *after* it has exited. It is rebuilt
/// by [`scan_cgroupfs`] when pods come and go; a [`lookup`](CgroupTable::lookup) miss means
/// the caller should fall back to the per-event `/proc` read (a host process, or a pod
/// cgroup created since the last scan).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupTable {
    by_id: std::collections::HashMap<u64, String>,
}

impl CgroupTable {
    /// The pod UID for a cgroup id, or `None` if this id isn't a known pod cgroup. `id == 0`
    /// (the kernel couldn't determine a cgroup id) always misses, by construction — a `0`
    /// id is never inserted, so the caller falls back to `/proc`.
    pub fn lookup(&self, cgroup_id: u64) -> Option<&str> {
        if cgroup_id == 0 {
            return None;
        }
        self.by_id.get(&cgroup_id).map(String::as_str)
    }

    /// Number of pod cgroup entries (for tests / heartbeat visibility).
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the table holds no pod cgroups. The `clippy::len_without_is_empty` companion to
    /// `len()`; the shipping (`ebpf`) build calls `len()` for heartbeat visibility but not this,
    /// so allow the dead-code warning rather than drop the clippy-required pair.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// Build a [`CgroupTable`] from `(cgroup_id, cgroup_path)` pairs (JEF-158). Pure — the
/// filesystem walk is injected so this is unit-testable without a real `/sys/fs/cgroup`.
/// Only paths that [`parse_pod_uid`] recognizes as a pod cgroup are kept (host cgroups are
/// dropped); a `cgroup_id` of `0` is skipped (it can never match an event, see
/// [`CgroupTable::lookup`]). When several directories under one pod (the pod slice and its
/// per-container scopes) parse to the same UID, each distinct inode maps to that one UID —
/// so an event stamped with the container-scope id and one stamped with the pod-slice id
/// both resolve to the same pod.
pub fn build_cgroup_table(entries: impl IntoIterator<Item = (u64, String)>) -> CgroupTable {
    let mut by_id = std::collections::HashMap::new();
    for (id, path) in entries {
        if id == 0 {
            continue;
        }
        if let Some(uid) = parse_pod_uid(&path) {
            by_id.insert(id, uid);
        }
    }
    CgroupTable { by_id }
}

/// Walk the cgroup v2 hierarchy under `root` (normally `/sys/fs/cgroup`) and build the
/// [`CgroupTable`] (JEF-158). For every directory, the directory's **inode number is the
/// cgroup id** that `bpf_get_current_cgroup_id()` returns for tasks in it, so we pair each
/// directory's inode with its path and let [`build_cgroup_table`] keep the pod ones.
///
/// Walk is iterative (an explicit stack, no recursion) and depth-bounded so a pathological
/// hierarchy can't blow the stack or run unbounded; unreadable directories are skipped
/// (best-effort — a partial table just means more `/proc` fallbacks, never a crash). Only
/// `/sys/fs/cgroup` is read, which the DaemonSet already mounts read-only.
#[cfg(any(feature = "ebpf", test))]
pub fn scan_cgroupfs(root: &std::path::Path) -> CgroupTable {
    use std::os::unix::fs::MetadataExt;

    /// Depth cap for the cgroup walk. The kubepods hierarchy is shallow
    /// (`kubepods.slice/<qos>.slice/<pod>.slice/<container>.scope` ≈ 4 below the root); a
    /// generous cap bounds the walk without truncating any real pod cgroup.
    const MAX_DEPTH: usize = 12;

    let mut entries: Vec<(u64, String)> = Vec::new();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue; // unreadable dir — skip, best-effort
        };
        for entry in read.flatten() {
            let path = entry.path();
            // Only descend real directories (cgroups are directories); skip symlinks so we
            // can't loop or escape the hierarchy. `file_type` avoids a stat per entry.
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => {}
                _ => continue,
            }
            if let Ok(meta) = entry.metadata()
                && let Some(text) = path.to_str()
            {
                entries.push((meta.ino(), text.to_string()));
            }
            stack.push((path, depth + 1));
        }
    }
    build_cgroup_table(entries)
}

/// Resolve an event's attribution from its in-kernel `cgroup_id` first, falling back to
/// the per-event `/proc/<pid>/cgroup` read only on a table miss (JEF-158). This is the
/// single decision point that keeps the hot path off `/proc`:
///
/// - A table hit is a [`Pod`](PodAttribution::Pod) — resolved with no `/proc` read, so it
///   works even after the process has exited (the race this ticket fixes).
/// - A miss (host process, or a pod cgroup newer than the last scan, or `cgroup_id == 0`)
///   falls through to `read_cgroup(pid)` and [`classify_cgroup`], preserving the existing
///   host-vs-pod separation and the genuine-miss accounting unchanged.
///
/// `read_cgroup` is injected (a `Fn(u32) -> Option<String>`) so this is unit-testable
/// without a real `/proc`.
pub fn resolve_attribution(
    table: &CgroupTable,
    cgroup_id: u64,
    pid: u32,
    read_cgroup: impl Fn(u32) -> Option<String>,
) -> PodAttribution {
    if let Some(uid) = table.lookup(cgroup_id) {
        return PodAttribution::Pod(uid.to_string());
    }
    classify_cgroup(read_cgroup(pid).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_slice_uid_with_underscores() {
        let path = "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/\
                    kubepods-besteffort-pod3f5e1a2b_4c6d_7e8f_9a0b_1c2d3e4f5a6b.slice/\
                    cri-containerd-abc123.scope";
        assert_eq!(
            parse_pod_uid(path).as_deref(),
            Some("3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b")
        );
    }

    #[test]
    fn parses_cgroupfs_uid() {
        let path = "/kubepods/besteffort/pod3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b/abc123";
        assert_eq!(
            parse_pod_uid(path).as_deref(),
            Some("3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b")
        );
    }

    #[test]
    fn non_pod_cgroup_yields_none() {
        assert_eq!(parse_pod_uid("/system.slice/sshd.service"), None);
        assert_eq!(parse_pod_uid("/"), None);
    }

    #[test]
    fn classify_readable_pod_cgroup_is_pod() {
        let path = "/kubepods/besteffort/pod3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b/abc123";
        assert_eq!(
            classify_cgroup(Some(path)),
            PodAttribution::Pod("3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b".to_string())
        );
    }

    #[test]
    fn classify_readable_host_cgroup_is_not_a_pod() {
        // A host daemon: readable cgroup, but not a pod's — expected, not a miss.
        assert_eq!(
            classify_cgroup(Some("/system.slice/sshd.service")),
            PodAttribution::NotAPod
        );
    }

    #[test]
    fn classify_unreadable_cgroup_is_unreadable() {
        // The pid is gone / `/proc` denied us — a genuine attribution miss.
        assert_eq!(classify_cgroup(None), PodAttribution::Unreadable);
    }

    // ---- JEF-158: cgroup_id → pod_uid table (build, lookup, scan, resolve+fallback) ----

    const POD_SLICE: &str = "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/\
        kubepods-besteffort-pod3f5e1a2b_4c6d_7e8f_9a0b_1c2d3e4f5a6b.slice";
    const POD_UID: &str = "3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b";

    #[test]
    fn build_table_keeps_pod_cgroups_and_drops_host_ones() {
        let table = build_cgroup_table([
            (100, POD_SLICE.to_string()),
            (200, "/sys/fs/cgroup/system.slice/sshd.service".to_string()),
        ]);
        // The pod cgroup id resolves to its UID; the host cgroup id was never inserted.
        assert_eq!(table.lookup(100), Some(POD_UID));
        assert_eq!(table.lookup(200), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn build_table_maps_container_and_pod_ids_to_the_same_uid() {
        // The pod slice and a per-container scope under it both belong to one pod, so an
        // event stamped with either inode must resolve to the same UID.
        let scope = format!("{POD_SLICE}/cri-containerd-abc123.scope");
        let table = build_cgroup_table([(100, POD_SLICE.to_string()), (101, scope)]);
        assert_eq!(table.lookup(100), Some(POD_UID));
        assert_eq!(table.lookup(101), Some(POD_UID));
    }

    #[test]
    fn build_table_skips_zero_id() {
        // cgroup_id 0 means the kernel couldn't determine it — never a table entry, so a
        // 0-id event always falls through to the `/proc` fallback.
        let table = build_cgroup_table([(0, POD_SLICE.to_string())]);
        assert!(table.is_empty());
        assert_eq!(table.lookup(0), None);
    }

    #[test]
    fn lookup_zero_id_always_misses() {
        let table = build_cgroup_table([(100, POD_SLICE.to_string())]);
        assert_eq!(table.lookup(0), None);
    }

    #[test]
    fn scan_cgroupfs_finds_pod_cgroup_by_inode() {
        // Build a miniature cgroup tree on disk and confirm the scan pairs each pod
        // directory's real inode with its UID — the inode IS the bpf_get_current_cgroup_id
        // value, so this is the exact id an event will carry.
        let tmp = std::env::temp_dir().join(format!("jef158-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let pod_dir = tmp.join("kubepods.slice").join(format!(
            "kubepods-besteffort-pod{}.slice",
            POD_UID.replace('-', "_")
        ));
        let scope_dir = pod_dir.join("cri-containerd-abc123.scope");
        let host_dir = tmp.join("system.slice").join("sshd.service");
        std::fs::create_dir_all(&scope_dir).unwrap();
        std::fs::create_dir_all(&host_dir).unwrap();

        let pod_ino = std::fs::metadata(&pod_dir).unwrap().ino_for_test();
        let scope_ino = std::fs::metadata(&scope_dir).unwrap().ino_for_test();
        let host_ino = std::fs::metadata(&host_dir).unwrap().ino_for_test();

        let table = scan_cgroupfs(&tmp);
        assert_eq!(table.lookup(pod_ino), Some(POD_UID));
        assert_eq!(table.lookup(scope_ino), Some(POD_UID));
        assert_eq!(table.lookup(host_ino), None);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Small extension trait so the inode read in the scan test reads clearly.
    trait InoForTest {
        fn ino_for_test(&self) -> u64;
    }
    impl InoForTest for std::fs::Metadata {
        fn ino_for_test(&self) -> u64 {
            use std::os::unix::fs::MetadataExt;
            self.ino()
        }
    }

    #[test]
    fn resolve_prefers_the_table_and_never_reads_proc_on_a_hit() {
        // The hot path: a table hit attributes with NO `/proc` read — which is what lets a
        // process that has already exited still attribute (the exited-process race).
        let table = build_cgroup_table([(100, POD_SLICE.to_string())]);
        let read = |_pid: u32| -> Option<String> {
            panic!("must not read /proc on a cgroup_id table hit");
        };
        assert_eq!(
            resolve_attribution(&table, 100, 4321, read),
            PodAttribution::Pod(POD_UID.to_string())
        );
    }

    #[test]
    fn resolve_falls_back_to_proc_on_a_table_miss() {
        // A miss (host process / pod not yet scanned / id 0) falls through to the `/proc`
        // read and the existing host-vs-pod classification — unchanged.
        let table = CgroupTable::default();
        // Fallback reads a pod cgroup → Pod.
        assert_eq!(
            resolve_attribution(&table, 999, 4321, |_| Some(
                "/kubepods/besteffort/pod3f5e1a2b-4c6d-7e8f-9a0b-1c2d3e4f5a6b/abc".to_string()
            )),
            PodAttribution::Pod(POD_UID.to_string())
        );
        // Fallback reads a host cgroup → NotAPod (expected, not a miss).
        assert_eq!(
            resolve_attribution(&table, 0, 7, |_| Some(
                "/system.slice/sshd.service".to_string()
            )),
            PodAttribution::NotAPod
        );
        // Fallback can't read (pid gone) → Unreadable (a genuine miss).
        assert_eq!(
            resolve_attribution(&table, 0, 7, |_| None),
            PodAttribution::Unreadable
        );
    }
}
