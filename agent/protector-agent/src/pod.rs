//! cgroup → pod UID attribution.
//!
//! An eBPF event carries a kernel identity (pid), not a pod. The agent reads the
//! process's cgroup and extracts the pod UID; the **engine** maps that UID to a
//! namespace/pod from its pod watch (so the agent needs no cluster credentials,
//! ADR-0014). A cgroup that isn't a pod's (a host process) yields `None` and the
//! event is dropped — a missing signal beats a mis-attributed one.

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
}
