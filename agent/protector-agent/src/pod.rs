//! cgroup → pod attribution.
//!
//! An eBPF event carries a kernel identity (pid / cgroup id), not a pod. The agent
//! resolves it: the kernel cgroup path encodes the pod UID, and a [`PodResolver`]
//! maps that UID to its namespace/name. Mis-resolution **drops** the signal rather
//! than mislabeling it — a wrong attribution is worse than a missing one (ADR-0014).

use std::collections::HashMap;

/// A resolved pod identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRef {
    pub namespace: String,
    pub name: String,
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

/// Resolves a pod UID to its namespace/name. The node deployment populates this from
/// the kubelet's read-only pod list (`/pods`), refreshed periodically; the agent never
/// calls the cluster API server (it has no kube credentials — see ADR-0014's scoping).
#[derive(Default)]
pub struct PodResolver {
    by_uid: HashMap<String, PodRef>,
}

impl PodResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the UID→pod map (called after each kubelet `/pods` refresh).
    pub fn replace(&mut self, mapping: HashMap<String, PodRef>) {
        self.by_uid = mapping;
    }

    pub fn resolve(&self, uid: &str) -> Option<&PodRef> {
        self.by_uid.get(uid)
    }
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
    fn resolver_maps_uid_to_pod() {
        let mut r = PodResolver::new();
        r.replace(HashMap::from([(
            "uid-1".to_string(),
            PodRef {
                namespace: "app".into(),
                name: "web".into(),
            },
        )]));
        assert_eq!(r.resolve("uid-1").unwrap().name, "web");
        assert!(r.resolve("missing").is_none());
    }
}
