//! On-host credential-path classification policy (JEF-320, Retire-Falco G3).
//!
//! The agent's `SecretRead` (via `security_file_open`) started out scoped to the tmpfs
//! superblock — the k8s Secret/ConfigMap/projected-volume mount point — so a read of a
//! **host-filesystem** credential file (the host shadow file, a user's SSH private-key
//! directory, a cloud-provider credential file) produced no CredentialAccess
//! corroboration, even though it lives on the container's ordinary rootfs and Falco's
//! "Read sensitive file untrusted" / "Read ssh information" rules fire on exactly this.
//! This module is the engine-side classifier that closes that gap.
//!
//! Authoritative source for the path list: the F0 Falco-parity audit
//! (`docs/falco-parity-audit.md` §3 Class E / §7-8 G3; removed from the tree in the F8
//! retirement commit but preserved in history — `git show a2c7620:docs/falco-parity-audit.md`,
//! landed in PR #169) plus the well-known on-disk conventions for the AWS/GCP/Azure CLIs.
//!
//! ENGINE-SIDE policy, not wire data (JEF-113, mirroring `exec_class`): the shared
//! [`crate::engine::graph::Behavior`] type stays pure — the agent emits a
//! `FileRead { path }` for a file it can't classify itself, unchanged wire shape. The
//! probe was minimally widened (JEF-320) to also emit a `FileRead` for a small, fixed
//! allowlist of on-host credential-file BASENAMES outside tmpfs (a cheap in-kernel volume
//! gate — see `is_sensitive_credential_basename` in
//! `agent/protector-agent-ebpf/src/main.rs` — NOT the security decision). This module makes
//! the actual "is this path a known on-host credential path" call, from the full path
//! alone, exactly like `adapter::enrich::secret_for_path` does for k8s Secret mounts.
//!
//! **Security rework (JEF-320 follow-up, four fixes from a HELD security review):**
//! 1. `/etc/passwd` and `~/.ssh/known_hosts` are dropped from the allowlist — both are
//!    world-readable / hold no secret material (`passwd` has no password hashes since
//!    shadow passwords; `known_hosts` holds OTHER hosts' PUBLIC keys), and both are read
//!    constantly by benign processes (`id`, `ls -l`, NSS, PAM, any SSH client). Matching
//!    them produced a standing false CredentialAccess corroboration on ~every workload.
//!    Falco itself fires on `shadow`, never `passwd`, for exactly this reason. `gshadow`
//!    (the group-password shadow file) and `sudoers` (root-equivalent grant list) are
//!    added — both hold or gate genuine credential material.
//! 2. The `.ssh` match is now ANCHORED: a matched path must be a non-empty file directly
//!    under a REAL home root (`/root/.ssh/<file>` or `/home/<user>/.ssh/<file>`), not a
//!    `.ssh` segment at any depth (which let a world-writable `/tmp/.../.ssh/…` or
//!    `/dev/shm/.../.ssh/…` path forge an SSH-key corroboration) and not the bare `.ssh`
//!    directory itself (a directory open, not a key read).
//! 3. The untrusted path is lexically NORMALIZED first (`.`/`..`/`//` collapsed via
//!    [`std::path::Path::components`], never `std::fs::canonicalize` — that would touch
//!    the ENGINE HOST's disk, violating zero-egress) before every check, closing a
//!    path-traversal gap that could both forge a match (an unrelated basename reached via
//!    a `..` that walks back out of a matched segment) and evade one (a dot/double-slash
//!    variant of an exact path like `/etc/./shadow` or `/etc//shadow`).
//!
//! (The fourth fix — foothold-gating the resulting `SecretReadSource::HostPath`
//! corroboration — lives in `engine::reason::proof::corroborate`, not here.)
//!
//! **FP-scoping (container/entry context only):** every `RuntimeSignal` that reaches a
//! Workload node in `RuntimeAdapter::contribute` is already attributed to a *Pod* — a
//! genuine host-system daemon (e.g. the node's real `sshd`, running outside any container
//! cgroup) has neither a resolvable `ByPodUid` nor a `ByNamespacedName` attribution, so its
//! events are dropped upstream (`unresolved`) before this classifier ever runs. That gives
//! "scope to container/entry context" for free from the existing attribution mechanism — no
//! extra check needed here. What this does NOT filter out: a *legitimate* in-container auth
//! process (e.g. a bastion/jump pod's own `sshd` reading its own `/etc/shadow` for PAM, or
//! its own `authorized_keys`) still matches. That residual false-positive is accepted
//! deliberately: this signal is CORROBORATION ONLY (`corroborates()` only ever sets
//! `corroborated`, never actuates — shadow-only, ADR-0014), it is combined with the model's
//! own reasoning and every other piece of evidence on the chain, and (post security-rework)
//! it is additionally gated to a proven internet-facing foothold entry
//! (`engine::reason::proof::corroborate::host_credential_read_on_foothold`) rather than
//! corroborating context-free on any workload.

/// Absolute on-host paths matched **exactly** (against the NORMALIZED form of the observed
/// path — see [`host_credential_path`]) — the host shadow/gshadow/sudoers files (F0 §3
/// Class E1, "Read sensitive file untrusted": `/etc/shadow` et al.). Deliberately a short,
/// exact list (not a directory-prefix match on all of `/etc`) so an unrelated `/etc/*`
/// config read never false-positives.
///
/// `/etc/passwd` is deliberately NOT here: it is world-readable and holds no secret
/// material (password hashes live in `/etc/shadow`), and is read constantly by benign
/// processes (`id`, `ls -l`, NSS, PAM) — including it produced a standing false
/// CredentialAccess corroboration on ~every workload (HIGH finding, security rework).
/// Falco's own rule set matches `shadow`, never `passwd`, for the same reason.
const EXACT_HOST_PATHS: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];

/// The path SEGMENT (not substring) that marks a per-user SSH directory (F0 §3 Class E1,
/// "Read ssh information"). See [`ssh_key_material_path`] for the ANCHORED match this
/// segment feeds — a bare segment-anywhere match was a security finding (security rework):
/// it let a `.ssh` directory under an attacker-writable temp/shm path forge a match.
const SSH_DIR_SEGMENT: &str = ".ssh";

/// The one basename under a `.ssh` directory that is deliberately EXCLUDED from a match:
/// `known_hosts` holds the PUBLIC keys of remote hosts the user has connected to — no
/// secret material — and is rewritten by an ordinary SSH client on every new connection.
/// Matching it (security rework finding 1) produced routine false CredentialAccess
/// corroborations indistinguishable from an actual private-key read.
const SSH_NON_CREDENTIAL_BASENAME: &str = "known_hosts";

/// Cloud-provider credential files for the major providers (AWS/GCP/Azure), each paired
/// with the provider's conventional config-directory SEGMENT so a same-named file in an
/// unrelated directory (e.g. some app's own `credentials` file) does not match. `file`
/// must be the exact basename; `dir_segment` must appear as a whole path segment (of the
/// NORMALIZED path — see [`host_credential_path`]).
const CLOUD_CREDENTIAL_FILES: &[(&str, &str)] = &[
    // AWS CLI / SDKs: ~/.aws/credentials.
    (".aws", "credentials"),
    // gcloud CLI application-default credentials and the legacy credentials DB.
    ("gcloud", "application_default_credentials.json"),
    ("gcloud", "credentials.db"),
    // Azure CLI: ~/.azure/{azureProfile.json,accessTokens.json,msal_token_cache.json}.
    (".azure", "azureProfile.json"),
    (".azure", "accessTokens.json"),
    (".azure", "msal_token_cache.json"),
];

/// Lexically normalize `path` into its `/`-separated NON-EMPTY components, collapsing
/// `.`/`..`/duplicate-`/` forms via [`std::path::Path::components`] — WITHOUT touching disk
/// (deliberately NOT `std::fs::canonicalize`, which would read the **engine host's** own
/// filesystem and resolve symlinks there, violating zero-egress: the path under
/// classification describes a file on a remote workload's rootfs, not anything that exists
/// on this host).
///
/// This closes a path-traversal finding (security rework): matching the raw, unnormalized
/// path let a crafted path both FORGE a match (e.g. `/tmp/.aws/../credentials` textually
/// contains the `.aws` segment and the `credentials` basename, but lexically resolves to
/// `/tmp/credentials` — nowhere near `.aws`) and EVADE one (e.g. `/etc/./shadow` or
/// `/etc//shadow` resolve to the real `/etc/shadow` but never matched the exact-string
/// list). Every check below runs against this normalized form.
fn normalized_components(path: &str) -> Vec<&str> {
    use std::path::{Component, Path};
    let mut out: Vec<&str> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(segment) => {
                out.push(segment.to_str().expect("path is valid UTF-8 str"));
            }
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Whether the normalized path `components` is a non-empty FILE directly under a real
/// home directory's `.ssh` — `/root/.ssh/<file>` or `/home/<user>/.ssh/<file>` — the
/// ANCHORED form of F0's "Read ssh information" rule (security rework finding 2).
///
/// Anchoring to a real home root (rather than a `.ssh` segment at any depth) means a
/// `.ssh` directory nested under an attacker-writable path — a world-writable temp or
/// `/dev/shm` directory, or any other non-home location — does NOT match: such a path can
/// be planted by an unprivileged attacker precisely to forge this corroboration, so it
/// carries none of the "this is really a user's SSH key material" signal a home-rooted
/// `.ssh` does. Requiring a non-empty component AFTER `.ssh` means a read/open of the
/// `.ssh` directory itself — not a file inside it — does not match either. `known_hosts`
/// directly under `.ssh` is excluded (finding 1: no secret material).
fn ssh_key_material_path(components: &[&str]) -> bool {
    let rest = match components {
        [root, seg, rest @ ..] if *root == "root" && *seg == SSH_DIR_SEGMENT => rest,
        [home, _user, seg, rest @ ..] if *home == "home" && *seg == SSH_DIR_SEGMENT => rest,
        _ => return false,
    };
    !rest.is_empty() && rest != [SSH_NON_CREDENTIAL_BASENAME]
}

/// Whether the normalized path `components` end in a known cloud-provider credential
/// basename AND contain that provider's config-directory segment somewhere earlier in the
/// (normalized) path — see [`CLOUD_CREDENTIAL_FILES`].
fn cloud_credential_path(components: &[&str]) -> bool {
    let Some(&name) = components.last() else {
        return false;
    };
    CLOUD_CREDENTIAL_FILES
        .iter()
        .any(|&(dir, file)| file == name && components.contains(&dir))
}

/// Classify `path` (a container-relative path the agent observed, from a `FileRead`) as a
/// well-known **on-host** sensitive credential path (JEF-320). Returns the NORMALIZED path
/// (see [`normalized_components`]) — used as the [`crate::engine::graph::Behavior::SecretRead`]
/// `secret` identifier (mirrors how a k8s-mounted secret is named by
/// `adapter::enrich::secret_for_path`) — or `None` for anything else, including deliberate
/// near-misses: a look-alike basename outside its expected directory, a backup/rotated file
/// (`shadow.bak`), a directory read of `.ssh` itself rather than a file inside it, or a
/// `.ssh` outside a real home root.
pub fn host_credential_path(path: &str) -> Option<String> {
    let components = normalized_components(path);
    let normalized = format!("/{}", components.join("/"));

    let is_credential = EXACT_HOST_PATHS.contains(&normalized.as_str())
        || ssh_key_material_path(&components)
        || cloud_credential_path(&components);
    is_credential.then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_shadow_gshadow_sudoers_match_exactly() {
        for path in EXACT_HOST_PATHS {
            assert_eq!(
                host_credential_path(path),
                Some((*path).to_string()),
                "{path}"
            );
        }
    }

    #[test]
    fn host_shadow_near_misses_do_not_match() {
        // A backup/rotated copy, a different directory, and a substring look-alike must
        // all stay unclassified — this is an exact-path list, not a prefix match.
        let near_misses = [
            "/etc/shadow.bak",
            "/etc/shadow-",
            "/mnt/host/etc/shadow", // a bind-mounted copy at a different absolute path
            "/etc/shadowdir/x",
            "/app/etc/passwd",
            "/etc/passwd.orig",
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn passwd_no_longer_matches() {
        // HIGH finding (security rework): world-readable, no secret material, read
        // constantly by benign processes (id / ls -l / NSS / PAM) — must NOT corroborate.
        assert_eq!(host_credential_path("/etc/passwd"), None);
    }

    #[test]
    fn known_hosts_no_longer_matches() {
        // Finding 1 (security rework): other hosts' PUBLIC keys, no secret material, and
        // rewritten by any ordinary SSH client — must NOT corroborate, unlike a real key.
        assert_eq!(host_credential_path("/root/.ssh/known_hosts"), None);
        assert_eq!(host_credential_path("/home/app/.ssh/known_hosts"), None);
    }

    #[test]
    fn ssh_key_material_matches_a_file_under_a_real_home_dot_ssh() {
        let matches = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_ed25519",
            "/home/app/.ssh/authorized_keys",
        ];
        for path in matches {
            assert_eq!(host_credential_path(path), Some(path.to_string()), "{path}");
        }
    }

    #[test]
    fn ssh_anchored_match_rejects_a_temp_or_shm_dot_ssh_path() {
        // MEDIUM finding (security rework): an attacker-writable temp/shm `.ssh` directory
        // must NOT forge an SSH-key corroboration — only a REAL home root anchors a match.
        let near_misses = [
            "/tmp/.ssh/id_rsa",
            "/dev/shm/.ssh/id_rsa",
            "/tmp/fake/.ssh/id_rsa",
            "/var/lib/jenkins/.ssh/id_rsa.pub", // not /root or /home/<user>
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn ssh_anchored_match_rejects_the_bare_dot_ssh_directory() {
        // MEDIUM finding (security rework): the `.ssh` directory ITSELF (no file
        // component beneath it) must NOT match — only a file inside it does.
        assert_eq!(host_credential_path("/root/.ssh"), None);
        assert_eq!(host_credential_path("/home/app/.ssh"), None);
        assert_eq!(host_credential_path("/root/.ssh/"), None);
    }

    #[test]
    fn ssh_look_alikes_do_not_match() {
        // A `.ssh`-PREFIXED name is a different, unrelated file/dir — substring
        // containment must never fire.
        let near_misses = [
            "/home/app/.sshrc",
            "/home/app/.ssh-backup/id_rsa",
            "/home/app/sshconfig",
            "/home/app/ssh/id_rsa", // "ssh", not ".ssh"
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn cloud_credential_files_match_under_their_provider_directory() {
        let matches = [
            "/root/.aws/credentials",
            "/home/app/.aws/credentials",
            "/root/.config/gcloud/application_default_credentials.json",
            "/root/.config/gcloud/credentials.db",
            "/home/app/.azure/azureProfile.json",
            "/home/app/.azure/accessTokens.json",
            "/home/app/.azure/msal_token_cache.json",
        ];
        for path in matches {
            assert_eq!(host_credential_path(path), Some(path.to_string()), "{path}");
        }
    }

    #[test]
    fn cloud_credential_look_alikes_do_not_match() {
        // The right basename in the WRONG directory, and the right directory with a
        // benign file, must both stay unclassified — the pairing is required, not either
        // half alone.
        let near_misses = [
            "/app/credentials",  // "credentials" but no .aws segment
            "/root/.aws/config", // .aws segment but not the credentials file
            "/root/.aws/credentials.bak",
            "/root/.config/gcloud/logs/credentials.db.old",
            "/home/app/.azure/clouds.config", // .azure segment, unrelated file
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn ordinary_application_paths_never_match() {
        // The general "don't false-positive on normal app I/O" sanity sweep.
        let benign = [
            "/app/config.yaml",
            "/app/data/users.db",
            "/var/log/app.log",
            "/tmp/scratch",
            "/usr/lib/libssl.so.3",
            "/etc/resolv.conf",
            "/etc/hosts",
        ];
        for path in benign {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn dot_and_double_slash_variants_of_shadow_still_match_normalized() {
        // MEDIUM finding (security rework), the EVADE case: `.`/`..`/`//` noise in the
        // observed path must not let a real `/etc/shadow` read slip past an exact-string
        // check — normalization must resolve it to the canonical form first.
        assert_eq!(
            host_credential_path("/etc/./shadow"),
            Some("/etc/shadow".to_string())
        );
        assert_eq!(
            host_credential_path("/etc//shadow"),
            Some("/etc/shadow".to_string())
        );
        assert_eq!(
            host_credential_path("/etc/foo/../shadow"),
            Some("/etc/shadow".to_string())
        );
    }

    #[test]
    fn traversal_past_a_matched_segment_does_not_forge_a_cloud_credential_match() {
        // MEDIUM finding (security rework), the FORGE case: a path that textually
        // contains a matched dir segment (`.aws`) and a matched basename
        // (`credentials`), but whose `..` walks back OUT of that directory before
        // reaching the file, must NOT match — it never actually reads through `.aws`.
        assert_eq!(host_credential_path("/tmp/.aws/../credentials"), None);
        assert_eq!(
            host_credential_path("/root/.aws/subdir/../../credentials"),
            None
        );
    }

    #[test]
    fn traversal_past_a_matched_ssh_segment_does_not_forge_a_match() {
        // The same FORGE shape against the anchored `.ssh` rule: `..` walks back out of
        // `/root/.ssh` before reaching a sibling file, so it must not match either.
        assert_eq!(host_credential_path("/root/.ssh/../id_rsa"), None);
    }
}
