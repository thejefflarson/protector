//! Tests for the shared registry-auth resolver (JEF-339).
//!
//! The env-mutating cases rely on nextest's per-test process isolation, so each test owns a
//! clean process env; the `unsafe { set_var }` blocks mirror the pattern the rest of the
//! crate's env tests use.

use super::{docker_config_basic, registry_auth};
use sigstore::registry::Auth;

/// Write a k8s `.dockerconfigjson` with a base64 `auth` for `ghcr.io` and return its path.
/// base64("thejefflarson:ghp_token") = dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4=
fn write_ghcr_config() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "protector-auth-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{"auths":{"ghcr.io":{"auth":"dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4="}}}"#,
    )
    .unwrap();
    path
}

#[test]
fn docker_config_decodes_ghcr_auth() {
    let path = write_ghcr_config();
    let p = path.to_str().unwrap();
    assert_eq!(
        docker_config_basic(p, "ghcr.io"),
        Some(("thejefflarson".into(), "ghp_token".into()))
    );
    // A registry not present in the config yields nothing (no fabricated creds).
    assert_eq!(docker_config_basic(p, "docker.io"), None);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn docker_config_prefers_explicit_username_password() {
    let dir = std::env::temp_dir().join(format!(
        "protector-auth-explicit-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{"auths":{"ghcr.io":{"username":"bot","password":"pw","auth":"aWdub3JlZDppZ25vcmVk"}}}"#,
    )
    .unwrap();
    assert_eq!(
        docker_config_basic(path.to_str().unwrap(), "ghcr.io"),
        Some(("bot".into(), "pw".into())),
        "explicit username/password wins over the base64 auth field"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The exact production config (JEF-339): the chart sets ONLY `PROTECTOR_REGISTRY_AUTH_FILE`
/// (via `registryAuth.dockerconfigSecret: github`); username/password env are UNSET. The
/// sweep path used to ignore the auth file and fall to `Anonymous`, 401ing every private
/// image into perpetual "checking". The shared resolver must return `Basic` from the file.
#[test]
fn registry_auth_reads_auth_file_when_only_file_is_set() {
    let path = write_ghcr_config();
    // SAFETY: nextest runs each test in its own process, so this env mutation is isolated.
    unsafe {
        std::env::remove_var("PROTECTOR_REGISTRY_USERNAME");
        std::env::remove_var("PROTECTOR_REGISTRY_PASSWORD");
        std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path);
    }
    match registry_auth() {
        Auth::Basic(user, pass) => {
            assert_eq!(user, "thejefflarson");
            assert_eq!(pass, "ghp_token");
        }
        other => panic!("expected Auth::Basic from the mounted auth file, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// With no credentials of any kind, auth is Anonymous — the safe default.
#[test]
fn registry_auth_is_anonymous_without_credentials() {
    // SAFETY: nextest per-test process isolation.
    unsafe {
        std::env::remove_var("PROTECTOR_REGISTRY_USERNAME");
        std::env::remove_var("PROTECTOR_REGISTRY_PASSWORD");
        std::env::remove_var("PROTECTOR_REGISTRY_AUTH_FILE");
    }
    assert!(matches!(registry_auth(), Auth::Anonymous));
}

/// Explicit username/password env takes precedence over the auth file.
#[test]
fn registry_auth_prefers_explicit_env_over_file() {
    let path = write_ghcr_config();
    // SAFETY: nextest per-test process isolation.
    unsafe {
        std::env::set_var("PROTECTOR_REGISTRY_USERNAME", "envuser");
        std::env::set_var("PROTECTOR_REGISTRY_PASSWORD", "envpass");
        std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path);
    }
    match registry_auth() {
        Auth::Basic(user, pass) => {
            assert_eq!(user, "envuser");
            assert_eq!(pass, "envpass");
        }
        other => panic!("expected explicit env creds, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
