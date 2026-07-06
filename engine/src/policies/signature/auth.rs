//! The single registry-auth resolver every cosign fetch path shares.
//!
//! Signatures of *private* first-party images inherit the (private) package's visibility, so
//! the verifier must fetch their manifests with the SAME credentials the kubelet pulls with —
//! otherwise the manifest fetch 401s ("Not authorized") and verification errors out. Both the
//! admission webhook and the engine's running-Pod signing sweep resolve auth here, so the two
//! can never drift (JEF-339): before this was unified, the sweep authenticated as `Anonymous`
//! and every private image sat in perpetual "checking".
//!
//! Resolution order: explicit `PROTECTOR_REGISTRY_USERNAME`/`PROTECTOR_REGISTRY_PASSWORD`, then
//! the mounted `PROTECTOR_REGISTRY_AUTH_FILE` dockerconfigjson (the cluster's `github` pull
//! secret), else `Anonymous`. Anonymous is the safe default: an unauthorized private image
//! simply observes as `checking`/`not-signed`, never a fabricated clean.

use std::env;

use sigstore::registry::Auth;

/// The registry the mounted dockerconfigjson is expected to carry first-party creds for.
const GHCR: &str = "ghcr.io";

/// Registry auth for pulling signatures of *private* gated images. Anonymous unless
/// credentials are supplied — either explicit username/password env, or a mounted
/// dockerconfigjson (the cluster's `github` pull secret, `PROTECTOR_REGISTRY_AUTH_FILE`).
pub fn registry_auth() -> Auth {
    if let (Ok(user), Ok(pass)) = (
        env::var("PROTECTOR_REGISTRY_USERNAME"),
        env::var("PROTECTOR_REGISTRY_PASSWORD"),
    ) {
        return Auth::Basic(user, pass);
    }
    // Reuse the mounted dockerconfigjson's ghcr creds. Signatures inherit the (private)
    // package's visibility, so the verifier needs the same creds the kubelet pulls with —
    // without this, manifest fetches of private first-party images 401 ("Not authorized")
    // and verification errors out.
    if let Ok(path) = env::var("PROTECTOR_REGISTRY_AUTH_FILE")
        && let Some((user, pass)) = docker_config_basic(&path, GHCR)
    {
        return Auth::Basic(user, pass);
    }
    Auth::Anonymous
}

/// Extract `(username, password)` for `registry` from a Docker `config.json`
/// (k8s `.dockerconfigjson`): prefer explicit username/password, else decode the
/// base64 `auth` field (`user:token`). `None` if absent/unparseable.
pub(crate) fn docker_config_basic(path: &str, registry: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let data = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let entry = json.get("auths")?.get(registry)?;
    if let (Some(u), Some(p)) = (
        entry.get("username").and_then(|v| v.as_str()),
        entry.get("password").and_then(|v| v.as_str()),
    ) {
        return Some((u.to_string(), p.to_string()));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(entry.get("auth")?.as_str()?)
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (user, pass) = pair.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
