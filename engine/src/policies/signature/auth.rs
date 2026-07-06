//! The single registry-auth resolver every cosign fetch path shares.
//!
//! Signatures of *private* images inherit the (private) repository's visibility, so the verifier
//! must fetch their manifests with the SAME credentials the kubelet pulls with — otherwise the
//! manifest fetch 401s ("Not authorized") and verification errors out. Both the admission webhook
//! and the engine's running-Pod signing sweep resolve auth here, so the two can never drift
//! (JEF-339): before this was unified, the sweep authenticated as `Anonymous` and every private
//! image sat in perpetual "checking".
//!
//! Auth is resolved **per image** from the WHOLE mounted dockerconfigjson `auths` map, not one
//! hardcoded registry (JEF-352). Before this, only `ghcr.io` authenticated — a private image on
//! any other registry (Docker Hub, a private `host:port`) 401ed into perpetual "checking". The
//! parsed config is loaded ONCE at construction ([`RegistryAuth::from_env`]); [`for_image`] then
//! extracts the image's registry host and looks up its creds.
//!
//! Resolution precedence, per image:
//!   1. explicit `PROTECTOR_REGISTRY_USERNAME`/`PROTECTOR_REGISTRY_PASSWORD` — a GLOBAL override
//!      applied to ANY registry when both are set;
//!   2. a matching entry in the mounted `PROTECTOR_REGISTRY_AUTH_FILE` dockerconfigjson for the
//!      image's registry host;
//!   3. else `Anonymous`.
//!
//! Anonymous is the safe per-image default: an unauthorized private image simply observes as
//! `checking`/`not-signed`, never a fabricated clean.
//!
//! [`for_image`]: RegistryAuth::for_image

use std::collections::HashMap;
use std::env;

use sigstore::registry::Auth;

/// The canonical lookup key every Docker Hub host variant folds to. Docker Hub is referenced
/// under several names — bare shorthand (`redis`), `docker.io`, `index.docker.io`,
/// `registry-1.docker.io`, and the legacy dockerconfig key `https://index.docker.io/v1/` — all
/// of which a container runtime resolves to the same registry, so they must share one creds entry.
const DOCKER_IO_KEY: &str = "docker.io";

/// The shared per-image registry-auth resolver (JEF-339, JEF-352). Built ONCE from the process
/// environment; `for_image` computes `Auth` for each image without re-reading any file.
///
/// Deliberately NOT `Debug`/`Clone`: it holds plaintext registry credentials, so a derived `Debug`
/// would be a credential-leak footgun. `Default` (an empty resolver ⇒ Anonymous everywhere) exists
/// only for tests that build a checker without any creds.
#[derive(Default)]
pub struct RegistryAuth {
    /// The explicit env override (`PROTECTOR_REGISTRY_USERNAME`/`PROTECTOR_REGISTRY_PASSWORD`),
    /// applied to any registry when set — precedence 1.
    env_override: Option<(String, String)>,
    /// registry host key → `(username, password)`, parsed once from the mounted dockerconfigjson.
    /// Keyed by the canonical registry host (see [`canonical_registry_key`]) — precedence 2.
    entries: HashMap<String, (String, String)>,
}

impl RegistryAuth {
    /// Build the resolver from the process environment, reading and parsing the whole mounted
    /// dockerconfigjson `auths` map ONCE. Never fails: a missing/unreadable/unparseable auth file
    /// yields an empty entry map (so every image resolves to `Anonymous` unless the env override is
    /// set) — the safe default, never a hard error at startup.
    pub fn from_env() -> Self {
        let env_override = match (
            env::var("PROTECTOR_REGISTRY_USERNAME"),
            env::var("PROTECTOR_REGISTRY_PASSWORD"),
        ) {
            (Ok(user), Ok(pass)) => Some((user, pass)),
            _ => None,
        };
        let entries = env::var("PROTECTOR_REGISTRY_AUTH_FILE")
            .ok()
            .map(|path| parse_docker_config(&path))
            .unwrap_or_default();
        Self {
            env_override,
            entries,
        }
    }

    /// Registry auth for pulling `image`'s signatures. Precedence: explicit env override (any
    /// registry) > a matching dockerconfig entry for the image's registry host > `Anonymous`
    /// (the safe per-image default). The env override intentionally wins over the file so an
    /// operator can force creds without editing the mounted secret.
    pub fn for_image(&self, image: &str) -> Auth {
        if let Some((user, pass)) = &self.env_override {
            return Auth::Basic(user.clone(), pass.clone());
        }
        match self.entries.get(&image_registry_key(image)) {
            Some((user, pass)) => Auth::Basic(user.clone(), pass.clone()),
            None => Auth::Anonymous,
        }
    }
}

/// Parse the whole dockerconfigjson `auths` map into a `host key → (user, pass)` table. Each entry
/// prefers explicit `username`/`password`, else decodes the base64 `auth` field (`user:token`).
/// Entries that carry neither (e.g. a `credHelpers`/`credsStore`-only entry — out of scope, since
/// k8s `.dockerconfigjson` inlines `auth`) are skipped rather than fabricated. A read/parse failure
/// yields an empty map (Anonymous per image), never an error.
fn parse_docker_config(path: &str) -> HashMap<String, (String, String)> {
    parse_docker_config_inner(path).unwrap_or_default()
}

fn parse_docker_config_inner(path: &str) -> Option<HashMap<String, (String, String)>> {
    let data = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let auths = json.get("auths")?.as_object()?;
    let mut map = HashMap::with_capacity(auths.len());
    for (key, entry) in auths {
        if let Some(creds) = entry_creds(entry) {
            map.insert(canonical_registry_key(key), creds);
        }
    }
    Some(map)
}

/// Extract `(username, password)` from one dockerconfig `auths` entry: prefer explicit
/// `username`/`password`, else decode the base64 `auth` field (`user:token`). `None` if the entry
/// carries no usable credential.
fn entry_creds(entry: &serde_json::Value) -> Option<(String, String)> {
    use base64::Engine as _;
    if let (Some(user), Some(pass)) = (
        entry.get("username").and_then(|v| v.as_str()),
        entry.get("password").and_then(|v| v.as_str()),
    ) {
        return Some((user.to_string(), pass.to_string()));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(entry.get("auth")?.as_str()?)
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (user, pass) = pair.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// The canonical registry-host lookup key for a dockerconfig `auths` key. Docker config keys come
/// in several shapes — a bare host (`ghcr.io`), a `host:port` (`myreg.example:5000`), or a full
/// URL (`https://index.docker.io/v1/`) — so we strip any scheme, take the `host[:port]` up to the
/// first `/`, lowercase it, and fold every Docker Hub variant to [`DOCKER_IO_KEY`].
fn canonical_registry_key(raw: &str) -> String {
    // Strip a leading scheme (`https://`, `http://`, …); the host is whatever follows `://`.
    let no_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    // The host[:port] is everything up to the first path separator.
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    let host = host.to_ascii_lowercase();
    if is_docker_io_host(&host) {
        DOCKER_IO_KEY.to_string()
    } else {
        host
    }
}

/// The canonical registry-host lookup key for an IMAGE reference — the same key space as
/// [`canonical_registry_key`], so an image resolves against the config it was parsed into. A ref
/// with no host segment (a bare Docker Hub shorthand like `redis:16` or `library/redis`) folds to
/// [`DOCKER_IO_KEY`], matching how a container runtime resolves it.
fn image_registry_key(image: &str) -> String {
    match image.split_once('/') {
        // A registry host has a dot (domain), a colon (port), or is `localhost`; a leading path
        // segment without any of those is a Docker Hub repo (`library/redis`), not a host.
        Some((host, _)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            canonical_registry_key(host)
        }
        _ => DOCKER_IO_KEY.to_string(),
    }
}

/// Whether `host` (already lowercased, scheme/path stripped) is one of Docker Hub's interchangeable
/// registry names. All fold to [`DOCKER_IO_KEY`].
fn is_docker_io_host(host: &str) -> bool {
    matches!(
        host,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    )
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
