use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use protector::metrics::Metrics;
use protector::policies::mesh::MeshInjectionPolicy;
use protector::policies::signature::{CosignChecker, SignaturePolicy};
use protector::policy::{EnforceScope, Engine};
use protector::server;
use sigstore::registry::Auth;
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse a numeric env var, falling back to `default` if unset or unparseable.
fn env_parse(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a comma-separated env var into a set, falling back to `default`.
fn env_set(key: &str, default: &str) -> HashSet<String> {
    env_or(key, default)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a comma-separated env var of `key=value` pairs.
fn env_pairs(key: &str) -> Vec<(String, String)> {
    env_or(key, "")
        .split(',')
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Build a policy's enforce scope from its namespaces + labels env vars. Empty
/// (the default) means audit everywhere — enforcement is strictly opt-in.
fn enforce_scope(ns_key: &str, labels_key: &str) -> EnforceScope {
    EnforceScope::new(env_set(ns_key, ""), env_pairs(labels_key))
}

/// Registry auth for pulling signatures of *private* gated images. Anonymous
/// unless both username and password are supplied (mounted from a Secret).
fn registry_auth() -> Auth {
    match (
        env::var("PROTECTOR_REGISTRY_USERNAME"),
        env::var("PROTECTOR_REGISTRY_PASSWORD"),
    ) {
        (Ok(user), Ok(pass)) => Auth::Basic(user, pass),
        _ => Auth::Anonymous,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let addr: SocketAddr = env_or("PROTECTOR_ADDR", "0.0.0.0:8443")
        .parse()
        .context("PROTECTOR_ADDR must be a host:port socket address")?;
    let cert = PathBuf::from(env_or("PROTECTOR_TLS_CERT", "/etc/protector/tls/tls.crt"));
    let key = PathBuf::from(env_or("PROTECTOR_TLS_KEY", "/etc/protector/tls/tls.key"));

    // Signature policy config. Defaults mirror the fleet-wide cosign incantation;
    // it ships in audit mode (enforce=false) so it can be observed before it can
    // reject a Pod.
    let identity_regexp = env_or(
        "PROTECTOR_IDENTITY_REGEXP",
        r"^https://github\.com/thejefflarson/",
    );
    let oidc_issuer = env_or(
        "PROTECTOR_OIDC_ISSUER",
        "https://token.actions.githubusercontent.com",
    );
    let gated_prefixes: Vec<String> = env_or("PROTECTOR_GATED_PREFIXES", "ghcr.io/thejefflarson/")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let tuf_cache = PathBuf::from(env_or("PROTECTOR_TUF_CACHE", "/tmp/sigstore"));
    let verify_timeout = Duration::from_secs(env_parse("PROTECTOR_VERIFY_TIMEOUT", 5));
    let cache_ttl = Duration::from_secs(env_parse("PROTECTOR_CACHE_TTL", 300));
    let max_images = env_parse("PROTECTOR_MAX_IMAGES", 32) as usize;

    // Enforcement is opt-in per policy, by namespace and/or pod label. An empty
    // scope (the default) audits everywhere — violations are logged + metered but
    // never block. Add namespaces/labels to start blocking, one slice at a time.
    let signature_enforce =
        enforce_scope("PROTECTOR_ENFORCE_NAMESPACES", "PROTECTOR_ENFORCE_LABELS");
    let mesh_enforce = enforce_scope(
        "PROTECTOR_MESH_ENFORCE_NAMESPACES",
        "PROTECTOR_MESH_ENFORCE_LABELS",
    );
    tracing::info!(
        signature = %signature_enforce.describe(),
        mesh = %mesh_enforce.describe(),
        "policy enforcement scopes"
    );

    let checker = CosignChecker::new(
        &identity_regexp,
        oidc_issuer,
        registry_auth(),
        tuf_cache,
        verify_timeout,
    )
    .context("building cosign checker")?;
    let signature = SignaturePolicy::new(
        Arc::new(checker),
        gated_prefixes,
        signature_enforce,
        max_images,
        cache_ttl,
    );

    let mesh = MeshInjectionPolicy::new(mesh_enforce);

    // Metrics are shared between the engine (which records violations) and the
    // server's /metrics scrape endpoint.
    let metrics = Arc::new(Metrics::new());

    // The policy set is fixed at startup and shared (read-only) across requests.
    let engine = Arc::new(Engine::new(
        vec![Box::new(signature), Box::new(mesh)],
        metrics.clone(),
    ));

    server::serve(addr, cert, key, engine, metrics).await
}
