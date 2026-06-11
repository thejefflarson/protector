use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use protector::policies::mesh::MeshInjectionPolicy;
use protector::policies::signature::{CosignChecker, SignaturePolicy};
use protector::policy::Engine;
use protector::server;
use sigstore::registry::Auth;
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
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
        "^https://github.com/thejefflarson/",
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
    let enforce = env_or("PROTECTOR_ENFORCE", "false") == "true";
    let tuf_cache = PathBuf::from(env_or("PROTECTOR_TUF_CACHE", "/tmp/sigstore"));

    let checker = CosignChecker::new(&identity_regexp, oidc_issuer, registry_auth(), tuf_cache)
        .context("building cosign checker")?;
    let signature = SignaturePolicy::new(Arc::new(checker), gated_prefixes, enforce);

    // The policy set is fixed at startup and shared (read-only) across requests.
    let engine = Arc::new(Engine::new(vec![
        Box::new(signature),
        Box::new(MeshInjectionPolicy),
    ]));

    server::serve(addr, cert, key, engine).await
}
