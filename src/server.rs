use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use tokio::signal::ctrl_c;
use tokio::signal::unix::{SignalKind, signal};

use crate::policy::{Decision, Engine};

/// Liveness/readiness probe. The webhook is ready as soon as TLS is bound; it
/// holds no external dependencies that need warming.
async fn healthz() -> &'static str {
    "ok"
}

/// The `/validate` endpoint the API server calls. Decodes the review, runs the
/// policy engine, and replies with an allow/deny `AdmissionResponse` carrying
/// the request's UID (required for the API server to correlate the reply).
async fn validate(
    State(engine): State<Arc<Engine>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(req) => req,
        Err(err) => {
            // No request UID to echo back; reply with an invalid response so the
            // API server applies the webhook's failurePolicy rather than hanging.
            tracing::warn!(%err, "malformed AdmissionReview");
            let review: AdmissionReview<DynamicObject> =
                AdmissionResponse::invalid(err.to_string()).into_review();
            return Json(review);
        }
    };

    let response = AdmissionResponse::from(&req);
    let response = match engine.evaluate(&req).await {
        Decision::Allow => response,
        Decision::Deny { reason } => response.deny(reason),
    };
    Json(response.into_review())
}

/// Largest AdmissionReview body we'll accept on /validate. Real Pod reviews are
/// tens of KB; this caps a hostile/oversized body well below the default.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the webhook router with the policy engine as shared state.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/validate", post(validate))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(engine)
}

/// Serve the webhook over HTTPS until SIGTERM/Ctrl-C.
///
/// The API server only speaks TLS to webhooks, so the cert/key are required;
/// they're mounted from a cert-manager-issued Secret. On shutdown we give
/// in-flight admission requests a short grace period so we don't reject a write
/// mid-evaluation during a rollout.
pub async fn serve(
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    engine: Arc<Engine>,
) -> Result<()> {
    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("loading TLS cert {cert:?} / key {key:?}"))?;

    let handle = Handle::new();
    tokio::spawn(shutdown(handle.clone()));

    tracing::info!(%addr, "admission webhook listening");
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router(engine).into_make_service())
        .await
        .context("webhook server failed")
}

/// Trigger a graceful shutdown of the server on the first termination signal.
async fn shutdown(handle: Handle<SocketAddr>) {
    let ctrl_c = async {
        ctrl_c().await.expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}
