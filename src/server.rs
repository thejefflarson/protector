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

use crate::metrics::Metrics;
use crate::policy::{Decision, Engine};

/// Shared, cheaply-cloneable handler state.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub metrics: Arc<Metrics>,
}

/// Liveness/readiness probe. The webhook is ready as soon as TLS is bound; it
/// holds no external dependencies that need warming.
async fn healthz() -> &'static str {
    "ok"
}

/// Prometheus scrape endpoint. Exposes the policy-violation counters, which are
/// the discovery signal for "what would enforcement reject".
async fn metrics_handler(State(state): State<AppState>) -> String {
    state.metrics.render()
}

/// The `/validate` endpoint the API server calls. Decodes the review, runs the
/// policy engine, and replies with an allow/deny `AdmissionResponse` carrying
/// the request's UID (required for the API server to correlate the reply).
async fn validate(
    State(state): State<AppState>,
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
    // The engine records audit/deny outcomes itself; here we only map the final
    // verdict. An Audit outcome never reaches here (the engine resolves it to
    // Allow), but treat it as allow defensively.
    let response = match state.engine.evaluate(&req).await {
        Decision::Deny { reason } => response.deny(reason),
        Decision::Allow | Decision::Audit { .. } => response,
    };
    Json(response.into_review())
}

/// Largest AdmissionReview body we'll accept on /validate. Real Pod reviews are
/// tens of KB; this caps a hostile/oversized body well below the default.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the webhook router with the engine + metrics as shared state.
pub fn router(engine: Arc<Engine>, metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .route("/validate", post(validate))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(AppState { engine, metrics })
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
    metrics: Arc<Metrics>,
) -> Result<()> {
    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("loading TLS cert {cert:?} / key {key:?}"))?;

    let handle = Handle::new();
    tokio::spawn(shutdown(handle.clone()));

    tracing::info!(%addr, "admission webhook listening");
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router(engine, metrics).into_make_service())
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
