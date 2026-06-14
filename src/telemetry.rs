//! OpenTelemetry wiring: export traces + metrics over OTLP to the node-local
//! collector, the same way the cluster's other services do (they set
//! `OTEL_EXPORTER_OTLP_ENDPOINT` to `agent-collector.metrics:4318`). Off by default:
//! with no endpoint set we install only the stdout `fmt` log subscriber, so local
//! runs and tests are unchanged and pull in no collector.
//!
//! Tracing spans/events flow through the `tracing-opentelemetry` bridge to the OTLP
//! span exporter; engine metrics are recorded against the global meter (see
//! [`crate::engine`]). When the endpoint is unset the global meter is a no-op, so the
//! engine's `metrics.*.add(...)` calls cost nothing.

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{MetricExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

/// Holds the providers so they can be flushed + shut down on exit (a batch span
/// processor and periodic metric reader buffer in the background; dropping without
/// shutdown loses the last window). `None` fields when OTLP export is off.
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Telemetry {
    /// Flush and stop the exporters. Best-effort: errors are logged, not propagated,
    /// since this runs on shutdown.
    pub fn shutdown(self) {
        if let Some(p) = self.tracer_provider
            && let Err(error) = p.shutdown()
        {
            tracing::warn!(%error, "otel tracer shutdown");
        }
        if let Some(p) = self.meter_provider
            && let Err(error) = p.shutdown()
        {
            tracing::warn!(%error, "otel meter shutdown");
        }
    }
}

/// Initialise logging and (when `OTEL_EXPORTER_OTLP_ENDPOINT` is set) OTLP export of
/// traces + metrics, tagged `service.name=<service>`. Installs the global subscriber;
/// call once at startup. Returns a [`Telemetry`] guard to shut down on exit.
pub fn init(service: &str, version: &str) -> Telemetry {
    let filter = EnvFilter::from_default_env();
    let fmt_layer = fmt::layer();

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|e| !e.is_empty());

    let Some(endpoint) = endpoint else {
        // No collector configured — stdout logs only (local/test default).
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .init();
        return Telemetry {
            tracer_provider: None,
            meter_provider: None,
        };
    };

    let resource = Resource::builder()
        .with_service_name(service.to_string())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            version.to_string(),
        ))
        .build();

    // Traces → OTLP/HTTP (protobuf). The collector listens on 4318 for HTTP.
    let span_exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint)
        .with_protocol(Protocol::HttpBinary)
        .build()
        .expect("building OTLP span exporter");
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();

    // Metrics → OTLP/HTTP, pushed on a periodic reader.
    let metric_exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(&endpoint)
        .with_protocol(Protocol::HttpBinary)
        .build()
        .expect("building OTLP metric exporter");
    let reader = PeriodicReader::builder(metric_exporter)
        .with_interval(Duration::from_secs(30))
        .build();
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    let tracer = tracer_provider.tracer(service.to_string());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    tracing::info!(%endpoint, "OTLP export enabled (traces + metrics)");
    Telemetry {
        tracer_provider: Some(tracer_provider),
        meter_provider: Some(meter_provider),
    }
}
