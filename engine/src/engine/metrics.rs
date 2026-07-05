//! The engine's OTLP instruments (extracted from `mod.rs` to keep it under the 1,000-line cap,
//! CLAUDE.md). A cohesive unit: the counters/gauges/histograms the engine records against the
//! global meter, and their one-shot construction. `pub(super)` so the engine core reads the fields.

/// OTLP instruments for the engine, recorded against the global meter (see
/// [`crate::telemetry`]). When no OTLP endpoint is configured the global meter is a
/// no-op, so these calls cost nothing — the engine is instrumented unconditionally.
/// Counters are cumulative; gauges hold the last pass's snapshot.
pub(super) struct EngineMetrics {
    /// Process passes (one per observed change).
    pub(super) passes: opentelemetry::metrics::Counter<u64>,
    /// Adjudicator model invocations, by `result` (`ok`/`unavailable`).
    pub(super) model_calls: opentelemetry::metrics::Counter<u64>,
    /// Mitigations actuated, by `action` (`applied`/`reverted`).
    pub(super) mitigations: opentelemetry::metrics::Counter<u64>,
    /// Proven chains in the last pass.
    pub(super) chains: opentelemetry::metrics::Gauge<u64>,
    /// Breach-relevant findings (internet-facing) in the last pass.
    pub(super) breach_paths: opentelemetry::metrics::Gauge<u64>,
    /// Active mitigations currently in the ledger.
    pub(super) active_mitigations: opentelemetry::metrics::Gauge<u64>,
    /// Breach-path count by model `verdict` (the current judgement distribution).
    pub(super) verdicts: opentelemetry::metrics::Gauge<u64>,
    /// Behavioral signals ingested this pass, by `behavior` variant (alert/connection/
    /// secret-read/library-load/file-read/priv-change/exec) — the shadow-bake (JEF-48)
    /// view of *what* the behavioral port is seeing, labeled low-cardinality (variant
    /// names only, never per-pod).
    pub(super) signals: opentelemetry::metrics::Counter<u64>,
    /// Signal attribution outcome, by `outcome` (`resolved`/`unresolved`): how many
    /// ingested signals the runtime adapter could attribute to a live workload vs drop as
    /// an unknown cgroup UID. A sustained `unresolved` means the agent's UIDs aren't
    /// matching pod metadata.
    pub(super) attribution: opentelemetry::metrics::Counter<u64>,
    /// `RuntimeEvents` store cardinality (distinct live observations) as of this pass —
    /// a gauge so the TTL'd store's working-set size is observable.
    pub(super) runtime_store: opentelemetry::metrics::Gauge<u64>,
    /// Corroborations fired this pass: proven breach-relevant chains whose `corroborated`
    /// predicate is set (ADR-0009). In shadow this is the countable answer to "would this
    /// have promoted?" without any behavior change.
    pub(super) corroborations: opentelemetry::metrics::Counter<u64>,
    /// Per-pass adjudications that issued a fresh model call (verdict-cache miss). A
    /// proper cumulative counter (replaces the prior `verdicts{verdict="judged_this_pass"}`
    /// gauge hack) so model-call frequency is rate-able.
    pub(super) judged: opentelemetry::metrics::Counter<u64>,
    /// Per-pass adjudications served from the verdict cache (cache hit). Cumulative
    /// counter, the companion to [`Self::judged`].
    pub(super) cached: opentelemetry::metrics::Counter<u64>,
    /// Per-pass cache MISSES the engine declined to send to the model because the entry
    /// (or the whole fleet, via the global breaker) was in inconclusive-adjudication
    /// backoff (JEF-234). A cumulative counter: a sustained nonzero rate means the model is
    /// degraded and the engine is correctly NOT hammering it (the bounding is working).
    pub(super) skipped: opentelemetry::metrics::Counter<u64>,
    /// Adjudicator model-call latency in milliseconds (histogram), recorded around each
    /// fresh `judge` call so the slow CPU model's tail is visible.
    pub(super) model_latency_ms: opentelemetry::metrics::Histogram<f64>,
    /// Shadow would-have-acted report headline (JEF-143): distinct workloads the engine
    /// WOULD have isolated over the default rolling window, as of this pass — the gates-
    /// exiting-shadow figure (JEF-50), mirrored to OTLP like the bake counts. A gauge:
    /// the current window snapshot, the in-process mirror of the would-have-acted report
    /// aggregation.
    pub(super) report_would_act: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: distinct proven-but-cleared paths the model left alone
    /// over the window (the trust half of the diff).
    pub(super) report_left_alone: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: would-acts whose projected cut was short-lived (likely
    /// false positives) — the subset to discount when judging the shadow bake.
    pub(super) report_short_lived: opentelemetry::metrics::Gauge<u64>,
    /// Shadow report headline: would-acts made during an enrichment-coverage gap (no CVE
    /// backing) — the ones to scrutinize first.
    pub(super) report_coverage_gap: opentelemetry::metrics::Gauge<u64>,
}

impl EngineMetrics {
    pub(super) fn new() -> Self {
        let m = opentelemetry::global::meter("protector.engine");
        Self {
            passes: m
                .u64_counter("protector.engine.passes")
                .with_description("Engine process passes (one per observed change).")
                .build(),
            model_calls: m
                .u64_counter("protector.engine.model_calls")
                .with_description("Adjudicator model invocations by result.")
                .build(),
            mitigations: m
                .u64_counter("protector.engine.mitigations")
                .with_description("Mitigations actuated by action.")
                .build(),
            chains: m
                .u64_gauge("protector.engine.chains")
                .with_description("Proven chains in the last pass.")
                .build(),
            breach_paths: m
                .u64_gauge("protector.engine.breach_paths")
                .with_description("Breach-relevant (internet-facing) findings in the last pass.")
                .build(),
            active_mitigations: m
                .u64_gauge("protector.engine.active_mitigations")
                .with_description("Active mitigations in the ledger.")
                .build(),
            verdicts: m
                .u64_gauge("protector.engine.verdicts")
                .with_description("Breach paths by model verdict (current distribution).")
                .build(),
            signals: m
                .u64_counter("protector.engine.signals")
                .with_description("Behavioral signals ingested by variant.")
                .build(),
            attribution: m
                .u64_counter("protector.engine.attribution")
                .with_description("Signal attribution outcome (resolved/unresolved).")
                .build(),
            runtime_store: m
                .u64_gauge("protector.engine.runtime_store")
                .with_description("RuntimeEvents store cardinality (live observations).")
                .build(),
            corroborations: m
                .u64_counter("protector.engine.corroborations")
                .with_description("Corroborations fired (corroborated breach chains) per pass.")
                .build(),
            judged: m
                .u64_counter("protector.engine.judged")
                .with_description("Adjudications that issued a fresh model call (cache miss).")
                .build(),
            cached: m
                .u64_counter("protector.engine.cached")
                .with_description("Adjudications served from the verdict cache (cache hit).")
                .build(),
            skipped: m
                .u64_counter("protector.engine.skipped")
                .with_description(
                    "Adjudications skipped (inconclusive-adjudication backoff / breaker open).",
                )
                .build(),
            model_latency_ms: m
                .f64_histogram("protector.engine.model_latency_ms")
                .with_description("Adjudicator model-call latency in milliseconds.")
                .build(),
            report_would_act: m
                .u64_gauge("protector.engine.report_would_act")
                .with_description(
                    "Shadow report: workloads that would have been isolated (window).",
                )
                .build(),
            report_left_alone: m
                .u64_gauge("protector.engine.report_left_alone")
                .with_description("Shadow report: proven-but-cleared paths left alone (window).")
                .build(),
            report_short_lived: m
                .u64_gauge("protector.engine.report_short_lived")
                .with_description("Shadow report: short-lived would-acts (likely false positives).")
                .build(),
            report_coverage_gap: m
                .u64_gauge("protector.engine.report_coverage_gap")
                .with_description("Shadow report: would-acts during an enrichment-coverage gap.")
                .build(),
        }
    }
}
