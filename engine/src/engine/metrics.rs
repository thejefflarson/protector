//! The engine's OTLP instruments (extracted from `mod.rs` to keep it under the 1,000-line cap,
//! CLAUDE.md). A cohesive unit: the counters/gauges/histograms the engine records against the
//! global meter, and their one-shot construction. `pub(super)` so the engine core reads the fields.

use crate::engine::state::RuntimeCoverage;

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
    /// Whether the model adjudicator looks degraded RIGHT NOW (`1`) or healthy (`0`) — the
    /// GLOBAL breaker's state, mirrored each pass. This is the actuation-trust
    /// signal `gate_on_judge_freshness` reads: while it is `1`, no NEW cut auto-applies (it
    /// holds as a proposal — see `protector.engine.mitigations{action="held_degraded"}` for
    /// the concrete held events), though a still-justified standing cut is unaffected and a
    /// self-revert still runs (the fail-safe asymmetry, ADR-0021 spirit). Distinct from the
    /// per-pass `skipped` counter: that counts individual re-judge skips, this is the
    /// at-a-glance current state to alert on.
    pub(super) judge_degraded: opentelemetry::metrics::Gauge<u64>,
    /// Breach-path count by model `verdict` (the current judgement distribution).
    pub(super) verdicts: opentelemetry::metrics::Gauge<u64>,
    /// Behavioral signals ingested this pass, by `behavior` variant (alert/connection/
    /// secret-read/library-load/file-read/priv-change/exec) — the shadow-bake
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
    /// backoff. A cumulative counter: a sustained nonzero rate means the model is
    /// degraded and the engine is correctly NOT hammering it (the bounding is working).
    pub(super) skipped: opentelemetry::metrics::Counter<u64>,
    /// Adjudicator model-call latency in milliseconds (histogram), recorded around each
    /// fresh `judge` call so the slow CPU model's tail is visible.
    pub(super) model_latency_ms: opentelemetry::metrics::Histogram<f64>,
    /// Shadow would-have-acted report headline: distinct workloads the engine
    /// WOULD have isolated over the default rolling window, as of this pass — the gates-
    /// exiting-shadow figure, mirrored to OTLP like the bake counts. A gauge:
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
    /// Runtime-corroboration coverage mirrored from the SAME
    /// [`derive_runtime_coverage`](crate::engine::state::derive_runtime_coverage) the dashboard
    /// reads (they must never disagree). In-scope expected nodes as of this pass — the agent
    /// DaemonSet's own pods, matching `RuntimeCoverage::expected_count`; out-of-scope reporters are
    /// excluded. Counts ONLY, with NO per-node label dimension: node names are attacker-influenceable,
    /// so a per-node series would be a cardinality/DoS vector (see `agent_liveness`).
    pub(super) coverage_expected: opentelemetry::metrics::Gauge<u64>,
    /// Expected nodes reporting with their probes loaded this pass (quiet counts as healthy).
    pub(super) coverage_healthy: opentelemetry::metrics::Gauge<u64>,
    /// Expected nodes reporting only partial probes this pass (degraded coverage).
    pub(super) coverage_degraded: opentelemetry::metrics::Gauge<u64>,
    /// Expected nodes with no live corroboration this pass (not reporting, or Ready-but-blind).
    /// A sustained nonzero value means a blind spot the dashboard would show — mirrored here so an
    /// operator watching only /metrics sees the same blind count.
    pub(super) coverage_blind: opentelemetry::metrics::Gauge<u64>,
    /// Total agent signals emitted across healthy nodes this pass — the shadow view of live
    /// corroboration volume, summed (no per-node dimension).
    pub(super) coverage_signals: opentelemetry::metrics::Gauge<u64>,
    /// Whether the break-glass kill switch (ADR-0021's enforcement gate, fast path) is
    /// engaged as of this pass (0/1) — a gauge, mirrored every pass so it's always current
    /// even across a long-quiet cluster.
    pub(super) break_glass_engaged: opentelemetry::metrics::Gauge<u64>,
    /// Break-glass engage/clear transitions, by `state` (`engaged`/`cleared`) — a
    /// cumulative, alert-able counter recorded ONCE per edge (never per pass), so an
    /// operator can page on "this fired at all" rather than poll the gauge.
    pub(super) break_glass_transitions: opentelemetry::metrics::Counter<u64>,
    /// `ProposedAction::ContainNode` (ADR-0040) events, by `event`
    /// (`proposed`/`applied`/`reverted`/`rail_refused`) and, for a `rail_refused` event,
    /// `reason` (`control-plane`/`one-node-cap`/`worker-floor`/`unlabelled`/`not-owned`/
    /// `unknown-node` — `respond::actuator::node_containment::RailRefusal::metric_reason`).
    /// A separate counter from the generic [`Self::mitigations`] one: `ContainNode` is
    /// `is_additive_live() == false`, so it never reaches `mitigations`' `applied`/
    /// `reverted` labels through the generic auto-apply path — it has its own apply-side
    /// gate (`respond::actuator::node_containment::evaluate_apply`), armed by the `node`
    /// rung (ADR-0040 §6) — and its deterministic rails must be observable even when
    /// unarmed (a rail refusal is exactly as meaningful in shadow), so a refusal is counted
    /// regardless of whether anything is armed.
    pub(super) contain_node: opentelemetry::metrics::Counter<u64>,
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
            judge_degraded: m
                .u64_gauge("protector.engine.judge_degraded")
                .with_description(
                    "Whether the model adjudicator's global breaker is open this pass (1) or \
                     closed (0) — the actuation-trust signal for new auto-applied cuts.",
                )
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
            coverage_expected: m
                .u64_gauge("protector.engine.coverage_expected_nodes")
                .with_description("Runtime coverage: in-scope expected agent nodes this pass.")
                .build(),
            coverage_healthy: m
                .u64_gauge("protector.engine.coverage_healthy_nodes")
                .with_description("Runtime coverage: expected nodes healthy (probes loaded).")
                .build(),
            coverage_degraded: m
                .u64_gauge("protector.engine.coverage_degraded_nodes")
                .with_description("Runtime coverage: expected nodes with only partial probes.")
                .build(),
            coverage_blind: m
                .u64_gauge("protector.engine.coverage_blind_nodes")
                .with_description("Runtime coverage: expected nodes with no live corroboration.")
                .build(),
            coverage_signals: m
                .u64_gauge("protector.engine.agent_signals_this_pass")
                .with_description("Runtime coverage: agent signals across healthy nodes this pass.")
                .build(),
            break_glass_engaged: m
                .u64_gauge("protector.engine.break_glass_engaged")
                .with_description("Whether the break-glass kill switch is engaged this pass (0/1).")
                .build(),
            break_glass_transitions: m
                .u64_counter("protector.engine.break_glass_transitions")
                .with_description("Break-glass engage/clear transitions, by state.")
                .build(),
            contain_node: m
                .u64_counter("protector.engine.contain_node")
                .with_description(
                    "ContainNode (ADR-0040) events by event (proposed/applied/reverted/\
                     rail_refused) and, for a refusal, reason.",
                )
                .build(),
        }
    }

    /// Mirror this pass's break-glass state into the gauge (called every pass).
    pub(super) fn record_break_glass(&self, engaged: bool) {
        self.break_glass_engaged.record(u64::from(engaged), &[]);
    }

    /// Record ONE engage/clear transition (called only on the edge, never per pass).
    pub(super) fn record_break_glass_transition(&self, engaged: bool) {
        let state = if engaged { "engaged" } else { "cleared" };
        self.break_glass_transitions
            .add(1, &[opentelemetry::KeyValue::new("state", state)]);
    }

    /// Record one `ContainNode` actuation event (ADR-0040): `event` is one of
    /// `proposed`/`applied`/`reverted`/`rail_refused`; `reason` is `Some` only for
    /// `rail_refused` — the refusal-reason label
    /// (`respond::actuator::node_containment::RailRefusal::metric_reason`) alert rules key
    /// on. Fires unconditionally — this counter carries no arming/mode gate of its own, so a
    /// `rail_refused` event is exactly as countable in shadow as it would be once a `node`
    /// arming rung exists.
    pub(super) fn record_contain_node(&self, event: &'static str, reason: Option<&'static str>) {
        let mut attrs = vec![opentelemetry::KeyValue::new("event", event)];
        if let Some(reason) = reason {
            attrs.push(opentelemetry::KeyValue::new("reason", reason));
        }
        self.contain_node.add(1, &attrs);
    }

    /// Mirror this pass's runtime-corroboration coverage into the OTLP gauges. A pure
    /// mirror of already-derived state: it takes the SAME [`RuntimeCoverage`] the dashboard reads
    /// (the caller passes back what `stamp_runtime_coverage` just stored), so the two can never
    /// disagree. Counts ONLY — no per-node label dimension, because node names are
    /// attacker-influenceable and a per-node series would be a cardinality/DoS vector.
    pub(super) fn record_coverage(&self, coverage: &RuntimeCoverage) {
        let CoverageGaugeValues {
            expected,
            healthy,
            degraded,
            blind,
            signals,
        } = coverage_gauge_values(coverage);
        self.coverage_expected.record(expected, &[]);
        self.coverage_healthy.record(healthy, &[]);
        self.coverage_degraded.record(degraded, &[]);
        self.coverage_blind.record(blind, &[]);
        self.coverage_signals.record(signals, &[]);
    }
}

/// The five runtime-coverage gauge values, derived from a [`RuntimeCoverage`]. Kept as a
/// pure function so the mirror's arithmetic is unit-testable without an OTLP reader — the gauges
/// [`EngineMetrics::record_coverage`] emits are exactly these values.
struct CoverageGaugeValues {
    expected: u64,
    healthy: u64,
    degraded: u64,
    blind: u64,
    signals: u64,
}

/// Derive the runtime-coverage gauge values from the SAME `RuntimeCoverage` the dashboard reads.
/// Excludes out-of-scope reporters (via `expected_count` / `healthy_count`), matching the readiness
/// row exactly. `expected == healthy + degraded + blind` by construction.
fn coverage_gauge_values(coverage: &RuntimeCoverage) -> CoverageGaugeValues {
    CoverageGaugeValues {
        expected: coverage.expected_count() as u64,
        healthy: coverage.healthy_count() as u64,
        degraded: coverage.degraded_count() as u64,
        blind: coverage.blind_count() as u64,
        signals: coverage.agent_signals(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{EngineMetrics, coverage_gauge_values};
    use crate::engine::state::{LiveNode, derive_runtime_coverage};

    /// `record_contain_node` takes no `EnabledActions`/mode/scope parameter — only the
    /// event and an optional reason — so a `rail_refused` event is recordable with nothing
    /// armed at all, exactly the "must be observable in shadow" requirement (ADR-0040 §5).
    /// A smoke test: constructing the no-op global meter and recording every event this
    /// ticket adds (with and without a reason) must not panic.
    #[test]
    fn record_contain_node_fires_every_event_with_no_armed_state_required() {
        let metrics = EngineMetrics::new();
        metrics.record_contain_node("proposed", None);
        metrics.record_contain_node("applied", None);
        metrics.record_contain_node("reverted", None);
        for reason in [
            "control-plane",
            "one-node-cap",
            "worker-floor",
            "unlabelled",
            "not-owned",
            "unknown-node",
        ] {
            metrics.record_contain_node("rail_refused", Some(reason));
        }
    }

    /// Build a `RuntimeCoverage` from the SAME `derive_runtime_coverage` the dashboard uses, so the
    /// mirror is tested against the real derivation, not a hand-built stand-in.
    fn coverage(expected: &[&str], live: &[(&str, LiveNode)]) -> super::RuntimeCoverage {
        let expected: BTreeSet<String> = expected.iter().map(|n| (*n).into()).collect();
        let live: BTreeMap<String, LiveNode> =
            live.iter().map(|(n, l)| ((*n).into(), *l)).collect();
        derive_runtime_coverage(&expected, &live)
    }

    fn node(probes_loaded: u32, probes_total: u32, signals: u64) -> LiveNode {
        LiveNode {
            probes_loaded,
            probes_total,
            signals,
        }
    }

    #[test]
    fn all_blind_mirrors_blind_equals_expected_and_no_healthy_no_signals() {
        // Two expected nodes, neither reporting → every gauge but expected/blind is zero.
        let cov = coverage(&["node-a", "node-b"], &[]);
        let v = coverage_gauge_values(&cov);
        assert_eq!(v.expected, 2);
        assert_eq!(v.blind, 2, "all-blind → blind == expected");
        assert_eq!(v.healthy, 0);
        assert_eq!(v.degraded, 0);
        assert_eq!(v.signals, 0, "no healthy node → no signals");
    }

    #[test]
    fn healthy_case_mirrors_healthy_and_summed_signals() {
        // Two healthy nodes (probes loaded), one quiet — signals sum across healthy nodes.
        let cov = coverage(
            &["node-a", "node-b"],
            &[("node-a", node(6, 6, 4)), ("node-b", node(6, 6, 0))],
        );
        let v = coverage_gauge_values(&cov);
        assert_eq!(v.expected, 2);
        assert_eq!(v.healthy, 2);
        assert_eq!(v.blind, 0);
        assert_eq!(v.degraded, 0);
        assert_eq!(v.signals, 4, "quiet node contributes 0, healthy node its 4");
    }

    #[test]
    fn mixed_case_partitions_expected_across_healthy_degraded_blind() {
        // healthy + degraded + blind == expected; an out-of-scope reporter is excluded entirely.
        let cov = coverage(
            &["node-a", "node-b", "node-c"],
            &[
                ("node-a", node(6, 6, 3)), // healthy
                ("node-b", node(4, 6, 1)), // degraded (partial probes)
                ("node-x", node(6, 6, 99)), // out-of-scope: not expected
                                           // node-c: no report → blind
            ],
        );
        let v = coverage_gauge_values(&cov);
        assert_eq!(v.expected, 3, "out-of-scope reporter is excluded");
        assert_eq!(v.healthy, 1);
        assert_eq!(v.degraded, 1);
        assert_eq!(v.blind, 1);
        assert_eq!(
            v.healthy + v.degraded + v.blind,
            v.expected,
            "the three states partition the expected set"
        );
        assert_eq!(
            v.signals, 3,
            "only healthy-node signals count; the out-of-scope node's 99 is excluded"
        );
    }
}
