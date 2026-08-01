# Alerting on the actuation-trust signals

protector's engine exposes its own health as OTLP instruments (`/metrics`, no-op unless an
OTLP endpoint is configured — see the README's Metrics section). Two of them exist
specifically so "the judge went quiet" and "the engine cut something" are never silent:

- `protector.engine.judge_degraded` (gauge, `0`/`1`) — the model adjudicator's global breaker
  is open this pass. While it is `1`, the engine will not auto-apply any **new** cut — a
  chain that would otherwise qualify is held as a proposal instead (the judge veto is
  load-bearing under `enforce`; don't arm blind). A **standing** cut and a self-revert are
  unaffected: the engine still lifts a cut whose justification or health no longer holds even
  while the judge is degraded — the fail-safe asymmetry is always toward lifting, never
  toward cutting.
- `protector.engine.mitigations{action="applied"|"reverted"|"held_degraded"}` (counter) — every
  actual actuation (`applied`/`reverted`) plus every new cut the freshness gate held back
  (`held_degraded`). A rising `held_degraded` rate alongside `judge_degraded == 1` is the
  concrete "we wanted to act but couldn't trust the judge" signal.

These sit alongside the existing model-health instruments, useful for the SAME
alert group: `protector.engine.model_calls{result="unavailable"}` (a model call came back
inconclusive), `protector.engine.skipped` (a re-judge was skipped for breaker/backoff —),
and `protector.engine.model_latency_ms` (the model's response-time tail).

## Example PromQL rules

Adjust `for:` windows to your pass cadence and Prometheus scrape interval; these are a
starting point, not a tuned production SLO.

```yaml
groups:
  - name: protector-judge-freshness
    rules:
      # The model has looked down for a sustained stretch — an operator should know before
      # the ~20-minute cold-start window (a restart, an Ollama outage, a flaky tier) turns
      # into "protector silently stopped auto-acting."
      - alert: ProtectorJudgeDegraded
        expr: max_over_time(protector_engine_judge_degraded[10m]) == 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "protector's model adjudicator has been degraded for 10+ minutes"
          description: >
            The engine's global adjudication breaker has been open continuously for at
            least 10 minutes. New cuts are being held as proposals, not auto-applied
            (existing cuts and reverts are unaffected). Check the model endpoint
            (PROTECTOR_ENGINE_MODEL) and the Ollama tier it points at.

      # A NEW cut actually wanted to fire and was held — a real proposal is waiting on a
      # judge that isn't currently trustworthy. Escalate above the plain "degraded" gauge
      # because this means something is HAPPENING, not just that the judge is quiet.
      - alert: ProtectorActuationHeldOnDegradedJudge
        expr: increase(protector_engine_mitigations_total{action="held_degraded"}[15m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "protector held a new cut because the judge is degraded"
          description: >
            A mitigation that would otherwise auto-apply under enforce is being held as a
            proposal because the model hasn't verifiably answered recently. Review the
            held proposal(s) on the dashboard and the model's health.

      # protector never applies AND its judge is degraded at the same time as reverts are
      # NOT happening — a sanity check that the fail-safe lift path is exercised, not just
      # present in the codebase. Tune the window to your pass cadence; a cluster with no
      # standing cuts at all will never fire the numerator and this rule is a no-op for it.
      - alert: ProtectorMitigationsStalledWhileDegraded
        expr: |
          max_over_time(protector_engine_judge_degraded[30m]) == 1
          and increase(protector_engine_mitigations_total{action="reverted"}[30m]) == 0
          and protector_engine_active_mitigations > 0
        for: 30m
        labels:
          severity: info
        annotations:
          summary: "protector has standing cuts and a degraded judge with no reverts"
          description: >
            Informational: standing cuts exist and the judge has been degraded for 30
            minutes with no reverts observed. This is EXPECTED when nothing has cleared
            (reverts only fire when a protected workload's health diverges or a chain's
            evidence disappears) — pair with a manual check of the affected entries if the
            outage runs long.
```

## Why these two, not a new operator toggle

Per [`CLAUDE.md`](../CLAUDE.md)'s configuration rule, protector adds a setting only for the
enforcement gate (`PROTECTOR_MODE`) or an egress carve-out — never a detection/actuation-trust
toggle. The freshness bound the `judge_degraded` gauge and the `held_degraded` counter are
derived from (`JUDGE_FRESHNESS_BOUND`, `engine/src/engine/mod.rs`) is a code default, not an
env knob: there is nothing to turn off, only a bound already tuned to sit comfortably above
the model's per-entry retry ceiling and the global breaker's cooldown, and well inside the
documented cold-start window.
