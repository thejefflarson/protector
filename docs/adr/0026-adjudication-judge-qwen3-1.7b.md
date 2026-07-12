# 0026. Promote qwen3:1.7b as the adjudication judge (pending Pi validation)

- Status: Proposed — bakeoff decided; operational validation gates the actual swap
- Date: 2026-07-11
- Refines: [0013](0013-proof-winnows-model-decides.md) (the model makes the
  exploitability call), [0023](0023-delta-aware-adjudication.md) (delta-aware prompt)
- Relates: JEF-405 (the prompt this bakeoff was run against), JEF-402 (the
  exposed-secret / reachable-secret distinction one of the cases exercises)

## Context

The adjudicator (ADR-0013) hands the model one call per internet-facing entry: is a
proven, reachable chain a *real breach* — does the reached objective carry exploitation
evidence (a known-exploited CVE loaded at runtime, an alert/hands-on-keyboard signal, or
a credential exposed in the image). The model is load-bearing for the foothold cut, so
*which* model judges is a consequential choice, not a tuning knob.

The judge runs on **CPU-only Raspberry Pi nodes** inside the cluster (zero egress — the
model is a local in-cluster Ollama, never a hosted API). That hardware constraint has
repeatedly been the deciding factor:

- `granite4:*-h` calibrated well on the prompt but is a **hybrid/recurrent** architecture
  whose KV cache is broken under Ollama — 8–20 minutes per call on the Pis, unusable, and
  it was retired from prod for exactly that reason.
- The current deployed judge is **`qwen2.5:3b-instruct`** (set explicitly in the cluster
  Helm `values.yaml` as `engine.model.name`; the engine's in-code default
  `qwen2.5:3b` at `engine/src/engine/model.rs:232` is only a fallback for when the env
  var is unset). It is a standard transformer, fast enough on the Pis, and correct on
  almost every calibration case — but it **misses `exposed_secret_in_field`**, i.e. it
  does not treat a credential actually listed in the "Exposed secrets baked into this
  image" field as exploitation evidence. That is one of the three evidence types
  ADR-0013 requires the model to recognize.

`scripts/judge_bakeoff.py` benches candidate judges on the JEF-405-fixed prompt (the same
`build_judgment_prompt` the engine runs) across cluster-representative cases: the three
exploitation-evidence types that MUST be `exploitable`, and the refute cases (broad RBAC,
cross-tenant network paths, not-observed CVEs, reachable-but-not-exposed secrets — the
JEF-402 false breach — the ArgoCD cluster-admin false positive) that MUST be `refuted`.

## Bakeoff result

Dev box, temperature 0, current JEF-405 prompt, single-shot per case:

| model | score | notes |
|---|---|---|
| **`qwen3:1.7b`** | **12/12** | The only model to get **all three** exploitation-evidence types (log4j loaded-at-runtime CVE, exposed-secret-in-field, live signal) **and** every refute case — including the ArgoCD cluster-admin false-positive refute. ~2.4 GB, ~86 gen tok/s, standard transformer (KV cache works). |
| `qwen2.5:3b-instruct` (deployed) | 11/12 | Correct everywhere **except** `exposed_secret_in_field` — does not treat a baked-in exposed credential as evidence. |
| `ibm/granite4:3b-h` | (retired) | Hybrid/recurrent; KV cache broken under Ollama; 8–20 min/call on the Pis — not viable regardless of judgement quality. |

`qwen3:1.7b` is the clean sweep: it recovers the one evidence type the deployed judge
misses while holding every refute case, and it is a standard transformer of the same
class as the deployed model (so the Pi-viability question is "measure it," not "will the
cache work at all").

## Decision

**Recommend promoting `qwen3:1.7b` to the adjudication judge — once, and only once, the
operational validation below passes on the real Pi CPU nodes.** The bakeoff decides the
*judgement-quality* question. It does **not** decide the *latency/RAM-on-Pi* question,
and it does not exercise the delta-aware prompt path. Both gate the actual swap.

This ADR records the judgement-quality decision now (so the eval is durable and the ticket
leaves a written recommendation), and enumerates the remaining human/operational steps so
the swap is executed deliberately, not inferred.

### Remaining human / operational steps (these gate the swap — none are in this PR)

a. **Bench Pi latency + resident RAM.** Measure `qwen3:1.7b` end-to-end latency and
   resident RAM on the Pi CPU nodes against `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS` and the
   engine's keep-warm interval. The 2.4 GB / ~86 tok/s figures are dev-box; the Pis are
   the binding constraint. It must comfortably clear the timeout with the model kept warm.

b. **Confirm strict-JSON on the Pi.** Verify the model emits the strict verdict JSON
   reliably on the Pi build of Ollama at temp 0 (the bakeoff checks JSON validity; confirm
   it holds on the target runtime, not just the dev box).

c. **Verify the delta-aware prompt path (ADR-0023), not just the single-shot bakeoff.**
   The bakeoff runs the full-state single-shot prompt. Production adds the "Changes since
   the last decisive verdict" delta section; confirm `qwen3:1.7b` judges the delta-aware
   prompt correctly (does not regress on new-object churn, still refutes subtractive/no-
   evidence deltas).

d. **Confirm in-cluster availability + zero-egress posture.** Confirm `qwen3:1.7b` is
   pulled to the **in-cluster** Ollama and that the linkerd-policy `ollamaClients` posture
   permits the engine→Ollama call — the zero-egress invariant must hold (the model is
   local; nothing leaves the cluster).

e. **THEN swap.** With (a)–(d) green: set `engine.model.name: qwen3:1.7b` in the cluster
   `values.yaml` (separate infra repo — a human change), and update the engine in-code
   default in the same spirit. **Neither of those is done here** — this PR is the recorded
   evaluation only.

## Consequences

- **Better evidence coverage.** The judge recovers `exposed_secret_in_field`, closing the
  one exploitation-evidence type the deployed model misses, with no regression on the
  refute cases (no new false positives on broad RBAC / cross-tenant reach).
- **Same architecture class, so Pi-viability is a measurement, not a gamble.** Unlike the
  retired granite4 hybrid, `qwen3:1.7b` is a standard transformer; the KV cache works.
- **The swap stays deliberate.** Recording the recommendation without flipping any
  prod-affecting default means the Pi-latency validation is not skipped — an unvalidated
  model change on the load-bearing foothold judge is exactly the risk this staging avoids.
- **Zero egress unchanged.** The model remains a local in-cluster Ollama; step (d) makes
  the zero-egress check an explicit gate on the swap.
