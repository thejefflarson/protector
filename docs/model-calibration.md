# Model calibration gate — pre-swap checklist

The adjudication model is load-bearing. Under [ADR-0013](adr/0013-proof-winnows-model-decides.md)
a proven, internet-facing foothold is auto-eligible for a cut **only** when the model
returns `exploitable`; on the speculative (no-CVE) lane the model's positive judgement is
what moves privilege. A miscalibrated model therefore either manufactures cuts it
shouldn't (over-eager) or sits on a textbook breach (timid). Neither is acceptable in
prod.

This doc is the gate: **a candidate model must pass both checks below before it is
allowed to replace the model in prod.** The architecture (deterministic foothold floor +
reversible, self-reverting actions) keeps a miscalibrated analyst survivable, but the gate
is what keeps it from being deployed in the first place.

## What "calibrated" means here

The model must, on cluster-representative cases, get the call right:

- **own-app** (its own namespace's `[MOUNTED]` secret / `[same-ns]` DB) → **refute**
- **argo / broad RBAC** (reaches many tenants' secrets, all `[RBAC-GRANTED]`) → **refute**
- **log4shell** (a critical, exploited-in-wild CVE loaded at runtime) → **exploitable**
- **cross-tenant network** (`[NETWORK]` `[cross-ns]` into a different tenant) → **exploitable**
- **escape-to-host** (a privilege-escalation / host-escape outcome) → **exploitable**

The principle: authorization (the `[RBAC-GRANTED]` / `[MOUNTED]` / `[same-ns]` /
`[cross-ns]` tags), not namespace-difference or breadth, drives the call. See
`build_judgment_prompt` in `engine/src/engine/reason/adjudicate.rs` for the decision
procedure the prompt encodes.

## How to run the gate

### 1. Bake-off (`scripts/judge_bakeoff.py`) — performance + judgement

Benches candidate models against the full case set above on the target hardware, answering
two separate questions: **performance** (resident RAM, load time, tokens/sec, latency,
strict-JSON validity — is it viable on the CPU Pis?) and **judgement** (does it score the
cases correctly?). It is OOM-safe: one model resident at a time, a free-RAM floor, capped
context, and a separate `--pull` phase.

```sh
python3 scripts/judge_bakeoff.py --pull       # phase 0: download missing models (idle)
python3 scripts/judge_bakeoff.py              # phase 1: bench the default shortlist
python3 scripts/judge_bakeoff.py qwen3:4b-instruct   # bench specific models
```

A candidate must score the bake-off cases correctly — own-app / argo **refuted**;
log4j / cross-tenant-net / escape-to-host **exploitable** — to pass. A model that misses
any case does not advance.

### 2. Gated competence probe (`real_model_judges_toxic_vs_unevidenced`)

The `#[ignore]`d e2e test in `engine/src/engine/reason/adjudicate.rs` drives the *real*
judgement path (`build_judgment_prompt` → the model → `parse_verdict`) end-to-end against
a live endpoint, and **hard-asserts the two anchor cases**: log4shell → `Exploitable`,
no-evidence own-app secret → `Refuted`. It fails the build if the candidate misses either,
so it is a real gate when run, not just a print.

```sh
PROTECTOR_E2E_MODEL=http://localhost:11434/v1/chat/completions \
PROTECTOR_E2E_MODEL_NAME=qwen2.5:1.5b \
cargo nextest run real_model_judges -- --ignored --nocapture
```

(It is `#[ignore]`d so ordinary `cargo test` / CI skip it; it needs `PROTECTOR_E2E_MODEL`
pointed at the candidate.)

## Checklist before swapping the prod model

1. `python3 scripts/judge_bakeoff.py` against the candidate — it scores every bake-off
   case correctly (own-app/argo refute; log4j/cross-tenant-net/escape exploitable) and is
   fast enough on the target hardware.
2. `cargo nextest run real_model_judges -- --ignored` against the candidate endpoint —
   the gated probe **passes** (both anchor assertions hold).
3. Only then update the prod model configuration.

## Follow-ups (not yet implemented)

- **Circuit breaker** around the model call (trip after sustained failures / timeouts so a
  degraded endpoint stops being retried every pass). Deferred from JEF-109 as a larger
  change; the bounded client timeout + the `protector.engine.model_client_fallback` and
  `model_calls{result=unavailable}` metrics are the current backstops.
