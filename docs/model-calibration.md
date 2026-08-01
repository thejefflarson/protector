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
- **cross-tenant network** (`[NETWORK]` `[cross-ns]` into a different tenant, no CVE/signal) →
  **refute** — a reachable path is loose topology (no NetworkPolicy), a severity finding to
  fix, not an attack in progress.
- **escape-to-host** (a privilege-escalation / host-escape outcome reachable, no CVE/signal)
  → **refute** — same principle: a scary OUTCOME being reachable is not the outcome being
  exploited.

The principle: the deterministic layer PROVES + ENRICHES — reachability, the
`[RBAC-GRANTED]` / `[MOUNTED]` / `[same-ns]` / `[cross-ns]` reach tags, and the CVE /
runtime evidence — and the **model decides breach holistically** from the *conjunction*
of reachability and evidence. Neither half alone is a breach: authorized-but-unevidenced
reach (`[RBAC-GRANTED]` / `[MOUNTED]`, however broad or high-severity) is **not** a
breach, and scary evidence on an unreachable workload is not a breach. The engine no
longer pre-decides via deterministic "promotion grounds" (those mis-gated ArgoCD into
`exploitable`); the only deterministic backstop left is anti-fabrication
(`guard_fabricated_cve`), which stops the model citing a CVE absent from the evidence — it
is not a decision gate. See the holistic prompt in `build_judgment_prompt`
(`engine/src/engine/reason/adjudicate.rs`).

### Edge vs. downstream — the exploitability path is not the same evidence bar

 gave the model its own evidence block for every workload on an entry's *proven* path,
not just the entry — but the two positions in the chain are not judged identically:

- **Edge (the internet-facing entry) — the CVE-exploitability path.** A critical CVE observed
  *loading at runtime* on the entry is directly hittable from the internet: reachability +
  a loaded CVE on the front door **is** exploitation evidence on its own → `exploitable`
  (`log4j_breach`).
- **Downstream (anything past the edge) — BEHAVIORAL evidence only.** Proving a *non-edge* CVE
  exploitable would require knowing that attacker input actually reaches the vulnerable code
  path *through* the edge — and reachability + "loaded-at-runtime" cannot show that: network
  reachability is not application dataflow, and "loaded" is not "the vulnerable function ran
  with attacker-controlled data". So a downstream workload's CVE, on its own, is **not**
  exploitation evidence — only an on-box **behavioral** signal on that downstream workload
  (an alert / hands-on-keyboard action — something happening *now*) is:
  - `downstream_only_cve` — a downstream hop with a loaded-at-runtime CVE and *no* behavioral
    evidence, behind a clean edge → **refute**. This is a deliberate keep-honest trap: the
    model must not over-promote on downstream reachability + a loaded CVE alone. (Whether a
    downstream CVE like this is exploitable via some other proxy/exposure path is the
    problem — deferred, not judged here.)
  - `downstream_behavioral_compromise` — a downstream hop with an alert / hands-on-keyboard
    signal and no CVE of its own, behind a clean edge → **exploitable**, the same bar as a
    live signal on the entry itself.
  - `downstream_clean_marker` — a downstream hop explicitly checked with nothing found →
    **refute**.

> **Recalibration gate (follow-up — arming, not the engine change):** removing the
> deterministic grounds makes "is argo a breach" the *model's* call, so whether the prod
> model (granite4:3b-h) decides correctly under the holistic prompt is verified by the
> bake-off + the `#[ignore]`d e2e gate below — a follow-up gate on arming a class, **not**
> a blocker for the engine, which stays shadow until a class is armed.

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

A candidate must score the bake-off cases correctly — own-app / argo / cross-tenant-net /
escape-to-host / `downstream_only_cve` / `downstream_clean_marker` **refuted**; log4j /
`downstream_behavioral_compromise` **exploitable** — to pass. A model that misses any case
does not advance.

### 2. Gated competence probe (`real_model_judges_toxic_vs_unevidenced`)

The `#[ignore]`d e2e test in `engine/src/engine/reason/adjudicate.rs` drives the *real*
judgement path (`build_judgment_prompt` → the model → `parse_verdict`) end-to-end against
a live endpoint, and **hard-asserts the anchor cases**: log4shell on a reachable
internet-facing entry → `Exploitable`; the same chain with no CVE / no runtime evidence
(own-app `[MOUNTED]` secret) → `Refuted`; and the argo anchor — an internet-facing
controller RBAC-granted secrets across many tenants (broad, some high-impact) with no CVE
and no behavior → `Refuted`. It fails the build if the candidate misses any, so it is a
real gate when run, not just a print.

```sh
PROTECTOR_E2E_MODEL=http://localhost:11434/v1/chat/completions \
PROTECTOR_E2E_MODEL_NAME=qwen2.5:1.5b \
cargo nextest run real_model_judges -- --ignored --nocapture
```

(It is `#[ignore]`d so ordinary `cargo test` / CI skip it; it needs `PROTECTOR_E2E_MODEL`
pointed at the candidate.)

## Checklist before swapping the prod model

1. `python3 scripts/judge_bakeoff.py` against the candidate — it scores every bake-off
   case correctly (own-app/argo/cross-tenant-net/escape/`downstream_only_cve` refute;
   log4j/`downstream_behavioral_compromise` exploitable) and is fast enough on the target
   hardware.
2. `cargo nextest run real_model_judges -- --ignored` against the candidate endpoint —
   the gated probe **passes** (all anchor assertions hold: log4shell exploitable; own-app
   and argo broad-RBAC refuted).
3. Only then update the prod model configuration.

## Follow-ups (not yet implemented)

- **Circuit breaker** around the model call (trip after sustained failures / timeouts so a
  degraded endpoint stops being retried every pass). Deferred from as a larger
  change; the bounded client timeout + the `protector.engine.model_client_fallback` and
  `model_calls{result=unavailable}` metrics are the current backstops.
- **Prompt text for the edge/downstream split (follow-up):** `build_judgment_prompt`'s
  "Downstream evidence" paragraph still tells the model a downstream CVE observed
  loading-at-runtime is exploitation evidence "exactly as if it were on the entry" — the SAME
  bar as an edge CVE. This doc's edge/downstream framing above (and the `downstream_only_cve`
  ground-truth flip to `refute`) is intentionally AHEAD of that prompt text: the fixture
  ground truth is corrected here (T2a, ASSESSMENT-only), but rewording the prompt itself to
  make downstream evidence behavioral-only is a separate engine change, not yet done. Until
  that lands, expect the bake-off/e2e gate to actually score `downstream_only_cve` as
  `exploitable` against the CURRENT prompt — that is the known, tracked gap this fixture
  exists to close, not a bug in the fixture.
