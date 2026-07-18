# 0029. Adjudication: the model's verdict is authoritative — no deterministic guards over it, no evidence caps

- Status: Accepted
- Date: 2026-07-18
- Reaffirms: [0013](0013-proof-winnows-model-decides.md) — the model decides breach from the proven,
  enriched chain; the deterministic layer PROVES + ENRICHES, it does not re-decide. And [0016](0016-severity-vs-urgency.md) — the engine runs shadow-first; a verdict
  proposes, it never acts.

## Context

The adjudicator occasionally returns a false `exploitable` on a large internet-facing entry
(argocd-server, protector) that carries no exploitation evidence — every CVE `[reachability:
not-observed]`, no exposed secret, and the only "runtime behavior" the workload's own `:8080`
self-connection. The model's stated reason is a *misjudgement* (it hallucinated a
`loaded-at-runtime` tag on a not-observed CVE in one case; it read the workload's own activity as a
"live signal" in another), not an ungrounded output.

This was diagnosed deliberately (~20 trials). It is **not** a config, model, or prompt bug: the
model refutes these same prompts correctly in every reproducible condition — local (arm64) and the
in-cluster (amd64) Ollama, single and 6-way concurrent, at 8192 and 16384 context, with the engine's
exact OpenAI-compat call (temperature 0, `max_tokens 1024`), against the byte-identical model
(digest `8f68893c685c`, Q4_K_M, `n_ctx_slot=16384`). The prod flips are a **rare temperature-0
non-determinism at the model's decision boundary** — these giant entries (120+ reachable objectives,
~24K chars) sit right at the edge, and the live engine's conditions (KV-cache prefix reuse across
back-to-back heterogeneous entries, batched decode, keep-warm churn) make temp-0 not bit-reproducible,
so once in a while the borderline argmax tips the wrong way. A tail event, not a defect we can point at.

Two "fixes" get proposed each time this recurs, and both are **rejected here**:

1. A **deterministic guard** that inspects an `exploitable` verdict and, if the engine can't itself
   point to loaded-at-runtime / a live alert / an exposed-secret-field entry, downgrades it to
   `refuted`.
2. **Capping / summarizing** the reachable-objectives list (show N, then "+K more") to shrink the
   prompt and make it less borderline.

## Decision

**The adjudicating model's verdict is authoritative. We do not add deterministic guards that override
or second-guess its breach judgement, and we do not cap, truncate, or summarize the evidence to steer
it.** The full enriched chain goes to the model; its call stands.

Why:

- A deterministic verdict-override **re-introduces exactly the deterministic breach-decision that
  ADR-0013 retired.** The architecture's whole thesis is that the model decides breach from the
  conjunction of reachability + evidence — a rule that re-derives that decision and overrules the
  model defeats the point, and in practice becomes unbounded whack-a-mole (every new
  false-positive shape spawns another clause). If a deterministic rule could reliably make this call,
  we would not need the model at all.
- **Capping the evidence starves the model of the picture it is entitled to reason over.** Breadth is
  part of the judgement; hiding objectives to make a prompt "easier" is a lossy, dishonest input that
  trades correctness on the real cases for comfort on the borderline ones.
- The failure is a **rare, non-reproducible tail flip**, and the engine is **shadow-first** — a false
  `exploitable` proposes, it never acts (ADR-0016). The cost of the occasional wrong proposal does not
  justify re-architecting the decision path around it.

Where a flip genuinely must be reduced, it is addressed at the **model / inference layer** — a more
capable judge (the bakeoff, `scripts/judge_bakeoff.py`, is the calibration tool and stays
faithful-to-prod for exactly this), or determinism settings — **not** by bolting an override onto the
model's output or truncating its input.

Scope note: this does **not** remove the existing anti-fabrication backstop (`guard_fabricated_cve`),
which drops an `exploitable` that cites a CVE **id absent from the evidence**. That guards output
*grounding/integrity* (the model referenced something that isn't there — an invalid output), not the
*judgement call* (whether present evidence amounts to a breach). This ADR forbids the latter class of
guard, not the former; and it adds no new guards.

## Consequences

- The adjudicator's verdict is the single call. Rare false-`exploitable` proposals on huge borderline
  entries are **accepted as a known tail cost**, mitigated only by choosing a better judge model, not
  by overriding or starving the model.
- No "evidence guard" and no objective-list cap will be added; proposals to add them are closed by
  pointing here. (JEF-414 is cancelled against this decision.)
- The bakeoff remains the sanctioned lever: it stays synced to the live `build_judgment_prompt` and
  carries the real full-scale entries as fixtures, so model choice is evaluated against what prod
  actually sends.
- If tail flips ever become frequent enough to matter operationally, the response is a model change
  (evaluated via the bakeoff) — a bounded, reversible knob — never a deterministic gate on the verdict.
