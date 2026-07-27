# Idea — The model as incident responder

**Status:** design brief (→ ADR-0032 Proposed; → `/plan-sprint`). Realizes the
[VISION.md](../VISION.md) north star. Resolves JEF-547 (supersedes the JEF-322 pivot
asymmetry).

**Idea in one line:** make the local model the incident responder over the whole
internet-facing attack path — it sees downstream evidence, decides what is an attack, and
chooses the minimum cut from a deterministically-proven action menu — while the
deterministic layer narrows to *prove + enrich + feed + bound*.

## Problem

The thesis (ADR-0013, reaffirmed 0029) is "proof winnows, the model decides." The code
honors it for the entry lane and violates it downstream in three verified ways
(clean fact-check of `origin/main`):

1. **Entry-scoped sight** — `render_evidence` feeds the model only the *entry's*
   CVEs/secrets/behavior; downstream objectives are one line each (name + reach-tag +
   ATT&CK outcome). A popped pod two hops in is invisible to the judge.
2. **Model-less downstream cuts** — `quarantine_targets_on_path` fires `RemotelyExploitable`
   on reachability + CVE *presence* and `ActivelyExploited` on a deterministic signal;
   `is_live_corroborated` then returns `true` **unconditionally** for `QuarantineWorkload`.
   Every downstream quarantine bypasses the model.
3. **The model chooses no cut** — its whole output is a 4-value verdict; containment scope
   is the deterministic `containment_for` precedence.

Operator rationale: *"if determinism worked, someone would have solved this problem
already."* This extends ADR-0029's anti-deterministic-override argument to the cut decision
itself.

## Approaches considered

- **A — Incident prompt + decision contract, one call per entry (menu-choice).** Keep the
  one-call-per-internet-entry cadence and its machinery (verdict cache, delta gate, breaker,
  journal). Restructure the prompt as an *incident document* — per-node evidence for the
  entry and every workload on its proven paths, plus a deterministically-rendered action
  menu. Output: assessment + chosen cut ids + reason.
- **B — Staged decomposition** (per-node judgment calls + a cut-selection call). Rejected:
  N+1 slow CPU calls, replicates the per-entry machinery per node, and the model never sees
  the whole incident at once — which is exactly the responder judgment we want.
- **C — Agentic responder loop** (model iterates with graph tools). Rejected: minutes/incident
  on CPU, unreliable small-model tool-use, and it destroys the deterministic-input cache/delta
  gate that makes a slow CPU model survivable; unvalidatable by the bakeoff.

## Recommended — A, with the model-capacity plan built in

The load-bearing move that makes A viable on a small-ish model is the **action menu**:
determinism enumerates the legal cuts (that is "prove + enrich + feed" applied to *actions*),
and the model's decision is a *closed-vocabulary selection*, guardable by membership tests
(ADR-0029-admissible grounding), never free-form action synthesis.

### Target architecture

- **What the model sees** (one incident document per internet-facing entry; the whole prompt
  is the cache key): the entry's calibrated content unchanged; **one evidence block per
  downstream workload on a proven path** (same `entry_evidence`/`entry_findings` accessors —
  they already work for any node; same JEF-453 reachable-CVE filter, same fencing/budgets,
  now per-node with a per-incident aggregate cap); clean path nodes get a one-line "no
  evidence observed"; the objectives list unchanged; and **the action menu** — each legal
  cut as a line with a content-derived id, mechanism, target, and a deterministic
  blast-radius note. Only actuator-legal (additive-live, reversible, labeled) actions are
  selectable.
- **What the model outputs:** `{assessment: attack|no_attack|uncertain, reason,
  cuts:[menu-id…]}`, instructed to the fewest/narrowest cuts (empty = leave everything).
  Parser defaults to the skeptic (`uncertain`, no cuts) on anything unparseable.
- **Grounding guards** (all ADR-0029-admissible; downgrade to `Uncertain`, never `Refuted`):
  cited CVE/tag must exist in *that node's* evidence; every cut id must be in the menu;
  assessment↔cuts inconsistency → `Uncertain` + re-judge.
- **Determinism demoted:** `quarantine_targets_on_path` stops producing decisions — it marks
  evidence-bearing path nodes and seeds the menu. `containment_for` becomes the
  human-proposal fallback when the model is unavailable/uncertain (nothing auto-fires without
  the model). The `is_live_corroborated` unconditional-`true` branch is **deleted**.
- **Rails unchanged (deterministic):** shadow-default + per-class arming + `enforceScope`;
  blast-radius/alive-collateral gate; reversible/additive-only + self-revert (ADR-0017);
  zero-egress; fenced/budgeted untrusted text; view-never-gates (ADR-0016). The model
  chooses *what*; the rails bound *how*.
- **Internal-only actively-exploited pods (no internet path) → propose-only** — outside the
  north star's two lanes; retires the JEF-322/JEF-284 auto-cut asymmetry.

### Model capacity — the plain answer

**Do not ship the responder contract on qwen3:1.7b, and do not assume it.** The 1.7B's
documented failure modes — n-gram parroting (JEF-134), tag fabrication (JEF-451), and
tail-flips that *grow with prompt size* — are exactly what a bigger whole-path prompt plus a
structured decision output will amplify. **Plan of record: qwen3:4b-class** (on the 32GB CPU
minis RAM is a non-issue — 4B Q4 ≈ 2.6GB, even 14B fits; latency is the only cost, ~15–25s
vs 7s, absorbed by the verdict cache + the small population of internet-facing entries). The
extended bakeoff (incident + cut-choice fixtures; bench 1.7B/4B/8B; mini latency/RAM
validation) decides the final pick and is recorded in **ADR-0033**; the design and sequence
*assume* 1.7B won't suffice.

## Key decisions (→ ADRs)

1. **ADR-0032** — the model is the incident responder; determinism proves/enriches/feeds/
   bounds and does not decide the cut; incident-scoped prompt; menu-choice decision contract;
   deletes the `QuarantineWorkload` unconditional auto-fire; demotes `containment_for` to a
   human-proposal fallback; internal-only live-alert → propose-only. Supersedes ADR-0022's
   JEF-284 decision procedure (its containment vocabulary/shapes/ladder survive as the menu);
   evolves ADR-0009's adjudicator from veto → cut-selector.
2. **Menu-choice, not free-form actions** — closed, engine-rendered cut vocabulary;
   membership guards are grounding-class under ADR-0029.
3. **Responder judge tier** — **ADR-0033**, written *after* the extended bakeoff (mirrors
   ADR-0026's discipline; expected qwen3:4b). Do not assume 1.7B.

## Risks

- **Calibration regression** on entries that work today — the extended bakeoff carries all
  current fixtures unchanged; step 1 is A/B'd before any contract change.
- **Decision-flip churn** — a tail-flip now flips *which cut* is armed; bounded by
  additive/reversible/self-revert + decisive-only caching + journaled decisions.
- **Prompt growth** on wide entries (argo ~110 objectives) — bounded by evidence-only blocks
  + per-incident budgets; a required bakeoff fixture; if 4B still flips there, the answer is
  8B (latency, not RAM), never an evidence cap.
- **Genuinely open:** whether minimality judgment ("cut the downstream edge, leave the
  entry") is reliable at 4B — only the cut-choice fixtures settle it; fallback is a
  constrained contract (model picks *nodes to contain*; menu maps node→narrowest action
  deterministically) — a smaller step still inside the north star.

## Sequence

1. **First shippable step (small, no big refactor):** (a) per-node downstream evidence in
   the prompt so the model finally sees the path (reuse the existing accessors; extend the
   judged-surface so downstream evidence changes re-judge; keep the 4-value verdict); (b)
   route `QuarantineWorkload` through the same model gate as the entry (delete the
   unconditional auto-fire; internal-only → propose-only). Bakeoff-A/B'd before merge. This
   alone closes the "model never sees/judges downstream" and "determinism decides the cut"
   violations for the auto-action path.
2. **Extended bakeoff + judge selection** (expect qwen3:4b) → ADR-0033.
3. **The hard refactor (one unit):** `IncidentDecision` type + action-menu render +
   parser/guards + ledger consumes model cuts + `containment_for` demoted + journal v2;
   `prompt.rs` → an `incident/` module dir. ADR-0032 lands here.
4. **Shadow bake** (with a model-chosen-vs-old-deterministic comparator) → arm one class at
   a time.

## Deferred

Node-level containment / new actuator mechanisms (the menu exposes only existing levers); the
agentic loop (approach C — future GPU hardware); model-judged internal-only incidents
(propose-only for now); Falco retirement (unchanged dependency).
