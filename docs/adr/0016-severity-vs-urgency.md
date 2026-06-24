# 0016. The breach model: prove chains, enrich them, the model decides and isolates until clear

- Status: Accepted
- Date: 2026-06-24
- Amends: [0013](0013-proof-winnows-model-decides.md), [0011](0011-positive-judgement.md), [0009](0009-asymmetric-action-bar.md)

## Context

We kept layering structure on the adjudicator — first deterministic "promotion
grounds," then a severity-vs-urgency split — and kept producing the wrong call. The
clearest failure: `argocd-server`, which reaches a `delete/persistentvolumeclaims`
capability and ~120 secrets entirely through authorized RBAC grants and mounts with no
live activity, was judged `Exploitable` because a deterministic ground (a high-severity
tactic) *forced the model a promotion candidate* and the model went along with it,
confabulating a `[NETWORK]` rationale the tags contradict. The deterministic gates were
pre-deciding the thing only the model should decide.

The model is simpler than the scaffolding we built around it. Three principles:

1. **Find provable attack chains** from configuration *and* actual communication. A path
   is real only when the config grants it and/or observed traffic demonstrates it; the
   proof layer cannot invent an edge (ADR-0002/0003/0004).
2. **Enrich those chains** with CVEs, static analysis, and behavioral (runtime) data —
   what is vulnerable, what is reachable in code, and what is happening now.
3. **The model decides whether there is a breach** given (1) and (2), and **makes the cuts
   necessary to isolate the workload, until (1) and (2) clear.** The model is the decider
   and the actor; the isolation persists while the breach condition holds and lifts when
   the chain or its enrichment clears.

## Decision

### 1. The deterministic layer does proof and enrichment only — it never pre-decides breach

The engine's deterministic job is principles (1) and (2): build provable chains and attach
evidence (CVEs, static analysis, behavioral signals). It does **not** decide breach. This
**retires** the `any_promotion_ground` / `guard_unjustified_exploitable` gating and the
severity-vs-urgency axes as a decision mechanism — they encoded analyst heuristics as
deterministic gates that pre-empted the model.

### 2. The model decides breach holistically, and promotes

Given the proven chain (1) and its full enrichment (2), the model decides **breach or not
a breach** — one holistic call per internet-facing entry over everything it reaches. It
**promotes** (decides breach → act) and refutes (no breach); ADR-0013's positive role and
the `judgement` action class stand. The model cannot invent a path — every edge is
proof-grade — so it judges a *proven* topology against real evidence, never the topology
itself.

### 3. On a breach, the model isolates the workload until the condition clears

The action is the reversible, additive, blast-radius-gated cut that isolates the workload
(ADR-0007/0010 — it cannot touch the control plane). The cut **persists until (1) or (2)
clears**: the chain is removed (config/comms change) or the enrichment clears (the CVE is
patched, the behavior stops). Then it self-reverts. This refines ADR-0009's
self-reverting action — the revert condition is "the breach condition cleared," tied to
the live proof+enrichment, not a fixed timer.

## Consequences

- **argo falls out correctly.** Provable chains via authorized RBAC (1); enrichment (2) is
  no CVE, no behavioral signal. The model decides *no breach* — no deterministic ground
  forces it. It stays context in `/findings`, not an action.
- **The engine gets simpler.** Proof and enrichment are deterministic and testable; the
  judgement is the model's, holistically. We stop maintaining heuristic gates that
  approximated the model's job.
- **`Exploitable` means the model judged a real breach** from the chain and its evidence —
  and the isolation it triggers lasts exactly as long as that breach condition does.
- **Safety is preserved.** The model decides over *proven* chains (it can't fabricate a
  path) using *real* enrichment; the only lever is the reversible, blast-radius-gated,
  self-reverting isolation. A wrong call is at worst a temporary, auto-lifting cut of one
  internet-exposed workload's network.
- **Enrichment coverage is load-bearing.** The decision is only as good as (2): CVE scan,
  static reachability (M2), and behavioral telemetry (eBPF agent + Falco). Gaps weaken the
  model's input. Prompt-injection hardening (JEF-106) matters precisely because the model
  decides on (2)'s evidence and acts on it.
