# 0013. Proof winnows the search space; the model makes the exploitability call

- Status: Accepted
- Date: 2026-06-14
- Supersedes the foothold mechanism of [0011](0011-positive-judgement.md) §1
- Amends: [0009](0009-asymmetric-action-bar.md)

> Note: an earlier ADR-0008 ("the model adjudicates with a one-way veto; it never
> authorizes") was **retracted** — this ADR is the current statement of the model's
> role. The model authorizes positively here: on a proven, internet-facing foothold
> its affirmative `exploitable` verdict is what moves privilege.

## Context

Two earlier framings drifted from what this tool is actually for, and we kept
talking past each other because of it.

1. **[ADR-0011](0011-positive-judgement.md) made the foothold lane
   "deterministic-promote unless the model refutes."** A proven foothold
   (internet-exposed ∧ critical/KEV CVE ∧ reachable) auto-cut *by rule*, and the
   model could only veto. We chose that because small local models were flaky and
   "log4j must promote." But it inverts the whole point: **a CVE being *present* in
   an image is not proof it can be *exercised*.** log4shell in a layer means nothing
   if the vulnerable code path is unreachable, the app never logs attacker input, or
   the endpoint isn't wired. Deciding "present ∧ exposed ⇒ cut" is exactly the
   pattern-match a model is supposed to *replace*, not defer to.

2. **The dashboard flagged every internal access path** — any workload that can read
   a secret or reach the database — as a finding. That is the normal shape of a
   Kubernetes cluster (assume-breach blast radius), not breach potential, and it
   buried the signal under ~1000 rows even on a small cluster.

The architecture we actually want, stated plainly:

> **Deterministic proof winnows the cluster down to a handful of candidate breach
> paths. The model makes the judgement a human analyst would: is this candidate
> genuinely exploitable, end to end, from the internet — or not.**

Proof is the search-space reducer; the model is the analyst. Neither alone is the
product.

## Decision

### 1. Breach-relevance gates what is even a finding

A proven chain is a *finding* (and a candidate for action) only when its **entry is
internet-facing** (`ProvenChain::is_breach_relevant`) — an origin an external
attacker can actually start from. An internal-only path (a control-plane workload
that can read a secret, a backend that can reach the DB) is the assume-breach
blast-radius map: still proven and still queryable in `/findings`, but it is
*context*, not a to-do. This is the search-space winnowing made explicit, and it is
what hands the model a short candidate list instead of the whole graph.

### 2. The foothold lane is a positive gate — the model decides (supersedes 0011 §1)

On a proven foothold, a cut now **requires the model's affirmative `exploitable`
verdict**. The earlier "promote unless `Refuted`" is reversed:

| model verdict (foothold lane) | outcome |
|---|---|
| `exploitable` (names the break-in primitive) | **promote → auto-eligible cut** |
| `refuted` / `uncertain` / **no model** | **propose-only** (surface for a human; do not cut) |

`NullAdjudicator` returns `Confirmed` (not `Exploitable`), so **with no model a
foothold is propose-only** — the engine never cuts on mere CVE presence. The model's
positive determination is the trigger; the deterministic layer only decides *what to
ask about*, never *whether it's exploitable*.

The runtime-corroborated lane ([ADR-0009](0009-asymmetric-action-bar.md)) is
unchanged: a *live* signal is genuine evidence of activity, so it stays auto-eligible
with the model as a veto. The distinction is principled — a live signal is "something
is happening now"; a CVE is "something *might* be possible," and the latter is the
judgement the model owns.

### 3. The auto-action bar also requires breach-relevance

`meets_action_bar` and `Mitigation::is_live_corroborated` require an internet-facing
entry in addition to corroboration/promotion. The engine auto-acts only on
**remote-exploitation** paths; it will not auto-cut internal-only activity even when a
Falco signal corroborates it. Dashboard and actuator agree on the threat surface.

## Why this is still safe (proof remains the floor)

The founding discipline is refined, not abandoned. "Only proof may move privilege"
becomes **"proof establishes what is *possible*; the model judges what is
*exploitable*; privilege moves only on their conjunction."**

- **The model can never invent a path.** Every edge is proof-grade; `confirm`
  discards any step without a real graph edge. The model judges severity of a
  *proven* topology, never the topology.
- **The action is unchanged and contained.** The only live lever is the reversible,
  additive, blast-radius-gated, self-reverting network cut (ADR-0007/0010), which
  cannot touch the control plane. A wrong "exploitable" is at worst a temporary,
  auto-reverting cut of one workload's network.
- **Evidence is fenced** as untrusted data in the prompt (CVE ids, rule names, node
  keys), in both the adjudicator and the hypothesis builder.
- **It is opt-in** (`judgement` action class, off by default, separate from
  `network`).

The guarantee is now: *a model can cause at most a reversible, self-reverting network
cut on an internet-exposed workload it affirmatively judges exploitable.*

## Consequences

Easier / better:

- The dashboard shows breach potential, not cluster topology — two graph sections
  (active/proposed remediations; possible attack paths per endpoint), no category
  noise. The internal-access mass collapses to context.
- The model does the job it's for: presence is no longer mistaken for
  exploitability. `granite4:3b-h` probed CALIBRATED on the real prompt (`exploitable`
  for log4shell naming the CVE; `refuted` for the no-evidence case).

Harder / accepted:

- **A foothold with no model is propose-only, not auto-cut.** This reverses
  "log4j must promote with no model" from [ADR-0011](0011-positive-judgement.md). It
  is the correct trade: without an analyst, CVE presence is a proposal, not an
  action. The deterministic floor's role shrinks to winnowing + a propose-only
  fallback.
- **The model is now load-bearing for the foothold cut** (it must affirm). Prompt
  fencing and a calibrated model matter more, not less; an absent/weak model
  degrades safely to propose-only.

## Validation

`scripts/e2e.sh` proves the corrected path end to end against a real k3d cluster:
deterministic proof winnows to the log4shell candidate, then —

- **No model:** the foothold is proven but **propose-only** — the engine asserts *no*
  NetworkPolicy is applied (presence does not cut).
- **Real model** (`granite4:3b-h` via `host.docker.internal`): the model examines the
  proven path, returns `exploitable`, and *that verdict* promotes the foothold → the
  engine cuts. The model's verdict is dumped from the pod logs.
- **Self-revert:** removing the durable allow stops the chain proving; the
  model-driven cut reverts.
