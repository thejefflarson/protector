# 0008. The model adjudicates (one-way veto); it never authorizes, and never exploits

- Status: Accepted — amended by [0011](0011-positive-judgement.md), [0013](0013-proof-winnows-model-decides.md)
- Date: 2026-06-12

> **Later doctrine (see [0013](0013-proof-winnows-model-decides.md)):** the "one-way
> veto, never authorizes" rule below was the starting point. The model is now also a
> **positive gate** on the foothold lane — on a proven, internet-facing foothold it
> *must* affirmatively judge `exploitable` for a cut (otherwise propose-only). It
> still never invents topology (proof owns that) and never exploits; what changed is
> that proof *winnows* and the model *decides exploitability*. The veto role here
> remains current for the runtime-corroborated lane.

## Context

We wired a model **hypothesis source** (ADR-0001's "propose") that emits candidate
chains the deterministic gate confirms. At this cluster's scale that is largely
redundant: the deterministic enumerator already finds every structural chain, so
the model's confirmed proposals are mostly de-duplicated away. Its real,
non-redundant value is *judgment*, on two questions a deterministic check cannot
answer well:

- **Is a KEV-listed CVE actually exploitable in this deployment?** CISA KEV says a
  CVE is exploited *in the wild, somewhere*. It does not say whether *this* image
  version, with *this* config and reachable code path, is actually exploitable, or
  already mitigated. `exploited_in_wild` from KEV is therefore an over-approximation.
- **Is a Falco runtime signal actually an attack?** A "terminal shell in container"
  fires for an adversary and for a benign `kubectl exec` or an init script alike.
  Corroboration that can't tell them apart is noisy.

These are exactly the judgments that reduce false positives and contextualize the
action bar. But there is a hard constraint: letting a model *decide to act* would
break the platform's founding rule — "a model may propose; only deterministic
proof may move privilege." A hallucinating or sycophantic model that could
*authorize* an action is precisely the failure mode the whole design exists to
prevent. And the model must not "exercise an exploit" to settle exploitability:
that is the named bound — we prove preconditions, not exploitation.

## Decision

The model's primary role is **adjudication**, and its verdict is **one-way: it can
only downgrade, never authorize.**

1. **Adjudication runs only on a chain that already meets the deterministic action
   bar** (reachable ∧ exploited-in-wild ∧ privileged ∧ corroborated-now). The
   model is asked: given this chain and its evidence (the entry workload, its
   image and the KEV CVE, the Falco rule that fired, the objective), is this a
   *real, contextually-exploitable attack* — or a false positive?

2. **The verdict can only subtract permission.** `Refuted` or `Uncertain` demotes
   an otherwise-eligible auto-action to a human proposal. The model can never turn
   a non-eligible finding into an action. So a wrong model causes at worst a missed
   auto-action (still surfaced to a human); it can never manufacture a cut. The
   adjudicator **defaults to skeptic** — refute when unsure — and the no-model
   default is `Confirmed`, so absent a model the deterministic bar alone governs
   (behaviour unchanged).

3. **The model never exercises an exploit.** It reasons about exploitability from
   context; it does not run code against the target. Exploitability-in-context is a
   *judgment that gates the auto-action*, not a *proof that changes the chain* — the
   proof remains the deterministic preconditions.

4. **Adjudication is the natural Tier-2 escalation point.** A high-stakes,
   ambiguous, proven chain (the existing `escalation_tier`) is exactly where a
   frontier model's second opinion is worth the cost — on redacted, structured
   input, with a human in the loop.

The hypothesis *source* (propose) stays — it is safe (gated by confirmation) and
earns its keep at larger scale — but adjudication is where the model adds value
here, and it is safe by construction because it is subtractive only.

## Consequences

Easier:

- The model's value is now clear and non-redundant: contextual exploitability and
  false-positive reduction, the two things deterministic checks do worst.
- Safe by construction: a one-way veto cannot cause a bad action, so the founding
  rule survives a model that is wrong, flattering, or non-deterministic.
- KEV's over-approximation and Falco's noise get a contextual filter without
  either becoming load-bearing for *authorization*.

Harder / accepted downsides:

- **A wrongly-refuting model suppresses real auto-actions.** Accepted: it is the
  safe direction (the finding still reaches a human), and skeptic-default trades
  auto-action coverage for never acting on a false positive.
- **Adjudication adds model calls**, bounded to chains that already meet the full
  action bar (a small set, by design).
- **"Exploitable in context" is a judgment, not proof.** It informs the
  auto-action decision; it must never be mistaken for, or substituted into, the
  deterministic proof. Holding that line is a permanent review responsibility.
</content>
</invoke>
