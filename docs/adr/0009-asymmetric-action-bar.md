# 0009. Asymmetric action bar: live evidence acts, latent exposure proposes

- Status: Accepted
- Date: 2026-06-12

> **Amendment (JEF-305, 2026-07-04):** this ADR describes the live-corroboration signal
> as "a live Falco signal" because Falco was the only sensor when it was written. That
> `corroborated-now` predicate is now **tool-agnostic and per-objective**
> ([ADR-0014](0014-behavioral-telemetry-ebpf.md)): any sensor (Falco, Tetragon, the
> first-party eBPF agent) feeds a normalized behavioral port, an *alerting* signal
> corroborates any chain, and the agent's own behaviors corroborate the objective class
> whose ATT&CK tactic they evidence. Read every "Falco" below as "a live corroboration
> signal from whichever sensor is present." The asymmetry decided here is unchanged.

## Context

[ADR-0001](0001-async-mitigation-engine.md) set the bar for automated response as
a strict conjunction: **reachable ∧ exploited-in-wild ∧ privileged ∧
corroborated-now**. We implemented it that way — `meets_action_bar` required both
a KEV foothold (exposed ∧ exploited-in-wild) *and* a live Falco signal.

Treating those two as equal partners in an AND is wrong, because the signals are
not equal in strength:

- **A live runtime signal (Falco) is the strongest evidence we have.** If Falco
  observes a shell or C2 on a workload that has a proven privileged path to an
  objective, the attack is happening *here, now* — independent of whether the CVE
  is on a public catalogue. Requiring a KEV match on top of observed exploitation
  is nearly redundant.
- **A KEV foothold without observed activity is weaker.** An exposed,
  KEV-vulnerable workload with no live signal is a strong reason to *propose a fix
  fast*, but auto-cutting a running service on a CVE that may not even be
  exploitable in this config is exactly the false positive the adjudicator
  (ADR-0013) exists to catch.

So the conjunction is both too strict (it ignores live-only incidents) and falsely
symmetric (it weights latent exposure like live exploitation).

## Decision

Split the bar by evidence type:

- **Auto-eligible ⟺ a proven chain (reachable ∧ privileged) that is
  `corroborated` (live) and adjudicator-`Confirmed`.** Live evidence on a
  privileged path is sufficient on its own; a KEV foothold is *not* required. The
  adjudicator's one-way veto (ADR-0013) is the safety net for a benign signal
  (e.g. a legitimate `exec`) — which is why it becomes load-bearing here.
- **Latent exposure (a KEV foothold, `corroborated == false`) is propose-only.**
  It is surfaced as a real, exploitable front door and routed to a human (and to
  the durable-fix PR), but never auto-cut unattended.
- **Both signals together** is the strongest case and is auto-eligible — the same
  path as live-alone, with higher confidence.

Concretely: `meets_action_bar()` is now `corroborated`; the auto-action gate
(`Mitigation::is_live_corroborated`) is `corroborated ∧ adjudicated` (the KEV
foothold is dropped from the AND). `meets_structural_action_bar()` (the foothold)
remains, now as the *latent-exposure* signal that drives the weaker, propose-only
case.

All the other gates are unchanged and still apply to every auto-action: the class
must be enabled, the action reversible and additive-live, and no currently-alive
workload may be collateral.

## Consequences

Easier:

- Live incidents (observed exploitation) are actionable on their own — the case
  the strict conjunction missed.
- The model adjudicator now earns its keep: it is the false-positive filter that
  makes "Falco-alone is sufficient" safe.
- The weaker, latent case is explicitly a *proposal* — the right disposition for
  "exploitable but not yet being exploited."

Harder / accepted downsides:

- **Falco-alone auto-action leans on the adjudicator.** With no model configured
  (the null adjudicator confirms everything), a benign signal on a privileged path
  could auto-cut once a class is enabled. Mitigated by: default-disarmed, the
  collateral guard, reversibility + self-revert, and the strong recommendation to
  run an adjudicator model in hard mode. Operators enabling a class without an
  adjudicator are accepting more false-positive cuts (that then self-heal).
- **This revises ADR-0001's conjunction.** That bar was the right conservative
  starting point; this is the considered refinement once the signals' asymmetry
  and the adjudicator were both in place.
