# 0011. The model corroborates positively; operator access is out of scope, defended in depth

- Status: Proposed
- Date: 2026-06-13
- Amends: [0008](0008-model-adjudicates-never-authorizes.md), [0009](0009-asymmetric-action-bar.md)

## Context

[ADR-0008](0008-model-adjudicates-never-authorizes.md) made the model a **one-way
veto**: it can downgrade an auto-eligible chain to a human proposal, never the
reverse. That is safe by construction, but it leaves the most valuable judgement
unmade — the positive call deterministic proof *cannot* make: "web is
internet-exposed, reaches a vulnerable pod, which reaches the database — this is
*game over*, act on it." The engine proves the path is reachable and privileged;
whether the combination is genuinely exploitable end-to-end is a judgement. We want
the model to make it.

The fear that blocked this: a live runtime signal ([ADR-0009](0009-asymmetric-action-bar.md))
fires identically for an attacker in a popped container and for the on-call
engineer debugging production — "a terminal shell" looks the same. If the model
promotes on "a shell happened," we quarantine the incident responder.

We considered discriminating operator from attacker by ingesting the kube-apiserver
audit log (who ran `exec`, with what RBAC) and process lineage. **We reject that as
out of scope.** Two reasons make it unnecessary:

1. **Our threat model is remote exploitation** — an external attacker reaching an
   internet-exposed workload. Authenticated, in-cluster operator access is a
   *different plane* with its own defenses (apiserver authn/authz, RBAC, audit,
   SSO, mesh mTLS). Re-adjudicating it here duplicates those controls.
2. **The only live lever is orthogonal to the operator's plane.** The engine's one
   action is a default-deny `NetworkPolicy` (ADR-0010) / ANP edge-cut (ADR-0007) —
   it severs *pod networking*. `kubectl exec`/`debug` ride the apiserver→kubelet
   control-plane stream, not pod networking, so an isolation cut **cannot** sever an
   operator's session. The operator keeps working; only the workload's lateral/
   egress network is cut, reversibly.

That orthogonality is the defense in depth: we do not need to forensically tell an
operator from an attacker, because our action can't lock out the operator and we
only reason about the remote attack surface.

## Decision

### 1. The model is a bidirectional corroboration source (revises ADR-0008)

The adjudicator keeps its veto and the engine gains **promotion** to auto-eligible
for proven, non-corroborated chains (behind the `judgement` opt-in). Two lanes, by
how strong the *deterministic* signal is:

- **Veto (unchanged).** On a runtime-corroborated chain, `Refuted`/`Uncertain`
  downgrades to a proposal.
- **Foothold promotion (deterministic + veto).** A proven chain whose entry is a
  **foothold** — internet-exposed ∧ exploited-in-wild/critical CVE ∧ a proof-grade
  path to the objective (i.e. log4shell on the front door reaching credentials) — is
  **auto-promoted unless the model confidently `Refuted`s it**. `Uncertain` or no
  model leaves the deterministic foothold to govern. This is the load-bearing case
  ("log4j must promote"): the positive signal is deterministic (KEV/critical +
  exposed + reachable, not a model guess), so a weak local model can't block it, and
  the model is back to its safe subtractive role — it can only veto a genuinely
  non-exploitable/mitigated CVE. *Real-world note: ≤3B local models tested all
  abstain (`Uncertain`/`Refuted`) even on log4shell, so making the model the
  positive gate was the wrong mechanism; the deterministic foothold is.*
- **Speculative promotion (model-positive).** A proven chain from an exposed entry
  with **no** CVE foothold can still be raised by an affirmative `Exploitable`
  verdict — the model judging an end-to-end game-over path. Only a real, capable
  (frontier-tier) model emits `Exploitable`; `NullAdjudicator` never does, so this
  lane is dark without one.

Promotion is contained so a wrong or prompt-injected positive cannot do real harm:

- **Proof still establishes the path.** Every edge is proof-grade; `confirm`
  rejects any step without a real graph edge. The model judges severity, never
  topology — it cannot invent a chain.
- **The action is unchanged and orthogonal to operators.** Only the bounded cut
  from ADR-0007/0010: reversible, additive, blast-radius-gated (the reachability
  fail-safe included), self-reverting — and, as above, unable to sever
  control-plane access. A wrong "yes" is at worst a temporary, auto-reverting cut of
  a workload's *network*.
- **Promotion needs an affirmative verdict only a real model emits.** `Exploitable`
  is distinct from the neutral `Confirmed`; `NullAdjudicator` returns `Confirmed`
  and therefore **never promotes**. Absent a model, behaviour is exactly ADR-0009.
- **Promotion runs on the escalation (frontier) tier**, on **fenced** evidence
  (untrusted CVE/rule/node strings delimited and labelled, closing the
  prompt-injection finding).
- **It is its own opt-in:** a `judgement` action class, off by default and separate
  from the runtime-corroborated `network` class.

The guarantee deliberately weakens from *"a model can never cause a cut"* to *"a
model can cause at most a reversible, self-reverting network cut, on a remotely-
exposed workload it judges exploitable."*

### 2. Operator and insider access are out of scope (no audit-log veto)

The engine does **not** ingest the apiserver audit log, do process-lineage
forensics, or otherwise try to distinguish operator from attacker. Legitimate
control-plane access is protected in depth by the platform's existing controls and
by the network/control-plane orthogonality above. protector defends the
**remote-exploitation** plane: an internet-exposed entry, a proof-grade path, and
(for auto-action) either live corroboration (ADR-0009) or a positive model verdict
(§1). Insider and control-plane threats are explicitly not its job.

## Consequences

Easier:

- The engine can close a *proven, game-over* remote-exploitation path fast, even
  with no live signal yet — the positive judgement deterministic proof can't make.
- No audit-log subsystem, no lineage heuristics: operator-safety is **structural**
  (the lever can't touch the control plane), not a fragile detector that would
  false-positive on real incident response.
- Honest scope: remote exploitation, stated plainly, with insider/control-plane
  threats delegated to the layers that own them.

Harder / accepted downsides:

- **The founding guarantee weakens.** "A model can never cause a cut" becomes "a
  model can cause a reversible, self-reverting network cut on a remotely-exposed
  workload." A deliberate, opt-in trade — not the default posture.
- **Prompt injection is re-rated** from suppress-only (ADR-0008) to promote-capable;
  prompt fencing and the frontier tier are now load-bearing.
- **A benign in-cluster signal could still trigger a reversible cut of a workload's
  network** (not an operator's access). Accepted: bounded, self-reverting, and it
  never severs the control plane.
- **We do not defend against insider/control-plane attackers.** Out of scope by
  design; that is the platform's job, not protector's.

## Validation

The e2e gains a remote-exploitation promotion case: an internet-exposed entry on a
proven path to a secret, no live Falco signal, and a positive `Exploitable` verdict
from a stubbed adjudicator → assert the engine promotes, applies the bounded cut,
and self-reverts once the chain stops being proven. The default (no model) must
still apply nothing — promotion requires the affirmative verdict.
