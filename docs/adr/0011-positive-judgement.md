# 0011. The model corroborates positively; operator access is out of scope, defended in depth

- Status: Superseded in part by [0013](0013-proof-winnows-model-decides.md)
- Date: 2026-06-13
- Amends: [0009](0009-asymmetric-action-bar.md)
- Superseded: §1's "deterministic-promote unless the model refutes" is replaced by
  [0013](0013-proof-winnows-model-decides.md) — the foothold lane is now a **positive
  gate** (a cut requires the model's affirmative `exploitable` verdict; no
  model/uncertain/refuted ⇒ propose-only). CVE *presence* no longer auto-cuts. §2
  (operator access out of scope; control-plane orthogonality) stands.

> **Superseded note (2026-06-14):** This ADR made the foothold a deterministic
> auto-cut with the model as a veto — "log4j must promote with no model." We reversed
> that in [0013](0013-proof-winnows-model-decides.md): a CVE being *present* is not
> proof it can be *exercised*, so the model must affirmatively judge it exploitable
> before a cut. Read §1 below as history; the operator-scope reasoning (§2) remains
> current.

## Context

ADR-0008 (retracted) made the model a **one-way
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

**The model is consulted only where there is evidence to weigh** — a CVE foothold
or a runtime signal. Asking a model to judge an evidence-empty chain (`(no CVE),
(no runtime)`) is asking it to invent a threat from nothing; empirically that is
exactly where small models flail (over-eager *or* timid, depending on framing). A
chain with neither is a deterministic *latent/structural proposal* and is never
sent to the model. Two evidence-bearing lanes, behind the `judgement` opt-in for the
non-corroborated one:

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
  non-exploitable/mitigated CVE.

*Real-world note (the `engine::adjudicate` competence probe against local Ollama):
with a hedging prompt, ≤3B models abstain even on log4shell; with a decisive
analyst prompt they over-promote evidence-empty paths. Anchoring the prompt on the
evidence — and never sending an evidence-empty chain at all — got `qwen3:1.7b` and
`granite4:3b-h` to classify CALIBRATED (promote log4shell, refuse the empty case),
and no model wrongly refuted a real foothold. A model **replaces the analyst** on
the evidence-bearing judgement; deterministic proof carries the rest. There is no
speculative "no-evidence game-over" lane — that was a misframing that fed the model
nothing and asked for a verdict.*

Promotion is contained so a wrong or prompt-injected positive cannot do real harm:

- **Proof still establishes the path.** Every edge is proof-grade; `confirm`
  rejects any step without a real graph edge. The model judges severity, never
  topology — it cannot invent a chain.
- **The action is unchanged and orthogonal to operators.** Only the bounded cut
  from ADR-0007/0010: reversible, additive, blast-radius-gated (the reachability
  fail-safe included), self-reverting — and, as above, unable to sever
  control-plane access. A wrong "yes" is at worst a temporary, auto-reverting cut of
  a workload's *network*.
- **The promotion signal is deterministic, not a model guess.** A foothold promotes
  on the proven facts (exposed ∧ KEV/critical ∧ reachable); the model only *vetoes*
  (`Refuted`). `NullAdjudicator` confirms, so a foothold promotes with no model at
  all — which is the point ("log4j must promote") and safe, because the trigger is
  deterministic and the action reversible.
- **Evidence is fenced** in the prompt (untrusted CVE/rule/node strings delimited and
  labelled), closing the prompt-injection finding; a capable model is the
  escalation tier for the veto.
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

The e2e proves the log4j case end-to-end: an internet-exposed `web` with a CRITICAL
`CVE-2021-44228` (a trivy `VulnerabilityReport`) reaching a secret, **no model and no
Falco signal** → the deterministic foothold auto-promotes, the engine applies the
bounded cut and labels it `foothold — auto-eligible`, then self-reverts once the
chain stops being proven. (The CVE attaches only because of the canonical image-key
fix — the pod's short ref and the scanner's qualified ref resolve to one node.) The
model's evidence-bearing judgement is covered by the `engine::adjudicate` competence
probe rather than the e2e, since it needs a live model.
