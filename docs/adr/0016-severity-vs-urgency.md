# 0016. Severity (reachability) and urgency (live exploitation) are separate axes; only urgency may auto-act

- Status: Accepted
- Date: 2026-06-24
- Amends: [0013](0013-proof-winnows-model-decides.md) §2, [0011](0011-positive-judgement.md), [0009](0009-asymmetric-action-bar.md)

## Context

[ADR-0013](0013-proof-winnows-model-decides.md) created two lanes to auto-eligibility:
a **corroborated** lane (a live runtime signal, model vetoes) and a **foothold** lane
(no live signal — the model's affirmative `exploitable` verdict *promotes* an
otherwise-latent chain). The deterministic "promotion grounds" that decide whether to
even ask the model are: (1) a CVE present, (2) a runtime alert, (3) an objective whose
ATT&CK tactic is PrivEsc/Execution/Persistence/Impact, (4) a `[NETWORK]` objective that
is `[cross-ns]`.

In practice that lane conflated two questions that are not the same thing:

1. **Severity (reachability)** — *if this were exploited, how bad would it be?* A pure
   property of what the entry can reach: the privilege of the objective (host escape,
   code execution, data destruction), whether the path crosses a tenant boundary, the
   blast radius, the CVE's rating. Knowable from the graph alone, before anything
   happens.
2. **Urgency (exploitation)** — *is this being exploited right now?* A property of live
   runtime evidence: a Falco alert or an agent behavior corroborating the chain's
   technique on this entry (`ProvenChain::corroborated`).

Grounds (3) and (4) are **severity** signals wired into the **urgency** decision: a
high-severity tactic or a cross-tenant reach was treated as a reason to *act now*, with
no live signal. The argo case made it concrete — `argocd-server` reaches a
`capability/cluster/delete/persistentvolumeclaims` (T1485, Impact) and ~120 secrets,
**all via RBAC grants or mounts, zero over the network**. Every objective is
authorized-by-design, yet the Impact tactic alone satisfied ground (3), the model was
asked, and `granite4:3b-h` returned `Exploitable` — confabulating a `[NETWORK]`
cross-namespace lateral-movement rationale that the actual `[RBAC-GRANTED]` tags
contradict.

Reachability tells you how bad a hypothetical is. It never tells you the hypothetical is
occurring. Treating "severe" as "urgent" manufactures act-now findings for every
broadly-privileged controller in a normal cluster.

## Decision

We separate the two axes and let **only urgency** drive action.

### 1. Urgency requires a live runtime signal — "something happening now"

Auto-action eligibility (the `exploitable` / promote outcome and `meets_action_bar`)
requires runtime corroboration: a Falco alert or an agent behavior matching the chain's
technique or foothold (`ProvenChain::corroborated`). On this lane the model's role is the
**veto** ([ADR-0009](0009-asymmetric-action-bar.md)): is the live signal a genuine
exploit, or benign activity? A non-confirming verdict demotes it to a proposal.

### 2. A model `exploitable` verdict no longer promotes an uncorroborated chain (amends ADR-0013 §2)

Reachability — however severe, however broad, however cross-tenant — never makes a chain
auto-eligible on its own. Without a live signal, a breach path is **propose-only**. This
reverses ADR-0013's positive-promotion thesis for the uncorroborated lane: the model does
not "authorize" a latent foothold to auto-cut. ADR-0013's insight (presence ≠
exploitability) stands; we go one step further — even the model's *belief* in
exploitability is not act-now without live evidence.

### 3. Reachability computes a Severity score, not a promotion

The severity inputs — objective tactic (host escape / code exec / data destruction rank
high; collection / credential-access lower), cross-tenant reach, privilege, blast radius,
CVE rating — combine into a **severity** on the finding. Severity ranks findings and
prioritizes the durable-fix remediation (e.g. revoke the over-broad RBAC grant, remove
the mount). It changes *how loud and how prioritized* a proposal is — never *whether to
act now*.

### 4. The deterministic "promotion grounds" are reclassified

| ground (ADR-0013) | axis | new role |
|---|---|---|
| runtime **Alert** | urgency | the corroboration signal — gates act-now (veto lane) |
| high-severity **tactic** (PrivEsc/Exec/Persist/Impact) | severity | severity input; never promotes |
| `[NETWORK]` `[cross-ns]` | severity | severity input; never promotes |
| **CVE** present | severity (mostly) | severity input; an exploited-in-wild CVE raises severity but still needs a live signal to be urgent |

The act-now gate becomes: **corroboration present ∧ breach-relevant ∧ model does not veto.**
Reachability/CVE/tactic/tenancy feed severity only.

## Consequences

Easier / better:

- **argo and every broadly-RBAC'd controller stop being `Exploitable`.** No live signal ⇒
  no urgency ⇒ the model is not even asked, so it cannot confabulate. They surface as
  high-severity, propose-only RBAC-revocation findings, ranked by severity.
- **`Exploitable` means what it says:** exploitation is happening, corroborated by a
  runtime signal. The verdict stops being a severity proxy.
- The severity axis gives the dashboard a real prioritization over the propose-only mass,
  instead of a binary exploitable/refuted that mislabels broad-but-authorized access.

Harder / accepted:

- **A genuine internet-facing foothold with an exploited-in-wild CVE but no observed
  runtime activity is propose-only (high severity), not auto-cut**, until the agent/Falco
  observes activity. Accepted: the posture is reversible, self-reverting actions plus a
  human on high-severity proposals; auto-acting on *un-observed* exploitation is exactly
  the speculative lane we are closing.
- **The `judgement` opt-in action class (promote-on-model-verdict) loses its lane** and is
  retired or repurposed; promotion is now corroboration-gated, not a separate speculative
  class. (Implementation detail tracked in the follow-up.)
- **Urgency now depends on runtime-signal coverage** (the eBPF agent + Falco). Gaps in
  corroboration mean real exploitation could go un-promoted; this raises the priority of
  broadening agent probes and keeping Falco as a corroboration source until they land.
