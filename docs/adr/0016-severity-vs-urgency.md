# 0016. Severity (reachability) and urgency (live exploitation) are separate axes

- Status: Accepted
- Date: 2026-06-24
- Amends: [0013](0013-proof-winnows-model-decides.md) §2 (the model still promotes — this fixes what it promotes *on*)

## Context

[ADR-0013](0013-proof-winnows-model-decides.md) is right that **the model promotes**:
its affirmative `exploitable` verdict is the positive authority that **upgrades** a
proven, internet-facing path to act-now. That is the point of the tool and it stays.
The bug this ADR fixes is not *that* the model promotes — it is **what we let it promote
on**.

The adjudicator conflated two questions that are not the same thing:

1. **Severity (reachability)** — *if this were exploited, how bad would it be?* A pure
   property of what the entry can reach: the privilege of the objective (host escape,
   code execution, data destruction), whether the path crosses a tenant boundary, the
   blast radius, the CVE's rating. Knowable from the graph alone, before anything
   happens.
2. **Urgency (exploitation)** — *is this being exploited right now?* A property of live
   runtime evidence: a Falco alert or an agent behavior corroborating the chain's
   technique on this entry (`ProvenChain::corroborated`).

The deterministic "promotion grounds" mixed them. Grounds (3) a high-severity tactic
(PrivEsc/Execution/Persistence/Impact) and (4) a `[NETWORK]` `[cross-ns]` reach are
**severity** signals, yet they gated the model's promotion — so reachability *alone*
handed the model a promotion candidate, and the model upgraded it. The argo case made it
concrete: `argocd-server` reaches a `capability/cluster/delete/persistentvolumeclaims`
(T1485, Impact) and ~120 secrets, **all via RBAC grants or mounts, none over the network,
with no live activity** — pure reachability. The Impact tactic satisfied a severity
ground, the model was asked, and it promoted to `Exploitable`, confabulating a `[NETWORK]`
lateral-movement rationale the `[RBAC-GRANTED]` tags contradict.

Reachability tells you how bad a hypothetical would be. It never tells you the
hypothetical is occurring. Promotion must be driven by **urgency**; reachability drives
**severity**.

## Decision

### 1. The model promotes — on urgency, not reachability (amends ADR-0013 §2)

The model's positive role is unchanged: it is the authority that **upgrades** a proven
path to `exploitable`/act-now. What changes is the **basis**: a promotion must be grounded
in **urgency** — a live runtime signal that exploitation is happening now (`corroborated`:
a Falco alert or an agent behavior matching the chain's technique/foothold). Reachability,
however severe or broad or cross-tenant, is **never** by itself a basis to promote. This
amends ADR-0013 §2, which let CVE-presence/reachability hand the model an uncorroborated
foothold to promote.

### 2. Urgency requires something happening now

No live runtime signal ⇒ no urgency ⇒ nothing for the model to promote to act-now,
however high the severity. A high-severity but quiet path is a **prioritized proposal**,
not an action.

### 3. Reachability computes a Severity score

The severity inputs — objective tactic (host escape / code exec / data destruction rank
high; collection / credential-access lower), cross-tenant reach, privilege, blast radius,
CVE rating — combine into a **severity** on the finding. Severity ranks findings and
prioritizes the durable-fix remediation (e.g. revoke the over-broad RBAC grant). It
changes *how loud and how prioritized* a proposal is — never *whether to act now*.

### 4. The deterministic "promotion grounds" are reclassified

| ground (ADR-0013) | axis | role |
|---|---|---|
| runtime **alert** / live signal | urgency | the model promotes on it (its positive verdict upgrades) |
| high-severity **tactic** (PrivEsc/Exec/Persist/Impact) | severity | severity input; never a promotion basis |
| `[NETWORK]` `[cross-ns]` | severity | severity input; never a promotion basis |
| **CVE** present | severity | severity input; raises severity, not a promotion basis |

The act-now path becomes: **a live signal (urgency) ∧ breach-relevant ∧ the model
affirmatively promotes it.** Reachability/CVE/tactic/tenancy feed severity only.

## Consequences

Easier / better:

- **argo and every broadly-RBAC'd controller stop being `Exploitable`.** With no live
  signal there is no urgency, so reachability alone no longer hands the model a promotion
  candidate. They surface as high-severity, propose-only RBAC-revocation findings, ranked
  by severity.
- **`Exploitable` (promoted) means the model judged live exploitation** — something
  happening now — not "this would be bad if it happened."
- The severity axis gives the dashboard a real prioritization over the propose-only mass,
  instead of a binary that mislabels broad-but-authorized access.

Harder / accepted:

- **A proven foothold with an exploited-in-wild CVE but no observed runtime activity is
  high-severity propose-only, not auto-cut**, until the agent/Falco observes activity.
  This narrows ADR-0013 §2's promote lane to corroborated exploitation. Accepted: the
  posture is reversible, self-reverting actions plus a human on high-severity proposals;
  auto-acting on *un-observed* exploitation is the speculative case we are closing.
- **The model's promotion role and the `judgement` action class STAY** — they are the
  point of the tool. This ADR does not retire them; it grounds them in urgency. Because
  the model promotes, prompt-injection hardening (JEF-106) remains important: a crafted
  input must not trick the model into upgrading a path that is not being exploited.
- **Urgency now depends on runtime-signal coverage** (the eBPF agent + Falco). Gaps mean
  real exploitation could go un-promoted; this raises the priority of broadening agent
  probes and keeping Falco as a corroboration source until they land.
