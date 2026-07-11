# 0005. Objectives are ATT&CK outcomes, not just secrets

- Status: Accepted
- Date: 2026-06-11

## Context

The proof layer ([ADR-0002](0002-change-driven-ir-loop.md), Question 2) currently
recognizes exactly one objective: **read a Secret.** In
[MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/)
terms that is a single technique (Unsecured Credentials, T1552) in a single
tactic (Credential Access, TA0006) — one cell of a ten-tactic matrix. An incident
is an adversary *achieving an objective*, and the matrix is the field's actual
enumeration of the objectives that matter in a container platform. Hardcoding
"objective = secret" means we can only ever prove one kind of incident and are
blind to the rest — most importantly container escape and RBAC self-escalation,
the two that turn a single compromised pod into a compromised cluster.

Studying the matrix surfaced two structural facts that shape the design:

1. **The techniques sort into the three roles the proof model already has.**
   *Entry* (Initial Access TA0001: Exploit Public-Facing Application T1190, Valid
   Accounts T1078). *Movement* (Lateral Movement T1550; Execution as a pivot —
   Deploy Container T1610, Container Administration Command T1609; Discovery
   TA0007 as reconnaissance over the graph). *Objective* (the high-value
   end-states). We do not need a new model — we need a richer objective set.

2. **Objectives come in just two structural shapes**, which is what lets us
   generalize without rewriting the BFS:
   - **Reach a high-value node** — a Secret (Credential Access), or a **Host**
     via container escape (Escape to Host, T1611). We already model Host nodes;
     escape is the marquee container attack and we simply do not target it yet.
   - **Hold a dangerous capability** — an Identity whose RBAC permissions are
     themselves the goal: `pods/create` (Deploy Container T1610, Resource
     Hijacking T1496), `pods/exec` (Container Administration Command T1609),
     rolebinding create/patch or `escalate`/`bind`/`*` (Additional Container
     Cluster Roles T1098/006 — self-escalation to admin), `delete` on PVCs/secrets
     (Data Destruction T1485, Inhibit System Recovery T1490), SA-token issuance
     (Steal Application Access Token T1528 → Use Alternate Auth Material T1550),
     and creating webhooks/daemonsets/cronjobs (Persistence T1525, T1543/005,
     T1053/007).

A third fact is a boundary, not a shape: ATT&CK techniques split into
**structural** (provable from the graph — who can reach or do what) and
**behavioral** (only visible at runtime — Masquerading T1036, Indicator Removal
T1070, Build Image on Host T1612, Brute Force T1110). The proof layer can only
prove structural objectives; the behavioral techniques are precisely what the
RuntimeEvidence port (Falco/Tetragon) is for. The graph proves a path *exists*;
runtime proves it is being *walked*.

## Decision

We will generalize "objective" into an **ATT&CK-mapped taxonomy** and target the
full set of structurally-provable objectives, leaving the proof walk itself
unchanged.

1. **An `Objective` is tagged with its ATT&CK (tactic, technique).** A
   `ProvenChain` records which objective it achieves and therefore which technique
   and tactic — so Q1 can say "this change opened a new path to *Privilege
   Escalation via T1611*", and chains can be prioritized by tactic (Impact and
   Privilege Escalation outrank Discovery).

2. **Objectives are recognized by a small registry**, the same pattern as the
   capability ports (ADR-0003): each recognizer marks graph nodes (or capability
   nodes) as objectives of a given technique. New objectives drop in without
   touching the BFS. The proof layer targets the union of recognized objective
   nodes and tags each chain with what it reached.

3. **The vocabulary grows to express the two shapes:**
   - **Capability nodes.** `can-do` edges must target more than Secrets. A
     Capability node is a (verb, resource-type, scope) — e.g. `pods/create@ns`,
     `rolebindings/*@cluster`. Identity →`can-do`→ Capability. Reading a secret
     becomes the special case where the resource is a concrete Secret object;
     dangerous capabilities are Capability nodes that recognizers mark as
     objectives. This keeps everything in the graph so the walk stays uniform.
   - **An escape-to-host edge.** A new Workload → Host relation, proof-grade when
     the pod's securityContext enables escape (privileged, hostPID/hostNetwork,
     hostPath mounts, escape-enabling capabilities). A small adapter reads
     securityContext; Host becomes a reach-a-node objective.

4. **The proof walk is untouched.** It still BFSes movement edges from each entry;
   it just (a) targets a richer objective set and (b) labels each chain with the
   technique achieved. Minimal-cut computation is unchanged.

5. **Structural vs behavioral is a firm boundary.** The proof layer proves
   structural objectives only. Behavioral techniques are not faked as graph facts;
   they enter as RuntimeEvidence corroboration — the "now" half of the action bar.

**Scope discipline (what to build first).** Not all ~40 techniques at once. The
first objective expansion targets the highest-value, graph-expressible outcomes:
Escape to Host (T1611), RBAC self-escalation (T1098/006), the execution/hijacking
capabilities (T1610/T1609/T1496), and Credential Access (already built). Impact
and Persistence capabilities follow. Behavioral techniques are explicitly deferred
to the RuntimeEvidence port. Every objective we do *not* yet recognize is named, so
the coverage gap is visible rather than silent.

## Consequences

Easier:

- We can prove the incidents that actually matter in containers — escape and
  self-escalation — not just credential theft.
- Findings speak ATT&CK, which is the shared language of detection and response,
  and gives a principled basis for prioritizing chains by tactic.
- Capability nodes unify privilege: "read secret X" and "create pods" are the same
  kind of edge to different targets, and a capability can be both a stepping stone
  and a goal.
- The structural/behavioral split gives a clean, honest division of labor between
  the proof layer and the RuntimeEvidence port.

Harder / accepted downsides:

- **The privilege model expands well beyond secret reads.** The RBAC adapter must
  resolve arbitrary verbs/resources into Capability nodes, and we must curate
  *which* capabilities are objectives (and at which ATT&CK technique) — a
  judgement that needs maintenance as the matrix and Kubernetes evolve.
- **Capability nodes risk graph blow-up.** A naive (verb × resource × namespace)
  expansion is large; recognizers must mint Capability nodes only for the
  security-relevant ones, not the full cartesian product.
- **Escape detection from securityContext is heuristic.** The signals (privileged,
  hostPath, capabilities) are strong indicators of escape *potential*, not proof
  of escape — consistent with ADR-0001's "we prove preconditions, not
  exploitation." The escape edge is proof-grade for *potential*, and the action
  bar still requires runtime corroboration before any response.
- **An objective taxonomy is a living artifact.** ATT&CK is versioned and
  changes; our mapping is a maintained translation, not a one-time table.
