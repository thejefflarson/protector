# 0006. Build the substrate; treat KubeHound/IceKube as catalogue and optional provider

- Status: Accepted
- Date: 2026-06-11

## Context

A prior-art scan found the attack-path-graph layer protector builds — a graph of
the cluster plus a BFS/min-cut over reachability and privilege edges — is a
solved, crowded space: [KubeHound](https://kubehound.io/) (Datadog, JanusGraph),
[IceKube](https://labs.reversec.com/tools/icekube) (Reversec, Neo4j, ~25
techniques), Krane, Konstellation, and every CNAPP. KubeHound in particular ships
a documented 26-edge catalogue with years of hardening on the genuinely hard part:
the container-escape and RBAC-escalation primitives (which capability + which
mount + which host namespace yields which escape).

That raised a real build-vs-adopt fork. Mapping KubeHound onto the ATT&CK
Containers matrix sharpened it:

- KubeHound covers the **path-building** tactics (Privilege Escalation/escape,
  Execution, Credential Access, Lateral Movement) — *how* an attacker climbs from
  a foothold to a powerful position.
- It does **not** model Persistence, Impact, or Stealth/Defense-Evasion — the
  *terminal goals* and *behaviors*, because those are not relationships between
  two cluster resources and so do not fit an attack-graph edge model.

So KubeHound and protector's objective layer are complementary, not redundant:
KubeHound = the edges, protector adds the destinations it can't express (Impact,
Persistence as objectives) and routes behavioral tactics to the RuntimeEvidence
port. And critically, ADR-0003's capability-port architecture means this is **not
an irreversible choice** — a graph engine is exactly what a `Reachability` /
`Privilege` / escape port is meant to abstract.

## Decision

We will **build the substrate ourselves**, while treating the existing tools as a
catalogue and a deferred option, not as something to reimplement blindly:

1. **Build the graph, proof, and response substrate in-tree.** It fits the
   project's minimal-dependency ethos (the webhook deliberately avoids heavy
   crates), keeps the proof layer maximally auditable (hand-walked, deterministic —
   the thing the whole "only proof moves privilege" rule depends on), and the
   differentiated layers (change-driven loop, proof-gated tiered-LLM,
   self-reverting min-cut, mitigation-as-debt) are ours regardless of who supplies
   the edges.

2. **Adopt KubeHound's and IceKube's technique catalogues as a specification,
   not their code or nomenclature.** Their enumerations are the authoritative list
   of what to detect; we map each into MITRE ATT&CK (ADR-0005) and implement
   against that. Where our coverage is coarser (e.g. one Escape-to-Host edge vs
   KubeHound's ~13 escape primitives), their catalogue is the checklist we work
   down — escape primitive by escape primitive.

3. **Preserve the port boundary so a KubeHound-backed adapter stays a future
   option.** If reimplementing the long tail of escape primitives proves not worth
   it, a `Reachability`/`Privilege`/escape adapter that ingests KubeHound's
   computed edges as proof-grade edges can be added without touching the proof or
   response layers. We do not foreclose adoption; we defer it.

What we explicitly will **not** do: re-derive the escape library from first
principles while ignoring KubeHound's, or invent edge names where ATT&CK or a
tool's catalogue already has them.

## Consequences

Easier:

- Full control over the substrate, no heavy graph-DB dependency, and a proof layer
  we can audit line by line — which is what the action-gating guarantee rests on.
- The differentiated work (the loop and response discipline) is unblocked now
  rather than waiting on integrating someone else's engine.
- The port boundary keeps adoption reversible: we can swap in KubeHound later as an
  edge provider with no proof/response rework.

Harder / accepted downsides:

- **We re-solve a solved problem in part.** The escape-primitive long tail is real
  work that already exists elsewhere; we accept doing it (guided by KubeHound's
  catalogue) for control and auditability, and we log coverage gaps rather than
  pretend completeness.
- **Catalogue drift.** KubeHound, IceKube, and ATT&CK all evolve; our mapping is a
  maintained translation, and a technique they add is a gap until we port it.
- **It would be faster to adopt.** If escape coverage becomes the bottleneck, this
  decision should be revisited via the port boundary it deliberately preserves.
</content>
</invoke>
