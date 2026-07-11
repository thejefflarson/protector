# 0003. Capability ports: depend on what a tool answers, not which tool it is

- Status: Accepted
- Date: 2026-06-11

## Context

[ADR-0001](0001-async-mitigation-engine.md) named an **evidence bus** — "normalize
what the cluster already emits" — and then, in the same breath, wrote specific
products into the decision: trivy, grype, semgrep, Falco, Linkerd, CISA KEV/EPSS,
cosign, Argo. [ADR-0002](0002-change-driven-ir-loop.md) grounded detection in
observed cluster state but inherited those names. The result is an engine whose
*architecture* is general (a graph, a proof layer, a response loop) but whose
*decisions* are parochial.

That is a problem on three fronts. **Adoption:** a cluster might run Cilium not
Linkerd, Tetragon not Falco, Flux not Argo, grype not trivy, Notation not cosign —
each a hard dependency the design need not have. **Testing:** an engine wired to
named products can't run without the whole stack standing up. **Honesty about the
core:** the graph/proof/response loop genuinely does not care *which* product
produced a fact — it cares only that the fact answers a specific question with a
known degree of trust. Coupling to products hides where the real value is.

There is a trap on the other side, though. protector is deliberately **not a
generic rules engine** (no Kyverno/OPA re-implementation — see the README). A
"plugin architecture" is exactly the kind of thing that drifts into one: open it
up far enough and you've rebuilt a policy DSL where the rules live in
user-supplied plugins and the core means nothing. The decision below exists to
get the decoupling without that drift.

## Decision

We will refactor the engine to depend on a small, fixed set of **typed capability
ports** — each defined by the *question it answers*, not the product that answers
it. The specific tools become **default adapters**: shipped, but swappable, and
never named in the core.

The governing rule:

> **Evidence is pluggable; the rules are not.** The chain grammar (entry →
> reachability → privilege → objective), the proof bar (reachable ∧
> exploited-in-wild ∧ privileged ∧ runtime-corroborated), and "only deterministic
> proof moves privilege" stay hardcoded and opinionated in the core. Only the
> *sources of facts* and the *actuators* are plugins. This is the line that keeps
> a fact-source plugin system from becoming a policy engine.

### The ports

Each port answers one question. The default adapter is what we run today; the
swap-ins are why the port exists.

- **Observer** — *what changed in observed state?* — K8s API informers (base);
  optional sync-event sources (Argo, Flux) as hints, never as the state itself.
- **Reachability** — *can A reach B on port P?* — Linkerd authz; or Cilium,
  Calico, raw NetworkPolicy.
- **Privilege** — *can subject S do verb V on resource R?* — RBAC `can-i`; or
  cloud IAM.
- **Vulnerability** — *what vulns are in this image digest?* — trivy; or grype,
  Clair, SBOM + OSV lookup.
- **ExploitIntel** — *is this CVE exploited in the wild?* — CISA KEV / EPSS; or
  vendor feeds.
- **Trust** — *is this image trusted?* — cosign/sigstore; or Notation.
- **RuntimeEvidence** — *is it happening right now?* — Falco; or Tetragon, eBPF,
  cloud audit logs.
- **Health** — *is service S alive / degraded / halted?* — Prometheus + synthetic
  prober; or another SLO source.
- **Actuator** — *cut this edge / revert it* — Linkerd `AuthorizationPolicy`; or
  deny `NetworkPolicy`, RBAC delete.
- **FixProposer** — *propose a durable fix* — open a PR to the GitOps repo
  (provider-agnostic; Argo/Flux only matter to whoever merges it).

### Three properties this typing buys

1. **Corroboration is structural.** ADR-0001's "trivy ∧ grype agreement" rule
   generalizes to "N providers registered for one port agree." A second runtime
   opinion is a second RuntimeEvidence adapter; the proof layer is unchanged.

2. **Determinism and provenance live in the port contract.** A port does not
   return an opinion — it returns a checkable answer from a real graph/RBAC/feed
   query, eligible to move privilege. "Only deterministic proof moves privilege"
   thereby becomes enforceable at the boundary instead of by convention. (Originally
   this was a **proof-grade / hypothesis-grade** tag on each edge; JEF-365 removed the
   tag — see the amendment below — because every edge is now a deterministic
   observation by construction, so the tag never had a second value to hold.)

3. **Plugin trust is an explicit security boundary**, because anything that builds
   the graph influences what gets cut on a cluster the engine can write to. A
   buggy or hostile Reachability adapter could hide a chain or trigger a bad cut.
   So: **first-party adapters are compile-time trait implementations** (in-process,
   type-safe, simplest); **any untrusted or third-party adapter runs
   out-of-process with its own identity** (gRPC/sidecar) and never shares the
   engine's cluster-write credential. We do not load foreign code in-process.

### Scope discipline

The canonical **graph vocabulary** (node and edge kinds, fact shapes) is the
stable core contract; adapters map their tool's output into it and own nothing
else. We define the port *traits* now but build no dynamic-plugin SDK until a
second real implementation of some port needs it — the trait is the contract;
premature loader machinery is waste. Default adapters are extracted from the
existing tool wiring, not rewritten.

## Consequences

Easier:

- The engine runs against whatever a given cluster already has, and is adoptable
  beyond this one cluster.
- Testable in isolation: fake adapters per port exercise the proof and response
  loops with no real stack.
- Cross-source corroboration is first-class, enforced at the port boundary rather
  than assumed. (The proof-grade/hypothesis-grade split was removed in JEF-365; see
  the amendment below.)
- The core's real value — graph, proof, response — is no longer hidden behind
  product names.

Harder / accepted downsides:

- **A port taxonomy is a commitment.** Pick the seams wrong and adapters fight the
  abstraction; the ten ports above are a bet that the proof bar's four predicates
  plus observe/health/actuate/propose are the natural joints.
- **More indirection** between a tool and its use — worth it for swappability,
  but real.
- **Out-of-process adapters add operational surface** (a second identity, a
  transport, failure modes) the moment we admit an untrusted provider. Deferred,
  not free.
- This does not loosen the core's opinions, and must not be read as doing so: the
  rules stay hardcoded. A contributor who wants a new *rule* still changes the
  core; plugins only add *evidence*. Holding that line is a permanent review
  responsibility, not a one-time decision.

## Amendment (JEF-365): the edge-grade tag is removed

The port contract above described each edge as carrying a **proof-grade /
hypothesis-grade** tag (`Grade`), with the action layer accepting only proof-grade
links. After ADR-0001's JEF-363 amendment removed the model-propose stage, no adapter
or graph builder ever constructed a hypothesis-grade edge — every port in this ADR is
deterministic, so every edge it emits is a deterministic observation. The tag became a
type-level guard against an edge that can no longer exist.

JEF-365 removes `Grade`, `Edge.grade`, and `Edge::is_proof_grade`. The edge contract is
now simpler and unconditional: **every edge is a deterministic observation by
construction, eligible to move privilege.** "Only deterministic proof moves privilege"
holds structurally — the graph contains nothing else. If an untrusted or heuristic
provider is ever admitted (the case the tag anticipated), the seam is reintroducible by
re-adding the grade and restoring the proof-walk filter (see ADR-0001's JEF-365
amendment); removing it now is safe because nothing constructs a hypothesis-grade edge.
