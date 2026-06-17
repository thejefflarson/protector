# 0001. Async mitigation engine: propose / prove / respond, local-first

- Status: Accepted
- Date: 2026-06-11

## Context

protector today is a synchronous validating admission webhook: it decodes an
`AdmissionReview`, runs self-contained policies (image signatures, mesh
injection) against the request body alone, and replies allow/deny in
milliseconds. That model is the right one for *structural* invariants — but it
cannot answer the question we actually care about for incident response: **"is a
genuinely dangerous, actively-exploitable attack path present in the cluster
right now, and can we break it?"**

The forces that rule out doing this in the admission path:

- **Latency.** A real answer needs vulnerability scans, a reachability walk of
  the Linkerd/NetworkPolicy graph, an RBAC walk, and (optionally) model
  reasoning — seconds to minutes. Admission webhooks are capped at 30s by the
  API server; we run 5s with `failurePolicy: Ignore`, so slow work just times
  out and fails open. Forcing it inline (`Fail` + 30s) would stall every Pod
  creation cluster-wide — a self-inflicted, cluster-wide outage.
- **Scan-after-admit.** trivy-operator scans an image *after* it is admitted and
  running. At admission a fresh image has no report, and a CVE disclosed against
  an already-running workload never re-fires admission. Detection of *new*
  danger is inherently asynchronous.
- **LLM unreliability.** Attack-chain reasoning is what models propose well and
  adjudicate badly: hallucinated inflation of issues, sycophancy, and
  non-determinism. An LLM must never sit in the deploy hot path, and must never
  be the thing that decides to take a privileged action.
- **Hardware.** Small, CPU-only nodes, no GPU. In-cluster models (e.g. Ollama) are small
  (~1–3B, quantized) and slow — weak reasoners, but free and private.
- **Cost and data egress.** Cloud inference over the cluster's SBOMs, vuln map,
  topology, RBAC, and secret *names* is both a recurring cost and a security
  regression: that data is a map of how to attack us.
- **Scale.** Multi-hop chain analysis does not scale to large clusters. It is
  tractable here *because* the cluster is small (dozens of workloads, a tiny
  graph) and deterministic pre-filters keep the search space minute.

## Decision

We will build a **separate, asynchronous mitigation engine** — not part of the
admission webhook. protector the webhook stays clean and self-contained; the
engine *consumes* its audit signal as one input among many.

The engine is structured around one non-negotiable boundary: **propose, prove,
and respond are separate layers, and only proofs move privilege.**

1. **Evidence bus.** Normalize what the cluster already emits, keyed by
   `(workload, image-digest, namespace)`: SBOMs (built in CI), trivy
   `VulnerabilityReport`s, optionally grype (a second DB for cross-source
   corroboration), semgrep code scans, **Falco** runtime events (the live "is it
   happening" signal), protector's audit metrics, and the Linkerd authz +
   NetworkPolicy graph and RBAC graph (the reachability and privilege maps).

2. **Hypothesis engine (model, cheaply gated).** On a *new* signal, generate
   candidate chains `entry → reachability → privilege/impact → objective`. The
   model is a hypothesis generator only; its output is a structured claim with
   named links, never a verdict.

3. **Proof layer (deterministic).** Every link a chain asserts is confirmed by a
   non-model check or dropped: reachability by a real graph query over
   mesh authorization policy + NetworkPolicies; privilege by a real RBAC check
   (`can-i`); active exploitation by CISA KEV / EPSS lookup; vuln presence by
   trivy ∧ grype agreement; "now" by a corroborating Falco event. A chain's
   strength is exactly the number of deterministically-proven links. This is the
   propose→adversarially-refute pattern (independent refuter passes,
   majority-vote, escalate on disagreement).

4. **Confidence → action tiers.** Model-asserted-but-unproven → **notify only**
   (the inflation/sycophancy quarantine). All structural links proven **+** live
   Falco corroboration → eligible for **automated response**. Automated
   privileged action is gated on deterministic proof, never on model confidence.

5. **Response: minimal-cut, reversible, out-of-band.** Because the engine runs
   async with privilege, it escapes the latency trap and gets a surgical action
   menu: sever the *one* proven-reachable edge via a scoped Linkerd
   `AuthorizationPolicy` / deny `NetworkPolicy`; revoke the one RBAC binding the
   chain rides; rotate the targeted secret; cordon/scale-to-zero only as last
   resort. Every action is recorded, announced (to the runtime-alert pipeline), and carries a
   dead-man auto-revert timer so a false positive self-heals.

**Model strategy is local-first, tiered:**

- **Tier 0 — no model.** Deterministic filters (KEV ∧ reachable ∧ privileged ∧
  Falco) do most of the work and are always on.
- **Tier 1 — local (Ollama), default.** Cheap, private, async: rank candidates,
  write the human narrative, drive tool calls. A weak local model is *safe here
  because verified downstream* — the cost of weakness is more rejected
  hypotheses, never a bad action. The model is given **deterministic tools**
  (`is_reachable`, `can_i`, `kev_lookup`) rather than asked to reason about
  topology — offloading exactly what small models are worst at to real queries —
  and run at temperature 0 with constrained/JSON-schema decoding for
  reproducible, well-formed output. The engine uses a **dedicated, internal-only
  model deployment** (not a public, internet-facing model instance), with its
  ServiceAccount scoped as an authorized client of the in-cluster model.
- **Tier 2 — selective escalation, rare.** Only a proven, high-severity,
  model-flagged-ambiguous chain escalates to a stronger model, **redacted first**
  (structured graph + CVE IDs, never raw secrets) and human-in-the-loop.

**Rollout is shadow-first.** The deterministic walking skeleton ships with **no
model** and **notify-only**; reversible actions (edge-cut, secret-rotate) are
armed first and only after a long bake measuring false-positive rate; eviction is
never auto-armed.

## Consequences

Easier:

- Detection of *new* danger becomes possible at all (async escapes scan-after-admit).
- Fast *and* safe: the expensive analysis is decoupled from the admission path.
- Inference is free and **never leaves the cluster** — a security property, not
  just a budget choice.
- Response is surgical and reversible: break the chain at one edge without
  killing the workload.
- The inflation/sycophancy/non-determinism risks are contained by construction —
  the model can shout, but nothing privileged listens until graph/RBAC/KEV/Falco
  agree, and every action self-reverts.

Harder / accepted downsides:

- protector gains its **first cluster-API access** (RBAC to read vuln reports,
  the authz/RBAC graph, and to apply scoped policies). The webhook's
  zero-API-access property no longer holds engine-side; the webhook itself keeps it.
- It is a **multi-component system** to build and operate, not a single webhook —
  weeks of work, phased behind the walking skeleton.
- A **dedicated internal model** instance (e.g. Ollama) plus authz wiring, with
  resource contention to manage (low-priority, rate-limited, circuit-broken,
  off-peak) so IR inference can't starve the user-facing services or the apps.
- **It does not scale** to large clusters; this is explicitly a small-cluster
  design. Accepted.
- **"Provable" means preconditions, not exploitation.** We cannot prove RCE
  without exploiting it (we won't). The bar for auto-action is *reachable ∧
  exploited-in-wild ∧ privileged ∧ runtime-corroborated* — proven preconditions
  plus live evidence — and the action is justified by severing a proven-reachable
  privileged path, not by a proof of exploitation. This is a deliberate, named
  bound on the claim.
