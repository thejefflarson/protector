# protector — Vision

## Where it starts

protector is a validating admission webhook. It verifies that first-party images
are cosign-signed and that workloads are meshed, and it does so the boring,
reliable way: synchronously, on the API request, with no cluster access and no
cleverness. That's deliberate. The webhook is the *floor* — a set of structural
invariants the cluster refuses to violate, enforced one namespace at a time as
each proves clean.

But a signature check and a mesh check are guardrails, not a guard. They answer
"is this Pod well-formed?" — not "is my cluster currently exploitable, and if so,
can I do something about it before it matters?" That second question is the real
ambition.

## Where it's going

protector becomes the cluster's **security and incident-response platform**: a
loop that watches everything it already knows, reasons about how those facts
*chain* into an attack, proves the dangerous chains, and — when a chain is proven
and live — **breaks it at a single point, automatically, with privilege, out of
the request path.**

The pieces are mostly already in the cluster, unjoined:

- **SBOMs** built in CI, **trivy** vulnerability reports, optionally **grype** for
  a corroborating second opinion, **semgrep** code scans.
- **Falco** watching syscalls — the difference between "theoretically vulnerable"
  and "something is happening right now."
- The **Linkerd authorization graph** and **NetworkPolicies** — a precise map of
  who can reach whom.
- **RBAC** — a precise map of who can do what.
- protector's own **audit stream** — where the floor is thin (unsigned, unmeshed,
  unscoped).

Each of these is a fact. The platform's job is to turn facts into *chains*:
*this internet-exposed workload runs a critical, actively-exploited CVE on a port
the graph says is reachable, and its identity can read that secret.* That is a
killchain, stated in things we can check.

## The superpower, and the discipline that earns it

Because this runs **asynchronously and with privilege — outside the admission
loop — it can do what an admission controller never can.** It isn't limited to
"admit or reject this one request" in five seconds. It can take minutes to think,
and then it can *act on the cluster*: tighten one authorization policy to sever
the reachable edge, revoke one RBAC binding, rotate one secret — breaking the
chain at its narrowest point while the workload keeps running. Minimal-cut, not
demolition.

That power is only safe because of one rule, and the whole design exists to
enforce it:

> **A model may propose. Only deterministic proof may move privilege.**

Large language models — and especially the small, local ones a Pi cluster can
run — are good at *imagining* attack paths and bad at *adjudicating* them. They
inflate, they flatter, they vary run to run. So the model never decides. It
generates a hypothesis with named links; deterministic checks (graph queries,
RBAC checks, KEV/EPSS lookups, Falco corroboration, cross-scanner agreement)
either confirm each link or drop it; and an automated action fires only when the
chain is proven *and* corroborated live — never on the model's confidence. The
model can be wrong all day and the worst it causes is wasted verifier cycles.
Every action it does enable is reversible, announced, and self-reverting.

## Local-first, by conviction

The reasoning runs **in-cluster, on local models** (Ollama), and that's a feature
twice over. It makes inference free, which is what lets the loop run continuously
on a homelab budget. And it keeps the cluster's vulnerability map, topology, and
secret names — a literal blueprint for attacking us — **inside the cluster**,
where security tooling's most sensitive data belongs. A weak local model is
acceptable precisely because it's fenced in by proof; when a rare, high-stakes,
genuinely ambiguous chain needs more horsepower, it escalates — redacted, and
with a human in the loop.

## What this is not

It is not a scanner, and it is not magic. It does not *prove exploitation* — you
can't, without exploiting. It proves **preconditions**: reachable, exploited in
the wild, privileged, corroborated now. It does not scale to thousands of pods;
it works here because the cluster is small enough to reason about exactly. And it
earns trust the same way the webhook does — **shadow first**: notify-only for a
long bake, reversible actions before destructive ones, eviction never automatic.

The floor keeps the cluster well-formed. The platform keeps it *defended* — and
tells you, honestly and with receipts, when it has quietly cut a wire to keep you
safe.

See [`adr/0001-async-mitigation-engine.md`](adr/0001-async-mitigation-engine.md)
for the architecture decision and the contracts behind this.
