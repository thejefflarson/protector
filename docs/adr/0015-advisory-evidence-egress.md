# 0015. Advisory evidence is mounted-snapshot-only (zero egress); injection-safe by construction

- Status: Accepted
- Date: 2026-06-22
- Relates to: [0013](0013-proof-winnows-model-decides.md) (the model is promote-capable, so its inputs are a security boundary), [0014](0014-behavioral-telemetry-ebpf.md) (same "in-cluster, no egress of cluster data" posture)

## Context

The model is the analyst that decides exploitability on a proven foothold
([ADR-0013](0013-proof-winnows-model-decides.md)). It would judge better with
**advisory evidence** for a CVE — a CWE class, whether a fix exists, and a short
summary — so it can reason "a fix exists but the workload is still on the vulnerable
version" vs "no fix at all" (the JEF-52 payoff). The question is *where that evidence
comes from* and *how it reaches the prompt safely*, given two hard constraints:

1. **Egress.** The platform's posture is in-cluster, local-first: the cluster graph
   never leaves (ADR-0001/0014). Fetching advisories live from a public API (OSV/NVD/
   GHSA) means outbound calls keyed on the cluster's own CVEs — a side channel that
   leaks which vulnerabilities a cluster runs, to a third party, on every pass.

2. **Injection.** Advisory text is **untrusted third-party data**, and the model it
   feeds is **promote-capable** (ADR-0013) — a successful prompt injection here could
   drive an auto-cut. `sanitize`/`fence` (strip fence/structure chars, wrap as data)
   is adequate for short structured tokens but weak for long free prose and impossible
   for patch diffs (JEF-106).

We need the evidence without the egress and without handing the promote-capable model
an injection surface.

## Decision

### 1. Mounted snapshot is the only source (zero egress)

Advisory evidence is loaded from a **mounted, CVE-keyed file** an operator syncs out
of band (a ConfigMap, exactly the KEV pattern in `exploit_intel.rs`). The engine
never makes an outbound advisory call. Unset/absent file ⇒ **empty store**, and the
rendered prompt is **byte-identical to today** — the feature is invisible until a
snapshot is mounted. This is the same "no egress of cluster data" rule ADR-0014 holds
for telemetry, applied to enrichment.

### 2. Opt-in live OSV fetch is DEFERRED, not built (JEF-110)

A future opt-in live fetch was considered and is explicitly **deferred**. It is not a
default and is out of scope for this work; nothing in the codebase reaches the network
for advisories. If it is ever built, it is an opt-in, off-by-default lane behind its
own decision — never the default posture this ADR sets.

### 3. Fix-diffs are out of scope for the local model

Patch text / fix diffs are **not** surfaced to the local promote-capable model. They
are unbounded free text that `sanitize` cannot make safe (JEF-106), and they buy
little for the exploitability call. If diffs are ever used, it is in a human or
frontier-model lane with a different trust model — never the local auto-promote path.

### 4. Structural extraction + hard caps for injection safety (JEF-106 folded in)

Advisory text reaches the model as **structured, length-capped, fenced data**:

- **Structured fields lead.** CWE id(s) and a fix reference — low-cardinality tokens
  that convey "what class of bug" and "is there a fix" without free prose — are the
  preferred signal.
- **The free-text summary is hard-capped twice.** Once at parse time (the store caps
  the stored string and bounds the CWE count, so an oversized snapshot entry can never
  enter the system) and again at the prompt boundary (an independent cap in
  `cve_evidence`), so the budget holds regardless of how the advisory arrived.
- **Everything is fenced + sanitized.** The whole CVE evidence list flows through
  `fence`/`sanitize` before the prompt, stripping fence-closing / structure characters
  — so a malicious summary is inert data, never instructions or a fence break.

### 5. Only stable fields enter the verdict fingerprint

The verdict cache keys on `entry_fingerprint`, which is the budget guard against
re-judging on every watch event (ADR-0013; one CPU-only model call is dear on a Pi —
JEF-63). The advisory contributes only its **stable** fields — summary, CWE, fix
reference — and **no timestamps**. So a freshly-synced snapshot busts the cache
**once** (the entry is re-judged with the new evidence) and is then stable across
passes; it does not thrash per pass.

## Consequences

Easier / better:

- The model gets the advisory context it needs for the exploitability call, fully
  offline and unit-testable — no new outbound dependency, no leak of the cluster's CVE
  profile.
- Injection safety is structural, not a promise: structured-fields-first + double hard
  caps + fence/sanitize, with the no-advisory path byte-identical to today (so the
  feature can't regress existing verdicts).

Harder / accepted:

- **Freshness is the operator's job.** A mounted snapshot is only as current as the
  operator's sync cadence — the trade we accept for zero egress (same as KEV).
- **No fix-diff reasoning in the local lane.** The local model reasons over CWE + fix-
  availability + a capped summary, not patch text. Diff-level reasoning waits for a
  human/frontier lane if it is ever wanted.

## Alternatives considered

- **Live OSV/NVD fetch as the default.** Rejected: outbound calls keyed on the
  cluster's own CVEs leak the cluster's vulnerability profile to a third party, against
  the in-cluster posture. Deferred to an opt-in lane (JEF-110), not built here.
- **Surface the raw advisory description / patch diff verbatim.** Rejected: unbounded
  untrusted free text into a promote-capable model is exactly the JEF-106 injection
  surface `sanitize` cannot close. Structural extraction + hard caps instead.
- **Put advisory timestamps in the fingerprint.** Rejected: volatile fields would
  thrash the verdict cache every pass and starve the slow CPU model (the JEF-63
  budget). Stable fields only.
