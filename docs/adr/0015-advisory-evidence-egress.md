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
- **Every free-text field is hard-capped twice.** Once at parse time (the store caps
  the stored summary, the `fix_ref`, each CWE string, and the CWE count, so an oversized
  snapshot entry can never enter the system) and again at the prompt boundary (independent
  per-field caps in `cve_evidence` for the title, summary, and `fix_ref`), so the bound
  holds regardless of how the advisory arrived — including a future live-OSV lane (JEF-110)
  that would bypass the parse-time cap.
- **A per-entry AGGREGATE budget bounds the whole prompt.** Per-field caps bound any one
  field, but a CVE-heavy image (hundreds of CVEs, each at its per-field cap) could still
  aggregate an unbounded prompt. So an entry has a fixed total free-text budget
  (`ENTRY_FREETEXT_BUDGET`, applied in `entry_evidence` over the CVEs in sorted-id order):
  early CVE lines keep their free prose; once the budget is spent, later lines fall back
  to the **structured fields only** (id / severity / reachability / fix-availability / CWE
  / fix-ref). The model never loses a CVE — only its unbounded prose. The budget spends
  deterministically (sorted order, all-or-nothing per field), so the same evidence always
  renders the same prompt and the verdict fingerprint stays stable across passes (§5).
- **Cap THEN sanitize THEN fence, in that order, per field.** Each untrusted field is
  length-capped first and `sanitize`d second (so whatever survives the cap is still
  stripped of fence-closing / structure chars), then the whole CVE list is fenced +
  sanitized again at prompt-build. A capped value therefore cannot reconstruct a `<<<` /
  `>>>` delimiter — a malicious summary is inert data, never instructions or a fence break.

### 5. Only stable fields enter the verdict fingerprint

The verdict cache keys on `entry_fingerprint`, which is the budget guard against
re-judging on every watch event (ADR-0013; one CPU-only model call is dear on a Pi —
JEF-63). The advisory contributes only its **stable** fields — summary, CWE, fix
reference — and **no timestamps**. So a freshly-synced snapshot busts the cache
**once** (the entry is re-judged with the new evidence) and is then stable across
passes; it does not thrash per pass.

## Amendment (JEF-238): a co-located feed-fetcher sidecar is the approved live-enrichment mechanism

The core rule above is unchanged: **the engine (and the security graph) make no outbound
advisory/KEV call and never transmit cluster data — they only READ mounted files.** What
this amendment settles is *how those files get refreshed* without an operator syncing them
by hand, and it does so without weakening the engine's zero-egress posture.

**The mechanism.** A **feed-fetcher sidecar** — a native sidecar (an `initContainer` with
`restartPolicy: Always`) co-located on the engine pod — fetches the public feeds into a
shared `emptyDir` the engine reads. This is **on by default** (`feedSync.enabled: true`).
It is sanctioned as the single approved live-enrichment lane:

- **Inbound-only public-feed egress.** The sidecar makes outbound GETs to **public,
  read-only** feed URLs (CISA KEV; an operator-supplied advisory source) and writes the
  results to the shared volume. It makes **no apiserver call** and has **no RBAC** — it
  cannot read or transmit any cluster state. The only bytes that leave are the plain feed
  GETs, keyed on nothing cluster-specific (the full CISA KEV catalogue is the same request
  for every cluster — it does **not** leak the cluster's own CVE profile, unlike a
  per-CVE live lookup, which is exactly why §2's per-CVE OSV fetch was rejected).
- **Engine + graph remain zero-egress.** The engine still only reads files; the §1 rule
  and the injection-safety guarantees (§4/§5) are untouched, because the file shape the
  engine parses is identical to the mounted-snapshot shape this ADR already governs.
- **Full data, no ConfigMap limit.** An `emptyDir` has no size cap, so the **full** CISA
  KEV JSON (~1.5 MiB) and advisory data are fetched and read in full.

**Supersedes.** This replaces the **JEF-228** feed-sync CronJob+ConfigMap path: raw CISA
KEV (~1.5 MiB) exceeds Kubernetes' 1 MiB ConfigMap limit (forcing a lossy CVE-IDs-only
extraction) and advisory data does not fit at all. It also definitively closes the
cancelled **JEF-110** engine-fetch option (§2): the engine never fetches; only the
co-located, no-cluster-access sidecar does. The advisory file the sidecar fetches must
already be in the `AdvisoryStore` CVE-keyed shape (§4) — a transform from a raw OSV/GHSA
bulk feed is a documented follow-up, not part of this lane today.

**Air-gapped escape hatch preserved.** Setting `feedSync.enabled=false` removes the
sidecar entirely (nothing in the chart egresses); an operator can still mount their own
snapshot files into the engine for fully-offline enrichment — the §1 mounted-snapshot
posture, verbatim.

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
