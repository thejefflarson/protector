# 0018. The breach notifier is the one sanctioned outbound path: operator-configured, off by default, redacted by default

- Status: Accepted
- Date: 2026-06-24
- Relates to: [0015](0015-advisory-evidence-egress.md) (the in-cluster, zero-egress posture this carves the single exception to; advisory-derived prose in the verdict is sanitized before it leaves), [0016](0016-severity-vs-urgency.md)/[0017](0017-isolation-persists-on-the-breach-condition.md) (the breach decision + shadow-vs-armed distinction the message reports), builds on [0014](0014-behavioral-telemetry-ebpf.md) (same "no egress of cluster data" rule, here with one explicit, opt-in hole)

## Context

Surfacing today is **pull-only**: a breach decision lands on `/findings` and
`/judgements`, and the durable journal ([JEF-141](journal.rs)) replays it after a
restart — but a solo operator never *learns* protector decided a breach unless they
are watching the dashboard. The motivating pain is exactly that gap (the
"dashboard blank after restart" memo): the decision is made, recorded, and then sits
there unseen.

The obvious fix is an outbound notification — the inverse of the falcosidekick
ingest the engine already accepts. But the platform's whole posture is in-cluster,
local-first: the cluster graph **never leaves** ([ADR-0001](0001-async-mitigation-engine.md)/
[0014](0014-behavioral-telemetry-ebpf.md)), and [ADR-0015](0015-advisory-evidence-egress.md)
went out of its way to keep advisory enrichment a mounted snapshot specifically so
the engine makes **zero** outbound calls keyed on the cluster's own state. An
unguarded notifier would undo that: it would be a side channel leaking the cluster's
topology, secret names, peer-by-peer reachability, and CVE inventory to wherever the
URL points — on every decision.

Two further forces:

1. **The verdict text is partly third-party.** The verdict prose can carry
   advisory-derived text ([ADR-0015](0015-advisory-evidence-egress.md): a CWE class,
   a capped summary). That is untrusted third-party data. It is fenced/sanitized
   before it reaches the promote-capable model; it must be **sanitized again before
   egress** so the notifier can't be used to smuggle structure into an operator's sink.

2. **Per-pass spam is real.** The engine re-publishes findings every pass. A naive
   notifier would POST the same decision on every watch event. The journal already
   solves this for durability (it dedupes a breach line on the decision's identity);
   the notifier must reuse that same identity so one decision yields one notification.

## Decision

### 1. Off entirely unless an operator sets the URL

The notifier is **disabled** unless `PROTECTOR_ENGINE_NOTIFY_URL` is set to a
non-empty value, mirroring the `PROTECTOR_ENGINE_*` mounted-contract convention
([ADR-0015](0015-advisory-evidence-egress.md), the journal). With it unset the engine
makes **zero** outbound calls and behaves **byte-identical to today**. There is no
default sink and no hosted/phone-home target — a default outbound path is **rejected**
outright, the same way [ADR-0015](0015-advisory-evidence-egress.md) rejected a default
live-fetch lane. The URL is documented to point at an **in-cluster** sink the operator
runs (Alertmanager, ntfy, gotify); pointing it off-cluster is the operator's explicit,
eyes-open choice, not a default.

### 2. Redacted by default — decision summary only

The default payload carries **only the decision summary**:

- the **decision** (the verdict kind — `exploitable` / `confirmed` / `refuted`),
- the **entry workload** (the internet-facing front door's identity — a workload key,
  which is not a secret),
- the **ATT&CK outcome** (the distinct tactic/technique IDs reached, and a *count* of
  objectives — never the per-objective list),
- the **verdict text** (the model's one-line reason), **sanitized** before egress, and
- the **enforcement posture** (shadow vs armed — see §4).

It does **NOT** carry the full topology, secret names, the peer-by-peer reachability
graph, or the CVE inventory. Richer detail is gated behind an explicit opt-in flag
(`PROTECTOR_ENGINE_NOTIFY_VERBOSE`) that adds only the per-objective ATT&CK list — and
even that never includes secret names, the peer graph, or the CVE list. Redaction is
the default; verbosity is opt-in and still bounded.

### 3. Reuse the journal's decision identity for dedupe (one decision, one notification)

The notifier fires at exactly the point the engine appends a **new** breach line to
the durable journal — i.e. a **decisive** verdict whose summary **changed** from the
last one recorded for that entry. A steady-state cluster re-publishing the same
decision every pass therefore notifies **once**, not per pass, and a transient
`Uncertain` (model timeout) never notifies. The dedupe key is the journal's decision
identity (entry + verdict summary), so durability and notification can never drift.

### 4. Shadow vs armed is explicit in the message

The message states whether protector **would isolate** (shadow — no action class
armed, the default posture) or **isolated** (armed). The operator must never have to
guess whether a decision was acted on; the same `armed` flag that titles the
dashboard's remediations section drives the wording.

### 5. Bounded client, fail-safe, never blocks the loop

The notifier uses the **bounded** HTTP client pattern from `model.rs`
(`timeout_only_client`) — never an unbounded `reqwest::Client::new()` — so a slow or
hung sink can't stall the single engine loop. A POST failure is logged once and
dropped; notification is best-effort and **never** affects a verdict, an actuation, or
the journal. The engine stays shadow by default; nothing here changes the action-class
posture.

## Consequences

Easier / better:

- A solo operator learns of a breach decision the moment it is made, without watching
  the dashboard — closing the pull-only gap.
- The zero-egress posture is preserved as the **default**: the one outbound path is
  opt-in, redacted, sanitized, and deduped, and is invisible until a URL is set.
- Dedupe and durability share one identity (the journal's), so they can't diverge.

Harder / accepted:

- **The operator owns the sink's trust.** A redacted summary still names the entry
  workload and the ATT&CK outcome; an operator who points the URL at an untrusted
  off-cluster endpoint accepts that exposure. We document the in-cluster target and
  redact by default, but we cannot enforce where the URL points.
- **Best-effort delivery.** A down sink drops the notification (logged once); the
  durable journal remains the source of truth, not the notifier.

## Alternatives considered

- **A default / hosted notifier (phone-home).** Rejected: a default outbound path is
  exactly the side channel [ADR-0014](0014-behavioral-telemetry-ebpf.md)/
  [0015](0015-advisory-evidence-egress.md) forbid. Off-by-default, operator-configured
  only.
- **Send the full finding (topology, secret names, peer graph, CVE list).** Rejected:
  that is the cluster's crown-jewel inventory leaving the cluster on every decision.
  Redacted summary by default; richer detail is a bounded, explicit opt-in that still
  excludes secrets, the peer graph, and the CVE list.
- **Notify on every pass / every published finding.** Rejected: per-pass spam. Dedupe
  on the journal's decision identity so one decision is one notification.
- **An unbounded reqwest client.** Rejected: a hung sink would stall the single engine
  loop — the exact failure `model.rs` bounds against. Reuse the timeout-only client.
