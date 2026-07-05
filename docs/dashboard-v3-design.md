# Dashboard v3 — design report

**Status:** agreed design, pre-build. This is the source of truth the v3 rebuild implements.

## Provenance

This is not one person's sketch. It is the **synthesis of nine independent design
passes** — three roles (Information Architect, UX, visual Designer) run three times each,
in a *clean room*: each pass read only the engine's domain code (`engine/src/engine/state/`,
`graph/`, `reason/`, `policy_log.rs`) and the ADRs, with **no access to any prior dashboard,
ADR, or style guide** (those were deleted first, and the read-sets were verified). Across
all nine passes the design **converged on the same shape** — strong evidence the IA is
*dictated by the engine's data model*, not copied from a prior UI. What follows is that
convergent design.

The prior dashboards failed because the information architecture was wrong, and editing an
IA doesn't fix it. The two specific failures this design exists to prevent:
1. **Burying "why."** The model's verdict is the product; it must be one glance + one click away, never a separate destination.
2. **Calm-when-blind.** A quiet green screen while the model is down/warming reads as "safe" when it means "we haven't looked." This is the cardinal sin and the design's #1 guard.

---

## 1. The operator and the one job

A **solo (or very small team) platform/security engineer** running a small-to-mid Kubernetes
cluster. They are *not* staring at a SOC console; they check in periodically (or get paged
by the notifier). The engine is autonomous and **shadow-by-default** — it proposes, it never
acts until armed. So the dashboard is a **decision-support view, never a control panel**
(ADR-0016: presentation is a view, never a gate). The operator's real jobs:

1. **Trust calibration** — is the engine's judgement sound enough to *arm* an action class?
2. **Triage** — which judged breaches are real and need a human fix?
3. **Coverage** — is the engine actually equipped to decide well right now (model up, feeds loaded)?

## 2. Core operator questions (ranked)

| # | Question | Backed by |
|---|----------|-----------|
| Q1 | **Is anything a breach right now, and would/did it cut?** | `Finding` (breach-relevant) + typed `Verdict` + `disposition` + `corroborated` + `cut` + recency Δ |
| Q2 | **Why — can I trust this specific call?** | per-finding `path`, `EntryEvidence` (CVE/KEV/EPSS/secrets/runtime), and the raw `Judgement` (prompt + reply) |
| Q3 | **Is the engine equipped to decide, or is "quiet" really "blind"?** | `Readiness` / `model_judging` / `warming_up` |
| Q4 | **If I armed it, what would it have done — how noisy?** | `Report` (`would_act`, `short_lived`, `coverage_gap`, `left_alone`) |
| Q5 | **What did it actually do, and did it undo it?** | `ReversionLog` + applied cuts |

Q2 is inseparable from Q1 — it's Q1's drill-down, never a separate page.

## 3. The honesty model (the load-bearing principle)

Three **orthogonal axes** that must never collapse into one signal:

- **breach vs safe** — the model's `Verdict`.
- **decided vs awaiting** — has the model judged this entry yet?
- **covered vs blind** — is the model up and are the feeds loaded?

**The overall green/all-clear is only honest when the model has affirmatively cleared everything
it is looking at** — `model_judging == true` AND not `warming_up` AND **covered** (no feed
degraded) AND **zero breaches AND zero entries still awaiting AND zero uncertain**. "Quiet because
the model affirmatively cleared it" (green) must look different from "quiet because the model
hasn't finished." If the model is up but anything is still `Awaiting` or `Uncertain`, the overall
posture is the elevated **"watching"** state — calm but **not** green (the model isn't sure yet).
If `warming_up` or `!model_judging`, exposed paths are *unjudged, not cleared*, and the UI says
so. `Uncertain` and `Awaiting` are **never** green. This is enforced by tests, not just
convention.

## 4. Information architecture

**A primary view + secondary views, with one persistent status strip — not a single page**
(one page recreates the unreadable monolith), **and not flat peers** (Q1 dominates).

| Surface | Question | Unit | Priority |
|---|---|---|---|
| **Status strip** (persistent, every view) | Q3 + freshness | the cluster | always-on |
| **Findings** (primary / landing) | Q1 + Q2 | an exposed `Finding` (entry→objective) | P0 |
| **Action** (would-have-acted + audit) | Q4 + Q5 | a `WouldActEntry` / `ReversionRecord` / `LeftAloneEntry` / `Judgement` | P1 |
| **Readiness** (coverage detail) | Q3 | a decision input (`ReadinessRow`) | P1 |

The four-tab bar is **Findings · Action · Readiness · Admission**. **Action** sits second (the
old Trust slot) and tells the engine's whole action story — it merges the former *Trust*
(would-have-acted) and *Activity* (audit) tabs into one lifecycle view (§6). **Admission/policy**
is the webhook-floor peer surface (the fourth tab).

Navigation: persistent status strip + the 4-tab bar, default **Findings**. Findings drill
**in place** (row → detail panel); "show the model's prompt" deep-links into the Action tab's
judgement-audit section. Never deeper than two levels. The legacy `?tab=trust` / `?tab=activity`
deep-links resolve to **Action** (soft-aliases), so they don't 404.

```
┌─ protector ▸ prod-east ───────────────────────  [ SHADOW · proposes, never acts ] ─┐
│ ● model judging · KEV ✓ · EPSS ✓ · agent quiet · last pass 12s ago     ← status strip│
│ [ Findings ]  Action  Readiness  Admission                              ← tab nav     │
├──────────────────────────────────────────────────────────────────────────────────────┤
│  1 BREACH · 2 awaiting · 14 cleared          ▲1 escalated since last pass             │
├──┬──────────┬───────────────────────┬──────────────────────┬─────────┬──────┬────────┤
│ Δ│ POSTURE  │ ENTRY → OBJECTIVE      │ PATH                 │ EVIDENCE│ DISP │ live?  │
│ ▲│●EXPLOIT  │ web → db-creds (T1552) │ web ─reach→ db ✂→ ●  │⚡KEV cvss│auto  │ judged │
│   └▼ verdict (verbatim) · path · evidence · cut+revert · [show model prompt]          │
│ ＋│◌AWAITING │ argo → ×120 secrets    │ …                    │  —      │ ctx  │  —     │  ← unjudged ≠ green
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## 5. Findings view (primary — built first)

- One row per **breach-relevant** `Finding`. Non-breach-relevant (internal assume-breach)
  chains are **not** findings — they're context behind a filter, never alarms.
- **Default sort = urgency, NOT severity** (ADR-0016): corroborated-live → model-promoted
  (`Exploitable`) → escalations (`Delta::Escalated`) → awaiting → cleared (collapsed group).
  A critical CVE on an unreachable workload is low-urgency; CVE severity is evidence in the
  drawer, never the headline sort.
- **Row:** posture rail+chip (Breach/Cleared/Uncertain/Awaiting — distinct colour **and**
  glyph **and** word; Uncertain & Awaiting are not green) · entry (node-kind glyph, 🌐 for
  internet foothold) · objective (ATT&CK tactic) · Δ glyph or age (steady shows age, not an
  alarm) · evidence cluster (CVE count + KEV + runtime + exposed-secret glyphs; empty →
  "no evidence", never blank) · disposition · a **live** (`Confirmed`) / **judged**
  (`Exploitable`) sub-tag.
- **Expands in place** to the "why": verbatim `Verdict::summary()` first → proven **path** as
  a text hop-list (`entry ─relation→ … → objective`, structural hops muted, the cut point
  marked) → **evidence** (CVE table id/sev/CVSS/KEV/EPSS/reachability/fix; runtime split
  corroborating-vs-context; exposed secrets redacted; misconfig/RBAC) → the proposed/applied
  **cut + its self-revert condition** → a "show model prompt" disclosure to the raw
  `Judgement` prompt + reply.
- **Fan-out** (argocd reaching ~120 objectives): collapse to `→ ×N secrets` with drill-in,
  framed as reachable-but-cleared, never alarm.

## 6. Secondary views

- **Action (would-have-acted + audit)** — the engine's whole action story, the merged *Trust* +
  *Activity* tabs, in **lifecycle order** as three stacked sections:
  1. **Proposed cuts** — the lifecycle of a would-be cut. The still-standing *would-act*
     proposals from `Report` (`would_act`, sustained-first; each tagged with its lifecycle
     status — would-cut-`open` = still standing; `short_lived` = likely FP; `coverage_gap` =
     affirmed with no CVE backing → scrutinise first), then the cuts that were applied then
     **self-reverted** (`ReversionLog` — reason + age, the safety story kept visible). Honest
     empties: `journal_empty` (no history) is distinct from "none-in-window", and an empty
     reversion set reads "no cuts reverted yet".
  2. **Left alone (cleared)** — proven paths the model judged not exploitable and deliberately
     cleared (`Report::left_alone`; the trust half).
  3. **Judgement audit (model debug)** — the `Judgement` ring (verbatim prompt/reply per call, as
     collapsed disclosures). Findings' "show model prompt" conceptually deep-links here.
- **Readiness (coverage)** — one row per input (model / KEV / EPSS / runtime corroboration /
  journal / arm-state): state (Present/Absent/Degraded) · live detail · why it matters · the env var to
  enable it. Inputs that `weakens_decisions` when absent float up. A quiet feed reads
  "no signals (quiet, or sensor down)" — the ambiguity preserved, not falsely resolved.
- **Admission/policy** — the webhook floor: `DecisionTallies` header (admitted/audited/denied,
  so a healthy view is never blank) + deduped decision rows (signature/mesh/decision + the
  "if enforced" what-if).

## 7. Interaction & states

- **Server-rendered** (maud), zero-egress. Drill = inline `<details>` accordion (keeps list
  context); deep links via URL fragment. Filter/sort via query params (shareable,
  back-button-correct). Live refresh polls the `/fragment` keyed on `last_pass`, **preserving
  scroll/expansion/filter**, and re-pulls readiness so a model that just went down flips the
  banner immediately.
- **Every state designed honestly:** cold-start/warming, model-absent, model-degraded
  (timeout), proven-but-awaiting, judged-breach (corroborated vs promoted), judged-safe
  (`Refuted`) vs `Uncertain` (not safe), genuinely-empty (only "all clear" when
  `model_judging`), stale, and dashboard-can't-reach-engine (distinct from blind). No state
  may render in a way that implies safety the engine can't back.

## 8. Visual system

- **Register:** a dense, **light-theme** information console (think Linear / GitHub / a clean
  admin data table) — a white/near-white surface with dark ink, monospace/tabular for all
  machine data so columns align. **Calm by default, loud only on a real breach** — saturated
  colour is a scarce resource on the light surface, reserved for a real breach.
- **Two separate channels:** *posture* (the model's verdict — the loud channel) and *severity*
  (CVE — a cooler, subordinate channel). A wall of critical CVEs must never look like a wall
  of breaches.
- **Meaning never by colour alone** — every status carries colour **+ glyph + word**.
- Full token set (colour/space/type), the component→token map, and the accessibility gate
  live in **`docs/STYLEGUIDE.md`** — a **light-theme** token system.

## 9. Invariants (test-enforced)

1. The overall green/all-clear renders ONLY when judging + covered + zero breach/awaiting/uncertain; if `!model_judging` or `warming_up`, the honest blind/warming banner renders; if judging but anything is still awaiting/uncertain, the elevated "watching" (non-green) state renders.
2. `Verdict::Uncertain` and awaiting (`None`) never map to the cleared/green token.
3. Empty evidence/coverage renders explicit "none"/"unknown", never a blank.
4. Components import no `engine::`/`state::` domain type (the view_model/component boundary).
5. No inline `<style>`/`style=`.
6. All untrusted text (verdict prose, CVE/finding titles, model prompts, node keys) is escaped at render.
7. No source file exceeds 1,000 lines.

## 10. Product decisions (defaults taken — change freely)

- Argo fan-out → collapse to `→ ×N secrets` with drill-in.
- `Confirmed` (live-corroborated) gets a **live** sub-tag; `Exploitable` (model-only) a **judged** sub-tag.
- Serving = server-rendered maud (not Grafana-over-OTLP).
- **Theme = light** — a clean light surface with dark ink (not a dark console); see `docs/STYLEGUIDE.md`.
