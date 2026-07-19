# Adjudication false-positive audit — the fabricated `loaded-at-runtime` tag

Date: 2026-07-19. Scope: the recurring false `exploitable` on protector/protector and
argocd-server, where the deployed judge (qwen3:1.7b, temp 0, num_ctx 16384, CPU) asserts a
`[reachability: loaded-at-runtime]` tag on CVEs the evidence tags `[reachability: not-observed]`.
Correct verdict on both entries: **refuted** (all CVEs not-observed, no alert/hands-on-keyboard
signal, exposed-secrets field `(none)`).

Artifacts referenced:
- Live flip prompt (exact bytes): scratchpad `protector_prompt.txt` (25,354 chars, ~6.3K tokens,
  120 objectives). Line numbers below (`P:n`) refer to that file.
- Live findings snapshot `findings3.json`: protector/protector displayed
  `Exploitable("A critical [reachability: loaded-at-runtime] CVE (CVE-2023-45853) is present …
  despite the CVE list being marked as '(none)'")` while every sibling entry refutes.
- Engine code: `engine/src/engine/reason/adjudicate/{prompt.rs,guards.rs,model_call.rs,
  evidence.rs,surface.rs}`, `engine/src/engine/adj_gate.rs`, `engine/src/engine/state/verdict_store.rs`.
- Bakeoff: `scripts/judge_bakeoff.py`.

---

## 1. Root cause

There is no single defect; the flip is the intersection of five mechanisms, each individually
verifiable in the prompt bytes and the model's own reason strings. The first two are the core.

### R1. Instructional token dominance: the fabricated phrase is the most-primed phrase in the prompt

Measured on the live prompt:

| phrase | occurrences | where |
|---|---|---|
| `loaded-at-runtime` | **10** | **all in instructions** (P:6 ×3, P:13, P:14 ×2, P:26 header, P:152, P:155, P:156) — **zero in evidence** |
| `not-observed` | 7 | only **4** attached to actual CVEs (P:26); 3 in instructions |
| `exploit*` | 138 | ~120 of them the objective boilerplate "…if exploited" (P:31–150) |
| `exploitation evidence` | 9 | instructions |

The tag the model must *not* emit is the most heavily reinforced n-gram in the context, and every
occurrence appears in the frame "`[reachability: loaded-at-runtime]` … IS exploitation evidence."
A 1.7B Q4 model generating a one-sentence justification leans on copy-from-context (induction);
the copy source it finds 10 times is the instruction phrase, not the 4 distant evidence tags. The
model doesn't "decide the CVE is running and then misreport" — it pattern-completes
`CVE-… [reachability: ` with the contextually dominant continuation.

### R2. The "reachability" vocabulary collision — the smoking gun in reply #1

P:3 asserts, in the strongest terms the prompt has: *"A deterministic analysis already **PROVED**
this workload can reach every objective listed — **reachability is a GIVEN**."* The CVE tag axis
is *literally named* `[reachability: …]` (P:26; rendered at `evidence.rs:97-103`). Reply #1 splices
the two: *"…despite not being observed running, **as their reachability is confirmed**."* The model
transferred the proven-objective-reachability assertion onto the CVE tag namespace: CVE has a
"reachability" attribute + "reachability is PROVEN/GIVEN" ⇒ reachability confirmed ⇒
`loaded-at-runtime`. Two unrelated concepts (network/RBAC reachability of objectives; whether
vulnerable *code* was observed loading) share one word, and the prompt globally asserts the word
is proven true.

### R3. Objective-list dominance and evidence→decision distance

The 120 near-identical objective lines are 16,415 chars — **65% of the prompt**. The CVE evidence
sits at char ~4,360; the `Decide:` block at ~24,153 — a ~4,900-token gap filled with lines each
containing "could read a credential store **if exploited**". At the decision point the model must
bind four single `not-observed` tokens seen ~5K tokens earlier, against a lexical field saturated
with "exploited" (138×). Reply #2 shows the binding failure directly: *"despite the CVE list being
marked as '(none)'"* — the CVE list is NOT `(none)`; the **adjacent** exposed-secrets (P:27) and
posture (P:29) fields are. The model can no longer reliably bind values to fields at this scale.
(ADR-0029 already diagnosed the flip as a decision-boundary tail event; R1–R4 are *why this prompt
shape sits at the boundary*.)

### R4. The runtime-behavior delta is the shape-specific trigger

The ADR-0023 "Changes since…" section (P:152) in the flip prompt duplicates the **entire**
"Observed runtime behavior" field (P:28) verbatim, as 8 lines each prefixed
**"newly-observed runtime behavior:"** — and it is the last evidence before `Decide:` (recency-
salient). "newly-**observed** … **runtime**" is lexically adjacent to the evidence-defining
concepts "observed running" / "loaded-at-**runtime**". A small model holding "critical CVEs
present" + "new runtime activity observed" blends them into "CVE observed at runtime". Reply #1 is
visibly wrestling with exactly this: *"…indicate exploitation evidence **despite not being observed
running**."*

This explains the measured shape-dependence: the flip experiment on the *newly-reachable-secret*
delta variant scored **0/20 flips**, while both live flips occurred on the *runtime-behavior* delta
variant. It also explains the recurrence pattern: after a protector restart the behavior windows
and baselines reset, so the entry's next judgment carries exactly this "everything newly-observed"
delta shape — the flip-prone prompt is re-rolled on every restart/behavior-window churn, on the
cluster's two biggest entries (protector, argocd).

### R5. Model capacity at temp-0 under live serving conditions

qwen3:1.7b Q4_K_M on CPU. ADR-0029's diagnosis stands: the same bytes refute in ~all controlled
trials; the live engine's serving conditions (KV prefix reuse, batched decode, keep-warm churn)
make temp-0 non-bit-reproducible, so a borderline argmax occasionally tips. R1–R4 are what put
this prompt shape *at* the border; R5 is what makes the tip stochastic and rare.

### R6 (amplifier, not cause): the flip used to freeze

On the deployed image (0.3.104, pre-JEF-445): a one-time `Exploitable` was (a) cached in the
exact-fingerprint LRU, (b) served by the ADR-0023 subtractive-delta hold, and (c) **persisted in
the durable decision journal and replayed on boot** ("an `Exploitable` replays as `Exploitable`,
never downgraded" — `adjudicate/mod.rs:42-45`, JEF-301). A ~1-in-N tail event therefore became a
*standing* false breach on the dashboard (findings3.json shows precisely this frozen state).
JEF-445 (merged, **not yet deployed**) removes the freeze by re-verifying positives every pass.

---

## 2. Prompt audit (line-referenced weaknesses)

- **W1 — vocabulary collision** (R2). P:3 ("reachability is a GIVEN … PROVED") vs the CVE tag
  namespace `[reachability: …]` (P:26; `evidence.rs:98`). One word, two concepts, one global
  assertion of truth.
- **W2 — the anti-fabrication instruction is id-scoped, not tag-scoped.** P:160 / `prompt.rs:363`:
  "that CVE id MUST appear VERBATIM in the CVE list above." The model *complied* — both flips cite
  real ids (CVE-2023-45853 etc.) — while fabricating the **tag**. Nothing says the *tag* you
  attribute to a CVE must appear on that CVE's line.
- **W3 — scar-tissue caveat density primes the failure it guards against.** The three-way evidence
  rule is stated **four** times (P:5–9, P:152 preamble, P:155–156, plus the traps list); the traps
  list has grown to four entries (P:11–15), two of them double-negative carve-outs added by
  earlier fixes (JEF-405's "…does NOT cancel a `loaded-at-runtime` CVE … never downgrades" at
  P:14; the "even when the matching library-load also appears" clause at P:6). Every incremental
  fix added more instruction mass containing `loaded-at-runtime` (now 10×, R1). The prompt is
  accreting exactly the way few-shot examples did before JEF-134 removed them for being parroted.
- **W4 — the JEF-402 outcome phrasing plants "exploited" 120×.** `evidence.rs:304-317` renders
  every authorized credential objective as "could read a credential store **if exploited**". The
  fix for the previous hallucination (exposed-secret conflation) saturated the context with the
  stem of the target verdict label (R3).
- **W5 — delta duplication + live-signal-flavored label.** `surface.rs:131` labels behavior
  additions "newly-observed runtime behavior"; `render_changes_block` (`prompt.rs:381-386`)
  re-renders lines already present at P:28, verbatim, closest to the decision point (R4). The
  preamble does restate the bar, but the label itself reads like a live signal.
- **W6 — latent self-contradicting label: "newly-running CVE".** `surface.rs:128` labels ANY CVE
  addition "newly-running CVE". A new trivy finding tagged `not-observed` would render as
  `newly-running CVE: CVE-… [reachability: not-observed]` — the prompt would then itself assert
  the contradiction the model currently has to fabricate. Not the trigger in these two flips (the
  delta was behaviors-only) but the same failure class, one scan away.
- **W7 — "known-exploited" framing over context-only evidence.** The header (P:26,
  `prompt.rs:350`) reads "Critical / known-exploited CVEs" over a list whose EPSS values are
  0.00–0.03 and which contains no KEV entry. Exploitation-flavored framing over CVEs the same line
  calls context-only.
- **W8 — no grounding requirement in the output.** The JSON asks for a one-sentence free-prose
  reason; the model is never required to *copy* the tag of the CVE it cites, so nothing forces the
  single token that decides the case through the output path.

## 3. Code audit (what amplifies or fails to catch it)

- **`guards.rs:86-107` (`guard_fabricated_cve`) checks CVE *presence*, not the claimed tag.** Both
  live flips cite ids genuinely in the evidence, so the guard passes. The guard exists because "a
  small CPU model can copy a CVE id … onto a workload that has none"; the model now copies the
  *tag* from the instructions instead. The grounding check stops one token short of the actual
  fabrication.
- **`guards.rs:143-161` (`guard_unsupported_exploitable`) is inert here by design.** Any CVE in
  the list (even all-not-observed) counts as an anchor, so a fabricated-tag promotion sails
  through. (Consistent with ADR-0029; noted for completeness.)
- **`adj_gate.rs` + `verdict_store.rs` + JEF-301 replay froze the flip** (R6). JEF-445 fixes this
  and is merged but not deployed — the cluster runs 0.3.104. Until it ships, every tail flip is
  sticky.
- **No flip observability.** `model_call.rs` records prompt/reply/verdict, but nothing counts
  "same fingerprint judged twice with different verdicts" — the one metric that would have
  quantified this class in prod instead of via ad-hoc archaeology.
- **Bakeoff drift** (`scripts/judge_bakeoff.py`, case `protector_notobserved_cves_broad_rbac`):
  - Fixture `runtime` is `"(none)"`; the live flip prompt has a full runtime section (internet
    egress to 7 providers + connections + journal file writes).
  - Fixture delta is one *newly-reachable secret*; the live flip delta is **8 "newly-observed
    runtime behavior" lines**. This is the variant that flips (R4) and the bakeoff never sends it —
    which is exactly why the fixture scores 0/20 while prod flips.
  - CVE metadata drift: fixture `CVE-2023-45853 [cvss: 9.8]` vs live `[cvss: 5.3]`; fixture
    `CVE-2026-13221` missing the live `[epss: 0.01]`.
  - Objective-set drift: fixture lacks `secret/data/patroni-endpoint-watchdog-alert-smtp`, carries
    an extra `secret/security/scan-vulnerabilityreport-…-regcred`, and tags
    `secret/security/trivy-operator-trivy-config` `[MOUNTED+RBAC-GRANTED]` where live says
    `[RBAC-GRANTED]`.
  - Structural drift risk: `SYS` is a hand-maintained copy of `prompt.rs`'s template. It matches
    today; nothing enforces it.

## 4. Ranked recommendations

Legend: layer / expected impact / cost / risk / ADR-0029 fit. All prompt changes invalidate every
cached verdict (the prompt is the cache key, JEF-350) — one-time full re-judge storm on deploy;
roll in a quiet window.

### 1. P1 — Split the CVE field by tag; make the crucial fact structural (prompt + evidence-shaping)
Render two labeled CVE fields instead of one:
`CVEs with exploitation evidence — observed loading at runtime: <<<(none)>>>` and
`CVEs present in image only — NOT observed running (context, never evidence): <<<CVE-… , …>>>`.
Lossless regrouping (no capping, no truncation, every CVE still shown in full), so it does not
touch ADR-0029's prohibition — it is enrichment of the same class as the JEF-79 reach tags. To
fabricate evidence the model must now cross a *section boundary* against a `(none)` it can see,
rather than flip one token 5K tokens from the decision. Kills the R1 copy-surface: the phrase
"loaded-at-runtime" need no longer appear per-CVE at all.
Impact: high (attacks R1+R3 directly). Cost: small (`prompt.rs` render + bakeoff SYS resync +
test updates). Risk: low; cache churn on deploy. ADR-0029: compliant (adds structure, hides
nothing).

### 2. P2 — De-collide the vocabulary (prompt, trivial)
Rename the CVE tag axis in the rendered prompt from `[reachability: …]` to `[runtime-load:
observed | not-observed | static-binary-unknowable]` (`evidence.rs:98` + every instruction
mention), and qualify P:3 to "can **reach every objective listed below**" so "reachability is a
GIVEN" can no longer be transferred to CVEs (R2). Also fix W7: "Critical / known-exploited CVEs" →
"Critical CVEs present in the image" (keep KEV/EPSS per-line where they actually exist).
Impact: high on the observed splice (reply #1 is literally this bug). Cost: trivial. Risk: none
identified. ADR-0029: compliant (naming, not gating).

### 3. G1 — Extend the grounding guard to the tag (guard — argued explicitly against ADR-0029)
Extend `guard_fabricated_cve`: if an `Exploitable` reason asserts `loaded-at-runtime` (post the
P2 rename: `runtime-load: observed`) and **no CVE line in the evidence carries that tag**, downgrade
to `Uncertain` — exactly as a fabricated id does today.
This is the honest answer for a *guaranteed* kill of this class, and I argue it is **inside**
ADR-0029's explicitly preserved scope, not against its decision. The ADR's scope note: the
fabrication guard "guards output *grounding/integrity* (the model referenced something that isn't
there — an invalid output), not the *judgement call* (whether present evidence amounts to a
breach)." A reachability tag the evidence does not contain is precisely "something that isn't
there": checking it is a string-membership test over a **closed three-value vocabulary rendered by
our own code** — no severity weighing, no breach re-derivation, no whack-a-mole surface (the
vocabulary cannot grow adversarially). The downgrade is to `Uncertain` (skeptic, re-judged next
pass), never `Refuted`, so the guard still decides nothing about breach in either direction. Both
live flips would have been caught; a legitimate exploitable citing a genuinely-tagged CVE is
untouched, and an exploitable that cites no tag at all is untouched.
Because the user is firm on ADR-0029, this should not ship silently: record it as a scope-note
amendment to ADR-0029 (or a short ADR-0030 "tag grounding is grounding") and let that recorded
decision be the gate. If the amendment is declined, recommendations 1–2 and 5–6 stand alone.
Impact: total for this signature (deterministic catch). Cost: small (one function + tests).
Risk: a future flip that names no tag evades it — the guard narrows, prompt fixes shrink, the
combination is the defense. ADR-0029: within the preserved grounding-guard class; requires an
explicit recorded decision because the boundary is the ADR's most sensitive line.

### 4. E1 — Fix the delta labels and mark duplicates (evidence-shaping, small)
`surface.rs:127-131`: "newly-running CVE" → "newly-listed CVE (its reachability tag decides its
weight)" (defuses W6 before it fires); "newly-observed runtime behavior" → "newly-observed
behavior (apply the live-signal test above)". In `render_changes_block`, suffix behavior lines
that are verbatim-present in the runtime field with "(also shown above)" so the delta reads as
attention-direction, not new activity. Keeps ADR-0023 fully intact (full state + delta, nothing
hidden).
Impact: medium (attacks R4, the shape-specific trigger). Cost: small. Risk: low. ADR-0029:
compliant.

### 5. M1 — Model-tier option (model)
Bakeoff `qwen3:4b-instruct` (already in `DEFAULT_MODELS` as "research #1") and a
`qwen3:1.7b` Q8 quant against the *new* flip-shaped fixture (see 6) — a larger/less-quantized
judge moves the decision boundary away from this shape without touching the architecture. This is
ADR-0029's sanctioned lever. Gate on the ADR-0026 operational steps (Pi latency/RAM, strict JSON,
delta-path behavior, in-cluster availability).
Impact: possibly high, unproven until measured. Cost: medium (bakeoff time + Pi validation +
values.yaml change in the infra repo — **human follow-up, not autonomous**). Risk: CPU latency
regression (4B ≈ 2–3× slower; keep-warm and timeout budgets must be re-checked).
ADR-0029: the explicitly preferred remedy.

### 6. PR1 — Process: deploy the unfreeze, resync the bakeoff, add flip observability (process)
a. **Deploy JEF-445** (image > 0.3.104). Independent of everything else: turns any residual tail
   flip from a standing false breach into a one-pass blip. Highest value-per-risk in this list.
b. **Add the flip-shaped fixture**: a `protector_runtime_delta` case mirroring the live flip
   prompt byte-faithfully — full runtime section, the 8-line "newly-observed runtime behavior"
   delta, current CVE metadata (cvss 5.3, epss 0.01) — and fix the enumerated fixture drift.
   Consider generating fixtures from a captured live prompt file rather than hand-maintaining
   `SYS` (drift-proof by construction).
c. **Add a boundary-mass mode to the bakeoff**: N seeded runs at temperature ~0.8 tallying the
   exploitable fraction. A rare temp-0 tail flip is invisible at N=20 (0/20 here), but the
   probability mass near the boundary is measurable at elevated temperature — that is the A/B
   metric that can actually validate prompt changes against a 1-in-many flip. (Harness exists:
   scratchpad `flip_t.py`.)
d. **Count verdict disagreement in prod**: same cache fingerprint, different verdict across passes
   → a loud log line + OTLP counter. Makes the flip rate a number instead of an incident.

### 7. P3 — Copy-then-decide structured output (prompt, larger — optional)
Require the JSON to carry a grounding map before the verdict:
`{"cve_tags": {"CVE-…": "<tag copied verbatim>"}, "verdict": …, "reason": …}`. Forcing the model
to transcribe each CVE's actual tag immediately before deciding is the strongest known small-model
mitigation (copy beats recall), and it gives G1 a structured field to check instead of prose.
Impact: high. Cost: medium (`parse_verdict`, guards, bakeoff, more output tokens on CPU).
Risk: JSON-shape regressions on a 1.7B; validate hard. ADR-0029: compliant (shapes output, not
verdict).

## 5. Concrete next step — smallest change most likely to kill the class

**Ship one PR: P1 + P2 + E1** (split CVE fields, de-collide "reachability", fix delta labels),
with the bakeoff resynced (PR1.b) in the same change. **Deploy JEF-445 to the cluster first** —
it is already merged and removes the freeze amplifier regardless of the prompt outcome.

Validation (deployed model, over the port-forward, A/B old-vs-new — per the repo's bakeoff
discipline):

1. `python3 scripts/judge_bakeoff.py qwen3:1.7b` — the full 12-case suite must stay clean
   single-shot (no regression on the three must-exploit cases; the prompt change must not weaken
   log4j/exposed-secret/live-signal detection).
2. Flip A/B on the new `protector_runtime_delta` case (PR1.b): old prompt vs new prompt,
   N=20 at temp 0 **and** N=20 seeded at temp 0.8 (boundary-mass, PR1.c). Ship when: temp-0 flips
   = 0/20 on the new prompt AND the temp-0.8 exploitable-mass is strictly lower than the old
   prompt's (the actual sensitivity metric; temp-0 alone cannot resolve a rare tail).
3. Post-deploy: watch the PR1.d disagreement counter (or, until it exists, the judgement log) on
   protector/protector and argocd-server across two restarts of protector — the historical
   recurrence trigger (R4) — expecting zero standing `Exploitable`.

G1 (the tag-grounding guard) is the deterministic backstop this class honestly wants; it awaits
the recorded ADR-0029 scope decision above and is deliberately *not* bundled into the minimal PR.

## Appendix — measurements

- Live prompt: 25,354 chars ≈ 6.3K tokens; 120 objective lines = 16,415 chars (65%);
  CVE evidence → `Decide:` gap ≈ 4.9K tokens; `loaded-at-runtime` ×10 (all instructions),
  `not-observed` ×7 (4 in evidence), `exploit*` ×138, `(none)` ×5.
- Prior flip experiment (parent-run): newly-reachable-secret delta variant, deployed qwen3:1.7b,
  temp 0: **0/20 flips** — the flip is prompt-shape-dependent (R4).
- Live flips (findings3.json + the two captured replies): 2 distinct fabricated-tag `exploitable`
  replies on protector/protector; both cite real CVE ids with the fabricated tag; one also
  misbinds `(none)` to the CVE list (R3).
- This audit's flip run on the exact live flip prompt (temp 0, N=10, port-forwarded deployed
  judge): 1/1 refuted (328 s/call), then terminated
  early — with a second N=20 flip run already in progress against the same shared model, calls
  serialized at ~5.5 min each and a full N=10 would have contended with the live engine for ~an
  hour for an under-powered measurement (a tail this rare is invisible at temp-0 N≤20, as the
  prior 0/20 showed). That under-power is precisely why the validation plan (§5) specifies the
  seeded temp-0.8 boundary-mass metric (PR1.c, harness `flip_t.py` + `variant_recap.txt` left in
  the session scratchpad) as the A/B-sensitive measurement for prompt changes.
