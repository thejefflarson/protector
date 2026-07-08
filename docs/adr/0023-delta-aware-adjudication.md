# 0023. Delta-aware adjudication: the state is the context, the delta is the question

- Status: Accepted
- Date: 2026-07-08

## Context

The adjudicator (ADR-0013) decides one thing per internet-facing entry: is a proven,
reachable chain a *real breach* — i.e. does the reachable objective carry exploitation
evidence (a running known-exploited CVE, an alert/hands-on-keyboard signal, an exposed
baked-in secret). The deterministic layer proves *what is reachable*; the model judges
*whether it is being exploited*.

Today the model's input (`build_judgment_prompt`) is a **static full-state snapshot**:
Entry, critical CVEs, exposed secrets, static posture, observed runtime behavior, and the
full reachable-objective set — the *current* state, with **no marker of what changed since
the last time we judged this entry**. The per-entry verdict cache (`VerdictStore`) keys a
decisive verdict on the SHA-256 of that whole prompt and re-judges whenever the hash
changes.

A 77-minute production capture (JEF-387 harness, 70 re-judges across 5 entries) showed:

- **100% of re-judges are prompt-churn**, 0% Uncertain-retry.
- **~85% are genuinely-new fingerprints** the cache has never seen — dominated by the
  reachable-objective set advancing as **ephemeral pods cycle** (a CI-runner scale-set
  churns per-pod registration secrets every few seconds; each new replica adds a new
  reachable `secret/…` objective).
- Only ~15% is exact-state ping-pong (a known peer aging in/out of the runtime window),
  recoverable by a multi-slot cache (JEF-390).

The key realization: **the churn is correct.** A newly-reachable object *is* new attack
surface and *should* be evaluated. The waste is not the re-judge — it is that on every
re-judge the model **re-derives the entire world from scratch**, and is never told that
the only thing different is one new object of a kind it has already judged fifty times.

Meanwhile the engine **already computes the delta** it would need: `graph::delta` emits
added/removed edges each pass, `first_seen` stamps when each node first appeared, and
`prev_posture` (JEF-201) diffs posture pass-over-pass. All of it feeds the dashboard's Δ
column — **none of it reaches the adjudication prompt.**

## Decision

Make adjudication **delta-aware**: keep the full current state as the *context*, and add
the *change* as the explicit *question*.

1. **Prompt shape.** The prompt keeps the full-state snapshot unchanged (see the
   correctness guard below), and gains one section:

   > `Changes since the last decisive verdict:` — the *additions* since the baseline
   > below: newly-reachable objectives, new peers, newly-loaded (running) CVEs, and newly
   > -corroborated behaviors. `(none)` when nothing was added.

   The instruction to the model becomes: *judge whether the current state is a breach,
   with particular attention to whether these NEW elements introduce exploitation
   evidence or complete an exploitable path.*

2. **Baseline.** The delta is computed against the state captured at this entry's **last
   decisive verdict** (not the last pass), stored alongside the cached verdict. So the
   "what's new" accumulates across inconclusive/uncached passes until a decision is made,
   then resets.

3. **Re-judge trigger = a non-empty ADDITIVE delta.** Re-judge an entry when something has
   been *added* to its reachable/observed surface since its baseline. A purely *subtractive*
   change (a pod went away, a peer aged out) can only *reduce* breach risk and does **not**
   trigger a fresh model call — a standing `Exploitable` verdict whose supporting surface
   disappeared is de-escalated by the existing recency/reversion path, not re-judged. This
   is what removes the ping-pong at its root: a known peer flickering out is subtractive,
   so it never re-judges; a genuinely new object is additive, so it does.

4. **Verdict/cache semantics.** A decisive verdict is now "valid for entry `E` as of
   baseline `B`", and stays valid until an additive delta arrives. This supersedes the
   whole-prompt-fingerprint gate for the re-judge decision (the fingerprint LRU of JEF-390
   remains as a second-level guard for exact-state returns and as the cache key within a
   baseline). Uncertain verdicts are still never cached; JEF-234 backoff still gates the
   retry of failed decisions.

## Correctness guard (non-negotiable)

**The full current state stays in the prompt.** The delta *directs attention*; it never
*replaces* the state. A new node can make an *old* chain exploitable in combination (a new
running CVE on a package that an already-reachable secret path depends on; a new
corroborating alert on a long-standing reachable objective). The model must always be able
to reason over the complete picture — we are adding "here is what's new" to a full
snapshot, not asking it to judge a diff in isolation. Any implementation that judges only
the delta is a rejection of this ADR.

## Consequences

- **Cheaper, sharper reasoning.** The model spends its (slow, CPU-bound) call judging the
  change in context rather than re-deriving the world — and its verdict becomes
  self-explaining ("a new runner-registration secret became reachable; it is the same
  low-value ephemeral credential class already judged non-exploitable — not a breach").
- **Churn stops being waste without being suppressed.** We still re-judge on new surface
  (correct), but each re-judge is a focused delta-judgment; subtractive flicker stops
  re-judging entirely.
- **New failure mode to guard:** a wrong or incomplete delta could *hide* new surface from
  attention. The delta must be derived from the same proven graph the full state is (no
  second source of truth), and the correctness guard (full state always present) bounds the
  blast radius — worst case the model sees the new object in the full set but without the
  "NEW" flag, i.e. today's behavior.
- **Interacts with:** ADR-0013 (adjudication — this refines *what* the model is asked),
  ADR-0001 (deterministic proof is the source of the delta), JEF-390 (LRU cache, second
  level), JEF-234 (Uncertain backoff, unchanged). The de-escalation of a verdict whose
  surface vanished is the reversion path (ADR-0009/JEF-141), not a re-judge.

## Open questions (to resolve before implementation, JEF-391)

- Exact projection of the graph delta into prompt lines (which node/edge kinds count as an
  "addition" worth flagging; how to summarize a burst of same-kind additions without hiding
  any).
- Where the baseline snapshot lives (in `VerdictEntry` alongside `cached`) and its memory
  bound.
- Whether "newly-loaded CVE" and "newly-corroborated behavior" deltas are computed from
  `first_seen`/`prev_posture` or need a small additional per-entry record.
