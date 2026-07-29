# 0033. Cut-choice judge: qwen3:1.7b holds the contract with an exact-set containment prompt

- Status: Accepted
- Date: 2026-07-28

## Context

[ADR-0034](0034-cut-choice-contract.md) fixes the cut-choice contract — the model emits
`{assessment, reason, contain:[node-key…]}`, determinism resolves each named node to its
narrowest reversible cut — but left one question to be **measured, not assumed** (JEF-568 /
T2b): can the deployed judge (qwen3:1.7b, a 1.7B CPU model) emit it reliably — correct 3-value
assessment, exact minimal cut-set, no over-cut — or must the judge escalate to a 4B model?
ADR-0034's own premise is that the contract "must be one **1.7b can emit reliably** … escalate
to 4B/8B only on measured failure." This ADR records that measurement and the resulting tier +
prompt.

## Decision

**The judge stays qwen3:1.7b.** A cut-choice bench (`scripts/judge_bakeoff_cutchoice.py`,
JEF-568) scores the ADR-0034 schema on the deployed judge across both evidence directions
(entry loaded-CVE; downstream behavioral / exposed-secret), the minimality centerpiece (clean
entry + live-compromised downstream → contain the downstream *only*), the JEF-588
downstream-CVE cut trap, and the JEF-402 / broad-RBAC refute traps. On the **deployed pod**
(temp-0, the greedy prod path):

- **Assessment: 8/8**, and **every refute/cut trap passes** — 1.7b never over-cuts a clean
  workload, and correctly returns `no_attack` / `[]` on a downstream loaded-CVE behind a clean
  edge (JEF-588) and on broad RBAC / reachable-secret-no-evidence (JEF-402).
- **The cut-set lands with a tightened output instruction.** The first deployed run exposed an
  *under-cut*: 1.7b recognized the attack but returned `contain=[]` on 3 of 4 real attacks — a
  recognized breach with no proposed cut. Pinning `contain` to **exactly the evidence-bearing
  set** — "name every compromised workload and no others; an `attack` with an empty `contain`
  is contradictory" — fixed all three on the deployed pod *without* inducing over-cut:
  entry-loaded-CVE → `{entry}`; clean-entry + live-downstream → `{downstream}` only (the
  minimality centerpiece, no entry over-cut); both-evidenced → `{entry, downstream}`.

**That tuned prompt is the one JEF-570 wires into `build_judgment_prompt`.** It is validated on
the deployed judge, not guessed. Escalation to 4B is deferred — unnecessary on this evidence,
and not authoritatively comparable without first adding 4B to a cluster ollama pod (see
Methodology).

### Methodology: the cut-choice bench must run on deployed hardware

A local (Mac arm64/Metal) run of the *same* model tag, prompt, and `num_ctx=16384` **diverges
from the deployed pod (amd64/CPU) on the cut-set**: local *over*-cut the clean entry; deployed
*under*-cut to `[]`. Assessment and the traps agreed across backends; only the cut-set —
decided at greedy tie-breaks a different llama.cpp backend resolves differently — diverged. The
judgement of a cut-choice change is therefore trustworthy only on the deployed judge; a local
proxy is unfaithful for the cut-set. The bench points at a port-forwarded pod via `OLLAMA_URL`
for exactly this reason.

## Consequences

- The cut-choice contract is armed on the deployed judge — no model swap, and no arming a 1.7b
  that could not emit it.
- The residual risk ADR-0034 named (grounded over-cut) is bounded by the exact-set prompt + the
  ADR-0034 guards, and is now a measurable, regression-tracked quantity — the bench's cut-set
  score and `--flip` over-cut mass, **run on the deployed pod**.
- A future escalation to 4B (e.g. if the downstream/pivot lane stresses 1.7b) requires an
  on-cluster 4B bench first; local numbers do not transfer.
- [JEF-570] wires the `incident/` module (ADR-0034, merged in #296) and this validated prompt
  into `adj_pass` / `reconcile` / the journal.
