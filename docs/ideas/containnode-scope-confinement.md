# Idea brief — Close the ContainNode enforceScope escape at the actuation boundary

**Status:** settled → ticketed (unblocks the deferred co-resident-deny scope-filter). Load-bearing decision recorded as an
addendum to [ADR-0040](../adr/0040-node-scoped-containment-mechanism-escalation.md).

## The idea (as posed)
Unblock the deferred scope-filter for node containment: `co_resident_denies`
(`engine/src/engine/respond/actuator/node_containment.rs`) returns one default-deny per
labelled pod co-resident on a contained node, **unfiltered by `enforceScope`**. Applying it
unfiltered would write default-deny `NetworkPolicy`s into namespaces the operator never
authorized — the enforce-everywhere escape [ADR-0021](../adr/0021-two-setting-operating-posture.md)
exists to prevent. The fix was deferred to "the future apply call-site," and the #324 review
ruled the shared helper must **not** be filtered (the revert path uses the full set; filtering
it would orphan out-of-scope denies).

## Two findings that reframe the unblock
1. **The "apply call-site" will never exist on the current trajectory.** Protector has *no*
   approve→apply mechanism for *any* action class: the dashboard is a view that never gates
   ([ADR-0016](../adr/0016-severity-vs-urgency.md)), the MCP is read-only by ADR
   ([ADR-0031](../adr/0031-read-only-mcp-server-tiered-redaction.md)), and `Decision::Propose`
   terminates in a log line. "Human approval" has always meant *the human acts out-of-band
   (kubectl)*. `NodeContainmentActuator::apply` is documented as having no `Engine` call site.
   Waiting for that call site is waiting forever.
2. **The deny set is not rendered anywhere** (grepped every surface). The `ContainNode`
   proposal an operator reads is the menu line + a *fixed-string* note (no names, no counts);
   the pre-arm scope preview *excludes* `ContainNode` (it requires `is_additive_live()`);
   nothing enumerates the co-resident denies. So there is no "misrepresenting render" to fix
   — the set's only non-test consumers are `contain_node_in_scope` (eligibility, already
   scope-aware), the revert seam (full set, must stay), and the caller-less `apply`.

## Recommended approach — scoped-subset function + newtype at the actuator seam
Add `co_resident_denies_in_scope(graph, host, scope)` beside the unfiltered helper: unscoped →
full set (historical meaning); scoped → retain denies where `scope.in_scope(deny)` holds (the
same ADR-0021 namespace-OR-label match the webhook uses). Wrap its result in a `ScopedDenies`
newtype constructible only by that function; change `NodeContainmentActuator::apply` to accept
`&ScopedDenies` (revert keeps `&[Mitigation]`, full set). Rebase `contain_node_in_scope` on the
same function so eligibility and the apply subset are **one scope-match source**, exercised
every pass — the filter is live code, not dead insurance. This makes the invariant structural
("safe by construction, not caller discipline" — mirroring the revert seam's own ownership
gate): the only door into `apply` demands a scope-confined set *by type*, the revert path is
untouched (per #324), and eligibility stops being a parallel scope implementation.

Approaches rejected: **enumerate + filter the deny set on operator surfaces** (filters a view
that doesn't exist and doesn't close the actuation escape — ADR-0016 says the view is never the
gate); **build the approve-to-apply flow** (a mutating authenticated surface on a
deliberately-read-only product — contradicts ADR-0016/0031; needs its own ADR if ever wanted).

## Key decisions (see the [ADR-0040](../adr/0040-node-scoped-containment-mechanism-escalation.md) addendum)
1. **No in-product approve→apply path for node containment** — the human act stays out-of-band
   (kubectl cordon + runbook). This retires "the future apply call-site" as a design location.
2. **Scoped apply is honest partial containment** — out-of-scope pods on a contained node stay
   reachable, because writing into an unauthorized namespace *is* the ADR-0021 escape. Filter,
   don't refuse-whole (consistent with the actuator's "partial containment is safer than none").
3. **Filter home:** a sibling pure function + newtype at the actuator seam; the shared full-set
   helper is untouched (revert semantics preserved).
4. **`contain_node_in_scope` derives from the same subset function** — one scope-match source.
5. **The model-visible fixed note is NOT amended** — encoding deployment scope into it would
   churn the prompt fingerprint for information the model has no business weighing (the model
   decides *what*, `enforceScope` governs *where-authorized*).

## Risks / open items
- Full-set revert vs filtered apply asymmetry is **safe**: revert deletes only protector-named
  objects, so lifting a never-placed deny is a harmless no-op. Invariant: the revert set ⊇ any
  set apply could have placed under any historical scope. Holds by construction.
- Scope changed between passes: the subset is computed fresh at each call site from current
  scope — no stored stale set.
- Genuinely open: none. Pure-function change with exhaustive unit coverage.

## HANDOFF TO PLAN-SPRINT
Theme: **"close the ContainNode enforceScope escape at the actuation boundary + record the
no-in-product-approve decision."** One small pure-function engine PR: `co_resident_denies_in_scope`
+ `ScopedDenies` newtype + `apply` takes the scoped set by type + rebase `contain_node_in_scope`
+ the ADR-0040 addendum. No chart/RBAC/config/dashboard surface. The deferred scope-filter ticket closes against it.
Panel: infra.
