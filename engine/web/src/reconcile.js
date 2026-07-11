// The Findings keyed-reconcile engine (ADR-0025 / JEF-397). The heart of the rewrite: instead of
// the v3 innerHTML swap that destroyed focus, `<details>` state, and scroll every poll, we key
// each row on its STABLE `finding.id` and let Preact patch only what changed — so a present-in-
// both row keeps its exact DOM (focus, open disclosures, selection) untouched.
//
// This module owns only the part Preact's keyed diff does NOT do for us: the GONE-WHILE-OPEN
// TOMBSTONE. When a finding the operator had expanded (or was focused inside) disappears from the
// new snapshot, snapping it out from under them is dishonest and jarring — so we hold a single
// calm tombstone render ("this finding cleared — the model no longer sees this path") keyed on the
// same id, then drop it. A gone finding that was NOT expanded/focused is hard-removed silently.
//
// `computeRows` is a PURE function (snapshot + prior render + interaction state → next render list)
// so it is trivially unit-testable offline — the reconcile logic is where a bug would silently wipe
// operator state, so it is tested without a browser.

/**
 * @typedef {{ id: string }} Finding a finding row (only `id` matters to the reconciler).
 * @typedef {{ finding: Finding, tombstone: boolean }} Row a row to render: either a live finding
 *   or a one-shot tombstone standing in for a just-gone finding.
 */

/**
 * Compute the next Findings render list from the incoming snapshot, the previously-rendered ids,
 * and the ids the operator currently cares about (expanded and/or focused). Pure — no DOM, no
 * store — so it is unit-tested directly.
 *
 * Rules (ADR-0025 / JEF-397):
 *  - Present in the new snapshot → rendered as a live row (Preact keys on `finding.id`, so its DOM
 *    — focus, open `<details>`, selection — is preserved in place; a NEW id is simply inserted at
 *    its already-sorted position and must not steal focus, which the keyed diff guarantees).
 *  - Gone from the snapshot AND it was expanded/focused → emit a single tombstone row (keyed on the
 *    same id) exactly ONCE, then never again. The caller purges the id after this render.
 *  - Gone and NOT expanded/focused → dropped silently (no tombstone).
 *
 * The snapshot's order is authoritative (the server already sorts by urgency); tombstones are
 * appended at the end so a clearing row doesn't shove the live list around.
 *
 * @param {Finding[]} incoming the new snapshot's findings, in server (urgency) order.
 * @param {Set<string>} priorIds the finding ids present in the PREVIOUS render (to detect gone ones).
 * @param {Set<string>} keptOpenIds ids the operator is invested in (expanded ∪ focused) — the set
 *   that earns a gone finding a tombstone instead of a silent drop.
 * @param {Set<string>} priorTombstoneIds ids already shown as a tombstone last render — so a
 *   tombstone lasts exactly one render and never loops.
 * @returns {{ rows: Row[], tombstonedNow: Set<string> }} the render list and the ids newly
 *   tombstoned THIS render (the caller drops+purges them next tick).
 */
export function computeRows(incoming, priorIds, keptOpenIds, priorTombstoneIds) {
  /** @type {Row[]} */
  const rows = [];
  const presentIds = new Set();

  for (const finding of incoming) {
    presentIds.add(finding.id);
    rows.push({ finding, tombstone: false });
  }

  /** @type {Set<string>} */
  const tombstonedNow = new Set();
  for (const id of priorIds) {
    if (presentIds.has(id)) continue; // still present — Preact keeps it in place.
    if (priorTombstoneIds.has(id)) continue; // already had its one tombstone render — drop it now.
    if (!keptOpenIds.has(id)) continue; // gone but unopened — silent hard-remove.
    // Gone while the operator was invested in it: one calm tombstone render, keyed on the same id.
    rows.push({ finding: { id }, tombstone: true });
    tombstonedNow.add(id);
  }

  return { rows, tombstonedNow };
}

/**
 * The set of finding ids currently present in a snapshot — the `priorIds` for the NEXT reconcile.
 * @param {Finding[]} findings
 * @returns {Set<string>}
 */
export function idsOf(findings) {
  return new Set(findings.map((f) => f.id));
}
