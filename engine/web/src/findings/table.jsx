// The Findings view (ADR-0025 / JEF-397): the semantic `<table>` (NOT role=grid) of keyed rows, or
// the honest empty-state. This component owns the RECONCILE lifecycle around the pure
// `computeRows` engine — it remembers the previously-rendered ids and the currently-tombstoned ids
// (via refs), tracks which finding the operator is focused inside, and after a render that showed a
// tombstone it schedules the id's drop + sessionStorage purge.
//
// The keyed rows do the real work: Preact patches only what changed, so an expanded row, an open
// disclosure, the active element's focus, and the text selection all survive a poll untouched —
// the boring default that the v3 innerHTML swap could never give.

import { useEffect, useRef } from "preact/hooks";
import { computeRows, idsOf } from "../reconcile.js";
import { FindingRow, TombstoneRow } from "./row.jsx";
import { FindingsEmpty } from "./empty.jsx";

/**
 * @param {object} props
 * @param {any} props.view the Findings view props (`{ strip, findings }`, serde kebab-case).
 * @param {import("../store.js").Store} props.store the client store (expansion/disclosure state).
 */
export function FindingsView({ view, store }) {
  const findings = Array.isArray(view.findings) ? view.findings : [];

  // Reconcile bookkeeping that must survive re-renders without causing one: the ids present last
  // render, and the ids currently shown as a one-shot tombstone.
  const priorIds = useRef(new Set());
  const tombstoneIds = useRef(new Set());
  const containerRef = useRef(null);

  // Which finding the operator is currently focused inside — a gone-while-focused finding earns a
  // tombstone (not a silent drop) so focus never vanishes without explanation.
  const focusedId = focusedFindingId(containerRef.current);
  const keptOpen = new Set(store.getState().expandedRows);
  if (focusedId) keptOpen.add(focusedId);

  const { rows, tombstonedNow } = computeRows(
    findings,
    priorIds.current,
    keptOpen,
    tombstoneIds.current,
  );

  // After committing this render: the present ids become the next reconcile's priors, and any id we
  // just tombstoned is dropped + purged so it never renders again (one tombstone, then gone).
  useEffect(() => {
    priorIds.current = idsOf(findings);
    tombstoneIds.current = tombstonedNow;
    if (tombstonedNow.size > 0) {
      // Purge the persisted expansion/disclosure ids for the cleared findings, and force one more
      // render on the next tick so the tombstone drops (its id is now in `tombstoneIds`, so
      // `computeRows` won't re-emit it).
      const timer = setTimeout(() => {
        store.purge(tombstonedNow);
      }, 0);
      return () => clearTimeout(timer);
    }
  });

  if (rows.length === 0) {
    return (
      <main class="view view-findings" ref={containerRef}>
        <FindingsEmpty strip={view.strip} />
      </main>
    );
  }

  return (
    <main class="view view-findings" ref={containerRef}>
      <table class="findings">
        <thead>
          <tr>
            <th class="col-expand" scope="col">
              <span class="visually-hidden">expand</span>
            </th>
            <th class="col-delta" scope="col">
              {"\u{0394}"}
            </th>
            <th class="col-posture" scope="col">
              POSTURE
            </th>
            <th class="col-entry" scope="col">
              ENTRY {"\u{2192}"} OBJECTIVE
            </th>
            <th class="col-path" scope="col">
              PATH
            </th>
            <th class="col-evidence" scope="col">
              EVIDENCE
            </th>
            <th class="col-disposition" scope="col">
              DISPOSITION
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) =>
            row.tombstone ? (
              <TombstoneRow key={row.finding.id} id={row.finding.id} />
            ) : (
              <FindingRow
                key={row.finding.id}
                f={row.finding}
                expanded={store.isExpanded(row.finding.id)}
                onToggle={() => store.toggleRow(row.finding.id)}
                promptOpen={store.isPromptOpen(row.finding.id)}
                onPromptToggle={(open) => store.setPromptOpen(row.finding.id, open)}
              />
            ),
          )}
        </tbody>
      </table>
    </main>
  );
}

/**
 * The finding id the active element sits inside, if any — read from the nearest `[data-finding]`
 * ancestor of `document.activeElement`. Used so a gone-while-focused finding earns a tombstone.
 * @param {Element | null} container
 * @returns {string | null}
 */
function focusedFindingId(container) {
  if (!container || typeof document === "undefined") return null;
  const active = document.activeElement;
  if (!active || !container.contains(active)) return null;
  const host = active.closest?.("[data-finding]");
  return host ? host.getAttribute("data-finding") : null;
}
