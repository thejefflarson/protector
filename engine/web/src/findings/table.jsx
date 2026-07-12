// The Findings view (ADR-0025 / JEF-397 / JEF-411): the semantic `<table>` (NOT role=grid) of keyed
// rows, or the honest empty-state. Each row is keyed on its STABLE `finding.id`, so Preact patches
// only what changed — an expanded row, an open disclosure, the active element's focus, and the text
// selection all survive a poll untouched. A finding that vanishes from the snapshot is removed by
// Preact's keyed diff (JEF-411 dropped the client-side tombstone; a future "recently cleared" cue is
// server-shipped). No reconcile bookkeeping remains — the keyed diff IS the reconcile.

import { FindingRow } from "./row.jsx";
import { FindingsEmpty } from "./empty.jsx";

/**
 * @param {object} props
 * @param {any} props.view the Findings view props (`{ strip, findings }`, serde kebab-case).
 */
export function FindingsView({ view }) {
  const findings = view.findings ?? [];

  if (findings.length === 0) {
    return (
      <main class="view view-findings">
        <FindingsEmpty strip={view.strip} />
      </main>
    );
  }

  return (
    <main class="view view-findings">
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
          {findings.map((f) => (
            <FindingRow key={f.id} f={f} />
          ))}
        </tbody>
      </table>
    </main>
  );
}
