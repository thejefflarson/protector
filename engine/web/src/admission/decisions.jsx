// The deduped admission decision rows (ADR-0025 / JEF-400) — a 1:1 Preact port of maud
// `decision_rows`: a semantic `<table>` (columns align, `<th scope>`), one row per distinct
// `(subject, image, decision)`. A `would-fail` mesh gate or a `would-deny` what-if is the attention
// case (a denied keyline).
//
// Reconcile keying (the only per-view variation): decision rows have NO id, so each keys on its
// `(subject, image, decision)` TUPLE (see `keys.js`) — the SAME server-dedup key. Two passes of the
// same tuple reconcile to the same node, so the `count` (×N) updates smoothly IN PLACE rather than
// the row tearing and re-inserting. Every untrusted string (subject / image / namespace / reason)
// renders via JSX text (Preact auto-escapes).

import { decisionKey } from "../keys.js";

const DECISION = {
  allow: { glyph: "\u{2713}", word: "admitted" }, // ✓
  audit: { glyph: "\u{25D0}", word: "audited" }, // ◐
  deny: { glyph: "\u{25CF}", word: "denied" }, // ●
  other: { glyph: "\u{2014}", word: "other" }, // —
};

/** Look up a decision's presentation, defaulting to `other` for an unknown tag. */
function decisionOf(tag) {
  return DECISION[tag] || DECISION.other;
}

const GATE = {
  verified: { glyph: "\u{2713}", word: "verified" }, // ✓
  wouldpass: { glyph: "\u{25CB}", word: "would-pass" }, // ○
  wouldfail: { glyph: "\u{2715}", word: "would-fail" }, // ✕
  na: { glyph: "\u{2014}", word: "n/a" }, // —
};

/** The gate status serializes as `verified` / `would-pass` / `would-fail` / `not-applicable`
 *  (kebab-case). Map the wire tag to the CSS token + presentation, defaulting to n/a. */
function gateOf(tag) {
  switch (tag) {
    case "verified":
      return { token: "verified", ...GATE.verified };
    case "would-pass":
      return { token: "wouldpass", ...GATE.wouldpass };
    case "would-fail":
      return { token: "wouldfail", ...GATE.wouldfail };
    default:
      return { token: "na", ...GATE.na };
  }
}

/**
 * @param {object} props
 * @param {any[]} props.rows the deduped decision rows (serde kebab-case).
 */
export function DecisionRows({ rows }) {
  return (
    <section class="admission-rows" aria-label="admission decisions">
      <h3 class="col-h t-h2">decisions</h3>
      <table class="decisions">
        <thead>
          <tr>
            <th class="t-micro" scope="col">
              decision
            </th>
            <th class="t-micro" scope="col">
              workload
            </th>
            <th class="t-micro" scope="col">
              mesh
            </th>
            <th class="t-micro" scope="col">
              if enforced
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <DecisionRow key={decisionKey(r)} r={r} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

/** One decision row: the decision chip · the subject/image/namespace · the mesh shadow status · the
 *  "if enforced" what-if. A row the engine would have rejected if enforced is keyline-flagged. */
function DecisionRow({ r }) {
  const attention = r["would-admit"] !== true;
  const d = decisionOf(r.decision);
  return (
    <tr
      class={attention ? "decision-row decision-row-attention" : "decision-row"}
      data-decision={r.decision}
    >
      <td class="cell-decision">
        <span class={`decision-chip decision-${r.decision}`}>
          <span class="glyph" aria-hidden="true">
            {d.glyph}
          </span>
          <span class="decision-word">{d.word}</span>
        </span>
        {r.count > 1 ? (
          <span
            class="decision-count t-micro muted"
            title="distinct workloads + image + outcome seen this many times"
          >
            {"\u{00D7}"}
            {r.count}
          </span>
        ) : null}
      </td>
      <td class="cell-workload">
        <span class="workload-subject t-data-strong">{r.subject}</span>
        {r.image ? <span class="workload-image t-data muted">{r.image}</span> : null}
        <span class="workload-ns t-micro muted">
          {r.namespace ? `ns ${r.namespace}` : "cluster-scoped"}
        </span>
        {r.reason ? <p class="decision-reason t-data">{r.reason}</p> : null}
      </td>
      <td class="cell-gate">
        <GateChip gate={r.mesh} />
      </td>
      <td class="cell-enforced">
        <IfEnforced wouldAdmit={r["would-admit"] === true} />
      </td>
    </tr>
  );
}

/** A per-gate shadow-status chip (colour + glyph + word, never colour alone). */
function GateChip({ gate }) {
  const g = gateOf(gate);
  return (
    <span class={`gate-chip gate-${g.token}`}>
      <span class="glyph" aria-hidden="true">
        {g.glyph}
      </span>
      <span class="gate-word">{g.word}</span>
    </span>
  );
}

/** The "if enforced" net what-if: would-admit / would-deny. A would-deny is the loud channel. */
function IfEnforced({ wouldAdmit }) {
  return wouldAdmit ? (
    <span class="enforced-chip enforced-admit">
      <span class="glyph" aria-hidden="true">
        {"\u{2713}"}
      </span>
      <span class="enforced-word">would admit</span>
    </span>
  ) : (
    <span class="enforced-chip enforced-deny">
      <span class="glyph" aria-hidden="true">
        {"\u{2715}"}
      </span>
      <span class="enforced-word">would deny</span>
    </span>
  );
}
