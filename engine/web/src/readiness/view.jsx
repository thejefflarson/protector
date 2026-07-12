// The Readiness (coverage) view (ADR-0025 / JEF-400) — a 1:1 Preact port of maud
// `readiness_view.rs`: one row per decision input with its honest Present/Absent/Degraded state
// (colour + glyph + word, never colour alone), the live detail, why it matters, and the env var to
// enable it. A weakening-when-absent input carries the amber keyline and surfaces its enablement
// instruction.
//
// Reconcile keying (the only per-view variation): rows key on `ReadinessRowProps.id`, so Preact
// patches each row in place across a poll. The per-node `<details>` breakdown is KEYED COMPONENT
// STATE (persisted in the store under `readiness:<row-id>`) so it survives reconcile exactly like
// the Findings extra-paths disclosure. The client derives no honesty — it renders the
// server-decided state tokens verbatim; every untrusted string (node name, detail) is JSX text.

import { NodeBreakdown } from "./nodes.jsx";

const STATE = {
  present: { glyph: "\u{2713}", word: "present" }, // ✓
  absent: { glyph: "\u{2014}", word: "absent" }, // —
  degraded: { glyph: "\u{25D0}", word: "degraded" }, // ◐
};

/** Look up a coverage state's presentation, defaulting to `absent` (never present/green) for an
 *  unknown tag — an unrecognised state must never read as covered. */
function stateOf(tag) {
  return STATE[tag] || STATE.absent;
}

/**
 * @param {object} props
 * @param {any} props.view the Readiness view props (`{ strip, rows }`, serde kebab-case).
 * @param {import("../store.js").Store} props.store the client store (disclosure state).
 */
export function ReadinessView({ view, store }) {
  const rows = Array.isArray(view.rows) ? view.rows : [];
  return (
    <main class="view view-readiness">
      <section class="coverage-detail" aria-label="decision-input coverage">
        <h2 class="section-h t-h2">decision inputs</h2>
        <p class="section-sub t-body muted">
          every input the model leans on to decide {"\u{2014}"} its live state, why it matters, and
          how to enable it. A weakening input that is absent is shown first.
        </p>
        <ul class="cov-rows">
          {rows.map((r) => (
            <CoverageRow key={r.id} r={r} store={store} />
          ))}
        </ul>
      </section>
    </main>
  );
}

/** One coverage row. An absent/degraded WEAKENING input gets the amber keyline (`cov-row-gap`) and
 *  reads its enablement instruction as an action ("enable with …"). */
function CoverageRow({ r, store }) {
  const present = r.state === "present";
  const weakGap = r["weakens-decisions"] === true;
  const isGap = weakGap && !present;
  const s = stateOf(r.state);
  const nodes = Array.isArray(r.nodes) ? r.nodes : [];
  const hasEnable = typeof r.enable === "string" && r.enable.length > 0;
  return (
    <li class={isGap ? "cov-row cov-row-gap" : "cov-row"} data-input={r.id} data-state={r.state}>
      <div class="cov-row-head">
        <span class={`cov-state cov-${r.state}`}>
          <span class="cov-state-glyph" aria-hidden="true">
            {s.glyph}
          </span>
          <span class="cov-state-word">{s.word}</span>
        </span>
        <span class="cov-row-label t-data-strong">{r.label}</span>
        {weakGap ? (
          <span class="cov-weakens t-micro" title="absence weakens the model's decision">
            weakens decisions
          </span>
        ) : null}
      </div>
      <p class="cov-detail t-data">{r.detail}</p>
      <p class="cov-why t-body muted">{r.why}</p>
      {nodes.length > 0 ? <NodeBreakdown rowId={r.id} nodes={nodes} store={store} /> : null}
      {hasEnable ? (
        <p class={isGap ? "cov-enable t-data cov-enable-action" : "cov-enable t-data"}>
          <span class="cov-enable-label t-micro">{isGap ? "enable with" : "configured via"}</span>{" "}
          <code class="cov-enable-var">{r.enable}</code>
        </p>
      ) : null}
    </li>
  );
}
