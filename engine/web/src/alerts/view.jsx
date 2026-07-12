// The Alerts view (ADR-0025 / JEF-400) — a 1:1 Preact port of maud `alerts_view.rs`: the live
// "alarming-now" activity list, or the honest calm/blind empty state. A CURRENT-WINDOW projection
// of the runtime signals alarming THIS pass (NOT a scrolling audit log), each an honest EVIDENCE
// note, never a verdict.
//
// Reconcile keying (the only per-view variation): an Alerts row has NO stable id BY DESIGN, so
// each card is keyed on a CONTENT HASH of `(kind, signal, workload, on-chain)` (see `keys.js`) —
// an identical alarm persisting across passes reconciles to the SAME node (no flicker), a
// genuinely new alarm is a new node. We never fabricate a persistent id.
//
// Honesty (carried VERBATIM from maud, invariant #1 — the client derives NOTHING): the LOUD
// blind-node caveat ("quiet — but partly blind"), the "evidence not verdict" live-note, and the
// calm empty ("no alarming activity right now") UNLESS `blind-caveat` is present. Every untrusted
// string (signal / workload / on-chain) renders via JSX text interpolation only (Preact
// auto-escapes; the raw-HTML escape hatch is banned by the guard).

import { alertKey } from "../keys.js";

/**
 * @param {object} props
 * @param {any} props.view the Alerts view props (`{ strip, alerts, blind-caveat }`, serde
 *   kebab-case). `blind-caveat` is the SERVER-DERIVED token — the client only selects copy.
 */
export function AlertsView({ view }) {
  const alerts = Array.isArray(view.alerts) ? view.alerts : [];
  return (
    <main class="view view-alerts">
      <LiveNote />
      {alerts.length === 0 ? (
        <EmptyState blindCaveat={view["blind-caveat"]} />
      ) : (
        <AlertsList alerts={alerts} />
      )}
    </main>
  );
}

/** The honest "this is a live window" note — evidence, not a verdict; nothing here means an action
 *  was taken. Carried verbatim from the maud `live_note`. */
function LiveNote() {
  return (
    <p class="alerts-note muted">
      Live view {"\u{2014}"} the runtime signals alarming right now (this observe pass). Corroboration
      evidence, not a verdict; nothing here means an action was taken.
    </p>
  );
}

/** The alarming-now events, one card each, keyed on the content hash so an identical persisting
 *  alarm reconciles in place. A real `<ul>` for semantics (a11y parity). */
function AlertsList({ alerts }) {
  return (
    <ul class="alerts-list" aria-label="alarming-now signals">
      {alerts.map((a) => (
        <AlertCard key={alertKey(a)} a={a} />
      ))}
    </ul>
  );
}

/** One alarming-now event card: the kind token (glyph-free but text-labelled), the signal, the
 *  workload, its recency, and the proven chain it is alarming ON (if any). Every untrusted string
 *  is a JSX text child, so Preact auto-escapes it. */
function AlertCard({ a }) {
  return (
    <li class={`alert-card alert-${a.kind}`}>
      <div class="alert-head">
        <span class={`alert-kind kind-${a.kind}`}>{a.kind}</span>
        <span class="alert-signal">{a.signal}</span>
      </div>
      <div class="alert-meta muted">
        <span class="alert-workload">
          <span class="alert-label">workload </span>
          {a.workload}
        </span>
        <span class="alert-recency">{a.recency}</span>
        {a["on-chain"] != null ? (
          <span class="alert-on-chain">
            <span class="alert-label">alarming on the chain </span>
            {a["on-chain"]}
          </span>
        ) : (
          <span class="alert-on-chain muted">
            no proven chain {"\u{2014}"} alarming on its own
          </span>
        )}
      </div>
    </li>
  );
}

/**
 * The honest empty/quiet state. CALM by default ("no alarming activity right now") — reassuring,
 * NOT an alarm. But when a node is blind the reassurance would be dishonest, so the LOUD caveat
 * ("quiet — but partly blind") replaces it and the state reads elevated, never green. `blindCaveat`
 * is the SERVER-DERIVED token: its mere presence selects the blind register (the client derives
 * nothing).
 */
function EmptyState({ blindCaveat }) {
  if (blindCaveat) {
    return (
      <div class="empty empty-alerts-blind">
        <p class="empty-head">quiet {"\u{2014}"} but partly blind</p>
        <p class="empty-sub blind-node-caveat" role="note">
          <span class="caveat-glyph" aria-hidden="true">
            {"\u{26A0} "}
          </span>
          {blindCaveat}
        </p>
      </div>
    );
  }
  return (
    <div class="empty empty-alerts-calm">
      <p class="empty-head">no alarming activity right now</p>
      <p class="empty-sub muted">
        no runtime signal is alarming this pass {"\u{2014}"} nothing is showing active attack
        behaviour right now. This is a live window, not a history.
      </p>
    </div>
  );
}
