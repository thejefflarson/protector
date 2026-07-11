// The Admission/policy view (ADR-0025 / JEF-400) — a 1:1 Preact port of maud `admission_view.rs`:
// the decision-tallies header (admitted / audited / denied, so a healthy cluster is never blank —
// counts honest at zero), the per-image signing inventory (JEF-262 / ADR-0020), and the deduped
// decision rows.
//
// Reconcile keying (the only per-view variation): decision rows have NO id → keyed on their
// `(subject, image, decision)` tuple (see `keys.js`), so the dedup `count` updates smoothly IN
// PLACE; signing rows key on their server-supplied `dom-id`. Every untrusted string (subject /
// image / reason / signer identity) renders via JSX text (Preact auto-escapes).

import { SigningInventory } from "./signing.jsx";
import { DecisionRows } from "./decisions.jsx";

/**
 * @param {object} props
 * @param {any} props.view the Admission view props (serde kebab-case).
 * @param {import("../store.js").Store} props.store the client store (signing-row expansion state).
 */
export function AdmissionView({ view, store }) {
  const rows = Array.isArray(view.rows) ? view.rows : [];
  return (
    <main class="view view-admission">
      <TalliesHeader v={view} />
      <SigningInventory signing={view.signing} store={store} />
      {rows.length === 0 ? <EmptyState /> : <DecisionRows rows={rows} />}
    </main>
  );
}

/** The tallies header: admitted / audited / denied counts (colour + glyph + word), honest at zero
 *  so the operator can always see the webhook is being asked. */
function TalliesHeader({ v }) {
  return (
    <section class="admission-summary" aria-label="admission decision tallies">
      <h2 class="section-h t-h2">admission {"\u{2014}"} the webhook floor</h2>
      <p class="section-sub t-body muted">
        every admission the webhook resolved: clean admits, would-deny-but-allowed audits, and
        enforced denials. In shadow the gates only PROPOSE {"\u{2014}"} the 'if enforced' column is
        the what-if, never the live decision.
      </p>
      <div class="admission-tallies">
        <span class="tally tally-admitted t-data-strong">
          <span class="glyph" aria-hidden="true">
            {"\u{2713}"}
          </span>{" "}
          {v.admitted} admitted
        </span>
        <span class="tally tally-audited t-data-strong">
          <span class="glyph" aria-hidden="true">
            {"\u{25D0}"}
          </span>{" "}
          {v.audited} audited
        </span>
        <span class="tally tally-denied t-data-strong">
          <span class="glyph" aria-hidden="true">
            {"\u{25CF}"}
          </span>{" "}
          {v.denied} denied
        </span>
        <span class="tally tally-total t-data muted">{v.total} total</span>
      </div>
    </section>
  );
}

/** The honest empty state: no admission decisions recorded — never read as "all clear". */
function EmptyState() {
  return (
    <div class="empty admission-empty">
      <p class="empty-head t-h2">no admission decisions recorded yet</p>
      <p class="empty-sub t-body muted">
        the webhook may not be receiving admission requests, or none have landed in this window.
        This is not an all-clear {"\u{2014}"} wire the admission webhook to populate the decision
        floor.
      </p>
    </div>
  );
}
