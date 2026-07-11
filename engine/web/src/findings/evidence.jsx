// The evidence tables for a finding's detail panel (ADR-0025 / JEF-397) — a 1:1 Preact port of the
// maud `evidence.rs` DOM: the CVE table, the runtime corroborating/context split, and the
// exposed-secrets / misconfig / RBAC scanner tables. Severity is the COOLER, subordinate channel;
// every untrusted string (advisory titles, secret matches, node keys) is interpolated as text, so
// Preact auto-escapes it — the raw-HTML escape hatch is banned in src/ (the JEF-396 guard enforces
// it).
//
// When a finding has NO evidence the whole section renders nothing (no implied-absent text),
// matching the maud omission exactly.

const DASH = "—"; // — the honest "no value" marker maud uses.

/** @param {any} ev the finding's `evidence` props object (serde kebab-case keys). */
export function EvidenceTables({ ev }) {
  if (isEmpty(ev)) return null;
  return (
    <section class="detail-section evidence-block">
      <h3 class="detail-h">evidence</h3>
      <CveTable cves={ev.cves} />
      <RuntimeBlock corroborating={ev.corroborating} context={ev.context} />
      <ScanTable title="exposed secrets" css="exposed-secrets" findings={ev["exposed-secrets"]} />
      <ScanTable title="misconfigurations" css="misconfigs" findings={ev.misconfigs} />
      <ScanTable title="RBAC findings" css="rbac" findings={ev["rbac-findings"]} />
    </section>
  );
}

/** Whether an evidence cluster is entirely empty (mirrors `EvidenceProps::is_empty`). */
function isEmpty(ev) {
  return (
    len(ev.cves) === 0 &&
    len(ev.corroborating) === 0 &&
    len(ev.context) === 0 &&
    len(ev["exposed-secrets"]) === 0 &&
    len(ev.misconfigs) === 0 &&
    len(ev["rbac-findings"]) === 0
  );
}

const len = (a) => (Array.isArray(a) ? a.length : 0);

function CveTable({ cves }) {
  if (len(cves) === 0) return null;
  return (
    <div class="ev-group">
      <h4 class="detail-h">CVEs</h4>
      <table class="ev-table">
        <thead>
          <tr>
            <th>id</th>
            <th>sev</th>
            <th class="num">cvss</th>
            <th>kev</th>
            <th class="num">epss</th>
            <th>reachability</th>
            <th>fix</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((c) => (
            <CveRow key={c.id} c={c} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CveRow({ c }) {
  return (
    <>
      <tr>
        <td class="mono">{c.id}</td>
        <td>
          <span class={`sev sev-${c.severity}`}>{c.severity}</span>
        </td>
        <td class="num">{c.score ?? DASH}</td>
        <td>{c.kev ? <span class="ev ev-kev">KEV</span> : <span class="muted">{DASH}</span>}</td>
        <td class="num">{c.epss ?? DASH}</td>
        <td class="mono">{c.reachability}</td>
        <td>{c.fix}</td>
      </tr>
      {c.title ? (
        <tr class="ev-subrow">
          <td colspan="7">
            <span class="muted">{c.title}</span>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function RuntimeBlock({ corroborating, context }) {
  if (len(corroborating) === 0 && len(context) === 0) return null;
  return (
    <div class="ev-group">
      <h4 class="detail-h">runtime</h4>
      {len(corroborating) > 0 ? (
        <>
          <p class="ev-sublabel">corroborating (live)</p>
          <ul class="behavior-list">
            {corroborating.map((b, i) => (
              <BehaviorItem key={i} b={b} />
            ))}
          </ul>
        </>
      ) : null}
      {len(context) > 0 ? (
        <>
          <p class="ev-sublabel muted">context</p>
          <ul class="behavior-list">
            {context.map((b, i) => (
              <BehaviorItem key={i} b={b} />
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

function BehaviorItem({ b }) {
  return (
    <li class={b.corroborating ? "behavior behavior-alert" : "behavior"}>
      <span class={`behavior-variant var-${b.variant}`}>{b.variant}</span>
      <span class="behavior-summary">{b.summary}</span>
    </li>
  );
}

function ScanTable({ title, css, findings }) {
  if (len(findings) === 0) return null;
  return (
    <div class={`ev-group ev-${css}`}>
      <h4 class="detail-h">{title}</h4>
      <table class="ev-table">
        <thead>
          <tr>
            <th>id</th>
            <th>sev</th>
            <th>category</th>
            <th>detail</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((s) => (
            <tr key={s.id}>
              <td class="mono">{s.id}</td>
              <td>
                <span class={`sev sev-${s.severity}`}>{s.severity}</span>
              </td>
              <td>{s.category ?? DASH}</td>
              <td>{s.title ?? DASH}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
