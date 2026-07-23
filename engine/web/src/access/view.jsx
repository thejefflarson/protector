// The "Access" view (JEF-490 / ADR-0031 §4) — the operator's window onto the read-only MCP server's
// forensic/raw disclosure audit. Two sections:
//
//  1. "your access" — the caller's OWN tier as a chip (colour + glyph + WORD, never colour alone;
//     glyph aria-hidden; raw = the loud/scarce posture colour), over a `cov-rows`-style list of what
//     each tier reveals vs withholds, marking which the caller holds.
//  2. "forensic & raw pulls" — a real semantic `<table>` (aligned columns, `<th scope>`), one row
//     per disclosure newest-first: when · who · tool · tier · target-class. A `raw` pull carries the
//     loud keyline. Every identity/target string is a JSX child (Preact auto-escapes).
//
// The tier-aware REDACTION is entirely server-side: the `target` this view renders is ALREADY the
// real workload identity (for a viewer whose tier unlocks it) or the withheld-workload sentinel (for
// a lower-tier viewer) — the client derives nothing, it only displays. The empty state honestly
// distinguishes "nobody pulled above redacted" (calm, least-privilege working) from the log-reset
// fact: the "resets on restart" sub-line shows ONLY when the audit sink is in-memory (`durable:false`).

import { contentHash } from "../keys.js";

// The disclosure tiers, each carried as colour + glyph + WORD. `raw` is the loud/scarce posture
// (the breach palette): a raw disclosure is the crown-jewel read. `redacted` is the calm floor.
const TIER = {
  redacted: { glyph: "\u{25CB}", word: "redacted" }, // ○ — minimal, safe-by-construction
  forensic: { glyph: "\u{25D0}", word: "forensic" }, // ◐ — partial cluster detail
  raw: { glyph: "\u{25CF}", word: "raw" }, // ● — the loud, scarce full disclosure
};

/** Look up a tier's presentation, defaulting to `redacted` (never a louder tier) for an unknown
 *  tag — an unrecognised tier must never read as more-disclosing than it is. */
function tierOf(tag) {
  return TIER[tag] || TIER.redacted;
}

/** The caller's / a pull's tier as a chip: colour + glyph + WORD (never colour alone), the glyph
 *  aria-hidden so the WORD carries it for a screen reader. */
function TierChip({ tier }) {
  const t = tierOf(tier);
  return (
    <span class={`access-tier access-tier-${tier}`}>
      <span class="access-tier-glyph" aria-hidden="true">
        {t.glyph}
      </span>
      <span class="access-tier-word">{t.word}</span>
    </span>
  );
}

/**
 * @param {object} props
 * @param {any} props.view the Access view props (`{ strip, tier, reveals, pulls, pull-count,
 *   durable }`, serde kebab-case).
 */
export function AccessView({ view }) {
  const reveals = Array.isArray(view.reveals) ? view.reveals : [];
  const pulls = Array.isArray(view.pulls) ? view.pulls : [];
  const durable = view.durable === true;
  return (
    <main class="view view-access">
      <section class="access-your" aria-label="your access">
        <h2 class="section-h t-h2">your access</h2>
        <p class="section-sub t-body muted">
          your token grants the <TierChip tier={view.tier} /> tier. every disclosure above the
          redacted floor is cluster-data egress {"\u{2014}"} recorded below, and itself redacted to
          your tier.
        </p>
        <ul class="cov-rows">
          {reveals.map((r) => (
            <RevealRow key={r.tier} r={r} />
          ))}
        </ul>
      </section>

      <section class="access-pulls-section" aria-label="forensic and raw pulls">
        <h2 class="section-h t-h2">forensic &amp; raw pulls</h2>
        {pulls.length === 0 ? (
          <EmptyPulls durable={durable} />
        ) : (
          <table class="decisions access-pulls">
            <thead>
              <tr>
                <th class="t-micro" scope="col">
                  when
                </th>
                <th class="t-micro" scope="col">
                  who
                </th>
                <th class="t-micro" scope="col">
                  tool
                </th>
                <th class="t-micro" scope="col">
                  tier
                </th>
                <th class="t-micro" scope="col">
                  target-class
                </th>
              </tr>
            </thead>
            <tbody>
              {pulls.map((p, i) => (
                <PullRow key={pullKey(p, i)} p={p} />
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}

/** One "what this tier reveals/withholds" row. The tier the caller HOLDS is marked (never colour
 *  alone — a "your tier" badge + the held keyline). */
function RevealRow({ r }) {
  const held = r.held === true;
  return (
    <li
      class={held ? "cov-row access-reveal access-reveal-held" : "cov-row access-reveal"}
      data-tier={r.tier}
    >
      <div class="cov-row-head">
        <TierChip tier={r.tier} />
        {held ? <span class="access-reveal-badge t-micro">your tier</span> : null}
      </div>
      <p class="cov-detail t-data">
        <span class="access-reveal-label t-micro">reveals</span> {r.reveals}
      </p>
      <p class="cov-why t-body muted">
        <span class="access-reveal-label t-micro">withholds</span> {r.withholds}
      </p>
    </li>
  );
}

/** One audit row: when · who · tool · tier · target-class. A `raw` pull carries the loud keyline.
 *  Identity/target are JSX children (auto-escaped). */
function PullRow({ p }) {
  return (
    <tr
      class={p.raw ? "access-pull-row access-pull-raw" : "access-pull-row"}
      data-tier={p.tier}
    >
      <td class="access-when t-micro muted">{p.when}</td>
      <td class="access-who t-data-strong">{p.who}</td>
      <td class="access-tool t-data">{p.tool}</td>
      <td class="access-tier-cell">
        <TierChip tier={p.tier} />
      </td>
      <td class="access-target t-data">{p.target}</td>
    </tr>
  );
}

/** The honest empty state. Calm — least-privilege is working — but NEVER misread as "nobody ever
 *  pulled": an in-memory sink adds the "resets on restart" caveat; a durable sink omits it (the log
 *  is authoritative). */
function EmptyPulls({ durable }) {
  return (
    <div class="empty empty-access-calm">
      <p class="empty-head">no forensic or raw pulls recorded</p>
      <p class="empty-sub muted">
        least-privilege is working {"\u{2014}"} nobody has pulled cluster-specific detail above the
        redacted floor
        {durable ? (
          "."
        ) : (
          <>
            , within this log's window.{" "}
            <span class="access-reset-note">this log lives in memory and resets on restart.</span>
          </>
        )}
      </p>
    </div>
  );
}

/** A reconcile key for one audit row. Pulls have no server id (an append-only log), so key on a
 *  content hash of the row's fields plus the index — stable enough that an unchanged tail reconciles
 *  in place, while a genuinely new top row is a new node. */
function pullKey(p, i) {
  const parts = [p.when, p.who, p.tool, p.tier, p.target, String(i)];
  return `pull-${contentHash(parts.join(" "))}`;
}
