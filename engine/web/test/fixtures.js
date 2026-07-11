// Test fixtures shaped exactly like the server's serde JSON (kebab-case keys, stable string tags)
// for the Findings view (ADR-0025 / JEF-397). Hand-built to the `FindingsViewProps` contract so the
// client tests exercise the real wire shape, not an invented one.

/** A live, judging status strip (nothing green forced — depends on the counts the caller sets). */
export function strip(overrides = {}) {
  return {
    cluster: "prod-test",
    armed: false,
    "model-judging": true,
    "warming-up": false,
    "model-attached": true,
    coverage: [],
    "last-pass": "3s",
    "breach-count": 0,
    "awaiting-count": 0,
    "uncertain-count": 0,
    "cleared-count": 0,
    "escalated-count": 0,
    "signing-regression-breach": 0,
    "signing-regression-uncertain": 0,
    "all-clear": false,
    watching: false,
    ...overrides,
  };
}

/** One finding row, defaulting to a plausible breach with a proven path and a model prompt. */
export function finding(id, overrides = {}) {
  return {
    id,
    posture: "breach",
    "live-tag": "judged",
    delta: { kind: "unchanged", age: "12s" },
    "entry-glyph": "\u{1F310}",
    entry: `entry-${id}`,
    foothold: true,
    objective: `objective-${id}`,
    fanout: null,
    replicas: null,
    "evidence-summary": { "cve-count": 1, kev: true, "runtime-alerts": 0, "exposed-secrets": 0 },
    disposition: "propose",
    "verdict-summary": `verdict for ${id}`,
    path: [{ from: "web", "from-glyph": "\u{1F310}", relation: "reaches", to: "db", "to-glyph": "\u{1F5C4}", structural: false, "is-cut": true, shared: false }],
    paths: [[{ from: "web", "from-glyph": "\u{1F310}", relation: "reaches", to: "db", "to-glyph": "\u{1F5C4}", structural: false, "is-cut": true, shared: false }]],
    "paths-truncated": false,
    cut: "web -> db",
    evidence: {
      cves: [{ id: "CVE-2021-0001", severity: "critical", score: "9.8", kev: true, epss: "90%", reachability: "reachable", fix: "upgrade", title: "a bad bug" }],
      corroborating: [],
      context: [],
      "exposed-secrets": [],
      misconfigs: [],
      "rbac-findings": [],
    },
    judgement: { prompt: `prompt for ${id}`, reply: `reply for ${id}`, verdict: "Confirmed" },
    "blind-node-caveat": null,
    alerts: [],
    ...overrides,
  };
}

/** A whole Findings view. */
export function findingsView(findings, stripOverrides = {}) {
  return { strip: strip(stripOverrides), findings };
}
