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

// ----- JEF-400: fixtures for the four secondary views, shaped exactly like the server serde JSON.

/** One Alerts row (an alarming-now event). No stable id by design — keyed on a content hash. */
export function alert(overrides = {}) {
  return {
    signal: "drop-and-execute: /usr/bin/x",
    kind: "exec",
    workload: "web",
    recency: "this pass",
    "on-chain": "web \u{2192} db-creds",
    ...overrides,
  };
}

/** A whole Alerts view. `blindCaveat` (server-derived) selects the blind empty register. */
export function alertsView(alerts, { blindCaveat = null, stripOverrides = {} } = {}) {
  return { strip: strip(stripOverrides), alerts, "blind-caveat": blindCaveat };
}

/** One Readiness coverage row. `nodes` populates the per-node runtime-corroboration breakdown. */
export function readinessRow(id, overrides = {}) {
  return {
    id,
    label: `label-${id}`,
    state: "present",
    why: `why ${id} matters`,
    enable: "",
    detail: `detail for ${id}`,
    "weakens-decisions": false,
    nodes: [],
    ...overrides,
  };
}

/** One per-node runtime-corroboration row. */
export function nodeRow(node, overrides = {}) {
  return { node, state: "healthy", detail: "quiet", ...overrides };
}

/** A whole Readiness view. */
export function readinessView(rows, stripOverrides = {}) {
  return { strip: strip(stripOverrides), rows };
}

/** One Action would-act entry (a still-standing proposed cut). */
export function wouldAct(entry, overrides = {}) {
  return {
    entry,
    episodes: 2,
    "would-act-decisions": 3,
    "max-lifetime": "4m",
    open: true,
    "short-lived": false,
    "coverage-gap": false,
    "last-verdict": `verdict for ${entry}`,
    ...overrides,
  };
}

/** One Action judgement-audit entry. */
export function judgement(entry, overrides = {}) {
  return {
    entry,
    objectives: 1,
    verdict: "Confirmed",
    prompt: `prompt for ${entry}`,
    reply: `reply for ${entry}`,
    ...overrides,
  };
}

/** A whole Action view. */
export function actionView(overrides = {}) {
  return {
    strip: strip(),
    "window-human": "7d",
    "journal-empty": false,
    "decisions-in-window": 0,
    "would-act": [],
    reversions: [],
    "left-alone": [],
    judgements: [],
    "would-act-count": 0,
    "short-lived-count": 0,
    "coverage-gap-count": 0,
    "left-alone-count": 0,
    "reverted-count": 0,
    ...overrides,
  };
}

/** One Admission decision row. No stable id — keyed on `(subject, image, decision)`. */
export function decisionRow(overrides = {}) {
  return {
    decision: "allow",
    subject: "Deployment/web",
    image: "registry/web:1",
    namespace: "prod",
    mesh: "verified",
    "would-admit": true,
    reason: "",
    count: 1,
    ...overrides,
  };
}

/** One signing-inventory image row. */
export function signingRow(domId, overrides = {}) {
  return {
    "dom-id": domId,
    image: `registry/app@${domId}`,
    label: domId,
    posture: "signed",
    signer: { "identity-short": "org/repo", "identity-full": "org/repo", "issuer-badge": "github actions", "issuer-full": "https://token.actions.githubusercontent.com" },
    provenance: "absent",
    "provenance-info": null,
    detail: "",
    enforcement: "would-admit",
    count: 1,
    ...overrides,
  };
}

/** One signing repo group. */
export function signingRepo(repo, images, overrides = {}) {
  return {
    repo,
    images,
    regression: null,
    exception: null,
    "provenance-change": null,
    strength: "log-corroborated",
    ...overrides,
  };
}

/** A whole Admission view. */
export function admissionView(overrides = {}) {
  return {
    strip: strip(),
    admitted: 0,
    audited: 0,
    denied: 0,
    total: 0,
    signing: [],
    rows: [],
    ...overrides,
  };
}
