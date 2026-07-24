// Axe route-smoke (JEF-499): mount every top-level dashboard surface with mocked props/API and run
// axe-core over the rendered DOM, asserting NO accessibility violation of impact `serious` or
// `critical`. This is the runtime companion to the static jsx-a11y lint gate — jsx-a11y catches
// authoring mistakes in the JSX, axe catches the assembled-DOM failures (bad landmark/heading/aria
// wiring) a static pass can't see. Both run under CI, so a PR that regresses a11y goes red.
//
// Each view already renders its OWN `<main>` landmark (that is how App mounts it), so we render the
// view directly — never wrapped in another landmark — mirroring production exactly.
//
// Scope of the assertion — `serious`/`critical` only (not `minor`/`moderate`): those two impact tiers
// are the ones that actually block a keyboard or screen-reader operator (missing names, broken aria
// references, non-contained interactive controls). The best-practice noise axe emits for a single view
// mounted OUTSIDE a full <html> document — `landmark-one-main`, `page-has-heading-one` — is
// `moderate`/best-practice and is a fixture artifact of mounting one view at a time, not a real
// defect; filtering by impact keeps the gate honest instead of blanket-muting rules.
//
// color-contrast is disabled: axe computes it from rendered pixel colours, which jsdom does not paint
// (getComputedStyle returns no real colours), so the rule can only ever return "incomplete" here — a
// contrast regression is caught by the design review / real-browser pass, never by this jsdom smoke.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/preact";
import { axe } from "vitest-axe";

import { StatusStrip } from "../src/strip.jsx";
import { FindingsView } from "../src/findings/table.jsx";
import { AlertsView } from "../src/alerts/view.jsx";
import { ActionView } from "../src/action/view.jsx";
import { ReadinessView } from "../src/readiness/view.jsx";
import { AdmissionView } from "../src/admission/view.jsx";
import { AccessView } from "../src/access/view.jsx";
import {
  finding,
  findingsView,
  alert,
  alertsView,
  actionView,
  wouldAct,
  judgement,
  readinessRow,
  readinessView,
  nodeRow,
  decisionRow,
  signingRow,
  signingRepo,
  admissionView,
  accessReveal,
  accessPull,
  accessView,
} from "./fixtures.js";

// Drive App through the real poll surface without a network fetch: capture the poll callbacks so a
// test can fire onSnapshot / onAuthError exactly as the live poll would, mounting the strip + shell +
// the AuthGate interstitial (both private to app.jsx, only reachable through App).
let lastOpts = null;
vi.mock("../src/poll.js", () => ({
  startPolling: (opts) => {
    lastOpts = opts;
    return () => {};
  },
}));
const { App } = await import("../src/app.jsx");

// jsdom can't paint colours, so color-contrast is un-evaluable here (see file header).
const AXE_OPTS = { rules: { "color-contrast": { enabled: false } } };
const BLOCKING = new Set(["serious", "critical"]);

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
  lastOpts = null;
});
afterEach(cleanup);

/** Run axe on a rendered container and assert zero serious/critical violations, naming any that fire
 *  (rule id + impact + node count) so a regression points straight at the offending rule. */
async function expectAccessible(container) {
  const results = await axe(container, AXE_OPTS);
  const blocking = results.violations.filter((v) => BLOCKING.has(v.impact));
  const summary = blocking
    .map((v) => `${v.id} (${v.impact}, ${v.nodes.length} node(s)): ${v.help}`)
    .join("\n");
  expect(blocking, `serious/critical a11y violations:\n${summary}`).toEqual([]);
}

describe("axe route-smoke — top-level views (no serious/critical violations)", () => {
  it("Findings — populated table", async () => {
    const { container } = render(
      <FindingsView view={findingsView([finding("f1"), finding("f2", { posture: "cleared" })])} />,
    );
    await expectAccessible(container);
  });

  it("Findings — honest empty state", async () => {
    const { container } = render(<FindingsView view={findingsView([])} />);
    await expectAccessible(container);
  });

  it("Alerts — populated list", async () => {
    const { container } = render(
      <AlertsView view={alertsView([alert(), alert({ kind: "connect", "on-chain": null })])} />,
    );
    await expectAccessible(container);
  });

  it("Alerts — blind-caveat empty state", async () => {
    const { container } = render(
      <AlertsView view={alertsView([], { blindCaveat: "1 node blind — kernel sensor down" })} />,
    );
    await expectAccessible(container);
  });

  it("Action — populated lifecycle sections", async () => {
    const { container } = render(
      <ActionView
        view={actionView({
          "would-act": [wouldAct("web -> db", { "coverage-gap": true })],
          "left-alone": [{ entry: "api -> cache", verdict: "not exploitable" }],
          judgements: [judgement("web -> db")],
          "would-act-count": 1,
          "left-alone-count": 1,
        })}
      />,
    );
    await expectAccessible(container);
  });

  it("Readiness — coverage rows incl. per-node breakdown", async () => {
    const { container } = render(
      <ReadinessView
        view={readinessView([
          readinessRow("kev", { state: "present" }),
          readinessRow("runtime", {
            state: "stalled",
            "weakens-decisions": true,
            enable: "RUNTIME_SENSOR=1",
            nodes: [nodeRow("node-a"), nodeRow("node-b", { state: "dark", detail: "no data" })],
          }),
        ])}
      />,
    );
    await expectAccessible(container);
  });

  it("Admission — tallies, signing inventory, decision rows", async () => {
    const { container } = render(
      <AdmissionView
        view={admissionView({
          admitted: 3,
          audited: 1,
          denied: 1,
          total: 5,
          signing: [
            signingRepo("org/repo", [signingRow("img1"), signingRow("img2", { posture: "unsigned" })]),
          ],
          rows: [decisionRow(), decisionRow({ decision: "deny", "would-admit": false, reason: "unsigned" })],
        })}
      />,
    );
    await expectAccessible(container);
  });

  it("Access — tier reveals + forensic/raw pull table", async () => {
    const { container } = render(
      <AccessView
        view={accessView({
          tier: "raw",
          reveals: [accessReveal("redacted"), accessReveal("raw", { held: true })],
          pulls: [accessPull(), accessPull({ tier: "forensic", raw: false })],
        })}
      />,
    );
    await expectAccessible(container);
  });
});

describe("axe route-smoke — status strip", () => {
  it("StatusStrip — live, with coverage chips + headline counts", async () => {
    const { container } = render(
      <StatusStrip
        strip={{
          cluster: "prod",
          armed: false,
          "auth-mode": "oidc",
          "judging-state": "judging",
          coverage: [
            { label: "kev", present: true, degraded: false },
            { label: "runtime", present: false, degraded: false, stalled: true },
          ],
          "last-pass": "3s",
          "breach-count": 2,
          "awaiting-count": 1,
          "uncertain-count": 0,
          "cleared-count": 5,
          "escalated-count": 1,
          "signing-regression-breach": 1,
          "signing-regression-uncertain": 0,
          "coverage-alert": {
            "feed-label": "Runtime",
            "last-observation": "2m ago",
            message: "runtime corroboration stalled — all sensor nodes went dark",
          },
        }}
      />,
    );
    await expectAccessible(container);
  });
});

describe("axe route-smoke — app shell + AuthGate interstitial", () => {
  it("App — live shell (strip + tab nav + view)", async () => {
    const { container } = render(<App initialTab="findings" liveRegion={() => null} />);
    act(() => lastOpts.onSnapshot(findingsView([finding("f1")])));
    await expectAccessible(container);
  });

  it("AuthGate — unauthenticated (401) interstitial", async () => {
    const { container } = render(<App initialTab="findings" liveRegion={() => null} />);
    act(() => lastOpts.onSnapshot(findingsView([finding("f1")])));
    act(() => lastOpts.onAuthError(401));
    await expectAccessible(container);
  });

  it("AuthGate — forbidden (403) interstitial", async () => {
    const { container } = render(<App initialTab="findings" liveRegion={() => null} />);
    act(() => lastOpts.onSnapshot(findingsView([finding("f1")])));
    act(() => lastOpts.onAuthError(403));
    await expectAccessible(container);
  });
});
