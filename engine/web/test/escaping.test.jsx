// Client escaping test (ADR-0025 / JEF-397): untrusted strings from the JSON (verdict prose, CVE
// titles, node keys, model prompts) render as TEXT, never as live HTML. Preact auto-escapes all
// interpolated text; `dangerouslySetInnerHTML` is banned in src/ (the JEF-396 guard). This asserts
// the guarantee holds end-to-end: an XSS-laden snapshot produces escaped DOM, no injected element.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { Store } from "../src/store.js";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

const XSS = '<img src=x onerror="window.__pwned=1">';

describe("untrusted text is escaped, never executed", () => {
  it("escapes an XSS-laden verdict, CVE title, node key, and model prompt", () => {
    window.__pwned = undefined;
    const store = new Store();
    const f = finding("evil", {
      entry: XSS,
      objective: XSS,
      "verdict-summary": XSS,
      evidence: {
        cves: [{ id: XSS, severity: "critical", score: "9.8", kev: false, epss: null, reachability: XSS, fix: XSS, title: XSS }],
        corroborating: [],
        context: [],
        "exposed-secrets": [],
        misconfigs: [],
        "rbac-findings": [],
      },
      judgement: { prompt: XSS, reply: XSS, verdict: XSS },
      path: [{ from: XSS, "from-glyph": "x", relation: XSS, to: XSS, "to-glyph": "x", structural: false, "is-cut": false, shared: false }],
      paths: [[{ from: XSS, "from-glyph": "x", relation: XSS, to: XSS, "to-glyph": "x", structural: false, "is-cut": false, shared: false }]],
      cut: null,
    });
    store.applySnapshot(findingsView([f]));
    const { container } = render(<FindingsView view={store.getState().data} store={store} />);

    // Expand so the detail (verdict, CVE table, prompt) renders too.
    fireEvent.click(container.querySelector('tr.row[data-finding="evil"]'));

    // No injected <img> anywhere — the payload never became a real element.
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();

    // The payload IS present as literal text (escaped), proving it rendered as data, not markup.
    expect(container.textContent).toContain(XSS);
  });

  it("escapes an XSS-laden tombstone id without injecting an element", async () => {
    const store = new Store();
    const evilId = '<svg onload="window.__pwned=1">';
    const f = finding(evilId);
    store.applySnapshot(findingsView([f]));
    const { container, rerender } = render(<FindingsView view={store.getState().data} store={store} />);
    store.toggleRow(evilId); // mark it open so it earns a tombstone when it clears
    rerender(<FindingsView view={store.getState().data} store={store} />);

    store.applySnapshot(findingsView([]));
    rerender(<FindingsView view={store.getState().data} store={store} />);
    expect(container.querySelector("svg")).toBeNull();
    expect(window.__pwned).toBeUndefined();
  });
});
