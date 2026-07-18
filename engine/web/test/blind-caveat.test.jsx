// Finding-level "runtime-blind on this node" caveat (JEF-424): a finding whose workload sits on a
// blind node carries a server-derived caveat string; the detail panel renders it in the verdict
// block as a `role="note"` (the existing `.verdict-caveat` precedent), with the node name — which is
// UNTRUSTED-adjacent — auto-escaped by Preact, never as live HTML. The caveat is metadata only: the
// client SELECTS it, it never derives or re-decides it.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Expand a finding row so its detail panel (and the caveat) render. */
function expand(container, id) {
  fireEvent.click(container.querySelector(`tr.row[data-finding="${id}"]`));
}

describe("finding-level runtime-blind caveat (JEF-424)", () => {
  it("renders the caveat as a role=note when the server ships one", () => {
    const f = finding("blind-1", {
      "blind-node-caveat": "runtime-blind on node-7 — no live sensor here, so absence of a signal is not evidence of safety",
    });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "blind-1");

    const note = container.querySelector(".blind-node-caveat[role='note']");
    expect(note).not.toBeNull();
    expect(note.textContent).toContain("runtime-blind on node-7");
  });

  it("renders NO caveat when the server ships none (a sensored / corroborated finding)", () => {
    const f = finding("clear-1", { "blind-node-caveat": null });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "clear-1");
    expect(container.querySelector(".blind-node-caveat")).toBeNull();
  });

  it("escapes an untrusted node name in the caveat — text, never live HTML", () => {
    window.__pwned = undefined;
    const XSS = 'node<img src=x onerror="window.__pwned=1">';
    const f = finding("blind-xss", {
      "blind-node-caveat": `runtime-blind on ${XSS} — absence of a signal is not evidence of safety`,
    });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "blind-xss");

    // The payload never became a real element, and its handler never fired...
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    // ...but the node name IS present as literal, escaped text inside the caveat note.
    const note = container.querySelector(".blind-node-caveat[role='note']");
    expect(note).not.toBeNull();
    expect(note.textContent).toContain(XSS);
  });
});
