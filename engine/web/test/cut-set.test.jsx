// The finding detail's cut-set list (ADR-0034): a REPLACEMENT for the old opaque
// single-cut-signature string — one line per node the model chose to contain (fenced key + fixed
// mechanism + entry-vs-downstream role + an advisory blast-radius note), plus the honest empty
// states: "attack" with no rows reads as "attack, no cut warranted" (a valid decision, never an
// error); "uncertain" NEVER renders as a green all-clear (ADR-0016); no incident decision yet
// reads as "awaiting".

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Expand a finding row so its detail panel (and the cut-set list) render. */
function expand(container, id) {
  fireEvent.click(container.querySelector(`tr.row[data-finding="${id}"]`));
}

describe("finding detail cut-set panel", () => {
  it("renders one row per contained node: fenced key, role, mechanism, blast note", () => {
    const f = finding("multi-1", {
      cuts: {
        assessment: "attack",
        rows: [
          {
            node: "workload/app/Pod/web",
            mechanism: "add a scoped deny NetworkPolicy/AuthorizationPolicy",
            "is-entry": true,
            "blast-note": "blast radius: no alive collateral",
          },
          {
            node: "workload/app/Pod/db-proxy",
            mechanism: "quarantine the compromised workload with a default-deny NetworkPolicy",
            "is-entry": false,
            "blast-note": "blast radius: 1 alive workload(s) affected",
          },
        ],
      },
    });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "multi-1");

    const rows = container.querySelectorAll(".cut-row");
    expect(rows.length).toBe(2);

    expect(rows[0].querySelector(".cut-row-node").textContent).toBe("workload/app/Pod/web");
    expect(rows[0].querySelector(".cut-row-role").textContent).toBe("entry");
    expect(rows[0].querySelector(".cut-row-mechanism").textContent).toContain("deny NetworkPolicy");
    expect(rows[0].querySelector(".cut-row-blast").textContent).toContain("no alive collateral");

    expect(rows[1].querySelector(".cut-row-node").textContent).toBe("workload/app/Pod/db-proxy");
    expect(rows[1].querySelector(".cut-row-role").textContent).toBe("downstream");
    expect(rows[1].querySelector(".cut-row-blast").textContent).toContain("1 alive workload(s)");
  });

  it('renders "attack, no cut warranted" explicitly when assessment is attack with no rows', () => {
    const f = finding("no-cut-1", { cuts: { assessment: "attack", rows: [] } });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "no-cut-1");

    expect(container.querySelectorAll(".cut-row").length).toBe(0);
    const body = container.querySelector(".cut-block");
    expect(body.textContent).toContain("attack, no cut warranted");
  });

  it("never renders uncertain as a green all-clear", () => {
    const f = finding("uncertain-1", { cuts: { assessment: "uncertain", rows: [] } });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "uncertain-1");

    const note = container.querySelector(".cut-uncertain");
    expect(note).not.toBeNull();
    expect(note.textContent).toContain("uncertain");
    // Never the cleared/green posture token, and never silently empty (no cut-row rendered).
    expect(note.className).not.toContain("posture-cleared");
    expect(container.querySelectorAll(".cut-row").length).toBe(0);
  });

  it('reads as "awaiting" when no incident decision has been made yet for the entry', () => {
    const f = finding("awaiting-1", { cuts: { assessment: "awaiting", rows: [] } });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "awaiting-1");

    expect(container.querySelector(".cut-block").textContent).toContain("awaiting judgement");
  });

  it("escapes an untrusted node key — text, never live HTML", () => {
    window.__pwned = undefined;
    const XSS = 'workload<img src=x onerror="window.__pwned=1">/evil';
    const f = finding("xss-1", {
      cuts: {
        assessment: "attack",
        rows: [
          {
            node: XSS,
            mechanism: "add a scoped deny NetworkPolicy/AuthorizationPolicy",
            "is-entry": true,
            "blast-note": "blast radius: no alive collateral",
          },
        ],
      },
    });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "xss-1");

    expect(container.querySelector(".cut-row img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.querySelector(".cut-row-node").textContent).toBe(XSS);
  });
});
