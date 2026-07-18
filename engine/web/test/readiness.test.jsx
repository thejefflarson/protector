// Readiness view tests (ADR-0025 / JEF-400 / JEF-411): the per-node `<details>` disclosure (NATIVE,
// UNCONTROLLED) stays open across a poll, rows key on `id` (patched in place), a blind node is
// surfaced loudly (server-derived state token), and an XSS node name renders inert. The view is
// `view`-only now (no store — JEF-411); a poll is modelled by re-rendering with a new `view` prop.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { ReadinessView } from "../src/readiness/view.jsx";
import { readinessRow, nodeRow, readinessView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Open a native <details> the way a user would. */
function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

const rowWithNodes = (id, nodes, over = {}) => readinessRow(id, { nodes, ...over });

describe("Readiness state preservation + keying", () => {
  it("keeps an opened per-node breakdown open across a poll", () => {
    const row = rowWithNodes("runtime-corroboration", [nodeRow("node-1"), nodeRow("node-2")]);
    const { container, rerender } = render(<ReadinessView view={readinessView([row])} />);

    const details = container.querySelector('li[data-input="runtime-corroboration"] details.cov-nodes');
    expect(details).toBeTruthy();
    openDetails(details);
    expect(details.open).toBe(true);

    // A poll updates the row's detail; the native disclosure must stay open (keyed diff keeps it).
    rerender(
      <ReadinessView
        view={readinessView([rowWithNodes("runtime-corroboration", [nodeRow("node-1"), nodeRow("node-2")], { detail: "2 signals" })])}
      />,
    );
    const after = container.querySelector('li[data-input="runtime-corroboration"] details.cov-nodes');
    expect(after.open).toBe(true);
  });

  it("keys rows on id and patches an updated row in place", () => {
    const { container, rerender } = render(
      <ReadinessView view={readinessView([readinessRow("model"), readinessRow("kev")])} />,
    );
    const modelRow = container.querySelector('li[data-input="model"]');
    modelRow.dataset.probe = "kept";

    rerender(
      <ReadinessView view={readinessView([readinessRow("model", { detail: "last call ok" }), readinessRow("kev")])} />,
    );
    const after = container.querySelector('li[data-input="model"]');
    expect(after.dataset.probe).toBe("kept");
    expect(after.textContent).toContain("last call ok");
  });
});

describe("Readiness honesty (blind nodes)", () => {
  it("surfaces a blind node loudly (server-derived state token, not a client derivation)", () => {
    const row = rowWithNodes("runtime-corroboration", [
      nodeRow("node-1", { state: "healthy" }),
      nodeRow("node-2", { state: "blind", detail: "no live sensor" }),
    ]);
    const { container } = render(<ReadinessView view={readinessView([row])} />);
    const summary = container.querySelector(".cov-nodes-summary");
    expect(summary.textContent).toContain("1 blind");
    const blindRow = container.querySelector('tr[data-state="blind"]');
    expect(blindRow.textContent).toContain("BLIND");
  });

  it("flags a weakening absent input with the amber-keyline gap class + enable action", () => {
    const gap = readinessRow("model", { state: "absent", "weakens-decisions": true, enable: "PROTECTOR_MODEL_URL" });
    const { container } = render(<ReadinessView view={readinessView([gap])} />);
    const row = container.querySelector('li[data-input="model"]');
    expect(row.classList.contains("cov-row-gap")).toBe(true);
    expect(container.querySelector(".cov-enable-action")).toBeTruthy();
    expect(container.textContent).toContain("enable with");
  });
});

describe("Readiness coverage-stall register (JEF-421)", () => {
  it("renders a STALLED runtime row loud + non-green: breach keyline, ⚠ glyph, stalled word", () => {
    const row = readinessRow("runtime-corroboration", {
      state: "stalled",
      "weakens-decisions": true,
      detail:
        "STALLED: runtime corroboration stalled — all 2 sensor nodes went dark (last observed 2m ago)",
    });
    const { container } = render(<ReadinessView view={readinessView([row])} />);
    const li = container.querySelector('li[data-input="runtime-corroboration"]');
    // The row escalates to the loud breach keyline (past the amber weakening-gap keyline).
    expect(li.classList.contains("cov-row-stalled")).toBe(true);
    expect(li.dataset.state).toBe("stalled");
    // The state carries colour + glyph + word (never colour alone) — and it's the stalled register.
    const stateWord = li.querySelector(".cov-state-word");
    expect(stateWord.textContent).toBe("stalled");
    expect(li.querySelector(".cov-state-glyph").textContent).toBe("⚠");
    expect(li.querySelector(".cov-state").classList.contains("cov-stalled")).toBe(true);
    // The last-observation time (server copy) surfaces in the detail.
    expect(li.textContent).toContain("last observed 2m ago");
  });

  it("an ABSENT input still renders MUTED (— glyph, absent word), never the stalled register", () => {
    const row = readinessRow("kev", { state: "absent", "weakens-decisions": true });
    const { container } = render(<ReadinessView view={readinessView([row])} />);
    const li = container.querySelector('li[data-input="kev"]');
    expect(li.classList.contains("cov-row-stalled")).toBe(false);
    expect(li.querySelector(".cov-state-word").textContent).toBe("absent");
    expect(li.querySelector(".cov-state-glyph").textContent).toBe("—");
    expect(li.querySelector(".cov-state").classList.contains("cov-stalled")).toBe(false);
  });
});

describe("Readiness escaping", () => {
  it("renders an XSS node name as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const row = rowWithNodes("runtime-corroboration", [nodeRow(XSS, { detail: XSS })]);
    const { container } = render(<ReadinessView view={readinessView([row])} />);
    openDetails(container.querySelector("details.cov-nodes"));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
