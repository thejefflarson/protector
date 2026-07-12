// App status + strip tests (ADR-0025 / ADR-0027 / ADR-0028 / JEF-411). These port the invariants the
// deleted store.test.js pinned, now that `App` owns the shared state as plain useState:
//
//  - the three connection-status transitions, incl. "never stale before the first snapshot"
//    (first-load → connecting…, live → no chrome, stale → the load-bearing "not an all-clear");
//  - the JEF-410 strip contract: the strip persists across a tab swap, and a snapshot that omits a
//    strip keeps the last one (the header never regresses to blank).
//
// The poll is stubbed so we drive `onSnapshot` / `onStale` directly (the same callbacks the real
// poll would fire) and assert via the DOM — no store, no internal state peeking.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";

// Capture the poll callbacks so a test can land a snapshot / mark stale exactly like the poll does.
let lastOpts = null;
vi.mock("../src/poll.js", () => ({
  startPolling: (opts) => {
    lastOpts = opts;
    return () => {};
  },
}));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
  lastOpts = null;
});

/** A minimal strip-props shape with an all-clear/judging-state token (the client only displays it). */
const stripProps = (over = {}) => ({ "all-clear": false, "judging-state": "watching", ...over });
/** A findings snapshot carrying a strip (the shape every tab's payload has). */
const snapshot = (strip, over = {}) => ({ strip, findings: [], ...over });

function mount() {
  const { container } = render(<App initialTab="findings" liveRegion={() => null} />);
  return container;
}

describe("connection status transitions (ported from store.test.js)", () => {
  it("starts first-load (connecting…) and NEVER goes stale before a snapshot lands", () => {
    const container = mount();
    // First-load: the honest "connecting…" banner.
    expect(container.querySelector(".dash-conn-connecting")).toBeTruthy();

    // A failed poll before any snapshot must NOT flip to the stale register — connecting is honest.
    act(() => lastOpts.onStale());
    expect(container.querySelector(".dash-conn-connecting")).toBeTruthy();
    expect(container.querySelector(".dash-conn-stale")).toBeNull();
  });

  it("goes live on a snapshot (no connection chrome — no false reassurance)", () => {
    const container = mount();
    act(() => lastOpts.onSnapshot(snapshot(stripProps())));
    expect(container.querySelector(".dash-conn-msg")).toBeNull();
  });

  it("goes stale AFTER a snapshot, keeping the last-good body on screen", () => {
    const container = mount();
    act(() => lastOpts.onSnapshot(snapshot(stripProps())));
    act(() => lastOpts.onStale());
    const stale = container.querySelector(".dash-conn-stale");
    expect(stale).toBeTruthy();
    expect(stale.textContent).toContain("Not updating");
    expect(stale.textContent).toContain("not an all-clear");
    // The strip (last-good posture) is still on screen — never blanked.
    expect(container.querySelector(".strip")).toBeTruthy();
  });
});

describe("persistent status strip (JEF-410)", () => {
  it("renders the strip from a snapshot and holds it across a tab swap", () => {
    const container = mount();
    // No snapshot yet — the strip is blank (absent is honest, never green).
    expect(container.querySelector(".strip")).toBeNull();

    act(() => lastOpts.onSnapshot(snapshot(stripProps({ "judging-state": "watching" }))));
    expect(container.querySelector(".strip")).toBeTruthy();
    expect(container.querySelector(".axis.judging").textContent).toContain("watching");
    // The findings body rendered too (empty state).
    expect(container.querySelector(".view-findings")).toBeTruthy();

    // Swap tabs. The poll is stubbed, so no refetch clobbers state — the body clears for the new tab
    // (a quiet placeholder), but the global strip MUST persist (the header never tears down).
    fireEvent.click(container.querySelector('a.tab[href="/?tab=alerts"]'));
    expect(container.querySelector('a.tab[href="/?tab=alerts"]').getAttribute("aria-current")).toBe(
      "page",
    );
    expect(container.querySelector(".strip")).toBeTruthy(); // header persists — no blank/redraw
    expect(container.querySelector(".axis.judging").textContent).toContain("watching");
    // The alerts body is the quiet placeholder (data cleared for the new tab), not the alerts view.
    expect(container.querySelector(".view-alerts")).toBeTruthy();
    expect(container.querySelector(".alerts-note")).toBeNull(); // no snapshot for the new tab yet
  });

  it("keeps the last strip if a later snapshot omits it (never regress the header to blank)", () => {
    const container = mount();
    act(() => lastOpts.onSnapshot(snapshot(stripProps({ "judging-state": "all-clear", "all-clear": true }))));
    expect(container.querySelector(".axis.judging.ok")).toBeTruthy(); // green all-clear

    // A snapshot that omits the top-level strip must not blank the header — the last strip stays.
    // (A finding keeps the body off the strip-reading empty state; the point here is the header.)
    act(() => lastOpts.onSnapshot({ findings: [{ id: "x", posture: "breach", delta: { kind: "new" }, disposition: "propose", "evidence-summary": {}, entry: "e", objective: "o", path: [], paths: [] }] }));
    expect(container.querySelector(".strip")).toBeTruthy();
    expect(container.querySelector(".axis.judging.ok")).toBeTruthy();
  });
});
