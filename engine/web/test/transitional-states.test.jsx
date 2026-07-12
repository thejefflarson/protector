// Visual-fidelity guard for the v4 transitional states (ADR-0025 / JEF-401 / JEF-411). The Preact
// client introduced states the maud server-render never had — a first-load "connecting…" and the
// load-bearing "not updating" stale banner. These lost their token colour + padding after the
// JEF-398 cutover (they carried classes with no CSS). These tests pin the class/token contract so
// the honesty register (a stale banner must be a distinct, non-calm register, NEVER a false
// all-clear — ADR-0016) can't silently drift again.
//
// (The one-shot cleared-row tombstone this file also guarded was removed in JEF-411 — a gone finding
// is now dropped by Preact's keyed diff, no client farewell row. That block is deleted.)

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/preact";

// Capture the poll callbacks so we can drive the connection state exactly like the real poll does,
// without firing a real fetch/interval — we assert render, not polling.
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

/** A minimal strip snapshot the app can land to go live. */
const snapshot = () => ({ strip: { "all-clear": false, "judging-state": "watching" }, findings: [] });

/** Mount the app shell, then drive it into a given connection state via the poll callbacks. */
function mount(drive = () => {}) {
  const { container } = render(<App initialTab="findings" liveRegion={() => null} />);
  act(() => drive());
  return { container };
}

describe("connection banner honesty register (JEF-401)", () => {
  it("first-load shows the calm 'connecting…' message with the connecting class", () => {
    // Fresh app: status is "first-load" until the first snapshot lands.
    const { container } = mount();
    const msg = container.querySelector(".dash-conn .dash-conn-msg");
    expect(msg, "connecting message is rendered").toBeTruthy();
    expect(msg.classList.contains("dash-conn-connecting")).toBe(true);
    expect(msg.textContent).toContain("connecting to the engine");
    // Calm, not loud: it must NOT carry the stale register.
    expect(msg.classList.contains("dash-conn-stale")).toBe(false);
  });

  it("stale carries the LOUD non-green register (never a calm all-clear)", () => {
    const { container } = mount(() => {
      lastOpts.onSnapshot(snapshot()); // go live first
      lastOpts.onStale(); // then lose the connection
    });
    const msg = container.querySelector(".dash-conn .dash-conn-msg");
    expect(msg, "stale banner is rendered").toBeTruthy();
    // The load-bearing register: the stale class carries the amber warning treatment (invariant #1).
    expect(msg.classList.contains("dash-conn-stale")).toBe(true);
    expect(msg.classList.contains("dash-conn-connecting")).toBe(false);
    // The honesty copy must be present verbatim: silence is a connection problem, not an all-clear.
    expect(msg.textContent).toContain("Not updating");
    expect(msg.textContent).toContain("not an all-clear");
    // And it must never render the cleared/green empty-state classes.
    expect(msg.className).not.toContain("empty-clear");
  });

  it("live shows NO connection chrome (no false reassurance)", () => {
    const { container } = mount(() => lastOpts.onSnapshot(snapshot()));
    expect(container.querySelector(".dash-conn .dash-conn-msg")).toBeNull();
  });
});
