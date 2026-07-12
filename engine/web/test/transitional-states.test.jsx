// Visual-fidelity guard for the v4 transitional states (ADR-0025 / JEF-401). The Preact client
// introduced states the maud server-render never had — a first-load "connecting…", the load-bearing
// "not updating" stale banner, and the one-shot cleared-row tombstone. These lost their token colour
// + padding after the JEF-398 cutover (they carried classes with no CSS). These tests pin the
// class/token contract so the honesty register (a stale banner must be a distinct, non-calm
// register, NEVER a false all-clear — ADR-0016) can't silently drift again.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/preact";
import { Store } from "../src/store.js";
import { findingsView, finding } from "./fixtures.js";
import { TombstoneRow } from "../src/findings/row.jsx";

// Stub the poll so mounting the app never fires a real fetch/interval — we assert render, not polling.
vi.mock("../src/poll.js", () => ({ startPolling: () => () => {} }));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Mount the app shell on a store in a given connection state, with the poll stubbed out. */
function mount(seed) {
  const store = new Store({ activeTab: "findings" });
  seed(store);
  const { container } = render(<App store={store} liveRegion={() => null} />);
  return { store, container };
}

describe("connection banner honesty register (JEF-401)", () => {
  it("first-load shows the calm 'connecting…' message with the connecting class", () => {
    // Fresh store: status is "first-load" until the first snapshot lands.
    const { container } = mount(() => {});
    const msg = container.querySelector(".dash-conn .dash-conn-msg");
    expect(msg, "connecting message is rendered").toBeTruthy();
    expect(msg.classList.contains("dash-conn-connecting")).toBe(true);
    expect(msg.textContent).toContain("connecting to the engine");
    // Calm, not loud: it must NOT carry the stale register.
    expect(msg.classList.contains("dash-conn-stale")).toBe(false);
  });

  it("stale carries the LOUD non-green register (never a calm all-clear)", () => {
    const { container } = mount((store) => {
      store.applySnapshot(findingsView([finding("a")])); // go live first
      store.markStale(); // then lose the connection
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
    const { container } = mount((store) => store.applySnapshot(findingsView([finding("a")])));
    expect(container.querySelector(".dash-conn .dash-conn-msg")).toBeNull();
  });
});

describe("cleared-row tombstone fidelity (JEF-401)", () => {
  it("carries the tombstone classes the CSS styles (calm, padded, not an alarm)", () => {
    const { container } = render(
      <table>
        <tbody>
          <TombstoneRow id="a" />
        </tbody>
      </table>,
    );
    const row = container.querySelector("tr.row-tombstone");
    expect(row, "tombstone row uses .row-tombstone").toBeTruthy();
    const label = row.querySelector(".tombstone");
    expect(label, "tombstone label uses .tombstone").toBeTruthy();
    expect(label.textContent).toContain("this finding cleared");
    // Calm register: it stays muted (never a breach red / alarm class).
    expect(label.className).not.toContain("posture-breach");
    expect(label.className).not.toContain("alert");
  });
});
