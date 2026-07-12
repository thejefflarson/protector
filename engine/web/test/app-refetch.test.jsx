// App-shell tab-swap refetch test (JEF-408): a client tab-swap must trigger an IMMEDIATE refetch of
// the new tab, not wait up to POLL_MS for the next interval (which left the swapped-to view blank).
// The App restarts the poll when `activeTab` changes; startPolling fetches once synchronously on
// start, so a restart == an immediate refetch. This would FAIL under the old effect that depended
// only on [store, liveRegion] (the poll never restarted, so the swap waited for the stale interval).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { Store } from "../src/store.js";
import { findingsView } from "./fixtures.js";

// Spy the real startPolling so we can count restarts AND assert the tab it repoints to, without
// firing real intervals. Each call records the tab getter; the returned stop is a no-op.
const startCalls = [];
vi.mock("../src/poll.js", () => ({
  startPolling: (opts) => {
    startCalls.push(opts.tab());
    return () => {};
  },
}));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
  startCalls.length = 0;
});

describe("tab-swap immediate refetch (JEF-408)", () => {
  it("restarts the poll (repointed to the new tab) on a client swap", () => {
    const store = new Store({ activeTab: "findings" });
    store.applySnapshot(findingsView([]));
    const { container } = render(<App store={store} liveRegion={() => null} />);

    // Mounted once, polling findings.
    expect(startCalls).toEqual(["findings"]);

    // Swap to Alerts — the effect re-runs because activeTab changed, restarting the poll on alerts
    // (an immediate refetch), rather than leaving the alerts view blank until the next interval.
    const link = container.querySelector('a.tab[href="/?tab=alerts"]');
    fireEvent.click(link);
    expect(store.getState().activeTab).toBe("alerts");
    expect(startCalls).toContain("alerts");
    expect(startCalls.length).toBeGreaterThan(1);
  });

  it("does not restart the poll when a fresh snapshot lands on the SAME tab", () => {
    const store = new Store({ activeTab: "findings" });
    store.applySnapshot(findingsView([]));
    render(<App store={store} liveRegion={() => null} />);
    expect(startCalls).toEqual(["findings"]);

    // A new snapshot on the SAME tab must NOT restart the poll — that would refetch on every tick.
    // The effect keys on activeTab, which is unchanged, so no restart.
    store.applySnapshot(findingsView([]));
    expect(startCalls).toEqual(["findings"]);
  });
});
