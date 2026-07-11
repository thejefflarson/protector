// Unit tests for the pure keyed-reconcile engine (ADR-0025 / JEF-397). These pin the tombstone
// lifecycle — the one thing Preact's keyed diff does NOT do for us — without a browser: a
// gone-while-open finding gets exactly ONE tombstone render, a gone-unopened finding is dropped
// silently, and present findings always render live (Preact keeps their DOM in place).

import { describe, it, expect } from "vitest";
import { computeRows, idsOf } from "../src/reconcile.js";

const F = (id) => ({ id });

describe("computeRows", () => {
  it("renders every present finding as a live row, in server order", () => {
    const { rows, tombstonedNow } = computeRows(
      [F("a"), F("b"), F("c")],
      new Set(),
      new Set(),
      new Set(),
    );
    expect(rows.map((r) => r.finding.id)).toEqual(["a", "b", "c"]);
    expect(rows.every((r) => !r.tombstone)).toBe(true);
    expect(tombstonedNow.size).toBe(0);
  });

  it("drops a gone finding SILENTLY when it was not expanded or focused", () => {
    // 'b' vanished but nobody had it open — no tombstone, just gone.
    const { rows, tombstonedNow } = computeRows(
      [F("a"), F("c")],
      new Set(["a", "b", "c"]),
      new Set(), // nothing kept open
      new Set(),
    );
    expect(rows.map((r) => r.finding.id)).toEqual(["a", "c"]);
    expect(tombstonedNow.size).toBe(0);
  });

  it("emits ONE tombstone for a gone finding that was expanded/focused", () => {
    const { rows, tombstonedNow } = computeRows(
      [F("a")],
      new Set(["a", "b"]),
      new Set(["b"]), // 'b' was open when it vanished
      new Set(),
    );
    const b = rows.find((r) => r.finding.id === "b");
    expect(b).toBeTruthy();
    expect(b.tombstone).toBe(true);
    expect(tombstonedNow.has("b")).toBe(true);
  });

  it("drops the tombstone on the NEXT render (one tombstone, then gone)", () => {
    // Simulate the follow-up render: 'b' is still gone, still kept-open, but already tombstoned.
    const { rows, tombstonedNow } = computeRows(
      [F("a")],
      new Set(["a", "b"]),
      new Set(["b"]),
      new Set(["b"]), // already had its one tombstone last render
    );
    expect(rows.map((r) => r.finding.id)).toEqual(["a"]);
    expect(tombstonedNow.size).toBe(0);
  });

  it("appends tombstones after the live rows so the list doesn't shift", () => {
    const { rows } = computeRows(
      [F("a"), F("c")],
      new Set(["a", "b", "c"]),
      new Set(["b"]),
      new Set(),
    );
    expect(rows.map((r) => r.finding.id)).toEqual(["a", "c", "b"]);
    expect(rows[2].tombstone).toBe(true);
  });

  it("keeps a present finding live even if it is in the kept-open set", () => {
    const { rows, tombstonedNow } = computeRows(
      [F("a")],
      new Set(["a"]),
      new Set(["a"]),
      new Set(),
    );
    expect(rows).toEqual([{ finding: { id: "a" }, tombstone: false }]);
    expect(tombstonedNow.size).toBe(0);
  });
});

describe("idsOf", () => {
  it("collects the id set of a findings list", () => {
    expect([...idsOf([F("x"), F("y")])].sort()).toEqual(["x", "y"]);
  });
});
