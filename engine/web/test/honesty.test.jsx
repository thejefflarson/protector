// Client honesty tests (ADR-0025 / JEF-397): the empty-state must NEVER read as a generic
// "no findings" / false all-clear. GREEN "all clear" renders ONLY when the SERVER token
// `all-clear` is true; blind/warming/watching render the matching non-green register. The client
// performs ZERO honesty derivation — it SELECTS the honest copy from server-decided tokens.

import { describe, it, expect, beforeEach } from "vitest";
import { render, cleanup } from "@testing-library/preact";
import { FindingsEmpty } from "../src/findings/empty.jsx";
import { strip } from "./fixtures.js";

beforeEach(cleanup);

const textOf = (node) => {
  const { container } = render(node);
  return container.textContent;
};

describe("Findings empty-state honesty", () => {
  it("renders GREEN all-clear ONLY when the server says all-clear", () => {
    const t = textOf(<FindingsEmpty strip={strip({ "all-clear": true })} />);
    expect(t).toContain("all clear");
    expect(t).toContain("found nothing exploitable");
  });

  it("renders WATCHING (not green) when the server says watching", () => {
    const t = textOf(<FindingsEmpty strip={strip({ watching: true })} />);
    expect(t).toContain("watching");
    expect(t).toContain("This is not an all-clear");
    expect(t).not.toContain("all clear"); // never the green headline
  });

  it("renders WARMING (loud, not green) when warming up", () => {
    const t = textOf(<FindingsEmpty strip={strip({ "model-judging": false, "warming-up": true })} />);
    expect(t).toContain("warming up");
    expect(t).toContain("not an all-clear");
    expect(t).not.toContain("all clear");
  });

  it("renders NO-MODEL when no model is attached — unjudged, not cleared", () => {
    const t = textOf(
      <FindingsEmpty strip={strip({ "model-judging": false, "model-attached": false })} />,
    );
    expect(t).toContain("no model configured");
    expect(t).toContain("unjudged, not cleared");
    expect(t).not.toContain("all clear");
  });

  it("renders MODEL-NOT-ANSWERING (blind) when the model is down", () => {
    const t = textOf(<FindingsEmpty strip={strip({ "model-judging": false })} />);
    expect(t).toContain("model not answering");
    expect(t).not.toContain("all clear");
  });

  it("never shows a bare generic 'no findings' — every empty state names WHY", () => {
    // Whatever the strip says, the empty-state always renders a specific honest register.
    for (const s of [
      strip({ "all-clear": true }),
      strip({ watching: true }),
      strip({ "model-judging": false, "warming-up": true }),
      strip({ "model-judging": false }),
    ]) {
      const t = textOf(<FindingsEmpty strip={s} />);
      expect(t).not.toBe("no findings");
      expect(t.length).toBeGreaterThan(10);
    }
  });
});
