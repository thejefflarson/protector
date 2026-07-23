// Status-strip client tests (ADR-0025 / JEF-408): the strip is now rendered by the Preact client
// (the server emits a root-only shell). This pins the 1:1 port of the retired maud `status_strip.rs`:
//
//  - the judging axis renders BY the server-derived `judging-state` token — each token → its exact
//    class + glyph + text (only `all-clear` is the green `.judging.ok`; the rest are non-green);
//  - the mode pill (armed → ENFORCE / shadow → SHADOW ⚠);
//  - the coverage chips (present ✓ / degraded ◐ / absent —);
//  - the headline counts + the escalation chip + the standing signing-regression chip.
//
// The strip renders NOTHING before the first snapshot (absent ≠ green — a blank is honest).

import { describe, it, expect, beforeEach } from "vitest";
import { render, cleanup } from "@testing-library/preact";
import { StatusStrip } from "../src/strip.jsx";
import { strip } from "./fixtures.js";

beforeEach(cleanup);

/** Render a StatusStrip from a strip-props override and hand back its root container. */
function mount(overrides = {}) {
  const { container } = render(<StatusStrip strip={strip(overrides)} />);
  return container;
}

describe("StatusStrip absence", () => {
  it("renders NOTHING before the first snapshot (blank is honest, never green)", () => {
    const { container } = render(<StatusStrip strip={undefined} />);
    expect(container.textContent).toBe("");
    expect(container.querySelector(".strip")).toBeNull();
  });
});

describe("StatusStrip judging axis by judging-state token", () => {
  // Each server token maps to exactly one class + glyph + text (mirrors the maud match arms).
  const cases = [
    {
      token: "all-clear",
      cls: "judging ok",
      glyphSel: ".dot",
      text: "model judging — all clear",
      green: true,
    },
    {
      token: "watching",
      cls: "judging watching",
      glyph: "◌",
      text: "model judging — watching (not yet all-clear)",
      green: false,
    },
    { token: "judging", cls: "judging ok", glyphSel: ".dot", text: "model judging", green: true },
    {
      token: "warming",
      cls: "judging warming",
      glyph: "◌",
      text: "warming up — exposed paths are unjudged, not cleared",
      green: false,
    },
    {
      token: "no-model",
      cls: "judging blind",
      glyph: "◐",
      text: "no model — nothing is judged exploitable",
      green: false,
    },
    {
      token: "blind",
      cls: "judging blind",
      glyph: "◐",
      text: "model not answering — exposed paths are unjudged, not cleared",
      green: false,
    },
  ];

  for (const c of cases) {
    it(`token "${c.token}" → its exact class + glyph + text`, () => {
      const container = mount({ "judging-state": c.token });
      const axis = container.querySelector(".axis.judging");
      expect(axis, "the judging axis is present").toBeTruthy();
      // The class carries the register (e.g. `judging ok` / `judging blind`).
      for (const cls of c.cls.split(" ")) {
        expect(axis.classList.contains(cls), `axis has class ${cls}`).toBe(true);
      }
      expect(axis.textContent).toContain(c.text);
      if (c.glyphSel) {
        expect(axis.querySelector(c.glyphSel), `axis has ${c.glyphSel}`).toBeTruthy();
      } else {
        expect(axis.querySelector(".glyph").textContent).toBe(c.glyph);
      }
    });
  }

  it("renders the green `.judging.ok` register ONLY for the all-clear/judging tokens", () => {
    // The honesty gate: `.judging.ok` (the green dot register) appears only when the model is up
    // (all-clear or judging) — never for watching / warming / no-model / blind.
    for (const c of cases) {
      const container = mount({ "judging-state": c.token });
      const isOk = !!container.querySelector(".axis.judging.ok");
      expect(isOk, `${c.token} greenness`).toBe(c.green);
    }
  });
});

describe("StatusStrip honesty — green iff all-clear (ADR-0016/0019)", () => {
  // The load-bearing product contract, ported to the client strip: the ONLY judging register that
  // reads as a calm green all-clear is the `all-clear` token. Every other state — watching, warming,
  // no-model, blind — must render its distinct NON-green axis and NEVER the "all clear" headline.
  it('reads "all clear" ONLY for the all-clear token', () => {
    const green = mount({ "judging-state": "all-clear" });
    expect(green.querySelector(".axis.judging").textContent).toContain("all clear");
    expect(green.querySelector(".axis.judging.ok")).toBeTruthy();

    for (const token of ["watching", "warming", "no-model", "blind"]) {
      const axis = mount({ "judging-state": token }).querySelector(".axis.judging");
      expect(axis.textContent, `${token} is never the green all-clear`).not.toContain("all clear");
    }
  });

  it("never renders a blank/absent judging axis — every state names WHY", () => {
    for (const token of ["all-clear", "watching", "judging", "warming", "no-model", "blind"]) {
      const axis = mount({ "judging-state": token }).querySelector(".axis.judging");
      expect(axis).toBeTruthy();
      expect(axis.textContent.length).toBeGreaterThan(10);
    }
  });
});

describe("StatusStrip mode pill", () => {
  it("armed → ENFORCE (calm, no warn glyph)", () => {
    const container = mount({ armed: true });
    // Target the mode pill specifically — the strip now carries a sibling auth-mode `.pill` too.
    const pill = container.querySelector(".mode-enforce");
    expect(pill.classList.contains("mode-enforce")).toBe(true);
    expect(pill.textContent).toContain("ENFORCE");
    expect(pill.textContent).toContain("acting");
    expect(pill.querySelector(".pill-glyph")).toBeNull(); // enforce carries no glyph
  });

  it("shadow → SHADOW with the ⚠ warning glyph", () => {
    const container = mount({ armed: false });
    // Target the mode pill specifically — the strip now carries a sibling auth-mode `.pill` too.
    const pill = container.querySelector(".mode-shadow");
    expect(pill.classList.contains("mode-shadow")).toBe(true);
    expect(pill.classList.contains("warn")).toBe(true);
    expect(pill.textContent).toContain("SHADOW");
    expect(pill.textContent).toContain("proposes, never acts");
    expect(pill.querySelector(".pill-glyph").textContent).toBe("⚠");
  });
});

describe("StatusStrip auth-mode pill (JEF-489)", () => {
  it("oidc → a calm OIDC pill (word, no warn glyph)", () => {
    const container = mount({ "auth-mode": "oidc" });
    const pill = container.querySelector(".auth-oidc");
    expect(pill).toBeTruthy();
    expect(pill.classList.contains("warn")).toBe(false);
    expect(pill.textContent).toContain("OIDC");
    expect(pill.querySelector(".pill-glyph")).toBeNull(); // calm — no warning glyph
  });

  it("edge-only → the loud EDGE-ONLY ⚠ warn pill (word + glyph, never colour alone)", () => {
    const container = mount({ "auth-mode": "edge-only" });
    const pill = container.querySelector(".auth-edge");
    expect(pill).toBeTruthy();
    expect(pill.classList.contains("warn")).toBe(true); // same warn register as the SHADOW pill
    expect(pill.textContent).toContain("EDGE-ONLY");
    expect(pill.querySelector(".pill-glyph").textContent).toBe("⚠");
  });

  it("a missing auth-mode falls to the conservative EDGE-ONLY warn (never silently 'oidc')", () => {
    const container = mount({ "auth-mode": undefined });
    const pill = container.querySelector(".auth-edge");
    expect(pill).toBeTruthy();
    expect(pill.classList.contains("warn")).toBe(true);
    expect(pill.textContent).toContain("EDGE-ONLY");
    expect(container.querySelector(".auth-oidc")).toBeNull();
  });
});

describe("StatusStrip coverage chips", () => {
  it("renders present ✓ / degraded ◐ / absent — with the feed label", () => {
    const container = mount({
      coverage: [
        { label: "kev", present: true, degraded: false },
        { label: "epss", present: false, degraded: true },
        { label: "runtime", present: false, degraded: false },
      ],
    });
    const chips = [...container.querySelectorAll(".cov")];
    expect(chips).toHaveLength(3);

    expect(chips[0].classList.contains("cov-present")).toBe(true);
    expect(chips[0].querySelector(".cov-label").textContent).toBe("kev");
    expect(chips[0].querySelector(".cov-glyph").textContent).toBe("✓");

    expect(chips[1].classList.contains("cov-degraded")).toBe(true);
    expect(chips[1].querySelector(".cov-glyph").textContent).toBe("◐");

    expect(chips[2].classList.contains("cov-absent")).toBe(true);
    expect(chips[2].querySelector(".cov-glyph").textContent).toBe("—");
  });

  it("renders a STALLED feed loud (breach chip + ⚠), distinct from present/degraded/absent (JEF-421)", () => {
    const container = mount({
      coverage: [{ label: "Runtime", present: false, degraded: false, stalled: true }],
    });
    const chip = container.querySelector(".cov");
    // The loud register: the breach `cov-stalled` class + the ⚠ glyph + the feed word.
    expect(chip.classList.contains("cov-stalled")).toBe(true);
    expect(chip.classList.contains("cov-present")).toBe(false);
    expect(chip.classList.contains("cov-degraded")).toBe(false);
    expect(chip.classList.contains("cov-absent")).toBe(false);
    expect(chip.querySelector(".cov-glyph").textContent).toBe("⚠");
    expect(chip.querySelector(".cov-label").textContent).toBe("Runtime");
  });

  it("an ABSENT feed stays muted (— glyph), never the loud stalled register (JEF-421)", () => {
    const container = mount({
      coverage: [{ label: "Runtime", present: false, degraded: false, stalled: false }],
    });
    const chip = container.querySelector(".cov");
    expect(chip.classList.contains("cov-absent")).toBe(true);
    expect(chip.classList.contains("cov-stalled")).toBe(false);
    expect(chip.querySelector(".cov-glyph").textContent).toBe("—");
  });
});

describe("StatusStrip coverage-stall banner (JEF-421)", () => {
  const alert = {
    "feed-label": "Runtime",
    "last-observation": "2m ago",
    message: "runtime corroboration stalled — all 2 sensor nodes went dark",
  };

  it("renders the banner as a POLITE live region (aria-live=polite, not assertive)", () => {
    const container = mount({ "coverage-alert": alert });
    const banner = container.querySelector(".strip-coverage-alert");
    expect(banner, "the banner is present when a feed stalled").toBeTruthy();
    expect(banner.getAttribute("role")).toBe("status");
    expect(banner.getAttribute("aria-live")).toBe("polite");
    expect(banner.getAttribute("aria-live")).not.toBe("assertive");
    // It carries the feed label, the server message, and the last-observed time (all server copy).
    expect(banner.textContent).toContain("Runtime");
    expect(banner.textContent).toContain("stalled");
    expect(banner.textContent).toContain("2m ago");
  });

  it("renders NO banner when the server ships no coverage-alert (never synthesized)", () => {
    expect(mount({}).querySelector(".strip-coverage-alert")).toBeNull();
    expect(mount({ "coverage-alert": null }).querySelector(".strip-coverage-alert")).toBeNull();
  });
});

describe("StatusStrip headline counts", () => {
  it("always shows the four counts, honest even at zero", () => {
    const container = mount({
      "breach-count": 2,
      "awaiting-count": 1,
      "uncertain-count": 0,
      "cleared-count": 5,
    });
    const headline = container.querySelector(".headline");
    expect(headline.querySelector(".count-breach").textContent).toContain("2 breach");
    expect(headline.querySelector(".count-awaiting").textContent).toContain("1 awaiting");
    expect(headline.querySelector(".count-uncertain").textContent).toContain("0 uncertain");
    expect(headline.querySelector(".count-cleared").textContent).toContain("5 cleared");
  });

  it("shows the ▲ escalation chip only when escalated-count > 0", () => {
    expect(mount({ "escalated-count": 0 }).querySelector(".count-escalated")).toBeNull();
    const chip = mount({ "escalated-count": 3 }).querySelector(".count-escalated");
    expect(chip.textContent).toContain("3 escalated since last pass");
    expect(chip.querySelector(".glyph").textContent).toBe("▲");
  });

  it("shows the ● signing-regression chip (breach-rail) summing established + cold", () => {
    expect(
      mount({ "signing-regression-breach": 0, "signing-regression-uncertain": 0 }).querySelector(
        ".count-regression",
      ),
    ).toBeNull();

    const one = mount({ "signing-regression-breach": 1 }).querySelector(".count-regression");
    expect(one.classList.contains("count-breach")).toBe(true); // rides the loud breach rail
    expect(one.textContent).toContain("1 signing regression");
    expect(one.querySelector(".glyph").textContent).toBe("●");

    const many = mount({
      "signing-regression-breach": 1,
      "signing-regression-uncertain": 2,
    }).querySelector(".count-regression");
    expect(many.textContent).toContain("3 signing regressions"); // pluralised
  });
});

describe("StatusStrip freshness", () => {
  it("shows the last-pass age when present, else the muted 'no pass yet'", () => {
    expect(mount({ "last-pass": "12s" }).querySelector(".freshness").textContent).toContain(
      "last pass 12s",
    );
    const none = mount({ "last-pass": null }).querySelector(".freshness");
    expect(none.textContent).toContain("no pass yet");
    expect(none.classList.contains("muted")).toBe(true);
  });
});
