import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setTechnicalDetail } from "./TechnicalDetail";
import { When, whenText } from "./When";
import { pinZone } from "../test-support/zone";

/**
 * One event read in local time on one panel and in unlabelled UTC on
 * another, on two calendar dates. Every time on screen now goes through one
 * element: the reader's clock with its zone, the ISO instant on hover.
 */

let restoreZone = () => undefined as void;

beforeEach(() => {
  restoreZone = pinZone("Europe/London");
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-25T12:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
  restoreZone();
  setTechnicalDetail(false);
});

describe("a time on screen", () => {
  it("prints the reader's local time with its zone, and the ISO instant in the title", () => {
    const html = renderToStaticMarkup(<When at="2026-09-21T17:28:42Z" />);
    expect(html).toMatch(/^<time dateTime="2026-09-21T17:28:42Z" title="21 Sept? 2026, 18:28 BST \(2026-09-21T17:28:42Z\)">21 Sept? 2026, 18:28 BST<\/time>$/);
  });

  it("reads relative where the screen asks, with the same title", () => {
    const html = renderToStaticMarkup(<When at={Date.parse("2026-09-25T09:00:00Z")} relative />);
    expect(html).toContain(">3 hours ago</time>");
    expect(html).toContain('dateTime="2026-09-25T09:00:00Z"');
    expect(html).toMatch(/title="25 Sept? 2026, 10:00 BST \(2026-09-25T09:00:00Z\)"/);
  });

  it("keeps the host's own string as the machine-readable value", () => {
    expect(renderToStaticMarkup(<When at="2026-09-21T18:28:42+01:00" />)).toContain('dateTime="2026-09-21T18:28:42+01:00"');
  });

  it("prints nothing for a value that is not a time", () => {
    expect(renderToStaticMarkup(<When at="not a time" />)).toBe("");
  });
});

/**
 * The investigator's view prints UTC, labelled, and never a relative time:
 * the instant was one hover away, and a hover is out of reach on a touch
 * screen. The plain view keeps the reader's clock.
 *
 * FAILS ON REVERT: print the plain words in both views and the technical
 * view reads "3 hours ago" in BST beside a host log in UTC.
 */
describe("a time in the technical view", () => {
  it("is UTC with its label, absolute where the plain view is relative", () => {
    setTechnicalDetail(true);
    expect(renderToStaticMarkup(<When at="2026-09-21T17:28:42Z" />)).toMatch(/>21 Sept? 2026, 17:28 UTC<\/time>$/);
    expect(renderToStaticMarkup(<When at={Date.parse("2026-09-25T09:00:00Z")} relative />)).toMatch(/>25 Sept? 2026, 09:00 UTC<\/time>$/);
    setTechnicalDetail(false);
    expect(renderToStaticMarkup(<When at="2026-09-21T17:28:42Z" />)).toMatch(/>21 Sept? 2026, 18:28 BST<\/time>$/);
  });

  it("chooses its words from the view alone", () => {
    expect(whenText("2026-09-21T17:28:42Z", false, true)).toMatch(/^21 Sept? 2026, 17:28 UTC$/);
    expect(whenText(Date.parse("2026-09-25T09:00:00Z"), true, false)).toBe("3 hours ago");
  });
});
