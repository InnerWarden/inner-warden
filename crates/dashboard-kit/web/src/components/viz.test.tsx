import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { arcPath, Bar, drawnParts, Gauge, partFill, Ring, RING_OFF, Spark, sparkPoints, TONE_HEX, type Part } from "./viz";

/**
 * The shared drawing primitives. A visual is read before a word is, so each
 * one must draw exactly its parts: no part it was not handed, no fill for a
 * part that is not confirmed, and silence drawn as silence.
 */

const part = (key: string, value: number, over: Partial<Part> = {}): Part => ({ key, value, tone: "working", label: key, ...over });

describe("the ring", () => {
  it("draws one segment per part with a value, in order, and a title on each", () => {
    const html = renderToStaticMarkup(<Ring label="three" parts={[part("a", 1, { tone: "proven" }), part("b", 0), part("c", 2)]} />);
    expect([...html.matchAll(/data-segment="([^"]+)"/g)].map((match) => match[1])).toEqual(["a", "c"]);
    expect(html).toContain("<title>a</title>");
    expect(html).toContain('aria-label="three"');
  });

  /**
   * FAILS ON REVERT: draw a hollow part with its tone as a fill and an
   * unconfirmed control reads as a confirmed one of that colour.
   */
  it("draws a hollow part as a dashed outline, never a filled stroke", () => {
    const html = renderToStaticMarkup(<Ring label="x" stroke={12} parts={[part("h", 1, { tone: "unknown", hollow: true }), part("w", 1)]} />);
    const hollow = html.slice(html.indexOf('data-segment="h"'), html.indexOf('data-segment="w"'));
    expect(hollow).toContain("stroke-dasharray");
    expect(hollow).toContain('stroke-width="1.5"');
    expect(hollow).not.toContain('stroke-width="12"');
    expect(hollow).not.toContain(TONE_HEX.proven);
    expect(hollow).not.toContain(TONE_HEX.working);
  });

  /**
   * FAILS ON REVERT: the bar's off (slate-200) on the ring's slate-100 track
   * is 1.1 to 1 and cannot be seen; the legend alone carried the count.
   */
  it("draws an off part a shade darker than the track", () => {
    const html = renderToStaticMarkup(<Ring label="x" parts={[part("o", 1, { tone: "off" }), part("w", 1)]} />);
    const off = html.slice(html.indexOf('data-segment="o"'), html.indexOf('data-segment="w"'));
    expect(off).toContain(RING_OFF);
    expect(off).not.toContain(TONE_HEX.off);
  });

  it("draws only the track when nothing has a value", () => {
    const html = renderToStaticMarkup(<Ring label="empty" parts={[part("a", 0)]} />);
    expect(html).not.toContain("data-segment");
  });

  it("draws a single part as a whole circle, and arcs from 12 o'clock clockwise", () => {
    expect(renderToStaticMarkup(<Ring label="one" parts={[part("a", 3)]} />)).not.toContain("<path");
    expect(arcPath(50, 40, 0, 0.25)).toBe("M50.00 10.00A40 40 0 0 1 90.00 50.00");
    expect(arcPath(50, 40, 0, 0.75)).toContain(" 0 1 1 ");
  });

  it("gauges a share, and a share it does not have is an empty track", () => {
    expect(renderToStaticMarkup(<Gauge share={0.115} label="cpu" />)).toContain("data-segment");
    expect(renderToStaticMarkup(<Gauge share={null} label="cpu" />)).not.toContain("data-segment");
  });
});

describe("the bar", () => {
  it("drops parts with nothing in them and sizes the rest by their share", () => {
    const html = renderToStaticMarkup(<Bar label="split" parts={[part("a", 1), part("b", 0), part("c", 3)]} />);
    const widths = [...html.matchAll(/data-segment="([^"]+)"[^>]*?style="width:([\d.]+)%/g)].map((match) => [match[1], Number(match[2])]);
    expect(widths).toEqual([["a", 25], ["c", 75]]);
    expect(drawnParts([part("x", Number.NaN), part("y", -1)])).toEqual([]);
  });

  it("hatches a part nobody answered, so it never reads as a settled state", () => {
    expect(partFill({ tone: "other", hatched: true })).toContain("repeating-linear-gradient(135deg");
    expect(partFill({ tone: "bad" })).toBe(TONE_HEX.bad);
  });
});

describe("the sparkline", () => {
  /**
   * FAILS ON REVERT: scale an all-zero series by zero and every point is
   * NaN; draw it mid-height and silence reads as activity.
   */
  it("draws a silent series flat on the baseline", () => {
    expect(sparkPoints([0, 0, 0], 24)).toBe("0.0,24.0 50.0,24.0 100.0,24.0");
  });

  it("puts the peak near the top of its own scale, with a quarter of the box above it", () => {
    expect(sparkPoints([0, 5, 10], 24)).toBe("0.0,24.0 50.0,15.4 100.0,6.8");
  });

  /**
   * FAILS ON REVERT: a steady series scaled to its peak filled the box, and
   * its 12% fill read as a solid slab, a rendering glitch rather than a flow.
   */
  it("draws a steady series as a level line at mid-height, and fades its area to nothing", () => {
    expect(sparkPoints([100, 104, 98, 101], 24)).toBe("0.0,12.0 33.3,12.0 66.7,12.0 100.0,12.0");
    const html = renderToStaticMarkup(<Spark values={[1, 3, 2]} label="a flow" />);
    expect(html).toContain("<linearGradient");
    expect(html).toContain('stop-opacity="0"');
    expect(html).not.toContain('fill-opacity="0.12"');
  });

  it("draws nothing for fewer than two points, and says what it plots", () => {
    const html = renderToStaticMarkup(<Spark values={[4]} label="one point" />);
    expect(html).not.toContain("polyline");
    expect(html).toContain('aria-label="one point"');
  });
});
