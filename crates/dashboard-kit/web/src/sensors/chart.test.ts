import { describe, expect, it } from "vitest";
import {
  BAND_COLORS,
  DEFAULT_COLUMN_MINUTES,
  MINUTES_IN_DAY,
  OTHER_BAND,
  bucketMinute,
  buildSensorChart,
  chartHourTicks,
  chartSummary,
  stackedBandPaths,
} from "./chart";
import type { EventTimeline } from "../api/sensors";

const COLUMNS = MINUTES_IN_DAY / DEFAULT_COLUMN_MINUTES;

describe("bucketMinute", () => {
  it("reads the HH:MM the endpoint sends", () => {
    expect(bucketMinute("00:00")).toBe(0);
    expect(bucketMinute("09:07")).toBe(547);
    expect(bucketMinute("23:59")).toBe(1_439);
  });

  /**
   * The producer strips the date prefix before serving, but the same key shape
   * exists undstripped inside it and has reached the wire before. A reader that
   * dropped it would draw an empty chart on a live host.
   */
  it("also reads the prefixed bucket key", () => {
    expect(bucketMinute("2026-08-06T09:07")).toBe(547);
  });

  it("refuses anything else rather than guessing a time", () => {
    for (const junk of ["", "9:07", "24:00", "09:60", "morning", "2026-08-06"]) {
      expect(bucketMinute(junk)).toBeNull();
    }
  });
});

describe("buildSensorChart", () => {
  /**
   * THE EMPTY CASE. A host with no time series must produce a chart that says
   * so, not a chart with a zero denominator. The panel refuses to draw axes
   * around this, and `stackedBandPaths` refuses to produce geometry for it.
   */
  it("reports an empty timeline as empty and draws nothing", () => {
    const chart = buildSensorChart({});
    expect(chart.empty).toBe(true);
    expect(chart.emptyReason).toBe("no_buckets");
    expect(chart.bands).toEqual([]);
    expect(chart.peak).toBe(0);
    expect(chart.total).toBe(0);
    expect(chart.firstActiveColumn).toBeNull();
    expect(chart.lastActiveColumn).toBeNull();
    expect(stackedBandPaths(chart, 720, 200)).toEqual([]);
    expect(chartSummary(chart)).toBe("No event time series was reported for today.");
  });

  it("separates buckets that are all zero from no buckets at all", () => {
    const chart = buildSensorChart({ "04:00": { ebpf: 0 }, "04:01": {} });
    expect(chart.empty).toBe(true);
    expect(chart.emptyReason).toBe("no_events");
    expect(stackedBandPaths(chart, 720, 200)).toEqual([]);
    expect(chartSummary(chart)).toBe("No events were recorded in any time bucket today.");
  });

  it("survives a timeline of nothing but unparseable keys", () => {
    const chart = buildSensorChart({ nonsense: { ebpf: 12 }, "": { auditd: 3 } });
    expect(chart.empty).toBe(true);
    expect(chart.emptyReason).toBe("no_buckets");
  });

  it("lays buckets on the real time axis, so silence keeps its width", () => {
    const chart = buildSensorChart({ "00:00": { ebpf: 5 }, "23:50": { ebpf: 7 } });
    expect(chart.empty).toBe(false);
    expect(chart.columns).toBe(COLUMNS);
    expect(chart.firstActiveColumn).toBe(0);
    expect(chart.lastActiveColumn).toBe(COLUMNS - 1);
    // Two populated buckets, and the twenty-four hours between them are drawn as
    // the gap they are rather than as two adjacent points.
    const values = chart.bands[0].values;
    expect(values[0]).toBe(5);
    expect(values[COLUMNS - 1]).toBe(7);
    expect(values.filter((value) => value > 0)).toHaveLength(2);
  });

  it("sums the minute buckets that share a column", () => {
    const timeline: EventTimeline = {};
    for (let minute = 0; minute < DEFAULT_COLUMN_MINUTES; minute += 1) {
      timeline[`00:${String(minute).padStart(2, "0")}`] = { ebpf: 2 };
    }
    const chart = buildSensorChart(timeline);
    expect(chart.bands[0].values[0]).toBe(2 * DEFAULT_COLUMN_MINUTES);
    expect(chart.total).toBe(2 * DEFAULT_COLUMN_MINUTES);
  });

  it("ranks bands by volume and gives each a distinct colour", () => {
    const chart = buildSensorChart({ "12:00": { auditd: 10, ebpf: 90, journald: 50 } });
    expect(chart.bands.map((band) => band.name)).toEqual(["ebpf", "journald", "auditd"]);
    expect(chart.bands.map((band) => band.color)).toEqual(BAND_COLORS.slice(0, 3));
    expect(chart.peak).toBe(150);
    expect(chart.total).toBe(150);
  });

  it("aggregates the tail instead of dropping it, so the total still adds up", () => {
    const sources: Record<string, number> = {};
    for (let index = 0; index < 12; index += 1) sources[`collector_${String(index).padStart(2, "0")}`] = 12 - index;
    const chart = buildSensorChart({ "08:00": sources }, { maxBands: 3 });
    expect(chart.bands).toHaveLength(4);
    expect(chart.bands[3].name).toBe(OTHER_BAND);
    const summed = chart.bands.reduce((total, band) => total + band.total, 0);
    expect(summed).toBe(chart.total);
    expect(chart.total).toBe(78);
  });

  it("is stable across polls: equal totals tie-break by name", () => {
    const first = buildSensorChart({ "01:00": { bravo: 4, alpha: 4 } });
    const second = buildSensorChart({ "01:00": { alpha: 4, bravo: 4 } });
    expect(first.bands.map((band) => band.name)).toEqual(["alpha", "bravo"]);
    expect(second.bands.map((band) => band.name)).toEqual(first.bands.map((band) => band.name));
  });
});

describe("stackedBandPaths", () => {
  it("stacks bands without overlapping them", () => {
    const chart = buildSensorChart({ "00:00": { a: 1, b: 1 }, "23:50": { a: 1, b: 1 } });
    const paths = stackedBandPaths(chart, 100, 100);
    expect(paths.map((path) => path.name)).toEqual(chart.bands.map((band) => band.name));
    // Peak is 2. The first band tops out at half height; the second reaches the
    // top of the plot, which is what "stacked" has to mean.
    expect(paths[0].line).toContain("M0 50");
    expect(paths[1].line).toContain("M0 0");
    for (const path of paths) expect(path.area.endsWith("Z")).toBe(true);
  });

  it("produces no geometry for a degenerate plot", () => {
    const chart = buildSensorChart({ "06:00": { ebpf: 4 } });
    expect(stackedBandPaths(chart, 0, 200)).toEqual([]);
    expect(stackedBandPaths(chart, 720, 0)).toEqual([]);
  });
});

describe("chart axis and caption", () => {
  it("marks the day every three hours from midnight to midnight", () => {
    const ticks = chartHourTicks();
    expect(ticks.map((tick) => tick.label)).toEqual([
      "00:00", "03:00", "06:00", "09:00", "12:00", "15:00", "18:00", "21:00", "24:00",
    ]);
    expect(ticks[0].fraction).toBe(0);
    expect(ticks[ticks.length - 1].fraction).toBe(1);
  });

  /**
   * The y axis is per COLUMN, not per minute. Saying so is the difference
   * between a peak an operator can act on and one they are off by a factor of
   * ten about.
   */
  it("names the column width in the caption", () => {
    const summary = chartSummary(buildSensorChart({ "05:00": { ebpf: 30 } }));
    expect(summary).toContain(`per ${DEFAULT_COLUMN_MINUTES}-minute column`);
    expect(summary).toContain("30 events today");
  });
});
