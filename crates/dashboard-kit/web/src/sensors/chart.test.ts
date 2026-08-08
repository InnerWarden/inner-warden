import { describe, expect, it } from "vitest";
import {
  BAND_COLORS,
  DEFAULT_COLUMN_MINUTES,
  MINUTES_IN_DAY,
  OTHER_BAND,
  bucketMinute,
  buildSensorChart,
  busiestColumn,
  chartHourTicks,
  chartSummary,
  chartValueTicks,
  columnAtFraction,
  columnReadout,
  columnWindowLabel,
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

  /**
   * The path must end at the last column that has data, not plunge to the
   * baseline and run flat to midnight. A day with events only up to 12:00 was
   * drawing every band down to zero and holding it there for the afternoon,
   * which reads as "the host died at noon" on a host that is alive and simply
   * has no future to plot yet.
   */
  it("ends the line at the last active column instead of falling to zero", () => {
    // Events only in the morning; the afternoon has not happened.
    const chart = buildSensorChart({ "00:00": { ebpf: 5 }, "12:00": { ebpf: 5 } });
    const [path] = stackedBandPaths(chart, 1440, 100);
    // 10-min columns => 12:00 is column 72. The line's last point must be there,
    // not at the final column 143 (23:50) sitting on the baseline.
    const points = path.line.match(/[ML]([\d.]+) ([\d.]+)/g) ?? [];
    const last = points[points.length - 1];
    const lastX = Number(/[ML]([\d.]+)/.exec(last)?.[1]);
    const lastY = Number(/[ML][\d.]+ ([\d.]+)/.exec(last)?.[1]);
    // x for column 72 of 144 (span 0..143) over width 1440.
    expect(lastX).toBeCloseTo((72 * 1440) / 143, 0);
    // and it must be at the top of the stack (peak), NOT the baseline (y=100).
    expect(lastY).toBeLessThan(100);
    // no point should sit past the last active column.
    for (const p of points) {
      const px = Number(/[ML]([\d.]+)/.exec(p)?.[1]);
      expect(px).toBeLessThanOrEqual((72 * 1440) / 143 + 0.5);
    }
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

/**
 * The readable half. None of it touches the numbers: a labelled axis, a window
 * in words and a per-column breakdown all read the same series the stack draws.
 */
describe("chart readability", () => {
  it("labels the vertical axis with real values, from the peak down to zero", () => {
    const ticks = chartValueTicks(buildSensorChart({ "05:00": { ebpf: 30 }, "06:00": { ebpf: 10 } }));
    expect(ticks.map((tick) => tick.label)).toEqual(["30", "15", "0"]);
    expect(ticks.map((tick) => tick.fraction)).toEqual([0, 0.5, 1]);
  });

  it("labels nothing when there is nothing to scale", () => {
    expect(chartValueTicks(buildSensorChart({}))).toEqual([]);
    expect(chartValueTicks(buildSensorChart({ "04:00": { ebpf: 0 } }))).toEqual([]);
  });

  /**
   * The y axis is per COLUMN. A reader who assumes per minute is off by the
   * column width, so the window a column covers is spelled out rather than
   * inferred from a tick.
   */
  it("names the window a column covers", () => {
    const chart = buildSensorChart({ "14:23": { ebpf: 4 } });
    expect(columnWindowLabel(chart, 0)).toBe("00:00 to 00:10");
    expect(columnWindowLabel(chart, 86)).toBe("14:20 to 14:30");
    expect(columnWindowLabel(chart, chart.columns - 1)).toBe("23:50 to 24:00");
  });

  it("maps a horizontal position to a column and refuses one off the plot", () => {
    const chart = buildSensorChart({ "12:00": { ebpf: 1 } });
    expect(columnAtFraction(chart, 0)).toBe(0);
    expect(columnAtFraction(chart, 1)).toBe(chart.columns - 1);
    expect(columnAtFraction(chart, -0.01)).toBeNull();
    expect(columnAtFraction(chart, 1.01)).toBeNull();
    expect(columnAtFraction(chart, Number.NaN)).toBeNull();
    expect(columnAtFraction(buildSensorChart({}), 0.5)).toBeNull();
  });

  it("reads one column back as its real totals, largest band first", () => {
    const chart = buildSensorChart({ "08:00": { auditd: 10, ebpf: 90 }, "08:05": { journald: 5 }, "20:00": { ebpf: 1 } });
    const readout = columnReadout(chart, 48);
    expect(readout).not.toBeNull();
    expect(readout?.window).toBe("08:00 to 08:10");
    expect(readout?.total).toBe(105);
    expect(readout?.entries.map((entry) => [entry.name, entry.value])).toEqual([["ebpf", 90], ["auditd", 10], ["journald", 5]]);
  });

  it("omits bands that contributed nothing to the column rather than listing zeroes", () => {
    const chart = buildSensorChart({ "08:00": { auditd: 10 }, "20:00": { ebpf: 4 } });
    expect(columnReadout(chart, 48)?.entries.map((entry) => entry.name)).toEqual(["auditd"]);
    expect(columnReadout(chart, 120)?.entries.map((entry) => entry.name)).toEqual(["ebpf"]);
  });

  it("has no readout for a column that does not exist or a chart with no data", () => {
    const chart = buildSensorChart({ "08:00": { auditd: 1 } });
    expect(columnReadout(chart, null)).toBeNull();
    expect(columnReadout(chart, -1)).toBeNull();
    expect(columnReadout(chart, chart.columns)).toBeNull();
    expect(columnReadout(chart, 1.5)).toBeNull();
    expect(columnReadout(buildSensorChart({}), 0)).toBeNull();
  });

  /**
   * The strip under the chart rests here, so it is never a blank box on load
   * and answers without a pointer on a touch screen.
   */
  it("rests on the busiest column, and on none at all when the day was silent", () => {
    const chart = buildSensorChart({ "01:00": { ebpf: 5 }, "14:20": { ebpf: 400 }, "22:00": { ebpf: 9 } });
    expect(busiestColumn(chart)).toBe(86);
    expect(columnReadout(chart, busiestColumn(chart))?.total).toBe(400);
    expect(busiestColumn(buildSensorChart({}))).toBeNull();
    expect(busiestColumn(buildSensorChart({ "04:00": { ebpf: 0 } }))).toBeNull();
  });

  /**
   * HONESTY ANCHOR. The prettier chart must not smooth anything: a single busy
   * ten minutes has to stay a single busy ten minutes, with zero on both sides,
   * and the tail aggregate keeps its own name.
   */
  it("keeps a lone spike a lone spike, and the tail an honest band", () => {
    const sources: Record<string, number> = { loud: 500 };
    for (let index = 0; index < 9; index += 1) sources[`quiet_${index}`] = 1;
    const chart = buildSensorChart({ "14:20": sources }, { maxBands: 2 });
    const spike = columnReadout(chart, 86);
    expect(spike?.total).toBe(509);
    expect(spike?.entries.map((entry) => entry.name)).toEqual(["loud", OTHER_BAND, "quiet_0"]);
    expect(columnReadout(chart, 85)).toEqual({ column: 85, window: "14:10 to 14:20", total: 0, entries: [] });
    expect(columnReadout(chart, 87)?.total).toBe(0);
  });
});
