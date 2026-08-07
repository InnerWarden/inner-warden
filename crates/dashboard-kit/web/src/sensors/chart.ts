/**
 * The stacked time series of events per collector, computed outside React.
 *
 * Hand-rolled on purpose. The bundle has react and react-dom as its only two
 * dependencies and it stays that way: a charting library would be a third-party
 * blob inside a bundle whose whole point is that its digest is reproducible and
 * verifiable. The maths here is a few dozen lines and it is testable without a
 * DOM, which a canvas library is not.
 *
 * ONE honesty rule drives the shape of everything below. The producer sends only
 * the minutes that HAD events, so plotting the payload's buckets side by side
 * would draw a busy, continuous day out of four scattered spikes. The series is
 * therefore laid out on a real time axis: the whole 24 hours, missing minutes
 * are zero, so silence occupies the width it actually occupied.
 */
import type { EventTimeline } from "../api/sensors";

export const MINUTES_IN_DAY = 1_440;

/**
 * Minutes per plotted column. The wire buckets are one minute wide; 1,440
 * points per band is a lot of path data for a chart three inches tall, so
 * columns aggregate. The width is reported on the chart so the y axis is never
 * read as "per minute" when it is not.
 */
export const DEFAULT_COLUMN_MINUTES = 10;

/**
 * How many collectors get their own band before the tail is aggregated. A host
 * runs around thirty collectors; thirty overlapping bands is a smear, not a
 * chart. The tail is summed into one honest band rather than dropped.
 */
export const DEFAULT_MAX_BANDS = 6;

export const OTHER_BAND = "Other collectors";

/**
 * Band colours. Distinct in hue and in lightness, so the stack survives a
 * monochrome print and the common forms of colour blindness; the legend prints
 * the name beside every swatch regardless, because colour alone is not a label.
 */
export const BAND_COLORS: readonly string[] = [
  "#22d3ee",
  "#a3e635",
  "#fbbf24",
  "#fb7185",
  "#a78bfa",
  "#38bdf8",
  "#f97316",
  "#2dd4bf",
];

export const OTHER_BAND_COLOR = "#94a3b8";

export type ChartBand = {
  name: string;
  color: string;
  /** One value per column, already aggregated. Length is always `columns`. */
  values: number[];
  total: number;
};

export type SensorChart = {
  /** Nothing to draw. The panel says which kind of nothing, and never draws axes around it. */
  empty: boolean;
  emptyReason?: "no_buckets" | "no_events";
  columns: number;
  columnMinutes: number;
  bands: ChartBand[];
  /** Tallest stacked column. Zero only when `empty`. */
  peak: number;
  total: number;
  /** Column index of the first and last non-zero column, or `null` when empty. */
  firstActiveColumn: number | null;
  lastActiveColumn: number | null;
};

/**
 * Minute-of-day for a wire bucket key.
 *
 * Accepts the `HH:MM` the endpoint sends today and the `YYYY-MM-DDTHH:MM` the
 * producer uses internally, because the endpoint has shipped both shapes and a
 * reader that silently drops one would draw an empty chart on a live host.
 * Anything else returns `null` and is skipped rather than guessed at.
 */
export function bucketMinute(label: string): number | null {
  const time = label.length > 5 && label.includes("T") ? label.slice(label.indexOf("T") + 1) : label;
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(time.trim());
  if (match === null) return null;
  return Number(match[1]) * 60 + Number(match[2]);
}

function columnFor(minute: number, columnMinutes: number, columns: number): number {
  return Math.min(columns - 1, Math.max(0, Math.floor(minute / columnMinutes)));
}

/**
 * Build the stacked series.
 *
 * Bands are ranked by total and tie-broken by name so the same host renders the
 * same chart on every poll: a stack whose order flickers is unreadable.
 */
export function buildSensorChart(
  timeline: EventTimeline,
  options: { columnMinutes?: number; maxBands?: number } = {},
): SensorChart {
  const columnMinutes = Math.max(1, Math.floor(options.columnMinutes ?? DEFAULT_COLUMN_MINUTES));
  const maxBands = Math.max(1, Math.floor(options.maxBands ?? DEFAULT_MAX_BANDS));
  const columns = Math.ceil(MINUTES_IN_DAY / columnMinutes);
  const empty = (reason: SensorChart["emptyReason"]): SensorChart => ({
    empty: true,
    emptyReason: reason,
    columns,
    columnMinutes,
    bands: [],
    peak: 0,
    total: 0,
    firstActiveColumn: null,
    lastActiveColumn: null,
  });

  const totals = new Map<string, number>();
  const perColumn = new Map<string, number[]>();
  let buckets = 0;
  let total = 0;

  for (const [label, sources] of Object.entries(timeline)) {
    const minute = bucketMinute(label);
    if (minute === null) continue;
    buckets += 1;
    const column = columnFor(minute, columnMinutes, columns);
    for (const [name, count] of Object.entries(sources)) {
      if (!Number.isFinite(count) || count <= 0) continue;
      totals.set(name, (totals.get(name) ?? 0) + count);
      let values = perColumn.get(name);
      if (values === undefined) {
        values = new Array<number>(columns).fill(0);
        perColumn.set(name, values);
      }
      values[column] += count;
      total += count;
    }
  }

  if (buckets === 0) return empty("no_buckets");
  // Buckets arrived but every one of them was zero. That is a different fact
  // from "the producer sent no buckets at all", and the panel says which.
  if (total === 0) return empty("no_events");

  const ranked = [...totals.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  const named = ranked.slice(0, maxBands);
  const tail = ranked.slice(maxBands);

  const bands: ChartBand[] = named.map(([name, bandTotal], index) => ({
    name,
    color: BAND_COLORS[index % BAND_COLORS.length],
    values: perColumn.get(name) ?? new Array<number>(columns).fill(0),
    total: bandTotal,
  }));

  if (tail.length > 0) {
    const values = new Array<number>(columns).fill(0);
    let tailTotal = 0;
    for (const [name, bandTotal] of tail) {
      const source = perColumn.get(name);
      if (source === undefined) continue;
      for (let index = 0; index < columns; index += 1) values[index] += source[index];
      tailTotal += bandTotal;
    }
    bands.push({ name: OTHER_BAND, color: OTHER_BAND_COLOR, values, total: tailTotal });
  }

  let peak = 0;
  let firstActiveColumn: number | null = null;
  let lastActiveColumn: number | null = null;
  for (let index = 0; index < columns; index += 1) {
    let sum = 0;
    for (const band of bands) sum += band.values[index];
    if (sum > peak) peak = sum;
    if (sum > 0) {
      if (firstActiveColumn === null) firstActiveColumn = index;
      lastActiveColumn = index;
    }
  }

  return { empty: false, columns, columnMinutes, bands, peak, total, firstActiveColumn, lastActiveColumn };
}

export type BandPath = { name: string; color: string; area: string; line: string };

/**
 * SVG paths for the stack, in draw order.
 *
 * Coordinates are rounded to two decimals: enough for a plot a few hundred
 * pixels wide, and it keeps both the DOM and these tests' expectations small.
 */
export function stackedBandPaths(chart: SensorChart, width: number, height: number): BandPath[] {
  if (chart.empty || chart.peak <= 0 || chart.columns < 2 || width <= 0 || height <= 0) return [];
  const round = (value: number) => Math.round(value * 100) / 100;
  const x = (index: number) => round((index * width) / (chart.columns - 1));
  const y = (value: number) => round(height - (value / chart.peak) * height);

  const lower = new Array<number>(chart.columns).fill(0);
  const paths: BandPath[] = [];
  for (const band of chart.bands) {
    const upper = lower.map((base, index) => base + band.values[index]);
    const top = upper.map((value, index) => `${index === 0 ? "M" : "L"}${x(index)} ${y(value)}`).join(" ");
    const bottom = lower
      .map((value, index) => ({ value, index }))
      .reverse()
      .map(({ value, index }) => `L${x(index)} ${y(value)}`)
      .join(" ");
    paths.push({ name: band.name, color: band.color, area: `${top} ${bottom} Z`, line: top });
    for (let index = 0; index < chart.columns; index += 1) lower[index] = upper[index];
  }
  return paths;
}

/**
 * Hour marks for the axis under the plot, as fractions of the width.
 *
 * The closing mark is "24:00", not a second "00:00": the axis ends where the day
 * ends, and two identical labels at both edges reads as an axis that wrapped.
 */
export function chartHourTicks(everyHours = 3): { label: string; fraction: number }[] {
  const ticks: { label: string; fraction: number }[] = [];
  for (let hour = 0; hour <= 24; hour += everyHours) {
    ticks.push({ label: `${String(hour).padStart(2, "0")}:00`, fraction: hour / 24 });
  }
  return ticks;
}

/**
 * What the chart is, in one sentence, for a screen reader and for the caption.
 *
 * The unit is spelled out because the y axis is per column, not per minute, and
 * a reader who assumes otherwise is off by the column width.
 */
export function chartSummary(chart: SensorChart): string {
  if (chart.empty) {
    return chart.emptyReason === "no_events"
      ? "No events were recorded in any time bucket today."
      : "No event time series was reported for today.";
  }
  const collectors = `${chart.bands.length} band${chart.bands.length === 1 ? "" : "s"}`;
  return `${chart.total.toLocaleString()} events today across ${collectors}, `
    + `peaking at ${chart.peak.toLocaleString()} events per ${chart.columnMinutes}-minute column.`;
}
