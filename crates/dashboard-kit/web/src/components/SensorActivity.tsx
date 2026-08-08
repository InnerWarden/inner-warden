import { useEffect, useId, useMemo, useState, type KeyboardEvent, type PointerEvent } from "react";
import { fetchSensorActivity, type SensorActivity as SensorActivityPayload } from "../api/sensors";
import {
  boardSummary,
  collectorGroups,
  collectorRows,
  sensorPanelState,
  type CollectorGroup,
  type CollectorRow,
  type CollectorTone,
  type SensorFeed,
} from "../sensors/board";
import {
  buildSensorChart,
  busiestColumn,
  chartHourTicks,
  chartSummary,
  chartValueTicks,
  columnAtFraction,
  columnReadout,
  stackedBandPaths,
  type ColumnReadout,
  type SensorChart,
} from "../sensors/chart";

const PLOT_WIDTH = 960;
const PLOT_HEIGHT = 240;
const POLL_MS = 30_000;

/**
 * The sensor activity panel: what every collector on this host produced today,
 * and which of them can be shown as running.
 *
 * Renders NOTHING at all when `/api/sensors` is not served. The free product
 * does not have a host sensor, and an empty panel, a skeleton or an error box
 * would each be this bundle telling that operator there is sensor data here,
 * loading or broken. Silence is the only honest rendering of "this product does
 * not collect that".
 */
export function SensorActivity() {
  const feed = useSensorFeed();
  const panel = sensorPanelState(feed);
  if (panel.render === "hidden") return null;

  const activity = panel.data;
  const chart = buildSensorChart(activity.event_timeline);
  const rows = collectorRows(activity);
  const groups = collectorGroups(rows);

  return (
    <section data-tour="overview-sensor" aria-labelledby="sensor-activity-title" className="min-w-0">
      <div className="mb-3 flex flex-col items-start gap-2 sm:flex-row sm:items-end sm:justify-between sm:gap-4">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Host sensor</p>
          <h2 id="sensor-activity-title" className="mt-1 text-lg font-semibold text-slate-950">Sensor activity</h2>
          <p className="mt-1 max-w-3xl text-sm leading-5 text-slate-600">
            Events per collector across today, and below it what each collector reports about itself. A collector is only
            shown as running when the sensor attests it or events were observed; being configured is not evidence of either.
          </p>
        </div>
        {activity.date ? <span className="shrink-0 text-xs tabular-nums text-slate-500">{activity.date} UTC</span> : null}
      </div>

      {panel.stale && (
        <div role="status" className="mb-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-900">
          Latest sensor refresh failed. The last good snapshot is retained.
        </div>
      )}

      {/* The chart is the attention-grabber and gets the full width; the board
          below it is a dense grid rather than a second column. The old
          two-column layout ended the chart after ~300px and ran the status
          column for ~1000px, which is a lopsided page with dead whitespace
          under the one thing worth looking at. */}
      <div className="min-w-0 space-y-4">
        <TimelineCard activity={activity} chart={chart} />
        <BoardCard rows={rows} groups={groups} />
      </div>
    </section>
  );
}

/**
 * Poll `/api/sensors`, and stop for good on an honest absence.
 *
 * A 404 here is a permanent property of the product being served, not a
 * transient failure, so retrying it every thirty seconds forever would be
 * request noise in someone's log for an answer that cannot change without a
 * reload. A real failure keeps polling, because that one can recover.
 */
function useSensorFeed(): SensorFeed {
  const [feed, setFeed] = useState<SensorFeed>({ status: "loading" });

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    let inFlight = false;
    let lastSerialised: string | undefined;

    const refresh = async () => {
      if (inFlight) return;
      inFlight = true;
      let keepPolling = true;
      try {
        const outcome = await fetchSensorActivity();
        if (!active) return;
        if (outcome.state === "absent") {
          // Not a transient failure: a permanent property of the product being
          // served. Retrying it forever would be request noise for an answer
          // that cannot change without a reload.
          keepPolling = false;
          setFeed({ status: "absent" });
        } else if (outcome.state === "unavailable") {
          setFeed((current) => ({ status: "failed", data: current.data }));
        } else {
          // An identical payload is not an update, and most polls return one.
          const serialised = JSON.stringify(outcome.data);
          if (serialised !== lastSerialised) {
            lastSerialised = serialised;
            setFeed({ status: "ready", data: outcome.data });
          }
        }
      } finally {
        inFlight = false;
        if (active && keepPolling) timer = window.setTimeout(() => void refresh(), POLL_MS);
      }
    };

    void refresh();
    return () => {
      active = false;
      if (timer != null) window.clearTimeout(timer);
    };
  }, []);

  return feed;
}

function TimelineCard({ activity, chart }: { activity: SensorActivityPayload; chart: SensorChart }) {
  const summary = chartSummary(chart);
  return (
    <div className="min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="text-sm font-semibold text-slate-900">Events per collector</h3>
        <p className="text-xs tabular-nums text-slate-500">
          {activity.total_events == null ? "Total not reported" : `${activity.total_events.toLocaleString()} events`}
          <span aria-hidden="true" className="px-1.5 text-slate-300">·</span>
          {activity.total_incidents == null ? "incidents not reported" : `${activity.total_incidents.toLocaleString()} incidents`}
        </p>
      </div>

      {chart.empty ? (
        <div className="mt-3 rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-10 text-center">
          <p className="text-sm font-semibold text-slate-800">
            {chart.emptyReason === "no_events" ? "No events recorded today" : "No time series reported"}
          </p>
          <p className="mx-auto mt-1 max-w-md text-xs leading-5 text-slate-600">
            {chart.emptyReason === "no_events"
              // The board moved below this card in the full-width layout and
              // this sentence went on pointing sideways at it.
              ? "The host reported its time buckets and every one was empty. That is a quiet day, not a failure. Collector status is below."
              : "This host sent no timeline for today, so there is nothing to draw. Collector status is below; none of it is guessed from the missing timeline."}
          </p>
        </div>
      ) : (
        <Plot chart={chart} summary={summary} />
      )}

      <p className="mt-2 text-xs leading-5 text-slate-500">{summary}</p>
    </div>
  );
}

/**
 * The stack itself: gradients, an axis with numbers on it, and a readout of the
 * column under the cursor.
 *
 * Nothing here touches the DATA. The columns are still ten real minutes wide,
 * the totals are still the producer's, the tail is still one honest aggregate
 * band, and no curve is interpolated between two points, so a one-column spike
 * still draws as a one-column spike. What changed is that a reader can now tell
 * what the height MEANS: the vertical axis is labelled, and pointing at a
 * column says which ten minutes it is and which collector filled it.
 */
function Plot({ chart, summary }: { chart: SensorChart; summary: string }) {
  const paths = stackedBandPaths(chart, PLOT_WIDTH, PLOT_HEIGHT);
  const hourTicks = chartHourTicks();
  const valueTicks = chartValueTicks(chart);
  // `useId` is per-instance, so two plots on one page cannot share a gradient.
  // The colons React puts in the id are stripped: they are legal in an id and a
  // needless argument with every `url(#...)` consumer.
  const gradientPrefix = `iw-band-${useId().replace(/:/g, "")}`;
  const [pointed, setPointed] = useState<number | null>(null);
  const resting = useMemo(() => busiestColumn(chart), [chart]);
  const column = pointed ?? resting;
  const readout = columnReadout(chart, column);
  const cursorX = column === null ? null : (column * PLOT_WIDTH) / Math.max(1, chart.columns - 1);

  const track = (event: PointerEvent<SVGSVGElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    if (box.width <= 0) return;
    setPointed(columnAtFraction(chart, (event.clientX - box.left) / box.width));
  };
  const step = (event: KeyboardEvent<SVGSVGElement>) => {
    const moves: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, PageUp: 6, PageDown: -6 };
    const move = moves[event.key];
    if (move === undefined && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const from = column ?? 0;
    const next = event.key === "Home" ? 0 : event.key === "End" ? chart.columns - 1 : from + move;
    setPointed(Math.min(chart.columns - 1, Math.max(0, next)));
  };

  return (
    <figure className="mt-3 min-w-0">
      <div className="relative min-w-0">
        <svg
          viewBox={`0 0 ${PLOT_WIDTH} ${PLOT_HEIGHT}`}
          // Stretched to the container rather than letter-boxed: a day-long time
          // series is read left to right, and a fixed aspect ratio would leave it
          // an inch tall on a phone. Every stroke below carries
          // `vector-effect="non-scaling-stroke"` so the distortion never reaches
          // a line weight.
          className="h-48 w-full rounded-xl border border-slate-800 bg-slate-950 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600 sm:h-64"
          role="img"
          aria-label={summary}
          preserveAspectRatio="none"
          tabIndex={0}
          onPointerMove={track}
          onPointerDown={track}
          onPointerLeave={() => setPointed(null)}
          onBlur={() => setPointed(null)}
          onKeyDown={step}
        >
          <defs>
            {paths.map((path, index) => (
              <linearGradient key={path.name} id={`${gradientPrefix}-${index}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={path.color} stopOpacity={0.5} />
                <stop offset="100%" stopColor={path.color} stopOpacity={0.06} />
              </linearGradient>
            ))}
          </defs>
          {valueTicks.map((tick) => (
            <line
              key={`value-${tick.fraction}`}
              x1={0}
              y1={PLOT_HEIGHT * tick.fraction}
              x2={PLOT_WIDTH}
              y2={PLOT_HEIGHT * tick.fraction}
              stroke="#1e293b"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {hourTicks.slice(1, -1).map((tick) => (
            <line
              key={`hour-${tick.label}`}
              x1={PLOT_WIDTH * tick.fraction}
              y1={0}
              x2={PLOT_WIDTH * tick.fraction}
              y2={PLOT_HEIGHT}
              stroke="#172033"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {paths.map((path, index) => (
            <g key={path.name}>
              <title>{path.name}</title>
              <path d={path.area} fill={`url(#${gradientPrefix}-${index})`} />
              <path
                d={path.line}
                fill="none"
                stroke={path.color}
                strokeWidth={1.5}
                strokeLinejoin="round"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
              />
            </g>
          ))}
          {cursorX !== null && (
            <line
              x1={cursorX}
              y1={0}
              x2={cursorX}
              y2={PLOT_HEIGHT}
              stroke="#94a3b8"
              strokeWidth={1}
              strokeDasharray="4 4"
              vectorEffect="non-scaling-stroke"
            />
          )}
        </svg>
        <div className="pointer-events-none absolute inset-y-0 left-0 flex flex-col justify-between py-1.5 pl-2 text-[10px] font-medium tabular-nums text-slate-500" aria-hidden="true">
          {valueTicks.map((tick) => <span key={tick.fraction}>{tick.label}</span>)}
        </div>
      </div>

      <div className="relative mt-1.5 h-4" aria-hidden="true">
        {hourTicks.map((tick) => (
          <span
            key={tick.label}
            className={`absolute top-0 text-[11px] tabular-nums text-slate-400 ${
              tick.fraction === 0 ? "" : tick.fraction === 1 ? "-translate-x-full" : "-translate-x-1/2"
            }`}
            style={{ left: `${tick.fraction * 100}%` }}
          >
            {tick.label}
          </span>
        ))}
      </div>

      {readout && <ColumnReadoutStrip readout={readout} minutes={chart.columnMinutes} pointing={pointed !== null} />}

      <figcaption className="mt-3 grid gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
        {chart.bands.map((band) => (
          <span key={band.name} className="flex min-w-0 items-center gap-2 text-[11px] text-slate-600">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: band.color }} aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate font-medium text-slate-700" title={band.name}>{band.name}</span>
            <span className="shrink-0 tabular-nums text-slate-500">{band.total.toLocaleString()}</span>
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

/**
 * One column, in numbers.
 *
 * It rests on the busiest ten minutes of the day rather than sitting blank
 * until someone hovers, so it is never an empty strip under a full chart, and
 * on a touch screen it still answers the question without a pointer.
 */
function ColumnReadoutStrip({
  readout,
  minutes,
  pointing,
}: {
  readout: ColumnReadout;
  minutes: number;
  pointing: boolean;
}) {
  return (
    <div className="mt-3 min-w-0 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2" aria-live="off">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="text-xs font-semibold text-slate-800">
          {pointing ? readout.window : `Busiest ${minutes} minutes: ${readout.window}`}
        </span>
        <span className="text-xs tabular-nums text-slate-600">{readout.total.toLocaleString()} events</span>
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
        {readout.entries.map((entry) => (
          <span key={entry.name} className="inline-flex min-w-0 max-w-full items-center gap-1.5 text-[11px] text-slate-600">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: entry.color }} aria-hidden="true" />
            <span className="truncate" title={entry.name}>{entry.name}</span>
            <span className="shrink-0 tabular-nums text-slate-500">{entry.value.toLocaleString()}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * The status board, dense on purpose.
 *
 * The first version rendered every collector as a full card with its own
 * explanatory paragraph, and identical states carried identical paragraphs: the
 * same sentence printed four, five times in a row down a column three screens
 * tall. Each state's explanation now renders ONCE, as a legend line under its
 * group header, and a row is a single compact line: state dot, name, pill,
 * count. Rows flow into up to three columns on wide screens. The only prose a
 * row may still carry is a fact about that row alone (its fault, its
 * contradiction), which is exactly the prose that cannot be shared.
 */
function BoardCard({ rows, groups }: { rows: CollectorRow[]; groups: CollectorGroup[] }) {
  return (
    <div className="min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="text-sm font-semibold text-slate-900">Collector status</h3>
        <p className="text-xs leading-5 text-slate-600">{boardSummary(rows)}</p>
      </div>
      {groups.length === 0 ? (
        <p className="mt-3 rounded-xl border border-dashed border-slate-300 bg-slate-50 px-3 py-6 text-center text-xs text-slate-600">
          This host listed no collectors. Nothing is being assumed about what it collects.
        </p>
      ) : (
        <div className="mt-4 space-y-5">
          {groups.map((group) => <Group key={group.category} group={group} />)}
        </div>
      )}
    </div>
  );
}

function Group({ group }: { group: CollectorGroup }) {
  return (
    <section aria-label={group.title}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-b border-slate-100 pb-1.5">
        <h4 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{group.title}</h4>
        <span className="text-[11px] tabular-nums text-slate-500">{group.caption}</span>
      </div>
      <ul className="mt-2 grid min-w-0 grid-cols-1 gap-x-6 gap-y-0.5 sm:grid-cols-2 xl:grid-cols-3">
        {group.rows.map((row) => <Row key={row.name} row={row} />)}
      </ul>
      {/* Each state's meaning, said once for the whole group. The dot and label
          match the rows above, so the legend maps by eye. */}
      <div className="mt-2 space-y-0.5">
        <p className="text-[11px] leading-4 text-slate-500">{group.meaning}</p>
        {group.notes.map((note) => (
          <p key={note.key} className="flex min-w-0 items-start gap-1.5 text-[11px] leading-4 text-slate-500">
            <span className={`mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full ${TONE_DOT[note.tone]}`} aria-hidden="true" />
            <span>
              <span className={`font-semibold ${TONE_TEXT[note.tone]}`}>{note.label}:</span> {note.text}
            </span>
          </p>
        ))}
      </div>
    </section>
  );
}

const TONE_DOT: Record<CollectorTone, string> = {
  warning: "bg-red-500",
  attention: "bg-amber-500",
  positive: "bg-emerald-500",
  neutral: "bg-slate-400",
};

const TONE_TEXT: Record<CollectorTone, string> = {
  warning: "text-red-800",
  attention: "text-amber-800",
  positive: "text-emerald-800",
  neutral: "text-slate-600",
};

const TONE_PILL: Record<CollectorTone, string> = {
  warning: "border-red-200 bg-red-50 text-red-800",
  attention: "border-amber-200 bg-amber-50 text-amber-800",
  positive: "border-emerald-200 bg-emerald-50 text-emerald-800",
  neutral: "border-slate-200 bg-slate-50 text-slate-600",
};

function Row({ row }: { row: CollectorRow }) {
  return (
    <li className="min-w-0 py-0.5">
      <div className="flex min-w-0 items-center gap-2">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${TONE_DOT[row.tone]}`} aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate font-mono text-xs font-medium text-slate-800" title={row.name}>{row.name}</span>
        <span className={`inline-flex shrink-0 rounded-full border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ${TONE_PILL[row.tone]}`}>
          {row.label}
        </span>
        <span className="w-12 shrink-0 text-right text-xs tabular-nums text-slate-600">{row.count.toLocaleString()}</span>
      </div>
      {row.note && <p className="mt-0.5 pl-3.5 text-[11px] leading-4 text-slate-600">{row.note}</p>}
    </li>
  );
}
