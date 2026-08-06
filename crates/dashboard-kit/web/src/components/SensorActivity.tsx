import { useEffect, useState } from "react";
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
  chartHourTicks,
  chartSummary,
  stackedBandPaths,
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
    <section aria-labelledby="sensor-activity-title" className="min-w-0">
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
              ? "The host reported time buckets and every one of them was empty. That is a quiet day, not a failure — the board beside this says which collectors are attached."
              : "This host sent no per-minute buckets for today. Nothing is being drawn from the gap, and no collector state is inferred from it."}
          </p>
        </div>
      ) : (
        <Plot chart={chart} summary={summary} />
      )}

      <p className="mt-2 text-xs leading-5 text-slate-500">{summary}</p>
    </div>
  );
}

function Plot({ chart, summary }: { chart: SensorChart; summary: string }) {
  const paths = stackedBandPaths(chart, PLOT_WIDTH, PLOT_HEIGHT);
  const ticks = chartHourTicks();
  const gridlines = [0.25, 0.5, 0.75];
  return (
    <figure className="mt-3 min-w-0">
      <svg
        viewBox={`0 0 ${PLOT_WIDTH} ${PLOT_HEIGHT}`}
        // Stretched to the container rather than letter-boxed: a day-long time
        // series is read left to right, and a fixed aspect ratio would leave it
        // an inch tall on a phone. Every stroke below carries
        // `vector-effect="non-scaling-stroke"` so the distortion never reaches
        // a line weight.
        className="h-48 w-full rounded-xl border border-slate-800 bg-slate-950 sm:h-64"
        role="img"
        aria-label={summary}
        preserveAspectRatio="none"
      >
        {gridlines.map((fraction) => (
          <line
            key={`h-${fraction}`}
            x1={0}
            y1={PLOT_HEIGHT * fraction}
            x2={PLOT_WIDTH}
            y2={PLOT_HEIGHT * fraction}
            stroke="#1e293b"
            strokeWidth={1}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {ticks.slice(1, -1).map((tick) => (
          <line
            key={`v-${tick.label}`}
            x1={PLOT_WIDTH * tick.fraction}
            y1={0}
            x2={PLOT_WIDTH * tick.fraction}
            y2={PLOT_HEIGHT}
            stroke="#1e293b"
            strokeWidth={1}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {paths.map((path) => (
          <g key={path.name}>
            <title>{path.name}</title>
            <path d={path.area} fill={path.color} fillOpacity={0.32} />
            <path d={path.line} fill="none" stroke={path.color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
          </g>
        ))}
      </svg>
      <div className="mt-1 flex justify-between text-[11px] tabular-nums text-slate-500" aria-hidden="true">
        {ticks.map((tick) => <span key={tick.label}>{tick.label}</span>)}
      </div>
      <figcaption className="mt-2 flex flex-wrap gap-x-3 gap-y-1.5">
        {chart.bands.map((band) => (
          <span key={band.name} className="inline-flex min-w-0 items-center gap-1.5 text-[11px] text-slate-600">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: band.color }} aria-hidden="true" />
            <span className="truncate font-medium text-slate-700" title={band.name}>{band.name}</span>
            <span className="tabular-nums text-slate-400">{band.total.toLocaleString()}</span>
          </span>
        ))}
      </figcaption>
    </figure>
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
