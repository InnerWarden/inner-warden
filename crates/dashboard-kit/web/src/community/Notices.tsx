import type { DashboardMeta } from "../api";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { formatCount } from "../presentation";
import { fetchRecordHealth, type RecordHealth } from "./api";
import { usePolled } from "./poll";

/** How often every page re-asks whether decisions are being recorded. */
export const RECORD_HEALTH_POLL_MS = 30_000;

/**
 * The notices at the top of every Community page, in both views, in order of
 * what matters: the dashboard is open to the network (rose: a bad thing that
 * is true right now), decisions are not being recorded (amber: a person has
 * to fix it), a newer InnerWarden is installed (slate: nothing is wrong).
 */
export function Notices({ meta, health }: { meta?: DashboardMeta; health?: RecordHealth }) {
  const exposed = meta?.exposed === true;
  const outage = health !== undefined && !health.recording;
  const update = meta?.update_pending === true && typeof meta.update_note === "string" && meta.update_note.trim().length > 0;
  if (!exposed && !outage && !update) return null;
  return (
    <div className="space-y-3">
      {exposed ? (
        <div role="alert" data-exposed="" className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm leading-6 text-rose-900">
          <p className="font-semibold">This dashboard is open to the network with no sign-in.</p>
          <p>
            Anyone who can reach this machine can read your agents' commands. Restart it without{" "}
            <code className="font-mono">--bind</code> to keep it on this machine.
          </p>
        </div>
      ) : null}
      {outage ? (
        <div role="alert" data-needs-you="" data-notice="recording" className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-900">
          <p className="font-semibold">
            InnerWarden is not recording decisions
            {health.sinceUnix === undefined ? null : (
              <>
                {" since "}
                <When at={health.sinceUnix * 1_000} />
              </>
            )}
            {health.lostActions === undefined ? "." : `: ${formatCount(health.lostActions)} ${health.lostActions === 1 ? "action was" : "actions were"} not recorded.`}
          </p>
          <p>
            The guard still screens every command; this dashboard cannot show what was not written down.{" "}
            <code className="font-mono">innerwarden status</code> says why.
          </p>
          {health.summary === undefined ? null : (
            <TechnicalOnly>
              <p className="mt-1 break-words text-xs [overflow-wrap:anywhere]">{health.summary}</p>
            </TechnicalOnly>
          )}
        </div>
      ) : null}
      {update ? (
        <div role="status" data-notice="update" className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm leading-6 text-slate-700">
          <span aria-hidden="true" className="mr-2 font-bold text-slate-500">i</span>
          {meta.update_note}
        </div>
      ) : null}
    </div>
  );
}

/** The notices, with the record's health polled for them. */
export function PageNotices({ meta }: { meta?: DashboardMeta }) {
  const health = usePolled(fetchRecordHealth, RECORD_HEALTH_POLL_MS, "record-health");
  return <Notices meta={meta} health={health.data} />;
}
