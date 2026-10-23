import type { PlanView } from "../plan";
import { formatClock, formatDay } from "../presentation";
import { CopyIdButton } from "./TruncatedId";

/**
 * The shell's notice about the host's licence (`plan.ts`). The sentence and
 * the step are the host's, printed as sent; the kit adds only the title, the
 * dates, "Next step:" and "Hide". Free mode cannot be hidden, and "Hide" is
 * kept in memory only, so a reload shows the notice again.
 *
 * Every class here is one a shared file already uses, so the notice adds
 * nothing to the stylesheet a composing build ships (`npm run css:shared`):
 * the amber box is the stale snapshot box from `CapabilityBoundary.tsx`.
 * Kept small on purpose, because it ships in every composing bundle.
 */
export function PlanNotice({ view, onHide }: { view: PlanView; onHide?: () => void }) {
  if (view.kind === "none") return null;
  const notice = view.kind === "renewed" ? undefined : view.notice;
  const title = view.kind === "renewed"
    ? `Licence valid again, read at ${formatClock(view.readAt)}.`
    : view.kind === "free_mode"
      ? view.notice.since === undefined ? "Free mode" : `Free mode since ${formatDay(view.notice.since)}`
      : view.notice.until === undefined ? "The licence ends soon" : `The licence ends on ${formatDay(view.notice.until)}`;
  return (
    <section
      data-plan-notice
      data-plan-state={view.kind}
      role="status"
      aria-labelledby="plan-notice-title"
      className={`rounded-xl border px-4 py-3 ${notice === undefined ? "border-slate-200 bg-slate-50" : "border-amber-200 bg-amber-50 text-amber-950"}`}
    >
      <p id="plan-notice-title" className="font-semibold">{title}</p>
      <p className="mt-0.5 text-sm">
        {notice === undefined ? "Each control shows its own state on Protection." : notice.line}
        {notice?.step !== undefined && (
          <> Next step: <code className="break-all font-mono">{notice.step}</code> <CopyIdButton value={notice.step} label="command" /></>
        )}
      </p>
      {view.kind !== "free_mode" && onHide && <button type="button" onClick={onHide} className="mt-3 text-sm font-semibold underline">Hide</button>}
    </section>
  );
}
