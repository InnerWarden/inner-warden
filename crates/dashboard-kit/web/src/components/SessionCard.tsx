import { useEffect, useId, useState } from "react";
import type { ActionView, SessionView } from "../api";
import { formatTimestamp, humanizeToken } from "../presentation";
import { DecidedBy } from "./DecidedBy";
import { Outcome } from "./Outcome";
import { Verdict } from "./Verdict";

const INITIAL_ACTIONS = 5;
const ACTION_PAGE = 10;

/**
 * A heading a person can find themselves in.
 *
 * Session ids are UUIDs minted by whatever agent produced the run, and the card
 * used to print one as its title:
 *
 *   › 86498977-2bae-499e-a894-32344a661ed5   13225 actions
 *   › 0f1bdd7e-c08f-4678-b0c9-cdfea8c8af0d     519 actions
 *
 * Nothing there tells an operator which run is which, and the first of those is
 * the session they are sitting in. The graph stores no attributes on a session
 * node, so there is no agent name to print, but every action carries
 * `recorded_at_ms`, and WHEN a run happened is what a person actually navigates
 * by. The id stays on the card, in the secondary line, for correlating with a
 * log; it just stops being the headline.
 */
export function sessionHeading(s: SessionView): string {
  if (s.label === "local") return "Local session";
  const stamps = s.items
    .map((item) => item.recorded_at_ms)
    .filter((ms): ms is number => typeof ms === "number" && Number.isFinite(ms));
  if (stamps.length === 0) return "Agent session";
  const first = new Date(Math.min(...stamps));
  const last = new Date(Math.max(...stamps));
  const day = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });
  const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
  const sameDay = first.toDateString() === last.toDateString();
  return sameDay
    ? `Agent session, ${day.format(first)} ${time.format(first)} to ${time.format(last)}`
    : `Agent session, ${day.format(first)} to ${day.format(last)}`;
}

/** The id, kept reachable but no longer shouted. */
export function shortId(label: string): string {
  return label.length > 12 ? `${label.slice(0, 8)}...` : label;
}

/** One recorded session with a bounded, progressively disclosed action list. */
export function SessionCard({
  s,
  open,
  focused,
  onToggle,
  onFocus,
  onPick,
}: {
  s: SessionView;
  open: boolean;
  focused: boolean;
  onToggle: () => void;
  onFocus: () => void;
  onPick: (action: ActionView) => void;
}) {
  const [visibleActions, setVisibleActions] = useState(INITIAL_ACTIONS);
  const denyVerdicts = s.deny_verdicts ?? s.blocked;
  const reviewVerdicts = s.review_verdicts ?? s.review;
  const unknownVerdicts = s.unknown_verdicts ?? 0;
  const generatedId = useId();
  const panelId = `session-panel-${generatedId.replace(/:/g, "")}`;
  const visible = s.items.slice(0, visibleActions);
  const remaining = Math.max(0, s.items.length - visible.length);

  useEffect(() => setVisibleActions(INITIAL_ACTIONS), [s.id]);

  return (
    <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <header className="flex items-center gap-2 px-3 py-3 sm:px-4">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex min-w-0 flex-1 items-start gap-3 rounded-md text-left disabled:cursor-default"
          disabled={focused}
        >
          <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center text-slate-500 transition-transform ${open ? "rotate-90" : ""}`} aria-hidden="true">›</span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-semibold text-slate-950">{sessionHeading(s)}</span>
            <span className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500">
              <span>{s.commands} action{s.commands === 1 ? "" : "s"}</span>
              {s.label !== "local" && <span className="font-mono text-slate-400" title={s.label}>{shortId(s.label)}</span>}
              {denyVerdicts > 0 && <span className="font-medium text-red-700">{denyVerdicts} deny verdict{denyVerdicts === 1 ? "" : "s"}</span>}
              {reviewVerdicts > 0 && <span className="font-medium text-amber-700">{reviewVerdicts} review</span>}
              {unknownVerdicts > 0 && <span className="font-medium text-slate-700">{unknownVerdicts} unknown</span>}
              {s.actual_blocks != null && s.actual_blocks > 0 && <span className="font-medium text-red-700">{s.actual_blocks} blocked</span>}
              {s.would_block != null && s.would_block > 0 && <span className="font-medium text-blue-700">{s.would_block} would block</span>}
            </span>
          </span>
        </button>
        {!focused && (
          <button
            type="button"
            onClick={onFocus}
            className="shrink-0 rounded-lg px-2.5 py-1.5 text-xs font-semibold text-cyan-800 hover:bg-cyan-50"
            aria-label={`Focus activity on ${s.label === "local" ? "local session" : s.label}`}
          >
            Focus
          </button>
        )}
      </header>

      {open && (
        <div id={panelId} className="border-t border-slate-100">
          {visible.length === 0 ? (
            <p className="px-4 py-4 text-sm text-slate-600">No actions are available for this session.</p>
          ) : (
            <ol className="divide-y divide-slate-100">
              {visible.map((action) => {
                const when = formatTimestamp(action.recorded_at_ms);
                return (
                  <li key={action.id ?? action.seq}>
                    <button
                      type="button"
                      onClick={() => onPick(action)}
                      className="group flex w-full items-start gap-3 px-3 py-3 text-left transition-colors hover:bg-slate-50 focus-visible:-outline-offset-2 sm:px-4"
                      aria-label={`Open decision details for action ${action.command}`}
                    >
                      <span className="mt-1 w-6 shrink-0 text-right text-[11px] tabular-nums text-slate-500" title={`Step ${action.seq}`}>#{action.seq}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Verdict rec={action.recommendation} />
                          <DecidedBy by={action.decided_by} />
                          <Outcome value={action.outcome ?? "unknown"} />
                        </div>
                        <code className="mt-2 block truncate text-sm font-medium text-slate-900">{action.command}</code>
                        {(action.categories.length > 0 || when) && (
                          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                            {action.categories.slice(0, 3).map((category) => (
                              <span key={category} className="max-w-full truncate rounded-full bg-slate-100 px-2 py-0.5 font-medium text-slate-600">{humanizeToken(category)}</span>
                            ))}
                            {action.categories.length > 3 && <span>+{action.categories.length - 3} more</span>}
                            {when && <span className="ml-auto">{when}</span>}
                          </div>
                        )}
                      </div>
                      <span className="mt-2 hidden shrink-0 text-xs font-semibold text-cyan-700 group-hover:text-cyan-900 sm:inline">Details →</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}

          {(remaining > 0 || s.truncated) && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 bg-slate-50/70 px-4 py-3 text-xs">
              {remaining > 0 ? (
                <span className="text-slate-600">{remaining} more action{remaining === 1 ? "" : "s"} loaded</span>
              ) : (
                <span className="text-slate-600">More actions exist on the server. Use search to narrow the session.</span>
              )}
              {remaining > 0 && (
                <button
                  type="button"
                  onClick={() => setVisibleActions((count) => Math.min(s.items.length, count + ACTION_PAGE))}
                  className="rounded-md px-2 py-1 font-semibold text-cyan-800 hover:bg-cyan-50"
                >
                  Show {Math.min(ACTION_PAGE, remaining)} more
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
