import type { KeyboardEvent } from "react";
import { CASE_LANES, everythingCount, type CaseLaneCounts } from "../api/lanes";
import { EVERYTHING_COPY, LANE_COPY, LANE_WINDOW_PHRASE, type CaseLaneChoice } from "../lanes";
import { CASE_WINDOW_LABELS, CASE_WINDOWS, type CaseWindow } from "./CaseFilters";
import { useTechnicalDetail } from "./TechnicalDetail";
import { formatCount } from "../presentation";

/**
 * The span beside a tab's count, short enough to sit in the badge: "1,298 ·
 * 7 days". A count with no span was how a reader compared 4 on the Overview
 * (7 days) with 2 here (24 hours) and read it as lost data.
 */
export const LANE_TAB_SPAN: Record<CaseWindow, string> = {
  "1h": "1 hour",
  "24h": "24 hours",
  "7d": "7 days",
  "30d": "30 days",
  all: "any day",
};

export type CaseLaneTab = {
  choice: CaseLaneChoice;
  label: string;
  /** The host's count for the lane, when it sent one. Never invented. */
  count?: number;
  selected: boolean;
};

/**
 * The tabs a Cases screen offers, in reading order.
 *
 * The three lanes always, each with the host's count when `lane_counts`
 * carried one; a lane the host did not count gets no badge rather than a zero.
 * "Everything" lists raw telemetry and response bookkeeping beside the lanes,
 * which is a technical view's question, so it is offered only there, or when
 * the address already opened it (a shared link must not land on a tab that is
 * not on screen). Its badge is the lanes and the cases in none added up, and
 * only when all four were counted.
 */
export function laneTabs(value: CaseLaneChoice, counts: CaseLaneCounts | undefined, technical: boolean): CaseLaneTab[] {
  const tabs: CaseLaneTab[] = CASE_LANES.map((lane) => ({
    choice: lane,
    label: LANE_COPY[lane].name,
    ...(counts?.[lane] === undefined ? {} : { count: counts[lane] }),
    selected: value === lane,
  }));
  if (technical || value === "everything") {
    const every = everythingCount(counts);
    tabs.push({
      choice: "everything",
      label: EVERYTHING_COPY.name,
      ...(every === undefined ? {} : { count: every }),
      selected: value === "everything",
    });
  }
  return tabs;
}

/**
 * Where the arrow keys, Home and End take the selection, per the tabs
 * pattern: arrows wrap around, Home and End go to the ends. Any other key
 * moves nothing.
 */
export function nextLaneTab(tabs: readonly CaseLaneTab[], current: CaseLaneChoice, key: string): CaseLaneChoice | undefined {
  if (tabs.length === 0) return undefined;
  const at = Math.max(0, tabs.findIndex((tab) => tab.choice === current));
  if (key === "ArrowRight") return tabs[(at + 1) % tabs.length].choice;
  if (key === "ArrowLeft") return tabs[(at - 1 + tabs.length) % tabs.length].choice;
  if (key === "Home") return tabs[0].choice;
  if (key === "End") return tabs[tabs.length - 1].choice;
  return undefined;
}

/** What the open tab lists, said once under the row. */
export function laneIntro(value: CaseLaneChoice): string {
  return value === "everything" ? EVERYTHING_COPY.intro : LANE_COPY[value].intro;
}

/**
 * What a tab with a count is called aloud: "Attacks on this server, 823
 * cases", and with the span it was counted over when the screen passed one:
 * "Attacks on this server, 823 cases in the last 7 days".
 */
export function laneTabName(tab: Pick<CaseLaneTab, "label" | "count">, window?: CaseWindow): string {
  if (tab.count === undefined) return tab.label;
  const counted = `${tab.label}, ${formatCount(tab.count)} ${tab.count === 1 ? "case" : "cases"}`;
  return window === undefined ? counted : `${counted} ${LANE_WINDOW_PHRASE[window]}`;
}

export function laneTabId(choice: CaseLaneChoice): string {
  return `case-lane-tab-${choice}`;
}

/**
 * The lane tabs on a Cases screen.
 *
 * Offer them only when the list answer says the lane was served
 * (`lane_filter.served`): that is the request the host answered carrying the
 * lane. A host older than lanes lists every case under one heading, as it
 * always did (`served: false`), and a tab row over that list would claim a
 * filter nothing applied. Whether `lane_counts` came back is NOT the sign:
 * the counts cost the host a full read, so a lane is polled without them
 * and keeps its tabs, with the badges from the last answer that had them.
 *
 * The screen owns the choice and the request; this draws the row, says what
 * the open tab lists, and moves the selection with the keyboard.
 */
export function CaseLaneTabs({
  value,
  counts,
  onChange,
  panelId,
  window,
  onWindowChange,
}: {
  value: CaseLaneChoice;
  counts?: CaseLaneCounts;
  onChange: (next: CaseLaneChoice) => void;
  /** The id of the list the tabs control, for `aria-controls`. */
  panelId?: string;
  /**
   * The span the counts cover, the list's own window. Printed beside every
   * count, so a badge never reads as a number over no span. Absent: badges as
   * before.
   */
  window?: CaseWindow;
  /**
   * Changes the list's window from beside the tabs, where the counts it
   * changes are. Offered only with `window`: a picker with no value is a
   * control over nothing. The screen owns the request and the address bar.
   */
  onWindowChange?: (next: CaseWindow) => void;
}) {
  const [technical] = useTechnicalDetail();
  const tabs = laneTabs(value, counts, technical);
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const next = nextLaneTab(tabs, value, event.key);
    if (next === undefined) return;
    event.preventDefault();
    onChange(next);
    // Focus follows the selection, as the tabs pattern expects. The button
    // exists already: every tab is rendered whichever one is selected.
    document.getElementById(laneTabId(next))?.focus();
  };
  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div role="tablist" aria-label="Case lanes" className="flex min-w-0 flex-wrap gap-2">
          {tabs.map((tab) => (
            <button
              key={tab.choice}
              id={laneTabId(tab.choice)}
              type="button"
              role="tab"
              aria-selected={tab.selected}
              aria-controls={panelId}
              tabIndex={tab.selected ? 0 : -1}
              data-lane={tab.choice}
              // The badge is a number on its own; said aloud it needs its noun.
              aria-label={tab.count === undefined ? undefined : laneTabName(tab, window)}
              onClick={() => onChange(tab.choice)}
              onKeyDown={onKeyDown}
              className={`inline-flex max-w-full items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm font-semibold transition-colors ${
                tab.selected
                  ? "border-slate-900 bg-slate-900 text-white"
                  : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
              }`}
            >
              <span className="min-w-0 break-words">{tab.label}</span>
              {tab.count !== undefined ? (
                <span
                  aria-hidden="true"
                  className={`rounded-full px-2 py-0.5 text-xs tabular-nums ${tab.selected ? "bg-white/20 text-white" : "bg-slate-100 text-slate-700"}`}
                >
                  {formatCount(tab.count)}
                  {window === undefined ? null : (
                    <span className="font-normal opacity-80"> · {LANE_TAB_SPAN[window]}</span>
                  )}
                </span>
              ) : null}
            </button>
          ))}
        </div>
        {window !== undefined && onWindowChange !== undefined ? (
          <label className="inline-flex items-center gap-2 text-xs font-semibold text-slate-700">
            Time window
            <select
              value={window}
              onChange={(event) => onWindowChange(event.target.value as CaseWindow)}
              className="rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-sm font-normal text-slate-950"
            >
              {CASE_WINDOWS.map((span) => <option key={span} value={span}>{CASE_WINDOW_LABELS[span]}</option>)}
            </select>
          </label>
        ) : null}
      </div>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{laneIntro(value)}</p>
    </div>
  );
}
