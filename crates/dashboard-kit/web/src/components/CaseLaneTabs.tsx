import type { KeyboardEvent } from "react";
import { CASE_LANES, everythingCount, type CaseLaneCounts } from "../api/lanes";
import { defaultCaseLane, EVERYTHING_COPY, LANE_COPY, LANE_WINDOW_PHRASE, type CaseLaneChoice } from "../lanes";
import { CASE_WINDOW_LABELS, CASE_WINDOWS, type CaseWindow } from "./CaseFilters";
import { useTechnicalDetail } from "./TechnicalDetail";
import { Glyph, laneGlyph } from "./icons";
import { formatCount } from "../presentation";
import { countWords } from "../readCount";
import { windowWords } from "../windows";

/**
 * The span beside a tab's count, short enough to sit in the badge: "1,298
 * cases · 7 days". A count with no span was how a reader compared 4 on the
 * Overview (7 days) with 2 here (24 hours) and read it as lost data.
 */
export const LANE_TAB_SPAN: Record<CaseWindow, string> = windowWords("short");

/**
 * What one case in each tab is, so a tab's count names its unit.
 *
 * The agent's Overview card counts COMMANDS, and its tab lists one case per
 * SESSION: with the unit said only aloud, the badge read "4 · 7 days" under
 * a card reading 7, and a reader took the two for one count that had lost
 * three ("Agent: 8, then 4"). A message is one case, and an attack or any
 * case in the whole list is a case.
 */
export const LANE_CASE_UNIT: Record<CaseLaneChoice, { one: string; many: string }> = {
  agent_messages: { one: "message", many: "messages" },
  agent_actions: { one: "session", many: "sessions" },
  server_attacks: { one: "case", many: "cases" },
  everything: { one: "case", many: "cases" },
};

/** What a screen may say one of a tab's counts is, in place of the lane's own unit. */
export type LaneUnit = { one: string; many: string };

/** A tab's count with its unit: "4 sessions", "1 message", "2,435 cases". */
export function laneTabCount(choice: CaseLaneChoice, count: number, unit: LaneUnit = LANE_CASE_UNIT[choice]): string {
  return `${formatCount(count)} ${count === 1 ? unit.one : unit.many}`;
}

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
export type LaneTabOptions = {
  /**
   * The tabs this screen offers, in its own order. Absent: the three lanes,
   * and Everything where the rule below allows it. A screen whose product has
   * no Everything list and no server lane (Community) passes only its own.
   */
  choices?: readonly CaseLaneChoice[];
  /**
   * The list's status filter, when the screen has one. With it, the plain
   * view offers Everything only while the list is narrowed to what is waiting
   * on a person: that is where the Overview's waiting link lands (every
   * lane's count), and once the reader releases the filter, Everything is the
   * raw telemetry this rule keeps behind the technical switch. Absent: the
   * rule is as it always was.
   */
  statusFilter?: string;
};

export function laneTabs(
  value: CaseLaneChoice,
  counts: CaseLaneCounts | undefined,
  technical: boolean,
  options: LaneTabOptions = {},
): CaseLaneTab[] {
  if (options.choices !== undefined) {
    return options.choices.map((choice) => {
      const count = choice === "everything" ? everythingCount(counts) : counts?.[choice];
      return {
        choice,
        label: choice === "everything" ? EVERYTHING_COPY.name : LANE_COPY[choice].name,
        ...(count === undefined ? {} : { count }),
        selected: value === choice,
      };
    });
  }
  const tabs: CaseLaneTab[] = CASE_LANES.map((lane) => ({
    choice: lane,
    label: LANE_COPY[lane].name,
    ...(counts?.[lane] === undefined ? {} : { count: counts[lane] }),
    selected: value === lane,
  }));
  const everythingOffered = options.statusFilter === undefined
    ? technical || value === "everything"
    : technical || (value === "everything" && options.statusFilter === "waiting");
  if (everythingOffered) {
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
 * The lane a plain viewer lands on when they release the waiting filter while
 * on Everything, or `undefined` when nothing needs to move.
 *
 * The Overview's waiting link opens Everything narrowed to what waits, because
 * the count it follows is every lane's. Released, that tab is the whole raw
 * list, telemetry included, which the plain view does not offer: the viewer is
 * taken to their own lane (`defaultCaseLane`) instead, and the screen says
 * where the rest is.
 */
export function laneAfterWaitingCleared(
  value: CaseLaneChoice,
  technical: boolean,
  remembered: CaseLaneChoice | undefined,
  counts: CaseLaneCounts | undefined,
): CaseLaneChoice | undefined {
  if (technical || value !== "everything") return undefined;
  const next = defaultCaseLane(remembered === "everything" ? undefined : remembered, counts);
  return next === "everything" ? "agent_actions" : next;
}

/** Said when a plain viewer is moved off Everything by `laneAfterWaitingCleared`. */
export const EVERYTHING_MOVED_NOTE =
  "Showing what your AI agent did. Every case, raw telemetry included, is under Show technical detail.";

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
 * cases", "What your AI agent did, 4 sessions", and with the span it was
 * counted over when the screen passed one: "Attacks on this server, 823
 * cases in the last 7 days".
 */
export function laneTabName(tab: Pick<CaseLaneTab, "choice" | "label" | "count">, window?: CaseWindow, unit?: LaneUnit, partial = false): string {
  if (tab.count === undefined) return tab.label;
  // A tab's count is a SAMPLE of a truncated read, never a floor (`readCount.ts`).
  const nouns = unit ?? LANE_CASE_UNIT[tab.choice];
  const counted = `${tab.label}, ${countWords(tab.count, !partial, "sample", "inline")} ${tab.count === 1 ? nouns.one : nouns.many}`;
  return window === undefined ? counted : `${counted} ${LANE_WINDOW_PHRASE[window]}`;
}

/** Said on a tab's count the host read only part of the window for. */
export const PARTIAL_COUNT = "Counted from the newest records: this number can fall as the oldest are dropped.";

export function laneTabId(choice: CaseLaneChoice): string {
  return `case-lane-tab-${choice}`;
}

/** The lane's glyph before its name; hidden from screen readers, the name says it. */
function TabGlyph({ choice }: { choice: CaseLaneChoice }) {
  const glyph = laneGlyph(choice);
  return glyph === undefined ? null : <Glyph name={glyph} className="h-4 w-4 opacity-80" />;
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
  intro = true,
  unitFor,
  partial = false,
  choices,
  statusFilter,
}: {
  /** See `LaneTabOptions.choices`. */
  choices?: readonly CaseLaneChoice[];
  /** See `LaneTabOptions.statusFilter`. */
  statusFilter?: string;
  value: CaseLaneChoice;
  counts?: CaseLaneCounts;
  onChange: (next: CaseLaneChoice) => void;
  /** The id of the list the tabs control, for `aria-controls`. */
  panelId?: string;
  /**
   * The span the counts cover. Printed beside every count with the count's
   * unit ("4 sessions · 7 days"), so a badge never reads as a number over no
   * span. Absent: badges as before, the number alone.
   *
   * Pass the window the SERVER echoed with the counts (`page.window`), never
   * the one the screen asked for: a server that did not honour `?window=`
   * sends no echo, and its counts cover no such span. Labelling them with the
   * dropdown's span would print "· 7 days" beside counts of every day.
   * `casePageCountLabel` reads the echo the same way.
   */
  window?: CaseWindow;
  /**
   * Changes the list's window from beside the tabs, where the counts it
   * changes are. Offered only with `window`: a picker with no value is a
   * control over nothing. The screen owns the request and the address bar.
   *
   * A screen that passes this must hide the filter form's own window select
   * (`CaseFiltersForm` with `hideWindow`), or it draws two controls named
   * "Time window" for one value, one applying at once and one on Apply.
   */
  onWindowChange?: (next: CaseWindow) => void;
  /**
   * Whether the row says what the open tab lists (`laneIntro`) under itself.
   * A screen that says it elsewhere, beside the lane's own numbers, passes
   * `false`, so the sentence is on screen once.
   */
  intro?: boolean;
  /**
   * What one of a tab's counts is, when the screen knows better than the
   * lane's default: every count "waiting" while the list shows only what
   * waits ("0 messages" read as data lost), or "cases" in a lane that holds
   * more than sessions. Absent, or `undefined` for a lane: its own unit.
   */
  unitFor?: (choice: CaseLaneChoice) => LaneUnit | undefined;
  /**
   * The counts come from a partial read: each badge says "~" before its
   * figure, with why in its title, as the lane's own card says its figure.
   */
  partial?: boolean;
}) {
  const [technical] = useTechnicalDetail();
  const tabs = laneTabs(value, counts, technical, {
    ...(choices === undefined ? {} : { choices }),
    ...(statusFilter === undefined ? {} : { statusFilter }),
  });
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
        {/* On a phone each tab is one full-width row, its name on the left and
            its badge whole on the right, so the widths line up and a badge
            never breaks mid-phrase. */}
        <div role="tablist" aria-label="Case lanes" className="flex w-full min-w-0 flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap">
          {tabs.map((tab) => {
            const unit = unitFor?.(tab.choice);
            return (
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
                aria-label={tab.count === undefined ? undefined : laneTabName(tab, window, unit, partial)}
                onClick={() => onChange(tab.choice)}
                onKeyDown={onKeyDown}
                className={`inline-flex w-full max-w-full items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left text-sm font-semibold transition-colors sm:w-auto sm:justify-start ${
                  tab.selected
                    ? "border-slate-900 bg-slate-900 text-white"
                    : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
                }`}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <TabGlyph choice={tab.choice} />
                  <span className="min-w-0 break-words">{tab.label}</span>
                </span>
                {tab.count !== undefined ? (
                  <span
                    aria-hidden="true"
                    title={partial ? PARTIAL_COUNT : undefined}
                    className={`shrink-0 whitespace-nowrap rounded-full px-2 py-0.5 text-xs tabular-nums ${tab.selected ? "bg-white/20 text-white" : "bg-slate-100 text-slate-700"}`}
                  >
                    {countWords(tab.count, !partial, "sample", "badge")}
                    {window === undefined ? null : ` ${tab.count === 1 ? (unit ?? LANE_CASE_UNIT[tab.choice]).one : (unit ?? LANE_CASE_UNIT[tab.choice]).many}`}
                    {window === undefined ? null : (
                      <span className="font-normal opacity-80"> · {LANE_TAB_SPAN[window]}</span>
                    )}
                  </span>
                ) : null}
              </button>
            );
          })}
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
      {intro ? <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{laneIntro(value)}</p> : null}
    </div>
  );
}
