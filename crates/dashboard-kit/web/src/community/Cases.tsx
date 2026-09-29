import { useEffect, useRef, useState, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import { OutcomeBreakdown, outcomeTone } from "../components/LaneCards";
import { CaseLaneTabs } from "../components/CaseLaneTabs";
import { casePageCountLabel } from "../components/casePageCount";
import { Bar, type Part } from "../components/viz";
import type { LanePart } from "../lanes";
import { formatCount, formatDay } from "../presentation";
import {
  fetchAttempts,
  fetchDecision,
  fetchDecisions,
  fetchHistory,
  NOT_IN_RECORD,
  type Decision,
  type DecisionsPage,
  type DecisionsQuery,
  type Reason,
} from "./api";
import { CaseDetail, CaseGuide, MessageDetail } from "./CaseDetail";
import { CaseRow, MessageRow } from "./CaseRow";
import { CARD, Eyebrow, PageHeader, Skeleton, StaleLine, Unreadable } from "./parts";
import { usePolled } from "./poll";
import { rowRuns, runHolds, type Run } from "./rows";
import { asPlatform, DECISION_OUTCOMES, OUTCOME_WORDS, type DecisionOutcomeKey } from "./words";

export const CASES_POLL_MS = 10_000;
export const MESSAGES_POLL_MS = 30_000;
const PARAM_MAX = 256;
const REASONS_OPEN = 4;

/** The outcomes a person can filter the list by, in the bar's order. */
const OUTCOME_FILTERS: DecisionOutcomeKey[] = [
  "would_have_refused",
  "flagged_ran",
  "refused_before_run",
  "unsafe_may_have_run",
  "checked_only",
];

type CasesParams = {
  lane: "agent_actions" | "agent_messages";
  open?: string;
  query: DecisionsQuery;
};

function bounded(value: string | null): string | undefined {
  return value !== null && value.length > 0 && value.length <= PARAM_MAX ? value : undefined;
}

/** The Cases screen's state, read from the address, so a reload or a shared link lands on the same list. */
export function casesParams(search: string): CasesParams {
  const params = new URLSearchParams(search);
  const outcome = bounded(params.get("outcome"));
  return {
    lane: params.get("lane") === "agent_messages" ? "agent_messages" : "agent_actions",
    ...(bounded(params.get("decision")) === undefined ? {} : { open: bounded(params.get("decision")) }),
    query: {
      ...(outcome !== undefined && (DECISION_OUTCOMES as readonly string[]).includes(outcome) ? { outcome } : {}),
      ...(bounded(params.get("reason")) === undefined ? {} : { reason: bounded(params.get("reason")) }),
      ...(bounded(params.get("session")) === undefined ? {} : { session: bounded(params.get("session")) }),
      ...(bounded(params.get("q")) === undefined ? {} : { q: bounded(params.get("q")) }),
      ...(bounded(params.get("cursor")) === undefined ? {} : { cursor: bounded(params.get("cursor")) }),
    },
  };
}

function toParams(state: CasesParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (state.lane === "agent_messages") out.lane = "agent_messages";
  if (state.open !== undefined) out.decision = state.open;
  for (const [key, value] of Object.entries(state.query)) {
    if (typeof value === "string" && value.length > 0) out[key] = value;
  }
  return out;
}

/** The outcome split of the matching set, as lane parts, or nothing when it does not add up. */
export function outcomeParts(page: Pick<DecisionsPage, "byOutcome" | "total">, filtered: boolean): LanePart[] | undefined {
  const parts = DECISION_OUTCOMES.flatMap((key) => {
    const count = page.byOutcome[key] ?? 0;
    return count > 0 ? [{ key, count, label: OUTCOME_WORDS[key] }] : [];
  });
  const sum = parts.reduce((total, part) => total + part.count, 0);
  if (parts.length === 0) return undefined;
  // With an outcome filter the bar counts every outcome and the figure only
  // one, so the two are not the same sum and the bar is still honest.
  return filtered || sum === page.total ? parts : undefined;
}

/**
 * Community's Cases: one case per command or tool call the guard flagged,
 * listed newest first beside the open case, like the paid Cases.
 */
export function CommunityCases({ context }: { context: CommunityScreenContext }) {
  const state = casesParams(context.search);
  const history = usePolled(fetchHistory, 60_000, "history");
  const messagesOffered = (history.data?.messages.recorded ?? 0) > 0 || state.lane === "agent_messages";
  const go = (next: CasesParams) => context.navigate("activity", toParams(next));
  const os = asPlatform(context.bootstrap?.platform.os);
  const installed = context.meta?.active_defence_installed === true;
  const refreshRef = useRef<() => void>(() => undefined);

  return (
    <div className="min-w-0 space-y-5">
      <PageHeader
        eyebrow="Investigate"
        title="Cases"
        titleId="cases-title"
        tour="activity"
        description="Every command or tool call the guard flagged: who asked, what was decided, and what you can do."
        aside={
          <button
            type="button"
            onClick={() => refreshRef.current()}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-semibold text-slate-800 hover:bg-slate-50"
          >
            Refresh cases
          </button>
        }
      />
      {messagesOffered ? (
        <CaseLaneTabs
          value={state.lane}
          choices={["agent_actions", "agent_messages"]}
          counts={{
            ...(history.data === undefined ? {} : { agent_messages: history.data.messages.recorded }),
          }}
          unitFor={(choice) => (choice === "agent_actions" ? { one: "case", many: "cases" } : undefined)}
          intro={false}
          panelId="cases-panel"
          onChange={(lane) => go({ lane: lane === "agent_messages" ? "agent_messages" : "agent_actions", query: {} })}
        />
      ) : null}
      <div id="cases-panel">
        {state.lane === "agent_messages" ? (
          <MessagesLane state={state} go={go} os={os} installed={installed} refreshRef={refreshRef} />
        ) : (
          <ActionsLane state={state} go={go} os={os} installed={installed} refreshRef={refreshRef} />
        )}
      </div>
    </div>
  );
}

type LaneProps = {
  state: CasesParams;
  go: (next: CasesParams) => void;
  os: ReturnType<typeof asPlatform>;
  installed: boolean;
  refreshRef: { current: () => void };
};

/** The list and the open case, side by side at `lg`; one above the other below it. */
function Layout({ list, detail, openId, count }: { list: ReactNode; detail: ReactNode; openId?: string; count: number }) {
  const open = openId !== undefined;
  const [listShown, setListShown] = useState(false);
  const column = useRef<HTMLDivElement>(null);
  useEffect(() => setListShown(false), [open]);
  // Beside the case, the list scrolls inside its own column: bring the open
  // row into that column's view (a deep link can open the 20th row), without
  // moving the page, which would take the case's title off the screen.
  useEffect(() => {
    const box = column.current;
    if (box === null || openId === undefined || box.scrollHeight <= box.clientHeight) return;
    const row = box.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(openId)}"]`);
    if (row === null) return;
    const top = row.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
    if (top < box.scrollTop || top + row.offsetHeight > box.scrollTop + box.clientHeight) {
      box.scrollTop = Math.max(0, top - box.clientHeight / 3);
    }
  }, [openId, count]);
  return (
    <div className="grid items-start gap-5 lg:grid-cols-[minmax(17rem,0.78fr)_minmax(0,1.72fr)]">
      <div ref={column} className="min-w-0 lg:sticky lg:top-4 lg:max-h-[calc(100dvh-2rem)] lg:overflow-y-auto lg:overscroll-contain">
        {open && !listShown ? (
          <button
            type="button"
            onClick={() => setListShown(true)}
            className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-left text-sm font-semibold text-cyan-700 shadow-sm lg:hidden"
          >
            Show the list ({formatCount(count)} {count === 1 ? "case" : "cases"} on this page)
          </button>
        ) : null}
        <div className={open && !listShown ? "hidden lg:block" : undefined}>{list}</div>
      </div>
      <div className="min-w-0">{detail}</div>
    </div>
  );
}

function ActionsLane({ state, go, os, installed, refreshRef }: LaneProps) {
  const query = state.query;
  const key = JSON.stringify(query);
  const page = usePolled(() => fetchDecisions(query), query.cursor === undefined ? CASES_POLL_MS : 0, key);
  const open = state.open;
  const detail = usePolled(() => (open === undefined ? Promise.resolve(undefined) : fetchDecision(open)), 0, open ?? "");
  refreshRef.current = () => {
    page.refresh();
    detail.refresh();
  };
  const items = page.data?.items ?? [];
  const at = open === undefined ? -1 : items.findIndex((item) => item.id === open);
  const openItem = (id: string) => go({ ...state, open: id });
  const move = (delta: number) => {
    const next = items[(at === -1 ? 0 : at + delta)];
    if (next !== undefined) {
      openItem(next.id);
      requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(next.id)}"]`)?.focus());
    }
  };
  const filtered = query.outcome !== undefined || query.reason !== undefined || query.q !== undefined || query.session !== undefined;

  const list = (
    <div className="min-w-0 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      {page.data === undefined ? (
        page.error === undefined ? (
          <div className="p-4"><Skeleton className="h-64 border-0" /></div>
        ) : (
          <div className="p-4">
            <Unreadable title="The decision record could not be read" body="innerwarden status says why." onRetry={page.refresh} />
          </div>
        )
      ) : (
        <>
          <FlaggedSummary page={page.data} filtered={filtered} query={query} onReason={(reason) => go({ ...state, open: undefined, query: { ...query, cursor: undefined, reason } })} />
          <ListControls
            page={page.data}
            query={query}
            visible={items.length}
            onQuery={(next) => go({ ...state, open: undefined, query: next })}
          />
          {page.stale ? <div className="px-4 pt-2"><StaleLine onRetry={page.refresh} /></div> : null}
          <CaseList page={page.data} open={open} onOpen={openItem} onMove={move} filtered={filtered} onClear={() => go({ lane: "agent_actions", query: {} })} />
          <Pager
            atStart={query.cursor === undefined}
            next={page.data.nextCursor}
            onNewest={() => go({ ...state, open: undefined, query: { ...query, cursor: undefined } })}
            onOlder={(cursor) => go({ ...state, open: undefined, query: { ...query, cursor } })}
          />
        </>
      )}
    </div>
  );

  let pane: ReactNode = <CaseGuide />;
  if (open !== undefined) {
    if (detail.data === NOT_IN_RECORD) {
      pane = (
        <section aria-labelledby="case-title" className={CARD}>
          <h2 id="case-title" className="text-lg font-semibold text-slate-950">This case is no longer in the record</h2>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            <span aria-hidden="true" className="mr-1 inline-flex h-4 w-4 items-center justify-center rounded-full border border-slate-400 text-[10px] font-bold text-slate-500">?</span>
            InnerWarden keeps the newest decisions, and this one has been dropped.
          </p>
        </section>
      );
    } else if (detail.data !== undefined) {
      const found = detail.data;
      pane = (
        <CaseDetail
          item={found.item}
          before={found.before}
          after={found.after}
          session={found.session}
          os={os}
          installed={installed}
          onNewer={at > 0 ? () => openItem(items[at - 1].id) : undefined}
          onOlder={at >= 0 && at < items.length - 1 ? () => openItem(items[at + 1].id) : undefined}
          onOpen={openItem}
          onSession={(session) => go({ lane: "agent_actions", open: found.item.id, query: { session } })}
        />
      );
    } else if (detail.error !== undefined) {
      pane = <Unreadable title="This case could not be read" onRetry={detail.refresh} />;
    } else {
      pane = <Skeleton className="h-96" />;
    }
  }

  return <Layout list={list} detail={pane} openId={open} count={items.length} />;
}

function FlaggedSummary({ page, filtered, query, onReason }: { page: DecisionsPage; filtered: boolean; query: DecisionsQuery; onReason: (reason: string | undefined) => void }) {
  const parts = outcomeParts(page, query.outcome !== undefined);
  const since = page.record.oldestAt === undefined ? undefined : formatDay(page.record.oldestAt);
  const top = page.reasons[0]?.count ?? 0;
  const [first, rest] = [page.reasons.slice(0, REASONS_OPEN), page.reasons.slice(REASONS_OPEN)];
  const hidden = page.reasonsDistinct - page.reasons.length;
  const mutes = page.suppress.muteRules + page.suppress.muteCategories;
  return (
    <section aria-labelledby="flagged-summary-title" className="border-b border-slate-200 p-4">
      <Eyebrow glyph="prompt" id="flagged-summary-title">What your AI agent did</Eyebrow>
      <p className="mt-2 flex flex-wrap items-baseline gap-x-1.5">
        {filtered ? (
          <>
            <span className="text-2xl font-semibold text-slate-950">{formatCount(page.total)}</span>{" "}
            <span className="text-sm text-slate-600">match · of {formatCount(page.flaggedTotal)} flagged</span>
          </>
        ) : (
          <>
            <span className="text-2xl font-semibold text-slate-950">{formatCount(page.flaggedTotal)}</span>{" "}
            <span className="text-sm text-slate-600">flagged{since === undefined ? "" : ` · since ${since}`}</span>
          </>
        )}
      </p>
      {parts === undefined ? null : (
        <OutcomeBreakdown parts={parts} label={`What happened to the ${formatCount(page.total)} flagged commands`} className="mt-3" />
      )}
      {page.reasons.length === 0 ? null : (
        <details className="group mt-4" open={typeof window === "undefined" || window.matchMedia?.("(min-width: 640px)").matches !== false}>
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
            Why they were flagged
          </summary>
          <ul className="mt-2 space-y-0.5">
            {first.map((reason) => <ReasonButton key={reason.key} reason={reason} top={top} active={query.reason === reason.key} onReason={onReason} />)}
          </ul>
          {rest.length === 0 ? null : (
            <details className="mt-1">
              <summary className="cursor-pointer text-xs font-semibold text-cyan-700">
                {rest.length + Math.max(0, hidden)} more {rest.length + Math.max(0, hidden) === 1 ? "reason" : "reasons"}
              </summary>
              <ul className="mt-1 space-y-0.5">
                {rest.map((reason) => <ReasonButton key={reason.key} reason={reason} top={top} active={query.reason === reason.key} onReason={onReason} />)}
              </ul>
              {hidden > 0 ? <p className="mt-1 text-xs text-slate-500">{formatCount(hidden)} rarer {hidden === 1 ? "reason is" : "reasons are"} not listed.</p> : null}
            </details>
          )}
        </details>
      )}
      {page.suppress.allow + mutes === 0 ? null : (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Your allow and mute list has {page.suppress.allow} {page.suppress.allow === 1 ? "pattern" : "patterns"} and {mutes} {mutes === 1 ? "rule" : "rules"}; commands they cover are not flagged.
        </p>
      )}
    </section>
  );
}

function ReasonButton({ reason, top, active, onReason }: { reason: Reason; top: number; active: boolean; onReason: (reason: string | undefined) => void }) {
  const parts: Part[] = [
    { key: "count", value: reason.count, tone: "watch", label: `${formatCount(reason.count)} flagged for this reason` },
    { key: "rest", value: Math.max(0, top - reason.count), tone: "off", label: "" },
  ];
  return (
    <li>
      <button
        type="button"
        aria-pressed={active}
        aria-label={`${reason.short}: ${formatCount(reason.count)} flagged`}
        onClick={() => onReason(active ? undefined : reason.key)}
        title={reason.words}
        className={`flex w-full min-w-0 items-center gap-2 rounded-md px-1.5 py-1 text-left text-xs ${active ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-50"}`}
      >
        <span className="w-10 shrink-0 text-right font-semibold tabular-nums">{formatCount(reason.count)}</span>
        <span className="w-24 shrink-0"><Bar parts={parts} label={`${formatCount(reason.count)} of ${formatCount(top)}`} className="h-1.5" /></span>
        <span className="min-w-0 flex-1 truncate">{reason.short}</span>
      </button>
    </li>
  );
}

function ListControls({ page, query, visible, onQuery }: { page: DecisionsPage; query: DecisionsQuery; visible: number; onQuery: (next: DecisionsQuery) => void }) {
  const [text, setText] = useState(query.q ?? "");
  useEffect(() => setText(query.q ?? ""), [query.q]);
  const any = query.outcome !== undefined || query.reason !== undefined || query.q !== undefined || query.session !== undefined;
  return (
    <div className="space-y-2 border-b border-slate-200 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-900">Case results</h2>
        <label className="text-xs text-slate-600">
          <span className="sr-only">Outcome</span>
          <select
            value={query.outcome ?? ""}
            onChange={(event) => onQuery({ ...query, cursor: undefined, outcome: event.target.value === "" ? undefined : event.target.value })}
            className="rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-sm font-normal text-slate-950"
          >
            <option value="">All outcomes</option>
            {OUTCOME_FILTERS.map((key) => <option key={key} value={key}>{OUTCOME_WORDS[key]}</option>)}
          </select>
        </label>
      </div>
      <form
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          onQuery({ ...query, cursor: undefined, q: text.trim() === "" ? undefined : text.trim().slice(0, PARAM_MAX) });
        }}
        className="flex gap-2"
      >
        <input
          type="search"
          value={text}
          onChange={(event) => setText(event.target.value)}
          aria-label="Search flagged commands"
          placeholder="Search flagged commands"
          className="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-950"
        />
        <button type="submit" className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-semibold text-slate-800 hover:bg-slate-50">Search</button>
      </form>
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span data-count-line>{casePageCountLabel(visible, { rows_in_window: page.total })}</span>
        {any ? <button type="button" onClick={() => onQuery({})} className="font-semibold text-cyan-700 hover:text-cyan-900">Clear filters</button> : null}
      </div>
      {query.session === undefined ? null : <p className="text-xs text-slate-600">Only the session {query.session.slice(0, 8)}.</p>}
    </div>
  );
}

function CaseList({
  page,
  open,
  onOpen,
  onMove,
  filtered,
  onClear,
}: {
  page: DecisionsPage;
  open?: string;
  onOpen: (id: string) => void;
  onMove: (delta: number) => void;
  filtered: boolean;
  onClear: () => void;
}) {
  if (page.items.length === 0) {
    return (
      <div className="px-4 py-6 text-sm leading-6 text-slate-600">
        {filtered ? (
          <>
            <p>No flagged command matches these filters.</p>
            <button type="button" onClick={onClear} className="mt-1 font-semibold text-cyan-700 hover:text-cyan-900">Clear filters</button>
          </>
        ) : page.record.decisions === 0 ? (
          <p>Nothing recorded yet. Connect an agent and its commands appear here.</p>
        ) : (
          <p>
            Nothing flagged{page.record.oldestAt === undefined ? "" : ` since ${formatDay(page.record.oldestAt)}`}. {formatCount(page.record.decisions)}{" "}
            {page.record.decisions === 1 ? "command was" : "commands were"} screened and allowed.
          </p>
        )}
      </div>
    );
  }
  const runs = rowRuns(page.items);
  return (
    <ul className="divide-y divide-slate-100">
      {runs.map((run) => <RunRows key={run.first.id} run={run} open={open} onOpen={onOpen} onMove={onMove} />)}
    </ul>
  );
}

function RunRows({ run, open, onOpen, onMove }: { run: Run<Decision>; open?: string; onOpen: (id: string) => void; onMove: (delta: number) => void }) {
  const holds = runHolds(run, open);
  const [expanded, setExpanded] = useState(false);
  const shown = expanded || holds;
  const id = `stack-${run.first.id}`;
  const parts: Part[] = DECISION_OUTCOMES.flatMap((key) => {
    const count = run.folded.filter((item) => item.outcomeKey === key).length;
    return count > 0 ? [{ key, value: count, label: `${OUTCOME_WORDS[key]}: ${count}`, ...outcomeTone(key) }] : [];
  });
  return (
    <>
      <CaseRow item={run.first} open={open === run.first.id} onOpen={onOpen} onMove={onMove} />
      {run.folded.length === 0 ? null : (
        <>
          <li className="flex items-center gap-3 border-l-2 border-dashed border-slate-300 bg-slate-50 py-2 pl-8 pr-4 text-xs text-slate-600">
            <span className="min-w-0 flex-1">
              <span className="block">{formatCount(run.folded.length)} more in a row, flagged for the same reason</span>
              <span className="mt-1 block w-24"><Bar parts={parts} label={`What happened to the ${run.folded.length} folded commands`} className="h-1.5" /></span>
            </span>
            <button
              type="button"
              aria-expanded={shown}
              aria-controls={id}
              disabled={holds}
              onClick={() => setExpanded((value) => !value)}
              className="shrink-0 font-semibold text-cyan-700 hover:text-cyan-900 disabled:opacity-40"
            >
              {shown ? "Hide" : "Show"}
            </button>
          </li>
          {shown ? (
            <li id={id}>
              <ul className="divide-y divide-slate-100">
                {run.folded.map((item) => <CaseRow key={item.id} item={item} open={open === item.id} onOpen={onOpen} onMove={onMove} />)}
              </ul>
            </li>
          ) : null}
        </>
      )}
    </>
  );
}

function Pager({ atStart, next, onNewest, onOlder }: { atStart: boolean; next?: string; onNewest: () => void; onOlder: (cursor: string) => void }) {
  if (atStart && next === undefined) return null;
  return (
    <div className="flex items-center justify-between gap-2 border-t border-slate-200 px-4 py-3 text-sm">
      <button type="button" onClick={onNewest} disabled={atStart} className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-40">
        Newest
      </button>
      <button type="button" onClick={() => next !== undefined && onOlder(next)} disabled={next === undefined} className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-40">
        Older <span aria-hidden="true">→</span>
      </button>
    </div>
  );
}

function MessagesLane({ state, go, os, installed, refreshRef }: LaneProps) {
  const cursor = state.query.cursor;
  const page = usePolled(() => fetchAttempts(cursor), cursor === undefined ? MESSAGES_POLL_MS : 0, cursor ?? "");
  refreshRef.current = page.refresh;
  const items = page.data?.items ?? [];
  const open = state.open;
  const at = open === undefined ? -1 : items.findIndex((item) => item.id === open);
  const openItem = (id: string) => go({ ...state, open: id });
  const move = (delta: number) => {
    const next = items[at === -1 ? 0 : at + delta];
    if (next !== undefined) openItem(next.id);
  };
  const list = (
    <div className="min-w-0 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 p-4">
        <Eyebrow glyph="chat">Messages to your AI agent</Eyebrow>
        <p className="mt-2 flex flex-wrap items-baseline gap-x-1.5">
          <span className="text-2xl font-semibold text-slate-950">{formatCount(page.data?.total ?? 0)}</span>{" "}
          <span className="text-sm text-slate-600">recorded</span>
        </p>
        <p className="mt-1 text-xs leading-5 text-slate-500">Risky messages people sent your agent, one case each. Observe records them; it does not block them.</p>
      </div>
      {page.data === undefined ? (
        page.error === undefined ? <div className="p-4"><Skeleton className="h-40 border-0" /></div> : <div className="p-4"><Unreadable title="The event log could not be read" onRetry={page.refresh} /></div>
      ) : items.length === 0 ? (
        <p className="px-4 py-6 text-sm text-slate-600">No risky message has been recorded.</p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {items.map((item) => <MessageRow key={item.id} item={item} open={open === item.id} onOpen={openItem} onMove={move} />)}
        </ul>
      )}
      {page.data === undefined ? null : (
        <Pager
          atStart={cursor === undefined}
          next={page.data.nextCursor}
          onNewest={() => go({ ...state, open: undefined, query: {} })}
          onOlder={(next) => go({ ...state, open: undefined, query: { cursor: next } })}
        />
      )}
    </div>
  );
  const openItemData = at === -1 ? undefined : items[at];
  const pane = open === undefined
    ? <CaseGuide />
    : openItemData === undefined
      ? page.data === undefined ? <Skeleton className="h-96" /> : <Unreadable title="This message is not on this page of the list" body="Use Newest to go back to the start." />
      : <MessageDetail item={openItemData} os={os} installed={installed} />;
  return <Layout list={list} detail={pane} openId={open} count={items.length} />;
}
