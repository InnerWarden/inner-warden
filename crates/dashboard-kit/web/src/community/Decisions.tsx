import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import { CaseLaneTabs } from "../components/CaseLaneTabs";
import { casePageCountLabel } from "../components/casePageCount";
import { formatCount, normaliseMode } from "../presentation";
import {
  fetchAttempts,
  fetchDecision,
  fetchDecisions,
  fetchSessions,
  NOT_IN_RECORD,
  type Decision,
  type DecisionsPage,
  type DecisionsQuery,
  type Reason,
  type RecordSpan,
} from "./api";
import { factsOf } from "./agentsView";
import { DecisionDetail, DecisionGuide, MessageDetail, wideLayout } from "./DecisionDetail";
import { StaleLine } from "./parts";
import { usePolled, type Polled } from "./poll";
import { rowRuns, runHolds, type Run } from "./rows";
import { useSource } from "./store";
import { BODY_TEXT, Disclosure, LINK_TEXT, META_TEXT, NotRead, onPlainClick, PANEL, ReadAt, SMALL_TEXT, SourceLine } from "./ui/blocks";
import { Icon } from "./ui/Icon";
import { OutcomeMark } from "./ui/marks";
import { DecisionRow, MessageRow, ReasonOutcomes, SessionRow, worstOutcome } from "./ui/rows";
import { restartFor, type AgentRestart } from "./restart";
import { isConnected, spanWords } from "./verdict";
import { asPlatform, DECISION_OUTCOMES, OUTCOME_WORDS, shortSession, type DecisionOutcomeKey } from "./words";

export const DECISIONS_POLL_MS = 10_000;
export const MESSAGES_POLL_MS = 30_000;
export const SESSIONS_POLL_MS = 30_000;
/** The whole record's count and reasons: the lane tab, the source line and the reasons lens. */
export const FLAGGED_POLL_MS = 60_000;
/** Sessions the By session lens lists. */
export const SESSIONS_LISTED = 20;
/** Reasons drawn open in the By reason lens; the rest the CLI sent are one press away. */
export const REASONS_OPEN = 6;
/** Decisions an opened reason shows before "Show all N". */
export const REASON_PREVIEW = 5;
const PARAM_MAX = 256;

/** The three ways the list can be read. `newest` is the default and is never written to the address. */
export const LENSES = ["newest", "reason", "session"] as const;
export type Lens = (typeof LENSES)[number];
export const LENS_WORDS: Record<Lens, string> = { newest: "Newest first", reason: "By reason", session: "By session" };

/** The outcomes a person can filter the list by, in the bar's order. */
export const OUTCOME_FILTERS: readonly DecisionOutcomeKey[] = ["refused_before_run", "would_have_refused", "unsafe_may_have_run", "flagged_ran"];

/** Where the list was scrolled to when a decision was opened on a phone, and from which row. */
export const SCROLL_KEY = "iw-community-decisions-list";

export type DecisionsParams = {
  lane: "agent_actions" | "agent_messages";
  open?: string;
  lens: Lens;
  query: DecisionsQuery;
};

function bounded(value: string | null): string | undefined {
  return value !== null && value.length > 0 && value.length <= PARAM_MAX ? value : undefined;
}

/**
 * The Decisions screen's state, read from the address, so a reload or a
 * shared link lands on the same list. `hide` is a reason the reader hid from
 * the list: a view, never a setting (the guard keeps flagging it).
 */
export function decisionsParams(search: string): DecisionsParams {
  const params = new URLSearchParams(search);
  const outcome = bounded(params.get("outcome"));
  const lens = params.get("lens");
  return {
    lane: params.get("lane") === "agent_messages" ? "agent_messages" : "agent_actions",
    ...(bounded(params.get("decision")) === undefined ? {} : { open: bounded(params.get("decision")) }),
    lens: lens === "reason" || lens === "session" ? lens : "newest",
    query: {
      ...(outcome !== undefined && (DECISION_OUTCOMES as readonly string[]).includes(outcome) ? { outcome } : {}),
      ...(bounded(params.get("reason")) === undefined ? {} : { reason: bounded(params.get("reason")) }),
      ...(bounded(params.get("hide")) === undefined ? {} : { reasonNot: bounded(params.get("hide")) }),
      ...(bounded(params.get("session")) === undefined ? {} : { session: bounded(params.get("session")) }),
      ...(bounded(params.get("q")) === undefined ? {} : { q: bounded(params.get("q")) }),
      ...(bounded(params.get("cursor")) === undefined ? {} : { cursor: bounded(params.get("cursor")) }),
    },
  };
}

export function toParams(state: DecisionsParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (state.lane === "agent_messages") out.lane = "agent_messages";
  if (state.lens !== "newest" && state.lane === "agent_actions") out.lens = state.lens;
  if (state.open !== undefined) out.decision = state.open;
  for (const [key, value] of Object.entries(state.query)) {
    if (typeof value === "string" && value.length > 0) out[key === "reasonNot" ? "hide" : key] = value;
  }
  return out;
}

/** "Newest 96 decisions, about 4 days.": the record the list is read from. */
export function recordLine(record: RecordSpan, now: number): string | undefined {
  if (record.decisions === 0) return undefined;
  const span = record.oldestAt === undefined
    ? ""
    : `, ${spanWords(Date.parse(record.oldestAt), record.newestAt === undefined ? now : Date.parse(record.newestAt))}`;
  return `Newest ${formatCount(record.decisions)} ${record.decisions === 1 ? "decision" : "decisions"}${span}.`;
}

/** "25 Sept, 17:34" in the reader's own clock, built per call so it follows the zone the page runs in. */
function stamp(ms: number): string {
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
}

/**
 * What an empty list says, decided by the RECORD's counts, never by how many
 * rows were drawn: a page whose rows could not all be read must not say
 * "Nothing flagged".
 */
export function emptyListWords(page: Pick<DecisionsPage, "flaggedTotal" | "total" | "record">, filtered: boolean): string {
  if (filtered) return page.total === 0 ? "No decision matches these filters." : `${formatCount(page.total)} flagged could not be shown.`;
  if (page.flaggedTotal > 0) return `${formatCount(page.flaggedTotal)} flagged could not be shown.`;
  if (page.record.decisions === 0) return "Nothing recorded yet. Connect an agent and ask it to run something.";
  const from = page.record.oldestAt === undefined ? undefined : stamp(Date.parse(page.record.oldestAt));
  return `Nothing flagged in the record${from === undefined ? "" : ` (${from} to now)`}.`;
}

/** A filter the server would not take: its own code, never a silently dropped filter. */
export function filterCode(error: unknown): string | undefined {
  const message = error instanceof Error ? error.message : undefined;
  return message !== undefined && /^[a-z_]{1,40}_invalid$/.test(message) ? message : undefined;
}

function Pending({ className = "h-24" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-lg bg-(--iw-surface-2) ${className}`} />;
}

const QUIET_BUTTON = "inline-flex min-h-9 items-center gap-1 rounded-md border border-(--iw-line-strong) bg-(--iw-surface) px-3 text-sm font-semibold text-(--iw-ink-2) hover:bg-(--iw-surface-2) disabled:border-(--iw-line) disabled:text-(--iw-ink-3) pointer-coarse:min-h-11";

/**
 * Community's Decisions (spec 6.3): every command or tool call the guard
 * flagged, from the decision record, read newest first, by reason or by
 * session. At a desk the list flows with the page beside a sticky detail;
 * on a phone a decision opens in place, and "Back to decisions" returns to
 * the row it was opened from, where the list was.
 */
export function CommunityDecisions({ context }: { context: CommunityScreenContext }) {
  const state = decisionsParams(context.search);
  const history = useSource("history");
  const protection = useSource("protection");
  // The whole record: the agent tab's count, the source line and the reasons.
  const flagged = usePolled(() => fetchDecisions({ limit: 1 }), FLAGGED_POLL_MS, "flagged-count");
  const messagesOffered = protection.data?.observe.available === true || (history.data?.messages.recorded ?? 0) > 0 || state.lane === "agent_messages";
  const go = (next: DecisionsParams) => context.navigate("activity", toParams(next));
  const messages = state.lane === "agent_messages";
  const record = flagged.data?.record;
  const line = record === undefined ? undefined : recordLine(record, Date.now());

  const header = (
    <div className="min-w-0 space-y-4">
      <div data-tour="activity" className="space-y-1">
        <h1 id="decisions-title" tabIndex={-1} className="text-2xl leading-[30px] font-semibold tracking-tight text-(--iw-ink)">Decisions</h1>
        <p className={BODY_TEXT}>
          {messages
            ? "Risky messages people sent your agent, from the guard's log: what was asked, who decided, and what you can do."
            : "Every command or tool call the guard flagged, from the decision record."}
        </p>
        {messages || line === undefined ? null : (
          <SourceLine>
            {line}
            {record?.capped === true ? " Older ones are dropped as new ones arrive." : null}
          </SourceLine>
        )}
      </div>
      {messagesOffered ? (
        <CaseLaneTabs
          value={state.lane}
          choices={["agent_actions", "agent_messages"]}
          counts={{
            ...(flagged.data === undefined ? {} : { agent_actions: flagged.data.flaggedTotal }),
            ...(history.data === undefined || !history.data.readable ? {} : { agent_messages: history.data.messages.recorded }),
          }}
          unitFor={(choice) => (choice === "agent_actions" ? { one: "decision", many: "decisions" } : undefined)}
          intro={false}
          panelId="decisions-panel"
          onChange={(lane) => go({ lane: lane === "agent_messages" ? "agent_messages" : "agent_actions", lens: "newest", query: {} })}
        />
      ) : null}
    </div>
  );

  return messages ? (
    <MessagesLane header={header} state={state} go={go} hostMode={normaliseMode(context.meta)} since={history.data?.readable ? history.data.since : undefined} />
  ) : (
    <ActionsLane header={header} state={state} go={go} flagged={flagged.data} context={context} />
  );
}

type Go = (next: DecisionsParams) => void;

/**
 * The phone's back-and-forth between the list and one decision: where the
 * list was scrolled to and which row opened it, kept in `sessionStorage`
 * (a convenience: wrapped, and the page works without it), restored when
 * the list comes back, with focus on that row.
 */
function rememberList(id: string) {
  try {
    window.sessionStorage.setItem(SCROLL_KEY, JSON.stringify({ id, y: window.scrollY }));
  } catch {
    // No storage here: back still works, from the top of the list.
  }
}

function recallList(): { id: string; y: number } | undefined {
  try {
    const raw = window.sessionStorage.getItem(SCROLL_KEY);
    if (raw === null) return undefined;
    window.sessionStorage.removeItem(SCROLL_KEY);
    const value = JSON.parse(raw) as { id?: unknown; y?: unknown };
    return typeof value.id === "string" && typeof value.y === "number" ? { id: value.id, y: value.y } : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Every connected agent's restart, from the shared agents source: a step
 * that switches every connected agent is followed by each one's words.
 * `undefined` while the agents were not read.
 */
function useConnectedRestarts(): AgentRestart[] | undefined {
  const agents = useSource("agents");
  const facts = factsOf(agents.data).facts;
  return facts?.agents.filter(isConnected).map((agent) => ({ agent: agent.name, words: restartFor(agent.id, agent.name, agent.restart) }));
}

/**
 * The list and the open decision: side by side at `lg`, the detail sticky;
 * below it the list alone, or the decision alone with a way back. With no
 * decision open at a desk the list takes the width and the guide is a short
 * aside, so a command shows as much of itself as it can.
 */
function Layout({
  header,
  list,
  detail,
  open,
  onBack,
}: {
  /** The page's heading and lane tabs: above the list, with the detail beside both at a desk. */
  header: ReactNode;
  list: ReactNode;
  detail: ReactNode;
  open?: string;
  onBack: () => void;
}) {
  const detailColumn = useRef<HTMLDivElement>(null);
  const previous = useRef<string | undefined>(open);
  useLayoutEffect(() => {
    const was = previous.current;
    previous.current = open;
    if (wideLayout()) return;
    if (open !== undefined && open !== was) {
      // A decision opened on a phone: it takes the page, from its top.
      detailColumn.current?.scrollIntoView({ block: "start" });
      return;
    }
    if (open === undefined && was !== undefined) {
      const back = recallList();
      if (back === undefined) return;
      window.scrollTo(0, back.y);
      document.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(back.id)}"]`)?.focus({ preventScroll: true });
    }
  }, [open]);
  // On a phone an open decision takes the page, and Escape goes back to the
  // list from anywhere on it: a decision opened from a link has not moved
  // focus into the detail (no focus move on a first load), and Escape still
  // works. Never while typing in a field.
  const back = useRef(onBack);
  back.current = onBack;
  useEffect(() => {
    if (open === undefined) return;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented || wideLayout()) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest("input, textarea, select, [contenteditable='true'], [role='dialog']")) return;
      event.preventDefault();
      back.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);
  const listSpan = open === undefined ? "lg:col-span-8" : "lg:col-span-5";
  const detailSpan = open === undefined ? "lg:col-span-4 lg:col-start-9" : "lg:col-span-7 lg:col-start-6";
  return (
    <div className="grid min-w-0 items-start gap-6 lg:grid-cols-12">
      <div className={`min-w-0 ${listSpan} lg:row-start-1`}>{header}</div>
      <div id="decisions-panel" className={`min-w-0 space-y-4 ${listSpan} lg:row-start-2 ${open === undefined ? "" : "hidden lg:block"}`}>{list}</div>
      <div
        ref={detailColumn}
        data-detail-column={open === undefined ? "guide" : "open"}
        className={`min-w-0 scroll-mt-4 lg:sticky lg:top-4 ${detailSpan} lg:row-span-2 lg:row-start-1 lg:max-h-[calc(100vh-2rem)] lg:overflow-y-auto ${open === undefined ? "hidden lg:block" : ""}`}
      >
        {open === undefined ? null : (
          <button type="button" onClick={onBack} className={`mb-3 inline-flex min-h-11 items-center gap-1 text-sm lg:hidden ${LINK_TEXT}`}>
            <span aria-hidden="true">←</span> Back to decisions
          </button>
        )}
        {detail}
      </div>
    </div>
  );
}

/** Back from a decision: the list it was opened from when that is the page before, otherwise the list without it. */
function useBack(state: DecisionsParams, go: Go) {
  const openedHere = useRef<string | undefined>(undefined);
  const open = (id: string) => {
    if (!wideLayout()) rememberList(id);
    openedHere.current = id;
    go({ ...state, open: id });
  };
  const back = () => {
    if (openedHere.current !== undefined && openedHere.current === state.open) {
      openedHere.current = undefined;
      window.history.back();
      return;
    }
    go({ ...state, open: undefined });
  };
  return { open, back };
}

function ActionsLane({
  header,
  state,
  go,
  flagged,
  context,
}: {
  header: ReactNode;
  state: DecisionsParams;
  go: Go;
  flagged?: DecisionsPage;
  context: CommunityScreenContext;
}) {
  // Whether this InnerWarden lists sessions at all: an older one answers 404,
  // and then the lens is not offered.
  const probe = usePolled(() => fetchSessions(1), 0, "sessions-probe");
  const sessionsServed = probe.data?.supported !== false;
  const lens: Lens = state.lens === "session" && !sessionsServed ? "newest" : state.lens;
  const shown: readonly Lens[] = sessionsServed ? LENSES : LENSES.filter((candidate) => candidate !== "session");
  const { open: openRow, back } = useBack(state, go);
  const restarts = useConnectedRestarts();
  // Whether the next decision drawn takes focus: only one the person opened
  // (a click, Enter, Newer, Older), never one the arrow keys moved to, so
  // the arrows keep working on the list, and never a first load.
  const focusDetail = useRef(false);
  const open = (id: string) => {
    focusDetail.current = true;
    openRow(id);
  };
  const detail = usePolled(() => (state.open === undefined ? Promise.resolve(undefined) : fetchDecision(state.open)), 0, state.open ?? "");
  const query = state.query;
  // The newest list is read only while it is the lens on screen: the other
  // two read their own sources, and nothing polls a list no one sees.
  const newest = lens === "newest";
  const page = usePolled(
    () => (newest ? fetchDecisions(query) : Promise.resolve(undefined)),
    newest && query.cursor === undefined ? DECISIONS_POLL_MS : 0,
    newest ? JSON.stringify(query) : `lens:${lens}`,
  ) as Polled<DecisionsPage>;
  const items = newest ? (page.data?.items ?? []) : [];
  const at = state.open === undefined ? -1 : items.findIndex((item) => item.id === state.open);
  const os = asPlatform(context.bootstrap?.platform.os);
  const installed = context.meta?.active_defence_installed === true;
  const hideReason = (reasonNot: string | undefined) =>
    go({ ...state, query: { ...query, cursor: undefined, reasonNot, ...(reasonNot !== undefined && query.reason === reasonNot ? { reason: undefined } : {}) } });
  const move = (delta: number) => {
    const next = items[at === -1 ? 0 : at + delta];
    if (next === undefined) return;
    focusDetail.current = false;
    go({ ...state, open: next.id });
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(next.id)}"]`)?.focus());
  };
  const openHere = (id: string) => {
    focusDetail.current = true;
    go({ ...state, open: id });
  };

  const list = (
    <>
      <LensTabs lens={lens} shown={shown} onChange={(next) => go({ ...state, lens: next, open: undefined, query: { ...query, cursor: undefined } })} />
      <div role="tabpanel" id="decisions-lens-panel" aria-labelledby={`lens-tab-${lens}`} className="min-w-0 space-y-4">
        {lens === "newest" ? (
          <NewestList state={state} go={go} page={page} open={state.open} onOpen={open} onMove={move} onHide={hideReason} />
        ) : lens === "reason" ? (
          <ReasonsList state={state} go={go} flagged={flagged} onOpen={open} onHide={hideReason} />
        ) : (
          <SessionsList state={state} go={go} />
        )}
      </div>
    </>
  );

  let pane: ReactNode = <DecisionGuide />;
  if (state.open !== undefined) {
    if (detail.data === NOT_IN_RECORD) {
      pane = (
        <section aria-labelledby="decision-title" className={`${PANEL} space-y-1`}>
          <h2 id="decision-title" tabIndex={-1} className="text-lg font-semibold text-(--iw-ink)">This decision is no longer in the record</h2>
          <p className={BODY_TEXT}>InnerWarden keeps the newest decisions, and this one has been dropped.</p>
        </section>
      );
    } else if (detail.data !== undefined) {
      const found = detail.data;
      pane = (
        <DecisionDetail
          item={found.item}
          before={found.before}
          after={found.after}
          session={found.session}
          os={os}
          installed={installed}
          onNewer={at > 0 ? () => openHere(items[at - 1].id) : undefined}
          onOlder={at >= 0 && at < items.length - 1 ? () => openHere(items[at + 1].id) : undefined}
          onOpen={openHere}
          onSession={(session) => go({ lane: "agent_actions", lens: "newest", open: found.item.id, query: { session } })}
          onHideReason={(reason) => hideReason(reason)}
          restarts={restarts}
          focusTitle={focusDetail.current}
        />
      );
    } else if (detail.error !== undefined) {
      pane = <NotRead onRetry={detail.refresh}>Not read: this decision could not be read.</NotRead>;
    } else {
      pane = <Pending className="h-96" />;
    }
  }

  return <Layout header={header} list={list} detail={pane} open={state.open} onBack={back} />;
}

/** The three lenses as tabs: the arrow keys move between them, Home and End to the ends. */
function LensTabs({ lens, shown, onChange }: { lens: Lens; shown: readonly Lens[]; onChange: (lens: Lens) => void }) {
  const refs = useRef<Partial<Record<Lens, HTMLButtonElement | null>>>({});
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const at = shown.indexOf(lens);
    const target = event.key === "ArrowRight"
      ? shown[(at + 1) % shown.length]
      : event.key === "ArrowLeft"
        ? shown[(at - 1 + shown.length) % shown.length]
        : event.key === "Home"
          ? shown[0]
          : event.key === "End"
            ? shown[shown.length - 1]
            : undefined;
    if (target === undefined) return;
    event.preventDefault();
    onChange(target);
    requestAnimationFrame(() => refs.current[target]?.focus());
  };
  return (
    <div role="tablist" aria-label="Read the decisions" className="flex flex-wrap gap-1 rounded-lg bg-(--iw-surface-2) p-1">
      {shown.map((candidate) => {
        const selected = candidate === lens;
        return (
          <button
            key={candidate}
            ref={(element) => {
              refs.current[candidate] = element;
            }}
            type="button"
            role="tab"
            id={`lens-tab-${candidate}`}
            data-lens={candidate}
            aria-selected={selected}
            aria-controls="decisions-lens-panel"
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(candidate)}
            onKeyDown={onKeyDown}
            className={`min-h-9 flex-1 rounded-md px-3 text-sm font-semibold whitespace-nowrap pointer-coarse:min-h-11 ${selected ? "bg-(--iw-surface) text-(--iw-ink) shadow-[0_0_0_1px_var(--iw-line)]" : "text-(--iw-ink-2) hover:text-(--iw-ink)"}`}
          >
            {LENS_WORDS[candidate]}
          </button>
        );
      })}
    </div>
  );
}

/** Each outcome as a filter: its mark, its words and how many in the list. Pressed shows only it. */
function OutcomeBar({ page, outcome, onOutcome }: { page: DecisionsPage; outcome?: string; onOutcome: (outcome: string | undefined) => void }) {
  // Each filter is the key to the marks too: its mark and its words, so no
  // separate legend repeats them.
  return (
    <div role="group" aria-label="Show one outcome only" data-outcome-bar data-tour="legend" className="grid grid-cols-2 gap-1.5">
      {OUTCOME_FILTERS.map((key) => {
        const pressed = outcome === key;
        return (
          <button
            key={key}
            type="button"
            data-outcome-filter={key}
            aria-pressed={pressed}
            onClick={() => onOutcome(pressed ? undefined : key)}
            className={`flex min-h-9 min-w-0 items-center gap-2 rounded-md border px-2.5 py-1 text-left pointer-coarse:min-h-11 ${SMALL_TEXT} ${pressed ? "border-(--iw-ink-2) bg-(--iw-surface-2) text-(--iw-ink)" : "border-(--iw-line) bg-(--iw-surface) text-(--iw-ink-2) hover:bg-(--iw-surface-2)"}`}
          >
            <OutcomeMark outcome={key} />
            <span className="min-w-0 flex-1">{OUTCOME_WORDS[key]}</span>
            <span className="font-semibold tabular-nums text-(--iw-ink)">{formatCount(page.byOutcome[key] ?? 0)}</span>
          </button>
        );
      })}
    </div>
  );
}

/** A filter that is on, said in words, with the press that takes it off. */
function Chip({ label, onRemove, what }: { label: ReactNode; onRemove: () => void; what: string }) {
  return (
    <span data-filter-chip={what} className={`inline-flex max-w-full items-center gap-1 rounded-full border border-(--iw-line-strong) bg-(--iw-surface) py-0.5 pr-1 pl-2.5 ${SMALL_TEXT} text-(--iw-ink-2)`}>
      <span className="min-w-0 truncate">{label}</span>
      <button type="button" onClick={onRemove} aria-label={`Remove the ${what} filter`} className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-(--iw-ink-3) hover:bg-(--iw-surface-2) hover:text-(--iw-ink) pointer-coarse:h-11 pointer-coarse:w-11">
        <span aria-hidden="true">×</span>
      </button>
    </span>
  );
}

function SearchBox({ query, onQuery }: { query: DecisionsQuery; onQuery: (next: DecisionsQuery) => void }) {
  const [text, setText] = useState(query.q ?? "");
  useEffect(() => setText(query.q ?? ""), [query.q]);
  return (
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
        className="min-h-9 min-w-0 flex-1 rounded-md border border-(--iw-line-strong) bg-(--iw-surface) px-2.5 text-sm text-(--iw-ink) placeholder:text-(--iw-ink-3) pointer-coarse:min-h-11"
      />
      <button type="submit" className={QUIET_BUTTON}>Search</button>
    </form>
  );
}

function NewestList({
  state,
  go,
  page,
  open,
  onOpen,
  onMove,
  onHide,
}: {
  state: DecisionsParams;
  go: Go;
  page: Polled<DecisionsPage>;
  open?: string;
  onOpen: (id: string) => void;
  onMove: (delta: number) => void;
  onHide: (reason: string | undefined) => void;
}) {
  const query = state.query;
  const filtered = query.outcome !== undefined || query.reason !== undefined || query.q !== undefined || query.session !== undefined;
  const onQuery = (next: DecisionsQuery) => go({ ...state, open: undefined, query: next });
  const data = page.data;
  const reasonWords = (key: string) => data?.reasons.find((reason) => reason.key === key)?.short ?? key.replace(/^rule:/, "");
  const clear = () => onQuery(query.reasonNot === undefined ? {} : { reasonNot: query.reasonNot });

  if (data === undefined) {
    if (page.error === undefined) return <Pending className="h-64" />;
    const code = filterCode(page.error);
    return code === undefined ? (
      <NotRead alert onRetry={page.refresh}>
        The decision record could not be read. <code className="font-mono">innerwarden status</code> says why.
      </NotRead>
    ) : (
      <NotRead alert>
        That filter is not valid here ({code}).{" "}
        <button type="button" onClick={() => onQuery({})} className={`min-h-9 pointer-coarse:min-h-11 ${LINK_TEXT}`}>Clear filters</button>
      </NotRead>
    );
  }
  const hidden = query.reasonNot === undefined ? undefined : reasonWords(query.reasonNot);
  return (
    <>
      <OutcomeBar page={data} outcome={query.outcome} onOutcome={(outcome) => onQuery({ ...query, cursor: undefined, outcome })} />
      <SearchBox query={query} onQuery={onQuery} />
      {query.reason === undefined && query.session === undefined && hidden === undefined ? null : (
        <div className="flex flex-wrap gap-2">
          {query.reason === undefined ? null : (
            <Chip what="reason" label={<>Reason: {reasonWords(query.reason)}</>} onRemove={() => onQuery({ ...query, cursor: undefined, reason: undefined })} />
          )}
          {query.session === undefined ? null : (
            <Chip what="session" label={<>Session {shortSession(query.session)}</>} onRemove={() => onQuery({ ...query, cursor: undefined, session: undefined })} />
          )}
        </div>
      )}
      {hidden === undefined ? null : (
        <p className={META_TEXT}>
          <span data-hidden-summary className="font-medium text-(--iw-ink-2)">{formatCount(data.total)} flagged without {hidden}.</span>{" "}
          Hidden from this list only; the guard still flags them.{" "}
          <button type="button" onClick={() => onHide(undefined)} className={`min-h-9 pointer-coarse:min-h-11 ${LINK_TEXT}`}>Show them again</button>
        </p>
      )}
      <div className={`flex flex-wrap items-center justify-between gap-2 ${META_TEXT}`}>
        <span data-count-line>{casePageCountLabel(data.items.length, { rows_in_window: data.total })}</span>
        {filtered ? <button type="button" onClick={clear} className={`min-h-9 pointer-coarse:min-h-11 ${LINK_TEXT}`}>Clear filters</button> : null}
      </div>
      {page.stale ? <StaleLine onRetry={page.refresh} /> : null}
      <div className={`${PANEL} p-2 sm:p-2`}>
        {data.items.length === 0 ? (
          <div className={`space-y-1 p-2 ${BODY_TEXT}`}>
            <p data-empty-list>{emptyListWords(data, filtered || query.reasonNot !== undefined)}</p>
            {filtered && data.total === 0 ? <button type="button" onClick={clear} className={`min-h-9 pointer-coarse:min-h-11 ${LINK_TEXT}`}>Clear filters</button> : null}
            {!filtered && data.record.decisions === 0 ? <a href="?view=agents" className={LINK_TEXT}>See Agents</a> : null}
          </div>
        ) : (
          <ul className="divide-y divide-(--iw-line)">
            {rowRuns(data.items).map((run) => <RunRows key={run.first.id} run={run} open={open} onOpen={onOpen} onMove={onMove} />)}
          </ul>
        )}
      </div>
      <Pager
        atStart={query.cursor === undefined}
        next={data.nextCursor}
        onNewest={() => onQuery({ ...query, cursor: undefined })}
        onOlder={(cursor) => onQuery({ ...query, cursor })}
      />
      <ReadAt data={data} path="/api/guard/decisions" />
    </>
  );
}

const href = (id: string) => `?view=activity&decision=${encodeURIComponent(id)}`;

/** A run of one reason in one session folds under its first row: it opens in one press. */
function RunRows({ run, open, onOpen, onMove }: { run: Run<Decision>; open?: string; onOpen: (id: string) => void; onMove: (delta: number) => void }) {
  const holds = runHolds(run, open);
  const [expanded, setExpanded] = useState(false);
  const shown = expanded || holds;
  const id = `run-${run.first.id}`;
  const row = (item: Decision) => (
    <DecisionRow key={item.id} decision={item} href={href(item.id)} current={open === item.id} onOpen={() => onOpen(item.id)} onMove={onMove} />
  );
  return (
    <>
      {row(run.first)}
      {run.folded.length === 0 ? null : (
        <>
          <li data-run-fold className={`flex items-center gap-3 border-l-2 border-(--iw-line) py-1.5 pr-3 pl-6 ${SMALL_TEXT} text-(--iw-ink-2)`}>
            <span className="min-w-0 flex-1">{formatCount(run.folded.length)} more in a row, flagged for the same reason</span>
            <button
              type="button"
              aria-expanded={shown}
              aria-controls={id}
              disabled={holds}
              onClick={() => setExpanded((value) => !value)}
              className={`min-h-9 shrink-0 pointer-coarse:min-h-11 ${LINK_TEXT}`}
            >
              {shown ? "Hide" : "Show"}
            </button>
          </li>
          {shown ? (
            <li id={id}>
              <ul className="divide-y divide-(--iw-line)">{run.folded.map(row)}</ul>
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
    <div className="flex items-center justify-between gap-2">
      <button type="button" onClick={onNewest} disabled={atStart} className={QUIET_BUTTON}>Newest</button>
      <button type="button" onClick={() => next !== undefined && onOlder(next)} disabled={next === undefined} className={QUIET_BUTTON}>
        Older <span aria-hidden="true">→</span>
      </button>
    </div>
  );
}

/**
 * Why commands were flagged, one reason a row: the outcome most of them
 * reached, the words, how many. Opening one shows its newest five, then
 * "Show all N"; Hide leaves it out of the newest list (a view only).
 */
function ReasonsList({
  state,
  go,
  flagged,
  onOpen,
  onHide,
}: {
  state: DecisionsParams;
  go: Go;
  flagged?: DecisionsPage;
  onOpen: (id: string) => void;
  onHide: (reason: string | undefined) => void;
}) {
  if (flagged === undefined) return <Pending className="h-64" />;
  if (flagged.reasons.length === 0) {
    return <p className={`${PANEL} ${BODY_TEXT}`}>{emptyListWords(flagged, false)}</p>;
  }
  const [first, rest] = [flagged.reasons.slice(0, REASONS_OPEN), flagged.reasons.slice(REASONS_OPEN)];
  const unlisted = Math.max(0, flagged.reasonsDistinct - flagged.reasons.length);
  const group = (reason: Reason) => (
    <ReasonGroup
      key={reason.key}
      reason={reason}
      hidden={state.query.reasonNot === reason.key}
      onHide={onHide}
      onOpen={onOpen}
      onAll={() => go({ ...state, lens: "newest", open: undefined, query: { ...state.query, cursor: undefined, reason: reason.key, ...(state.query.reasonNot === reason.key ? { reasonNot: undefined } : {}) } })}
    />
  );
  return (
    <div className="space-y-3">
      <p className={META_TEXT}>
        {formatCount(flagged.flaggedTotal)} flagged, for {formatCount(flagged.reasonsDistinct)} {flagged.reasonsDistinct === 1 ? "reason" : "reasons"}.
      </p>
      <ul className={`${PANEL} divide-y divide-(--iw-line) p-2 sm:p-2`}>{first.map(group)}</ul>
      {rest.length === 0 ? null : (
        <Disclosure summary={`And ${formatCount(rest.length)} more ${rest.length === 1 ? "reason" : "reasons"}`}>
          <ul className={`${PANEL} divide-y divide-(--iw-line) p-2 sm:p-2`}>{rest.map(group)}</ul>
        </Disclosure>
      )}
      {unlisted > 0 ? <p className={META_TEXT}>{formatCount(unlisted)} rarer {unlisted === 1 ? "reason is" : "reasons are"} not listed here.</p> : null}
      <ReadAt data={flagged} path="/api/guard/decisions" />
    </div>
  );
}

function ReasonGroup({
  reason,
  hidden,
  onHide,
  onOpen,
  onAll,
}: {
  reason: Reason;
  hidden: boolean;
  onHide: (reason: string | undefined) => void;
  onOpen: (id: string) => void;
  onAll: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const worst = worstOutcome(reason.byOutcome);
  const panel = `reason-${reason.key.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
  return (
    <li data-reason-group={reason.key} className={`py-1 ${hidden ? "opacity-70" : ""}`}>
      <div className="flex items-start gap-1">
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={panel}
          onClick={() => setExpanded((value) => !value)}
          className="flex min-h-9 min-w-0 flex-1 items-start gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-(--iw-surface-2) pointer-coarse:min-h-11"
        >
          {worst === undefined ? <span className="h-2.5 w-2.5 shrink-0" /> : <OutcomeMark outcome={worst} className="mt-1.5" />}
          <span className="min-w-0 flex-1">
            <span className="block text-sm leading-[21px] font-medium text-(--iw-ink)">{reason.short}</span>
            {reason.detail === undefined ? null : <span className={`block break-all font-mono ${META_TEXT}`}>{reason.detail}</span>}
          </span>
          <span className="shrink-0 text-right">
            <span className="block text-sm font-semibold tabular-nums text-(--iw-ink)">{formatCount(reason.count)}</span>
            <ReasonOutcomes byOutcome={reason.byOutcome} />
          </span>
        </button>
        <button
          type="button"
          aria-pressed={hidden}
          aria-label={hidden ? `Show ${reason.short} in the newest list again` : `Hide ${reason.short} from the newest list`}
          onClick={() => onHide(hidden ? undefined : reason.key)}
          className={`min-h-9 shrink-0 rounded-md px-2 text-xs font-semibold text-(--iw-ink-3) hover:bg-(--iw-surface-2) hover:text-(--iw-ink) pointer-coarse:min-h-11`}
        >
          {hidden ? "Show" : "Hide"}
        </button>
      </div>
      {expanded ? <ReasonPreview id={panel} reason={reason} onOpen={onOpen} onAll={onAll} /> : null}
    </li>
  );
}

function ReasonPreview({ id, reason, onOpen, onAll }: { id: string; reason: Reason; onOpen: (id: string) => void; onAll: () => void }) {
  const page = usePolled(() => fetchDecisions({ reason: reason.key, limit: REASON_PREVIEW }), 0, `reason-preview:${reason.key}`);
  return (
    <div id={id} className="space-y-1 pb-2 pl-6">
      {page.data === undefined ? (
        page.error === undefined ? <Pending className="h-20" /> : <NotRead onRetry={page.refresh}>Not read: the decisions for this reason could not be read.</NotRead>
      ) : (
        <>
          <ul className="divide-y divide-(--iw-line)">
            {page.data.items.slice(0, REASON_PREVIEW).map((item) => (
              <DecisionRow key={item.id} decision={item} href={href(item.id)} onOpen={() => onOpen(item.id)} />
            ))}
          </ul>
          <a
            href={`?view=activity&reason=${encodeURIComponent(reason.key)}`}
            onClick={onPlainClick(onAll)}
            className={`inline-flex min-h-9 items-center gap-1 px-3 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}
          >
            Show all {formatCount(reason.count)} <Icon name="arrow-right" className="h-3.5 w-3.5" />
          </a>
        </>
      )}
    </div>
  );
}

/** The sessions that still have decisions in the record; one opens the newest list of that session. */
function SessionsList({ state, go }: { state: DecisionsParams; go: Go }) {
  const sessions = usePolled(() => fetchSessions(SESSIONS_LISTED), SESSIONS_POLL_MS, "sessions");
  const data = sessions.data;
  if (data === undefined) {
    return sessions.error === undefined ? <Pending className="h-64" /> : (
      <NotRead alert onRetry={sessions.refresh}>
        The decision record could not be read. <code className="font-mono">innerwarden status</code> says why.
      </NotRead>
    );
  }
  if (!data.supported) return <p className={BODY_TEXT}>This InnerWarden does not list sessions.</p>;
  const choose = (id: string) => go({ ...state, lens: "newest", open: undefined, query: { session: id } });
  return (
    <div className="space-y-2">
      {sessions.stale ? <StaleLine onRetry={sessions.refresh} /> : null}
      {data.value.items.length === 0 ? (
        <p className={`${PANEL} ${BODY_TEXT}`}>No session has decisions in the record.</p>
      ) : (
        <ul className={`${PANEL} divide-y divide-(--iw-line) p-2 sm:p-2`}>
          {data.value.items.map((session) => (
            <SessionRow
              key={session.id}
              session={session}
              href={`?view=activity&session=${encodeURIComponent(session.id)}`}
              onOpen={() => choose(session.id)}
            />
          ))}
        </ul>
      )}
      <p className={META_TEXT}>Sessions with decisions still in the record.</p>
      <ReadAt data={data} path="/api/guard/sessions" />
    </div>
  );
}

function MessagesLane({ header, state, go, hostMode, since }: { header: ReactNode; state: DecisionsParams; go: Go; hostMode: string; since?: string }) {
  const cursor = state.query.cursor;
  const page = usePolled(() => fetchAttempts(cursor), cursor === undefined ? MESSAGES_POLL_MS : 0, cursor ?? "");
  const { open: openRow, back } = useBack(state, go);
  const restarts = useConnectedRestarts();
  // As on the decisions: only an open the person made moves focus.
  const focusDetail = useRef(false);
  const open = (id: string) => {
    focusDetail.current = true;
    openRow(id);
  };
  const items = page.data?.items ?? [];
  const at = state.open === undefined ? -1 : items.findIndex((item) => item.id === state.open);
  const move = (delta: number) => {
    const next = items[at === -1 ? 0 : at + delta];
    if (next === undefined) return;
    focusDetail.current = false;
    go({ ...state, open: next.id });
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(next.id)}"]`)?.focus());
  };
  const sinceDay = since === undefined ? undefined : new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }).format(Date.parse(since));
  const list = (
    <>
      {page.data === undefined ? null : (
        <p className={SMALL_TEXT}>
          <span className="text-lg font-semibold tabular-nums text-(--iw-ink)">{formatCount(page.data.total)}</span>{" "}
          <span className="text-(--iw-ink-2)">recorded{sinceDay === undefined ? "" : ` since ${sinceDay}`}.</span>{" "}
          <span className="text-(--iw-ink-3)">Observe records them; it does not block them.</span>
        </p>
      )}
      {page.stale ? <StaleLine onRetry={page.refresh} /> : null}
      <div className={`${PANEL} p-2 sm:p-2`}>
        {page.data === undefined ? (
          page.error === undefined ? <Pending className="h-40" /> : <NotRead alert onRetry={page.refresh}>Not read: the guard's log could not be read.</NotRead>
        ) : items.length === 0 ? (
          <p className={`p-2 ${BODY_TEXT}`}>
            {page.data.total === 0 ? "No risky message has been recorded." : `${formatCount(page.data.total)} recorded could not be shown.`}
          </p>
        ) : (
          <ul className="divide-y divide-(--iw-line)">
            {items.map((item) => (
              <MessageRow
                key={item.id}
                message={item}
                href={`?view=activity&lane=agent_messages&decision=${encodeURIComponent(item.id)}`}
                current={state.open === item.id}
                onOpen={() => open(item.id)}
                onMove={move}
              />
            ))}
          </ul>
        )}
      </div>
      {page.data === undefined ? null : (
        <Pager
          atStart={cursor === undefined}
          next={page.data.nextCursor}
          onNewest={() => go({ ...state, open: undefined, query: {} })}
          onOlder={(next) => go({ ...state, open: undefined, query: { cursor: next } })}
        />
      )}
      <ReadAt data={page.data} path="/api/guard/history?kind=attempt" />
    </>
  );
  const found = at === -1 ? undefined : items[at];
  const pane = state.open === undefined
    ? <DecisionGuide />
    : found === undefined
      ? page.data === undefined
        ? <Pending className="h-96" />
        : <NotRead>This message is not on this page of the list. Use Newest to go back to the start.</NotRead>
      : <MessageDetail item={found} hostMode={hostMode} restarts={restarts} focusTitle={focusDetail.current} />;
  return <Layout header={header} list={list} detail={pane} open={state.open} onBack={back} />;
}
