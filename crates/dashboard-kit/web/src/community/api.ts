import { getJson, type AgentsResponse } from "../api";
import { DASHBOARD_FETCH_TIMEOUT_MS, requestDeadline } from "../api/client";
import type { RestartWords } from "./restart";
import { hasControlCharacters } from "../presentation";
import {
  asChannel,
  asDecisionAction,
  asLaunchMode,
  asLayer,
  asLifecycle,
  asPlatform,
  asTrustSource,
  asVerdict,
  effectiveTrust,
  isDecisionOutcome,
  isMessageOutcome,
  TRUSTS,
  worseTrust,
  type AgentDecisionAction,
  type Channel,
  type DecisionOutcomeKey,
  type LaunchMode,
  type Layer,
  type Lifecycle,
  type MessageOutcomeKey,
  type PlatformOs,
  type Trust,
  type TrustSource,
  type Verdict,
} from "./words";

/**
 * The Community routes the free CLI serves (`guard/decisions`,
 * `guard/decision`, `guard/history`, `guard/protection`,
 * `guard/record-health`), read strictly.
 *
 * The rule every reader here follows: a malformed PAGE is an error, never a
 * zero (a list that could not be read must not say "nothing flagged"), and a
 * malformed ITEM is dropped on its own (one bad row does not blank the rest).
 * Every text the page prints is length-bounded. A LABEL carrying a control or
 * format character is dropped; EVIDENCE carrying one (a command, a message,
 * the rule's words about them) never is: its hidden characters are written
 * out (`revealHidden`) and the item says so. A command with a bidi override,
 * or a message in invisible tag characters, is more suspicious, not less, and
 * dropping it would hide the evasion from the one page meant to show it.
 */

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

type Json = Record<string, unknown>;

function record(value: unknown): Json | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Json) : undefined;
}

function text(value: unknown, max = 1_024): string | undefined {
  if (typeof value !== "string" || value.length > max || hasControlCharacters(value.replace(/[\n\t]/g, " "))) return undefined;
  return value;
}

/**
 * `text` with every control and format character written out where a reader
 * can see it (`\u{202E}`), newlines and tabs kept, and whether there was one.
 * The CLI already does this before it serves; a page left open against an
 * older CLI does it here rather than drop the row.
 */
export function revealHidden(value: string): { text: string; hidden: boolean } {
  let hidden = false;
  const shown = value.replace(/[\p{Cc}\p{Cf}]/gu, (character) => {
    if (character === "\n" || character === "\t") return character;
    hidden = true;
    return `\\u{${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}}`;
  });
  return { text: shown, hidden };
}

/** Evidence text: bounded, and never dropped for a hidden character, which is shown instead. */
function evidence(value: unknown, max = 1_024): { text: string; hidden: boolean } | undefined {
  if (typeof value !== "string" || value.length > max) return undefined;
  return revealHidden(value);
}

function plain(value: unknown, max = 1_024): string | undefined {
  const read = text(value, max)?.trim();
  return read === undefined || read.length === 0 ? undefined : read;
}

function count(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value + 0 : undefined;
}

function time(value: unknown): string | undefined {
  return typeof value === "string" && RFC3339.test(value) && Number.isFinite(Date.parse(value)) ? value : undefined;
}

function strings(value: unknown, max = 64): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const read = plain(item, max);
    return read === undefined ? [] : [read];
  });
}

function bool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

/** Drop `undefined` values so an absent field stays absent, never `undefined`. */
function defined<T extends Json>(object: T): T {
  for (const key of Object.keys(object)) if (object[key] === undefined) delete object[key];
  return object;
}

/** A piece of a CLI sentence: words, a folder or command as code, or a time. */
export type Segment = { kind: "text"; text: string } | { kind: "code"; text: string } | { kind: "time"; at: string };

export type NextStep = {
  label: string;
  command?: string;
  line: string;
  /** The command holds a `<placeholder>` for the reader to fill in: shown, never copied. */
  template?: boolean;
  /** A step the page carries out itself, on its own view only (the CLI's `view_action`). */
  viewAction?: "hide_reason";
};

export type Concern = "credential_read" | "domain_fetch" | "other";

export type Decision = {
  id: string;
  session: string;
  seq: number;
  command: string;
  commandWhole: boolean;
  /** The command carried a character a reader cannot see; `command` shows it written out. */
  hiddenCharacters: boolean;
  channel: Channel;
  /** The agent's name in words, only when the record names it. */
  agent?: string;
  agentId?: string;
  /** The folder's basename, never a path. */
  project?: string;
  recommendation: string;
  outcome: string;
  mode: string;
  outcomeKey: DecisionOutcomeKey;
  recordedAt?: string;
  decidedBy: string;
  risk?: number;
  reason: { key: string; words: string; short: string };
  reasonsMore: number;
  rules: string[];
  categories: string[];
  asi: string[];
  explanation: string;
  concern: Concern;
  happened: Segment[];
  did: string;
  next: NextStep[];
  allowedByYou: boolean;
  /** Which instance asked and which layer decided; absent where the record holds none. */
  identity?: DecisionIdentity;
};

export type SessionFacts = {
  agent?: string;
  channel: Channel;
  project?: string;
  decisions: number;
  flagged: number;
  firstAt?: string;
  lastAt?: string;
};

export type Reason = {
  key: string;
  words: string;
  short: string;
  count: number;
  mute?: string;
  /** What the reason quoted, cut short by the CLI, for a muted line under `short`. */
  detail?: string;
  /** The reason's decisions by outcome, only the outcomes it has; absent from an older CLI. */
  byOutcome?: Partial<Record<DecisionOutcomeKey, number>>;
};

export type RecordSpan = {
  decisions: number;
  /** Flagged decisions an agent made; a check by hand is not one. */
  flagged: number;
  /** Decisions that were a check by hand (`innerwarden check`). */
  checked: number;
  oldestAt?: string;
  newestAt?: string;
  /**
   * The record is full: the oldest decisions are dropped as new ones arrive.
   * Absent from an older CLI, and then nothing is said about it.
   */
  capped?: boolean;
};

export type SuppressCounts = { allow: number; muteRules: number; muteCategories: number };

export type DecisionsPage = {
  items: Decision[];
  nextCursor?: string;
  total: number;
  flaggedTotal: number;
  byOutcome: Partial<Record<DecisionOutcomeKey, number>>;
  reasons: Reason[];
  reasonsDistinct: number;
  suppress: SuppressCounts;
  record: RecordSpan;
  sessions: Record<string, SessionFacts>;
};

export type Brief = { id: string; command: string; hiddenCharacters: boolean; outcomeKey: DecisionOutcomeKey; recordedAt?: string; flagged: boolean };

export type DecisionDetail = { item: Decision; before: Brief[]; after: Brief[]; session: SessionFacts };

function readSegments(value: unknown): Segment[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) return undefined;
  const segments: Segment[] = [];
  for (const entry of value) {
    const item = record(entry);
    if (item === undefined) return undefined;
    if (item.kind === "time") {
      const at = time(item.at);
      if (at === undefined) return undefined;
      segments.push({ kind: "time", at });
    } else if (item.kind === "text" || item.kind === "code") {
      // The rule's words can quote what they flagged: shown, never dropped.
      const words = evidence(item.text, 600);
      if (words === undefined) return undefined;
      segments.push({ kind: item.kind, text: words.text });
    } else {
      return undefined;
    }
  }
  return segments;
}

function readNext(value: unknown): NextStep[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 2).flatMap((entry) => {
    const item = record(entry);
    const label = plain(item?.label, 120);
    const line = plain(item?.line, 300);
    if (item === undefined || label === undefined || line === undefined) return [];
    const command = plain(item.command, 600);
    const step: NextStep = command === undefined ? { label, line } : { label, command, line };
    if (command !== undefined && item.command_is_template === true) step.template = true;
    if (item.view_action === "hide_reason") step.viewAction = "hide_reason";
    return [step];
  });
}

function readConcern(value: unknown): Concern {
  return value === "credential_read" || value === "domain_fetch" ? value : "other";
}

export function readDecision(value: unknown): Decision | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const id = plain(item.id, 256);
  const command = evidence(item.command, 2_048);
  const outcomeKey = item.outcome_key;
  const reason = record(item.reason);
  const story = record(item.story);
  const happened = readSegments(story?.happened);
  const did = plain(story?.did, 600);
  if (id === undefined || command === undefined || !isDecisionOutcome(outcomeKey) || reason === undefined || happened === undefined || did === undefined) {
    return undefined;
  }
  const words = evidence(reason.words, 600)?.text ?? "";
  const hiddenCharacters = command.hidden || item.hidden_characters === true;
  return defined({
    id,
    session: plain(item.session, 256) ?? "",
    seq: count(item.seq) ?? 0,
    command: command.text,
    // A command shown with its hidden characters written out is not the
    // command that ran, so it is never "whole" and never copied.
    commandWhole: (bool(item.command_whole) ?? false) && !hiddenCharacters,
    hiddenCharacters,
    channel: asChannel(item.channel),
    agent: plain(item.agent, 64),
    agentId: plain(item.agent_id, 64),
    project: plain(item.project, 120),
    recommendation: plain(item.recommendation, 32) ?? "unknown",
    outcome: plain(item.outcome, 32) ?? "unknown",
    mode: plain(item.mode_at_decision, 32) ?? "unknown",
    outcomeKey,
    recordedAt: time(item.recorded_at),
    decidedBy: plain(item.decided_by, 32) ?? "unknown",
    risk: typeof item.risk === "number" && Number.isFinite(item.risk) ? item.risk : undefined,
    reason: { key: plain(reason.key, 256) ?? "none", words, short: plain(reason.short, 80) ?? words },
    reasonsMore: count(item.reasons_more) ?? 0,
    rules: strings(item.rules),
    categories: strings(item.categories),
    asi: strings(item.asi, 16),
    explanation: evidence(item.explanation, 1_024)?.text ?? "",
    concern: readConcern(item.concern),
    happened,
    did,
    next: readNext(item.next),
    allowedByYou: bool(item.allowed_by_you) ?? false,
    identity: readDecisionIdentity(item.identity),
  });
}

function readSession(value: unknown): SessionFacts | undefined {
  const item = record(value);
  const decisions = count(item?.decisions);
  const flagged = count(item?.flagged);
  if (item === undefined || decisions === undefined || flagged === undefined) return undefined;
  return defined({
    agent: plain(item.agent, 64),
    channel: asChannel(item.channel),
    project: plain(item.project, 120),
    decisions,
    flagged,
    firstAt: time(item.first_at),
    lastAt: time(item.last_at),
  });
}

function readRecordSpan(value: unknown): RecordSpan | undefined {
  const item = record(value);
  const decisions = count(item?.decisions);
  const flagged = count(item?.flagged);
  if (item === undefined || decisions === undefined || flagged === undefined) return undefined;
  return defined({
    decisions,
    flagged,
    checked: count(item.checked) ?? 0,
    oldestAt: time(item.oldest_at),
    newestAt: time(item.newest_at),
    capped: bool(item.capped),
  });
}

function readSuppress(value: unknown): SuppressCounts {
  const item = record(value);
  return {
    allow: count(item?.allow) ?? 0,
    muteRules: count(item?.mute_rules) ?? 0,
    muteCategories: count(item?.mute_categories) ?? 0,
  };
}

/**
 * Counts by outcome (`by_outcome`), only the keys this page has words for;
 * `undefined` when the field is not an object, so an absent count is never
 * read as an empty one.
 */
function readOutcomeCounts(value: unknown): Partial<Record<DecisionOutcomeKey, number>> | undefined {
  const outcomes = record(value);
  if (outcomes === undefined) return undefined;
  const counts: Partial<Record<DecisionOutcomeKey, number>> = {};
  for (const [key, raw] of Object.entries(outcomes)) {
    const read = count(raw);
    if (isDecisionOutcome(key) && read !== undefined) counts[key] = read;
  }
  return counts;
}

export class UnreadableAnswer extends Error {
  constructor(what: string) {
    super(`${what}: the answer could not be read`);
    this.name = "UnreadableAnswer";
  }
}

/** A page of flagged decisions, or an error: never a page of nothing made up. */
export function readDecisionsPage(value: unknown): DecisionsPage {
  const page = record(value);
  const total = count(page?.total);
  const flaggedTotal = count(page?.flagged_total);
  const span = readRecordSpan(page?.record);
  if (page === undefined || !Array.isArray(page.items) || total === undefined || flaggedTotal === undefined || span === undefined) {
    throw new UnreadableAnswer("guard/decisions");
  }
  const byOutcome = readOutcomeCounts(page.by_outcome) ?? {};
  const reasons = Array.isArray(page.reasons)
    ? page.reasons.flatMap((entry) => {
        const item = record(entry);
        const key = plain(item?.key, 256);
        const words = evidence(item?.words, 600)?.text;
        const reasonCount = count(item?.count);
        if (item === undefined || key === undefined || words === undefined || reasonCount === undefined) return [];
        const reason: Reason = defined({
          key,
          words,
          short: plain(item.short, 80) ?? words,
          count: reasonCount,
          mute: plain(item.mute, 200),
          detail: evidence(item.detail, 120)?.text,
          byOutcome: readOutcomeCounts(item.by_outcome),
        });
        return [reason];
      })
    : [];
  const sessions: Record<string, SessionFacts> = {};
  for (const [label, raw] of Object.entries(record(page.sessions) ?? {})) {
    const facts = readSession(raw);
    if (facts !== undefined && label.length <= 256) sessions[label] = facts;
  }
  return defined({
    items: page.items.flatMap((item) => {
      const decision = readDecision(item);
      return decision === undefined ? [] : [decision];
    }),
    nextCursor: plain(page.next_cursor, 2_048),
    total,
    flaggedTotal,
    byOutcome,
    reasons,
    reasonsDistinct: count(page.reasons_distinct) ?? reasons.length,
    suppress: readSuppress(page.suppress),
    record: span,
    sessions,
  });
}

function readBrief(value: unknown): Brief | undefined {
  const item = record(value);
  const id = plain(item?.id, 256);
  const command = evidence(item?.command, 2_048);
  if (item === undefined || id === undefined || command === undefined || !isDecisionOutcome(item.outcome_key)) return undefined;
  return defined({
    id,
    command: command.text,
    hiddenCharacters: command.hidden || item.hidden_characters === true,
    outcomeKey: item.outcome_key,
    recordedAt: time(item.recorded_at),
    flagged: bool(item.flagged) ?? false,
  });
}

export function readDecisionDetail(value: unknown): DecisionDetail {
  const body = record(value);
  const item = readDecision(body?.item);
  const around = record(body?.around);
  if (body === undefined || item === undefined) throw new UnreadableAnswer("guard/decision");
  const briefs = (list: unknown) =>
    Array.isArray(list)
      ? list.flatMap((entry) => {
          const brief = readBrief(entry);
          return brief === undefined ? [] : [brief];
        })
      : [];
  return {
    item,
    before: briefs(around?.before).slice(-2),
    after: briefs(around?.after).slice(0, 1),
    session: readSession(body.session) ?? { channel: item.channel, decisions: 0, flagged: 0 },
  };
}

export type DecisionsQuery = {
  /** What the rules said (`deny`, `review`, `allow`): the Overview's newest denies. */
  verdict?: "deny" | "review" | "allow";
  outcome?: string;
  reason?: string;
  /** A reason the reader hid from the list: a view only, the guard keeps flagging it. */
  reasonNot?: string;
  session?: string;
  q?: string;
  cursor?: string;
  limit?: number;
};

export function decisionsPath(query: DecisionsQuery): string {
  const params = new URLSearchParams();
  params.set("flagged", "1");
  for (const name of ["verdict", "outcome", "reason", "session", "q", "cursor"] as const) {
    const value = query[name];
    if (value !== undefined && value.length > 0) params.set(name, value);
  }
  // Showing one reason and hiding the same one would list nothing: the reason asked for wins.
  if (query.reasonNot !== undefined && query.reasonNot.length > 0 && query.reasonNot !== query.reason) {
    params.set("reason_not", query.reasonNot);
  }
  params.set("limit", String(query.limit ?? 25));
  return `api/guard/decisions?${params.toString()}`;
}

export async function fetchDecisions(query: DecisionsQuery): Promise<DecisionsPage> {
  return readDecisionsPage(await getJson(decisionsPath(query)));
}

/** The server said this decision is no longer in the record (a prune dropped it). */
export const NOT_IN_RECORD = "decision_not_in_record";

export async function fetchDecision(id: string): Promise<DecisionDetail | typeof NOT_IN_RECORD> {
  try {
    return readDecisionDetail(await getJson(`api/guard/decision?id=${encodeURIComponent(id)}`));
  } catch (error) {
    if (error instanceof Error && error.message === NOT_IN_RECORD) return NOT_IN_RECORD;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// The guard's event log
// ---------------------------------------------------------------------------

export type RefusalWeek = {
  start: string;
  blocked: number;
  wouldBlock: number;
  /** The week still under way: a line must not draw it as if it were whole. */
  partial: boolean;
};

/** One UTC day of the guard's log. */
export type RefusalDay = {
  date: string;
  blocked: number;
  wouldBlock: number;
  /** Today: the day is still under way, so its bar is drawn as "so far". */
  partial: boolean;
};

export type History = {
  readable: boolean;
  since?: string;
  unparsableLines: number;
  /**
   * `days`: the last 14 UTC days, oldest first. Absent from an older CLI,
   * and then a page counts from the decision record instead, never zero.
   */
  refusals: { blocked: number; wouldBlock: number; weeks: RefusalWeek[]; days?: RefusalDay[] };
  messages: { recorded: number; last7d: number; latest?: { at: string; detail: string } };
  suppressionChanges: number;
  /** What people decided about agents, most recent first; absent where the log holds none. */
  agentDecisions?: AgentDecisionLine[];
};

export function readHistory(value: unknown): History {
  const body = record(value);
  const refusals = record(body?.refusals);
  const messages = record(body?.messages);
  const readable = bool(body?.readable);
  const blocked = count(refusals?.blocked);
  const wouldBlock = count(refusals?.would_block);
  const recorded = count(messages?.recorded);
  if (body === undefined || readable === undefined || blocked === undefined || wouldBlock === undefined || recorded === undefined) {
    throw new UnreadableAnswer("guard/history");
  }
  const weeks = Array.isArray(refusals?.weeks)
    ? refusals.weeks.flatMap((entry) => {
        const week = record(entry);
        const start = typeof week?.start === "string" && /^\d{4}-\d{2}-\d{2}$/.test(week.start) ? week.start : undefined;
        const b = count(week?.blocked);
        const w = count(week?.would_block);
        return start === undefined || b === undefined || w === undefined ? [] : [{ start, blocked: b, wouldBlock: w, partial: week?.partial === true }];
      })
    : [];
  const days = Array.isArray(refusals?.days)
    ? refusals.days.slice(-14).flatMap((entry): RefusalDay[] => {
        const day = record(entry);
        const date = typeof day?.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(day.date) ? day.date : undefined;
        const b = count(day?.blocked);
        const w = count(day?.would_block);
        return date === undefined || b === undefined || w === undefined ? [] : [{ date, blocked: b, wouldBlock: w, partial: day?.partial === true }];
      })
    : undefined;
  // No day that could be read is no days at all: the page then counts from
  // the record, and never sums nothing into a zero.
  const readDays = days === undefined || days.length === 0 ? undefined : days;
  const latestRecord = record(messages?.latest);
  const latestAt = time(latestRecord?.at);
  const latestDetail = evidence(latestRecord?.detail, 400)?.text;
  return defined({
    readable,
    since: time(body.since),
    unparsableLines: count(body.unparsable_lines) ?? 0,
    refusals: defined({ blocked, wouldBlock, weeks, days: readDays }),
    messages: defined({
      recorded,
      last7d: count(messages?.last_7d) ?? 0,
      latest: latestAt !== undefined && latestDetail !== undefined ? { at: latestAt, detail: latestDetail } : undefined,
    }),
    suppressionChanges: count(body.suppression_changes) ?? 0,
    agentDecisions: readAgentDecisions(body.agent_decisions),
  });
}

export async function fetchHistory(): Promise<History> {
  return readHistory(await getJson("api/guard/history"));
}

export type Attempt = {
  id: string;
  at: string;
  channel: string;
  channelWords: string;
  /** Technical view only. */
  sender?: string;
  surface: string;
  decider: string;
  deciderKey: string;
  enforced: boolean;
  recommendation: string;
  risk?: number;
  detail: string;
  /** The message carried a character a reader cannot see; `detail` shows it written out. */
  hiddenCharacters: boolean;
  outcomeKey: MessageOutcomeKey;
};

export type AttemptsPage = { items: Attempt[]; nextCursor?: string; total: number };

export function readAttempt(value: unknown): Attempt | undefined {
  const item = record(value);
  const id = plain(item?.id, 64);
  const at = time(item?.at);
  const detail = evidence(item?.detail, 400);
  if (item === undefined || id === undefined || at === undefined || detail === undefined || !isMessageOutcome(item.outcome_key)) return undefined;
  return defined({
    id,
    at,
    channel: plain(item.channel, 32) ?? "",
    channelWords: plain(item.channel_words, 64) ?? "a chat",
    sender: plain(item.sender, 64),
    surface: plain(item.surface, 32) ?? "",
    decider: plain(item.decider, 120) ?? "",
    deciderKey: plain(item.decider_key, 32) ?? "",
    enforced: bool(item.enforced) ?? false,
    recommendation: plain(item.recommendation, 32) ?? "",
    risk: count(item.risk),
    detail: detail.text,
    hiddenCharacters: detail.hidden || item.hidden_characters === true,
    outcomeKey: item.outcome_key,
  });
}

export function readAttemptsPage(value: unknown): AttemptsPage {
  const body = record(value);
  const total = count(body?.total);
  if (body === undefined || !Array.isArray(body.items) || total === undefined) throw new UnreadableAnswer("guard/history?kind=attempt");
  return defined({
    items: body.items.flatMap((item) => {
      const attempt = readAttempt(item);
      return attempt === undefined ? [] : [attempt];
    }),
    nextCursor: plain(body.next_cursor, 64),
    total,
  });
}

export async function fetchAttempts(cursor?: string): Promise<AttemptsPage> {
  const params = new URLSearchParams({ kind: "attempt", limit: "25" });
  if (cursor !== undefined) params.set("cursor", cursor);
  return readAttemptsPage(await getJson(`api/guard/history?${params.toString()}`));
}

// ---------------------------------------------------------------------------
// What Community covers here
// ---------------------------------------------------------------------------

/**
 * The record's flagged decisions counted by what they reached for, so a paid
 * capability on Protection can say what happened HERE. Absent when the
 * record could not be read.
 */
export type FlaggedConcerns = { ran: number; credentialRead: number; domainFetch: number; since?: string };

export type Protection = {
  os: PlatformOs;
  record: { recording: boolean; since?: string; lostActions?: number };
  /**
   * `checksPass`: whether the checks a jail needs pass on this machine. Absent
   * (an older CLI) and `null` (not checked yet) both read "Not checked here
   * yet": only `true` is ready. `advice` is the CLI's own words when not.
   */
  jail: { available: boolean; backend?: string; checksPass?: boolean; advice: string[]; checkedAt?: string };
  /** `available`: an OpenClaw config is here, so `observe install` can work. */
  observe: { installed: boolean; available: boolean };
  alerts: { channels: number };
  secondOpinion: { configured: boolean; provider?: string };
  suppress: SuppressCounts;
  flagged?: FlaggedConcerns;
};

export function readProtection(value: unknown): Protection {
  const body = record(value);
  const recordFacts = record(body?.record);
  const jail = record(body?.jail);
  const recording = bool(recordFacts?.recording);
  const jailAvailable = bool(jail?.available);
  if (body === undefined || recording === undefined || jailAvailable === undefined) throw new UnreadableAnswer("guard/protection");
  const second = record(body.second_opinion);
  const flagged = record(body.flagged);
  const ran = count(flagged?.ran);
  const credentialRead = count(flagged?.credential_read);
  const domainFetch = count(flagged?.domain_fetch);
  const installed = bool(record(body.observe)?.installed) ?? false;
  return defined({
    os: asPlatform(record(body.platform)?.os),
    record: defined({ recording, since: time(recordFacts?.since), lostActions: count(recordFacts?.lost_actions) }),
    jail: defined({
      available: jailAvailable,
      backend: plain(jail?.backend, 32),
      checksPass: bool(jail?.checks_pass),
      advice: Array.isArray(jail?.advice)
        ? jail.advice.slice(0, 6).flatMap((line) => {
            const read = plain(line, 300);
            return read === undefined ? [] : [read];
          })
        : [],
      checkedAt: time(jail?.checked_at),
    }),
    // An older CLI sends no `available`: then only an installed hook says yes.
    observe: { installed, available: bool(record(body.observe)?.available) ?? installed },
    alerts: { channels: count(record(body.alerts)?.channels) ?? 0 },
    secondOpinion: defined({ configured: bool(second?.configured) ?? false, provider: plain(second?.provider, 32) }),
    suppress: readSuppress(body.suppress),
    flagged: ran === undefined || credentialRead === undefined || domainFetch === undefined
      ? undefined
      : defined({ ran, credentialRead, domainFetch, since: time(flagged?.since) }),
  });
}

export async function fetchProtection(): Promise<Protection> {
  return readProtection(await getJson("api/guard/protection"));
}

export type RecordHealth = { recording: boolean; sinceUnix?: number; lostActions?: number; summary?: string };

export function readRecordHealth(value: unknown): RecordHealth {
  const body = record(value);
  const recording = bool(body?.recording);
  if (body === undefined || recording === undefined) throw new UnreadableAnswer("guard/record-health");
  return defined({
    recording,
    sinceUnix: count(body.since_unix),
    lostActions: count(body.lost_actions),
    summary: plain(body.summary, 600),
  });
}

export async function fetchRecordHealth(): Promise<RecordHealth> {
  return readRecordHealth(await getJson("api/guard/record-health"));
}

// ---------------------------------------------------------------------------
// Additions the CLI makes to shared payloads
// ---------------------------------------------------------------------------

/**
 * The newest decision each channel screened (`hook`, `mcp`), named or not:
 * whether a screening path is working, for Protection's "Seen working".
 */
export function readScreenedByChannel(value: unknown): { hook?: string; mcp?: string } {
  const item = record(record(value)?.screened_by_channel);
  return defined({ hook: time(item?.hook), mcp: time(item?.mcp) });
}

/**
 * The newest decision each channel screened that names NO agent, or
 * `undefined` when the CLI did not say (an older CLI): then nothing may be
 * concluded from an absent channel.
 */
export function readUnnamedByChannel(value: unknown): { hook?: string; mcp?: string } | undefined {
  const item = record(record(value)?.unnamed_by_channel);
  return item === undefined ? undefined : defined({ hook: time(item.hook), mcp: time(item.mcp) });
}

/**
 * The CLI's sentence about a profiles file that is there and cannot be used
 * (`profiles_file`), or `undefined` when there is none, which is every
 * payload of a host without one.
 */
export function readProfilesFile(value: unknown): { sentence: string } | undefined {
  const item = record(record(value)?.profiles_file);
  const sentence = plain(item?.sentence, 1_024);
  return item?.state === "invalid" && sentence !== undefined ? { sentence } : undefined;
}

/** The one command the CLI says fixes an agent, printed as sent. */
export type AgentNextStep = { label: string; command: string; line: string };

export function readAgentNextStep(value: unknown): AgentNextStep | undefined {
  const item = record(value);
  const label = plain(item?.label, 120);
  const command = plain(item?.command, 200);
  const line = plain(item?.line, 300);
  return label === undefined || command === undefined || line === undefined ? undefined : { label, command, line };
}

// ---------------------------------------------------------------------------
// Agent identity, as the CLI sends it (only where it exists)
// ---------------------------------------------------------------------------

const INSTANCE_ID = /^[0-9a-f]{32}$/;
/** Most instances one agent row lists; the CLI counts the rest in `more_instances`. */
export const MAX_INSTANCES = 20;
const MAX_SESSIONS = 5;
const MAX_AGENT_DECISIONS = 50;

export type AgentProfile = {
  /** `undefined` is the general rules. */
  name?: string;
  label: string;
  source?: "builtin" | "system" | "user";
  confined: number;
  other: number;
  appliesFrom: "now" | "next_start";
};

export type InstanceSession = { session: string; firstAt?: string; lastAt?: string; caseId?: string };

export type LocalInstance = {
  instanceId: string;
  trust: Trust;
  trustReason: string;
  /** Who the label says decided its rules: the jail's own reading, or the host. */
  trustSource?: TrustSource;
  user?: string;
  uid?: number;
  project?: string;
  mode?: LaunchMode;
  startedAt?: string;
  lastActivityAt?: string;
  /** `false` is "ended"; absent is "not said", never "ended". */
  live?: boolean;
  sessions: InstanceSession[];
  technical: {
    jailPid?: number;
    jailStartTicks?: number;
    pidNs?: number;
    scopeUnit?: string;
    launcherPath?: string;
    launcherRootOwned?: boolean;
    /** `true` when the jail was started with user namespaces closed; absent is "not said". */
    usernsClosed?: boolean;
  };
};

/**
 * What the CLI says about who an agent is and what was decided about it. Every
 * field is optional: a CLI without the identity flag sends none of them, and
 * `readAgentIdentity` then returns `undefined`, so the row is what it was.
 */
export type AgentIdentity = {
  trust?: Trust;
  trustReason?: string;
  lifecycle?: Lifecycle;
  lifecycleBy?: string;
  lifecycleAt?: string;
  owner?: string;
  profile?: AgentProfile;
  confine?: AgentNextStep;
  decisionSteps: AgentNextStep[];
  instances: LocalInstance[];
  moreInstances: number;
};

function readTrust(value: unknown): Trust | undefined {
  return typeof value === "string" && (TRUSTS as readonly string[]).includes(value) ? (value as Trust) : undefined;
}

function readProfile(value: unknown): AgentProfile | undefined {
  const item = record(value);
  const label = plain(item?.label, 80);
  if (item === undefined || label === undefined) return undefined;
  const source: AgentProfile["source"] = item.source === "builtin" || item.source === "system" || item.source === "user" ? item.source : undefined;
  return defined({
    name: plain(item.name, 64),
    label,
    source,
    confined: count(item.confined_instances) ?? 0,
    other: count(item.other_instances) ?? 0,
    appliesFrom: item.applies_from === "next_start" ? ("next_start" as const) : ("now" as const),
  });
}

function readInstance(value: unknown): LocalInstance | undefined {
  const item = record(value);
  const id = plain(item?.instance_id, 64);
  if (item === undefined || id === undefined || !INSTANCE_ID.test(id)) return undefined;
  const reason = plain(item.trust_reason, 64) ?? "";
  // The reason is the ceiling: a trust above what it supports is never shown,
  // and an instance whose label names another source is not a jail's word.
  const source = item.trust_source === undefined ? "jail" : asTrustSource(item.trust_source);
  const claimed = source !== undefined ? (readTrust(item.trust) ?? "declared") : "declared";
  const sessions = Array.isArray(item.sessions)
    ? item.sessions.slice(0, MAX_SESSIONS).flatMap((entry): InstanceSession[] => {
        const session = record(entry);
        const label = plain(session?.session, 64);
        return session === undefined || label === undefined
          ? []
          : [defined({ session: label, firstAt: time(session.first_at), lastAt: time(session.last_at), caseId: plain(session.case_id, 256) })];
      })
    : [];
  const technical = record(item.technical);
  return defined({
    instanceId: id,
    trust: effectiveTrust(claimed, reason),
    trustReason: reason,
    trustSource: source,
    user: plain(item.user, 64),
    uid: count(item.uid),
    project: plain(item.project, 120),
    mode: asLaunchMode(item.mode),
    startedAt: time(item.started_at),
    lastActivityAt: time(item.last_activity_at),
    live: bool(item.live),
    sessions,
    technical: defined({
      jailPid: count(technical?.jail_pid),
      jailStartTicks: count(technical?.jail_start_ticks),
      pidNs: count(technical?.pid_ns),
      scopeUnit: plain(technical?.scope_unit, 200),
      launcherPath: plain(technical?.launcher_path, 300),
      launcherRootOwned: bool(technical?.launcher_root_owned),
      usernsClosed: technical?.userns_closed === true ? true : undefined,
    }),
  });
}

/** Worst trust of the live instances, or of all of them where none says it is live. */
export function worstTrust(instances: readonly LocalInstance[]): Trust | undefined {
  const live = instances.filter((instance) => instance.live !== false);
  const pool = live.length > 0 ? live : instances;
  return pool.length === 0 ? undefined : pool.map((instance) => instance.trust).reduce(worseTrust);
}

/**
 * The identity fields of one `guard/agents` row, or `undefined` when the row
 * carries none of them (which is the whole payload of a CLI without them).
 */
export function readAgentIdentity(agent: unknown): AgentIdentity | undefined {
  const item = record(agent);
  if (item === undefined) return undefined;
  const instances = Array.isArray(item.instances)
    ? item.instances.slice(0, MAX_INSTANCES).flatMap((entry) => {
        const read = readInstance(entry);
        return read === undefined ? [] : [read];
      })
    : [];
  const lifecycle = asLifecycle(item.lifecycle);
  const profile = readProfile(item.profile);
  const confine = readAgentNextStep(item.confine_step);
  const decisionSteps = Array.isArray(item.decision_steps)
    ? item.decision_steps.flatMap((step) => {
        const read = readAgentNextStep(step);
        return read === undefined ? [] : [read];
      })
    : [];
  const claimed = readTrust(item.trust);
  const reason = plain(item.trust_reason, 64);
  if (
    lifecycle === undefined
    && profile === undefined
    && confine === undefined
    && decisionSteps.length === 0
    && instances.length === 0
    && claimed === undefined
  ) {
    return undefined;
  }
  // The row's trust is its own label when it sent one, never above what its
  // reason supports and never above its worst live instance; the reason shown
  // is the one that belongs to the trust shown.
  const own = claimed === undefined ? undefined : effectiveTrust(claimed, reason ?? "");
  const worst = worstTrust(instances);
  let trust = own;
  let trustReason = own === undefined ? undefined : (reason ?? "");
  if (worst !== undefined && (own === undefined || TRUSTS.indexOf(worst) < TRUSTS.indexOf(own))) {
    trust = worst;
    trustReason = instances.find((instance) => instance.trust === worst && instance.live !== false)?.trustReason
      ?? instances.find((instance) => instance.trust === worst)?.trustReason;
  }
  return defined({
    trust,
    trustReason,
    lifecycle,
    lifecycleBy: plain(item.lifecycle_by, 64),
    lifecycleAt: time(item.lifecycle_at),
    owner: plain(item.owner, 64),
    profile,
    confine,
    decisionSteps,
    instances,
    moreInstances: count(item.more_instances) ?? 0,
  });
}

/** Which instance asked, and which layer decided (`guard/decision`'s `identity`). */
export type DecisionIdentity = {
  instanceId?: string;
  sessionId?: string;
  trust: Trust;
  trustReason: string;
  layer?: Layer;
  profile?: string;
  relaxationWithheld: boolean;
  /** `host` when the hook asked Active Defence on its host and recorded its answer. */
  trustSource?: TrustSource;
  /** The host's id for its decision, as the hook recorded it. */
  hostDecision?: string;
  /** The host's word for not relaxing, kept without being read. */
  hostWithheld?: string;
};

export function readDecisionIdentity(value: unknown): DecisionIdentity | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const reason = plain(item.trust_reason, 64) ?? "";
  const id = plain(item.instance_id, 64);
  return defined({
    instanceId: id !== undefined && INSTANCE_ID.test(id) ? id : undefined,
    sessionId: plain(item.session_id, 256),
    trust: effectiveTrust(readTrust(item.trust) ?? "declared", reason),
    trustReason: reason,
    layer: asLayer(item.deciding_layer),
    profile: plain(item.profile, 64),
    relaxationWithheld: item.relaxation_withheld === true,
    trustSource: asTrustSource(item.trust_source),
    hostDecision: typeof item.host_decision === "string" && DECISION_ID.test(item.host_decision) ? item.host_decision : undefined,
    hostWithheld: typeof item.host_withheld === "string" && WITHHELD_WORD.test(item.host_withheld) ? item.host_withheld : undefined,
  });
}

/** A host decision id as the hook records it: 32 lowercase hex characters. */
const DECISION_ID = /^[0-9a-f]{32}$/;
/** A host's word for not relaxing: 1 to 48 of `[a-z_]`. */
const WITHHELD_WORD = /^[a-z_]{1,48}$/;

/** The verdict a decision's recommendation names, for the layer's words. */
export function decisionVerdict(recommendation: string): Verdict | undefined {
  return asVerdict(recommendation);
}

/** One line of what people decided about agents (`guard.agent_decision`). */
export type AgentDecisionLine = {
  at: string;
  action: AgentDecisionAction;
  agent: string;
  instanceId?: string;
  by: string;
  owner?: string;
  rule?: string;
  profileBefore?: string;
  profileAfter?: string;
  confined?: number;
  result: string;
};

function readAgentDecisions(value: unknown): AgentDecisionLine[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const lines = value.slice(0, MAX_AGENT_DECISIONS).flatMap((entry): AgentDecisionLine[] => {
    const item = record(entry);
    const at = time(item?.ts);
    const action = asDecisionAction(typeof item?.action === "string" ? item.action.replace(/^agent_/, "") : undefined);
    const agent = plain(item?.agent, 64);
    const by = plain(item?.by, 64);
    const result = plain(item?.result, 120);
    if (item === undefined || at === undefined || action === undefined || agent === undefined || by === undefined || result === undefined) return [];
    const rule = record(item.rule);
    const id = plain(item.instance_id, 64);
    return [
      defined({
        at,
        action,
        agent,
        instanceId: id !== undefined && INSTANCE_ID.test(id) ? id : undefined,
        by,
        owner: plain(item.owner, 64),
        // `{ kind, value }`, as the verbs write it and the CLI serves it
        // (spec 104 5b.1); any other shape names no rule.
        rule: rule !== undefined && (rule.kind === "category" || rule.kind === "mcp_tool") ? plain(rule.value, 120) : undefined,
        profileBefore: plain(item.profile_before, 80),
        profileAfter: plain(item.profile_after, 80),
        confined: count(item.confined_instances),
        result,
      }),
    ];
  });
  return lines.length === 0 ? undefined : lines;
}

/** A lane card's own command, sent beside a `no_source` lane. */
export function readLaneNextStep(lanes: unknown, lane: string): { command: string; line: string } | undefined {
  const item = record(record(record(lanes)?.[lane])?.next_step);
  const command = plain(item?.command, 200);
  const line = plain(item?.line, 300);
  return command === undefined || line === undefined ? undefined : { command, line };
}

/** The decision record's span, as `guard/overview` sends it in `record`. */
export function readOverviewRecord(value: unknown): RecordSpan | undefined {
  return readRecordSpan(value);
}

// ---------------------------------------------------------------------------
// What the CLI says about each agent (`guard/agents`): how it is connected,
// what it judges, how to change and restart it. Every field is optional: a
// CLI that does not send one leaves it absent, and each page says the
// fallback its section names, never a zero and never "off".
// ---------------------------------------------------------------------------

/** What an agent's connection judges before a call runs (`judges`). */
export const JUDGES = ["shell_and_privileged_files", "shell_only", "mcp_server_calls"] as const;
export type Judges = (typeof JUDGES)[number];

/** An agent's own mode, as one word a page can branch on. */
export type AgentMode = "enforce" | "monitor" | "mixed" | "partial" | "not_configured" | "unknown";

/** A proxy agent's MCP servers: how many run locally, how many are wrapped, how many are remote. */
export type McpCounts = { stdio: number; wrapped: number; remote: number };

/** A step for THIS agent only (`mode_steps`), served only where the switch is proven. */
export type ModeSteps = { enforce?: AgentNextStep; monitor?: AgentNextStep };

export type AgentFacts = {
  id: string;
  name: string;
  mode: AgentMode;
  mechanism?: "hook" | "mcp";
  /** `false` only when the CLI says the agent cannot be wired (`setup_support: "unsupported"`). */
  supported: boolean;
  /** Installed, or found running or on the PATH: not only a configuration left behind. */
  present: boolean;
  installed: boolean;
  /** `null` where the platform does not check (macOS): never "not running". */
  running: boolean | null;
  lastObservedAt?: string;
  configChangedAt?: string;
  judges?: Judges;
  judgesLine?: string;
  restart?: RestartWords;
  modeSteps?: ModeSteps;
  mcp?: McpCounts;
  nextStep?: AgentNextStep;
};

function agentMode(guardrail: Json | undefined): AgentMode {
  const raw = guardrail?.mode;
  // A policy row nobody has seen working says so, and its intent is the mode
  // it was set to; nothing about it is taken as seen.
  const mode = raw === "configured_not_observed" ? guardrail?.configured_mode : raw;
  if (mode === "dry-run") return "monitor";
  if (mode === "enforcing") return "enforce";
  return mode === "enforce" || mode === "monitor" || mode === "mixed" || mode === "partial" || mode === "not_configured" ? mode : "unknown";
}

function readRestart(value: unknown): RestartWords | undefined {
  const item = record(value);
  const how = plain(item?.how, 200);
  const why = plain(item?.why, 200);
  return how === undefined || why === undefined ? undefined : { how, why };
}

function readModeSteps(value: unknown): ModeSteps | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const steps = defined({ enforce: readAgentNextStep(item.enforce), monitor: readAgentNextStep(item.monitor) });
  return steps.enforce === undefined && steps.monitor === undefined ? undefined : steps;
}

function readMcp(value: unknown): McpCounts | undefined {
  const item = record(value);
  const stdio = count(item?.stdio);
  const wrapped = count(item?.wrapped);
  const remote = count(item?.remote);
  return stdio === undefined || wrapped === undefined || remote === undefined ? undefined : { stdio, wrapped, remote };
}

/** One `guard/agents` row, or `undefined` when it carries no id or name. */
export function readAgentFacts(value: unknown): AgentFacts | undefined {
  const item = record(value);
  const id = plain(item?.id, 64);
  const name = plain(item?.display_name, 64);
  if (item === undefined || id === undefined || name === undefined) return undefined;
  const guardrail = record(item.guardrail);
  const mechanism: AgentFacts["mechanism"] = guardrail?.mechanism === "pretooluse_hook" ? "hook" : guardrail?.mechanism === "mcp_proxy" ? "mcp" : undefined;
  const detectedBy = Array.isArray(item.detected_by) ? item.detected_by : [];
  const installed = item.installed === true;
  const judges = (JUDGES as readonly unknown[]).includes(item.judges) ? (item.judges as Judges) : undefined;
  return defined({
    id,
    name,
    mode: agentMode(guardrail),
    mechanism,
    supported: guardrail?.setup_support !== "unsupported",
    present: installed || detectedBy.some((evidence) => evidence === "process" || evidence === "executable_on_path"),
    installed,
    running: typeof item.running === "boolean" ? item.running : null,
    lastObservedAt: time(guardrail?.last_observed_at),
    configChangedAt: time(guardrail?.config_changed_at),
    judges,
    judgesLine: plain(item.judges_line, 400),
    restart: readRestart(item.restart),
    modeSteps: readModeSteps(item.mode_steps),
    mcp: mechanism === "mcp" ? readMcp(item.mcp) : undefined,
    nextStep: readAgentNextStep(item.next_step),
  });
}

export type AgentsFacts = {
  agents: AgentFacts[];
  /** The newest decision each channel screened, named or not. */
  screened: { hook?: string; mcp?: string };
  /** The newest decision each channel screened that names no agent; `undefined` when the CLI did not say. */
  unnamed?: { hook?: string; mcp?: string };
  autoConnect?: { enabled: boolean; mode?: string; everySeconds?: number };
};

/** The whole `guard/agents` answer, or an error: a list that could not be read is never "no agent". */
export function readAgentsFacts(value: AgentsResponse | unknown): AgentsFacts {
  const body = record(value);
  if (body === undefined || !Array.isArray(body.agents)) throw new UnreadableAnswer("guard/agents");
  const auto = record(body.auto_connect);
  const enabled = bool(auto?.enabled);
  return defined({
    agents: body.agents.flatMap((entry) => {
      const read = readAgentFacts(entry);
      return read === undefined ? [] : [read];
    }),
    screened: readScreenedByChannel(body),
    unnamed: readUnnamedByChannel(body),
    autoConnect: enabled === undefined
      ? undefined
      : defined({ enabled, mode: plain(auto?.mode, 32), everySeconds: count(auto?.refresh_interval_secs) }),
  });
}

// ---------------------------------------------------------------------------
// Routes an older CLI does not serve. A 404 is "this InnerWarden does not
// serve it", which a page says in words; it is never read as an empty list.
// ---------------------------------------------------------------------------

export type Served<T> = { supported: true; value: T } | { supported: false };

/** The answer to a route a CLI may not serve: unsupported on a 404, an error on any other failure. */
export async function getServed(path: string): Promise<Served<unknown>> {
  const deadline = requestDeadline(undefined, DASHBOARD_FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(path, { cache: "no-store", signal: deadline.signal });
    if (response.status === 404) return { supported: false };
    if (!response.ok) {
      const payload = (await response.json().catch(() => undefined)) as { error?: unknown } | undefined;
      throw new Error(typeof payload?.error === "string" ? payload.error : `${path}: ${response.status}`);
    }
    return { supported: true, value: await response.json() };
  } catch (error) {
    if (deadline.timedOut()) throw new Error(`${path}: no answer in time`);
    throw error;
  } finally {
    deadline.done();
  }
}

/** One session that still has decisions in the record (`guard/sessions`). */
export type SessionSummary = {
  id: string;
  agent?: string;
  agentId?: string;
  channel: Channel;
  project?: string;
  firstAt?: string;
  lastAt?: string;
  decisions: number;
  flagged: number;
  byOutcome: Partial<Record<DecisionOutcomeKey, number>>;
};

export type SessionsPage = { items: SessionSummary[]; record?: RecordSpan };

/** At most this many sessions are asked for, as the route bounds it. */
export const MAX_SESSIONS_LIMIT = 50;

export function readSessionsPage(value: unknown): SessionsPage {
  const body = record(value);
  if (body === undefined || !Array.isArray(body.items)) throw new UnreadableAnswer("guard/sessions");
  return defined({
    items: body.items.slice(0, MAX_SESSIONS_LIMIT).flatMap((entry): SessionSummary[] => {
      const item = record(entry);
      const id = plain(item?.id, 256);
      const decisions = count(item?.decisions);
      const flagged = count(item?.flagged);
      if (item === undefined || id === undefined || decisions === undefined || flagged === undefined) return [];
      return [
        defined({
          id,
          agent: plain(item.agent, 64),
          agentId: plain(item.agent_id, 64),
          channel: asChannel(item.channel),
          project: plain(item.project, 120),
          firstAt: time(item.first_at),
          lastAt: time(item.last_at),
          decisions,
          flagged,
          byOutcome: readOutcomeCounts(item.by_outcome) ?? {},
        }),
      ];
    }),
    record: readRecordSpan(body.record),
  });
}

export async function fetchSessions(limit = 20): Promise<Served<SessionsPage>> {
  const bounded = Math.min(MAX_SESSIONS_LIMIT, Math.max(1, Math.floor(limit)));
  const answer = await getServed(`api/guard/sessions?limit=${bounded}`);
  return answer.supported ? { supported: true, value: readSessionsPage(answer.value) } : answer;
}

/** One allow pattern (`guard/suppress`). */
export type AllowEntry = {
  pattern: string;
  /** It matches more than one command: no anchor holds it to one. */
  unanchored: boolean;
  /** It held a secret, which the CLI replaced before serving it. */
  redacted: boolean;
  hiddenCharacters: boolean;
  /** Never present for a redacted pattern or one with hidden characters: the step would not remove it. */
  remove?: AgentNextStep;
};

export type SuppressList = {
  /** The lists are hidden because this dashboard is open to the network; the counts still show. */
  withheld: boolean;
  counts: SuppressCounts;
  allow: AllowEntry[];
  /** Patterns the guard ignores because they match every command. */
  dropped: string[];
  muteRules: { id: string; title?: string; remove?: AgentNextStep }[];
  muteCategories: { id: string; remove?: AgentNextStep }[];
  /** How many more each list holds than it shows. */
  more: SuppressCounts;
  /** How many times the lists changed, counted from the guard's log: never a pattern from it. */
  changes: { count: number; since?: string; lastAt?: string };
  listSteps: { allow?: AgentNextStep; mute?: AgentNextStep };
};

/** Most entries one list carries, as the route bounds it. */
export const MAX_SUPPRESS_ENTRIES = 200;

export function readSuppressList(value: unknown): SuppressList {
  const body = record(value);
  const counts = record(body?.counts);
  if (body === undefined || counts === undefined || !Array.isArray(body.allow)) throw new UnreadableAnswer("guard/suppress");
  const withheld = body.withheld === "exposed";
  const list = (entries: unknown) => (withheld || !Array.isArray(entries) ? [] : entries.slice(0, MAX_SUPPRESS_ENTRIES));
  const changes = record(body.changes);
  const steps = record(body.list_steps);
  return {
    withheld,
    counts: readSuppress(counts),
    allow: list(body.allow).flatMap((entry): AllowEntry[] => {
      const item = record(entry);
      const pattern = evidence(item?.pattern, 1_024);
      if (item === undefined || pattern === undefined) return [];
      const redacted = item.redacted === true;
      const hiddenCharacters = pattern.hidden || item.hidden_characters === true;
      const remove = redacted || hiddenCharacters ? undefined : readAgentNextStep(item.remove);
      return [defined({ pattern: pattern.text, unanchored: item.warning === "unanchored", redacted, hiddenCharacters, remove })];
    }),
    dropped: list(body.dropped).flatMap((entry) => {
      const pattern = evidence(record(entry)?.pattern, 1_024);
      return pattern === undefined ? [] : [pattern.text];
    }),
    muteRules: list(body.mute_rules).flatMap((entry) => {
      const item = record(entry);
      const id = plain(item?.id, 64);
      return item === undefined || id === undefined
        ? []
        : [defined({ id, title: plain(item.title, 120), remove: readAgentNextStep(item.remove) })];
    }),
    muteCategories: list(body.mute_categories).flatMap((entry) => {
      const item = record(entry);
      const id = plain(item?.id, 64);
      return item === undefined || id === undefined ? [] : [defined({ id, remove: readAgentNextStep(item.remove) })];
    }),
    more: readSuppress(body.more),
    changes: defined({ count: count(changes?.count) ?? 0, since: time(changes?.since), lastAt: time(changes?.last_at) }),
    listSteps: defined({ allow: readAgentNextStep(steps?.allow), mute: readAgentNextStep(steps?.mute) }),
  };
}

export async function fetchSuppress(): Promise<Served<SuppressList>> {
  const answer = await getServed("api/guard/suppress");
  return answer.supported ? { supported: true, value: readSuppressList(answer.value) } : answer;
}
