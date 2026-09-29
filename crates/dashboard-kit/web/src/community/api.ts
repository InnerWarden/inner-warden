import { getJson } from "../api";
import { hasControlCharacters } from "../presentation";
import {
  asChannel,
  asPlatform,
  isDecisionOutcome,
  isMessageOutcome,
  type Channel,
  type DecisionOutcomeKey,
  type MessageOutcomeKey,
  type PlatformOs,
} from "./words";

/**
 * The Community routes the free CLI serves (`guard/decisions`,
 * `guard/decision`, `guard/history`, `guard/protection`,
 * `guard/record-health`), read strictly.
 *
 * The rule every reader here follows: a malformed PAGE is an error, never a
 * zero (a list that could not be read must not say "nothing flagged"), and a
 * malformed ITEM is dropped on its own (one bad row does not blank the rest).
 * Every text the page prints is length-bounded and free of control
 * characters, or the item is dropped.
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

export type NextStep = { label: string; command?: string; line: string };

export type Concern = "credential_read" | "domain_fetch" | "other";

export type Decision = {
  id: string;
  session: string;
  seq: number;
  command: string;
  commandWhole: boolean;
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

export type Reason = { key: string; words: string; short: string; count: number; mute?: string };

export type RecordSpan = { decisions: number; flagged: number; oldestAt?: string; newestAt?: string };

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

export type Brief = { id: string; command: string; outcomeKey: DecisionOutcomeKey; recordedAt?: string; flagged: boolean };

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
      const words = text(item.text, 600);
      if (words === undefined) return undefined;
      segments.push({ kind: item.kind, text: words });
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
    return [command === undefined ? { label, line } : { label, command, line }];
  });
}

function readConcern(value: unknown): Concern {
  return value === "credential_read" || value === "domain_fetch" ? value : "other";
}

export function readDecision(value: unknown): Decision | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const id = plain(item.id, 256);
  const command = text(item.command, 2_048);
  const outcomeKey = item.outcome_key;
  const reason = record(item.reason);
  const story = record(item.story);
  const happened = readSegments(story?.happened);
  const did = plain(story?.did, 600);
  if (id === undefined || command === undefined || !isDecisionOutcome(outcomeKey) || reason === undefined || happened === undefined || did === undefined) {
    return undefined;
  }
  const words = text(reason.words, 600) ?? "";
  return defined({
    id,
    session: plain(item.session, 256) ?? "",
    seq: count(item.seq) ?? 0,
    command,
    commandWhole: bool(item.command_whole) ?? false,
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
    reason: { key: plain(reason.key, 256) ?? "none", words, short: plain(reason.short, 64) ?? words },
    reasonsMore: count(item.reasons_more) ?? 0,
    rules: strings(item.rules),
    categories: strings(item.categories),
    asi: strings(item.asi, 16),
    explanation: text(item.explanation, 1_024) ?? "",
    concern: readConcern(item.concern),
    happened,
    did,
    next: readNext(item.next),
    allowedByYou: bool(item.allowed_by_you) ?? false,
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
  return defined({ decisions, flagged, oldestAt: time(item.oldest_at), newestAt: time(item.newest_at) });
}

function readSuppress(value: unknown): SuppressCounts {
  const item = record(value);
  return {
    allow: count(item?.allow) ?? 0,
    muteRules: count(item?.mute_rules) ?? 0,
    muteCategories: count(item?.mute_categories) ?? 0,
  };
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
  const byOutcome: Partial<Record<DecisionOutcomeKey, number>> = {};
  const outcomes = record(page.by_outcome) ?? {};
  for (const [key, raw] of Object.entries(outcomes)) {
    const value = count(raw);
    if (isDecisionOutcome(key) && value !== undefined) byOutcome[key] = value;
  }
  const reasons = Array.isArray(page.reasons)
    ? page.reasons.flatMap((entry) => {
        const item = record(entry);
        const key = plain(item?.key, 256);
        const words = text(item?.words, 600);
        const reasonCount = count(item?.count);
        if (item === undefined || key === undefined || words === undefined || reasonCount === undefined) return [];
        const mute = plain(item.mute, 200);
        const reason: Reason = { key, words, short: plain(item.short, 64) ?? words, count: reasonCount };
        return mute === undefined ? [reason] : [{ ...reason, mute }];
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
  const command = text(item?.command, 2_048);
  if (item === undefined || id === undefined || command === undefined || !isDecisionOutcome(item.outcome_key)) return undefined;
  return defined({
    id,
    command,
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
  outcome?: string;
  reason?: string;
  session?: string;
  q?: string;
  cursor?: string;
  limit?: number;
};

export function decisionsPath(query: DecisionsQuery): string {
  const params = new URLSearchParams();
  params.set("flagged", "1");
  for (const name of ["outcome", "reason", "session", "q", "cursor"] as const) {
    const value = query[name];
    if (value !== undefined && value.length > 0) params.set(name, value);
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

export type History = {
  readable: boolean;
  since?: string;
  unparsableLines: number;
  refusals: { blocked: number; wouldBlock: number; weeks: { start: string; blocked: number; wouldBlock: number }[] };
  messages: { recorded: number; last7d: number; latest?: { at: string; detail: string } };
  suppressionChanges: number;
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
        return start === undefined || b === undefined || w === undefined ? [] : [{ start, blocked: b, wouldBlock: w }];
      })
    : [];
  const latestRecord = record(messages?.latest);
  const latestAt = time(latestRecord?.at);
  const latestDetail = text(latestRecord?.detail, 400);
  return defined({
    readable,
    since: time(body.since),
    unparsableLines: count(body.unparsable_lines) ?? 0,
    refusals: { blocked, wouldBlock, weeks },
    messages: defined({
      recorded,
      last7d: count(messages?.last_7d) ?? 0,
      latest: latestAt !== undefined && latestDetail !== undefined ? { at: latestAt, detail: latestDetail } : undefined,
    }),
    suppressionChanges: count(body.suppression_changes) ?? 0,
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
  outcomeKey: MessageOutcomeKey;
};

export type AttemptsPage = { items: Attempt[]; nextCursor?: string; total: number };

export function readAttempt(value: unknown): Attempt | undefined {
  const item = record(value);
  const id = plain(item?.id, 64);
  const at = time(item?.at);
  const detail = text(item?.detail, 400);
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
    detail,
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

export type Protection = {
  os: PlatformOs;
  record: { recording: boolean; since?: string; lostActions?: number };
  jail: { available: boolean; backend?: string };
  observe: { installed: boolean };
  alerts: { channels: number };
  secondOpinion: { configured: boolean; provider?: string };
  suppress: SuppressCounts;
};

export function readProtection(value: unknown): Protection {
  const body = record(value);
  const recordFacts = record(body?.record);
  const jail = record(body?.jail);
  const recording = bool(recordFacts?.recording);
  const jailAvailable = bool(jail?.available);
  if (body === undefined || recording === undefined || jailAvailable === undefined) throw new UnreadableAnswer("guard/protection");
  const second = record(body.second_opinion);
  return {
    os: asPlatform(record(body.platform)?.os),
    record: defined({ recording, since: time(recordFacts?.since), lostActions: count(recordFacts?.lost_actions) }),
    jail: defined({ available: jailAvailable, backend: plain(jail?.backend, 32) }),
    observe: { installed: bool(record(body.observe)?.installed) ?? false },
    alerts: { channels: count(record(body.alerts)?.channels) ?? 0 },
    secondOpinion: defined({ configured: bool(second?.configured) ?? false, provider: plain(second?.provider, 32) }),
    suppress: readSuppress(body.suppress),
  };
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

/** The one command the CLI says fixes an agent, printed as sent. */
export type AgentNextStep = { label: string; command: string; line: string };

export function readAgentNextStep(value: unknown): AgentNextStep | undefined {
  const item = record(value);
  const label = plain(item?.label, 120);
  const command = plain(item?.command, 200);
  const line = plain(item?.line, 300);
  return label === undefined || command === undefined || line === undefined ? undefined : { label, command, line };
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
