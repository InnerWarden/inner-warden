import { CASE_LANES, isCaseLane, type CaseLane, type CaseLaneCounts } from "./api/lanes";
import type { CaseListWindow } from "./api/cases";

/**
 * Three questions, one place each.
 *
 * Someone opening this dashboard wants to know three different things, and
 * the Overview answered none of them directly: about forty figures, nearly all
 * of them about the agent's screened commands, one amber line about the
 * server, and nothing at all about the messages people sent the agent. The
 * lanes are those three questions:
 *
 *  - `prompt`: messages to the AI agent, including anyone trying to talk it
 *    into something, and who stopped each one;
 *  - `agent`: what the agent tried to run, and what InnerWarden decided;
 *  - `host`: attacks on the server itself.
 *
 * The HOST files each case into a lane and writes each lane's sentence, from
 * the same facts it counts (the `HeadlineAnswer` rule: the screen renders the
 * conclusion and never forms its own). This file holds what a person reads
 * ABOUT a lane (its name, what it covers, where its link goes) and reads the
 * host's answer strictly enough that a malformed one is dropped rather than
 * shown.
 */

export type LaneCopy = {
  /** The lane's name: a card heading and a tab label. */
  name: string;
  /** What the lane covers, in one plain line under the name. */
  blurb: string;
  /** The card's link into Cases. */
  link: string;
  /** Said under the tab row when this lane is open in Cases. */
  intro: string;
};

export const LANE_COPY: Record<CaseLane, LaneCopy> = {
  prompt: {
    name: "Messages to your AI agent",
    blurb: "Someone trying to talk your agent into something, and who stopped it.",
    link: "See the messages",
    intro:
      "Messages sent to your AI agent. For each one that tried to make it do something unsafe, who stopped it: the agent itself, its AI provider's filter, or InnerWarden.",
  },
  agent: {
    name: "What your AI agent did",
    blurb: "Every command your agent tried, and what InnerWarden decided.",
    link: "See every command",
    intro:
      "Every command your AI agent tried to run, what InnerWarden decided, and whether the kernel had to step in.",
  },
  host: {
    name: "Attacks on this server",
    blurb: "Attacks from the internet, the honeypot, and what the kernel caught.",
    link: "See the attacks",
    intro:
      "Attacks on this server: password guessing, known-bad addresses, probes, the honeypot and the kernel's own findings, and what InnerWarden did about each.",
  },
};

/** The tab that lists every case, lanes or none: raw telemetry and response
 * bookkeeping belong to no lane and are only listed here. */
export const EVERYTHING_COPY = {
  name: "Everything",
  intro:
    "Every case on this host, including raw telemetry and the bookkeeping of responses, which belong to none of the three lanes.",
} as const;

/** What the card's small print says about the span its number covers. */
export const LANE_WINDOW_PHRASE: Record<CaseListWindow, string> = {
  "1h": "in the last hour",
  "24h": "in the last 24 hours",
  "7d": "in the last 7 days",
  "30d": "in the last 30 days",
  all: "in everything this host has kept",
};

const WINDOWS: readonly CaseListWindow[] = ["1h", "24h", "7d", "30d", "all"];

/** The newest case in a lane, as the host named it. */
export type LaneLatest = {
  title: string;
  /** RFC 3339. */
  at: string;
  /** The case to open, when the host could place it in one. */
  caseId?: string;
};

/**
 * One lane card, read from the host's `overview.lanes.<lane>`.
 *
 * `no_source` is a real answer, not a zero: nothing on this host feeds the
 * lane (for example, no conversation is recorded), so the card carries no
 * number at all, only the host's sentence saying how to turn the source on.
 * A zero there would claim the lane was watched and found empty.
 */
export type LaneCard =
  | {
      lane: CaseLane;
      state: "available";
      count: number;
      window: CaseListWindow;
      sentence: string;
      /** Cases in the lane waiting on a person. Absent when not sent. */
      waiting?: number;
      latest?: LaneLatest;
    }
  | { lane: CaseLane; state: "no_source"; sentence: string };

const SENTENCE_MAX = 600;
const TITLE_MAX = 1_024;
const CASE_ID_MAX = 256;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown, maximum: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= maximum ? trimmed : undefined;
}

function wholeCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value + 0 : undefined;
}

function latestOf(value: unknown): LaneLatest | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const title = text(item.title, TITLE_MAX);
  const at = typeof item.at === "string" && RFC3339.test(item.at) && !Number.isNaN(Date.parse(item.at)) ? item.at : undefined;
  if (title === undefined || at === undefined) return undefined;
  const caseId = text(item.case_id, CASE_ID_MAX);
  return caseId === undefined ? { title, at } : { title, at, caseId };
}

/**
 * One lane, or nothing when the host's answer cannot be shown honestly.
 *
 * An available lane needs its number, its window and its sentence: a number
 * with no span, or a sentence with no number, is half an answer, and the card
 * is dropped rather than completed by guesswork. The extras are optional and
 * dropped one by one: a malformed `latest` or `waiting` costs the card that
 * line, never the card. An availability this bundle does not know is dropped
 * too, because it cannot know what the host meant by it.
 */
export function parseLaneCard(lane: CaseLane, value: unknown): LaneCard | undefined {
  const item = record(value);
  if (item === undefined) return undefined;
  const sentence = text(item.sentence, SENTENCE_MAX);
  if (sentence === undefined) return undefined;
  if (item.availability === "no_source") return { lane, state: "no_source", sentence };
  if (item.availability !== "available") return undefined;
  const count = wholeCount(item.count);
  const window = WINDOWS.find((candidate) => candidate === item.window);
  if (count === undefined || window === undefined) return undefined;
  const card: LaneCard = { lane, state: "available", count, window, sentence };
  const waiting = wholeCount(item.waiting);
  if (waiting !== undefined) card.waiting = waiting;
  const latest = latestOf(item.latest);
  if (latest !== undefined) card.latest = latest;
  return card;
}

/**
 * The lane cards the host sent, in the fixed reading order: the messages,
 * then what the agent did, then the server.
 *
 * ABSENT IS NOT EMPTY, the rule `host_attention` already follows. A host that
 * sends no `lanes` (every Community host today, and every paid host older than
 * the field) gets `undefined`, and the Overview renders exactly as it did
 * before lanes existed. A host that sends only some lanes gets only those
 * cards: a Community host with agent records and nothing else shows one.
 */
export function overviewLaneCards(lanes: unknown): LaneCard[] | undefined {
  const item = record(lanes);
  if (item === undefined) return undefined;
  const cards = CASE_LANES.flatMap((lane) => {
    const card = parseLaneCard(lane, item[lane]);
    return card === undefined ? [] : [card];
  });
  return cards.length > 0 ? cards : undefined;
}

/** A lane choice in the address bar: one lane, or every case. */
export type CaseLaneChoice = CaseLane | "everything";

export function isCaseLaneChoice(value: unknown): value is CaseLaneChoice {
  return value === "everything" || isCaseLane(value);
}

/** The `lane` a list request carries for a choice: every case is no lane at all. */
export function laneParameter(choice: CaseLaneChoice): CaseLane | "" {
  return choice === "everything" ? "" : choice;
}

/**
 * The lane the Cases screen opens on when the address names none.
 *
 * The lane this viewer last used, when there is one. Otherwise the agent's
 * lane when this host has agent records, because that is the question most
 * readers arrive with, and the server's lane when it has none, so a host with
 * no agent never opens on an empty tab. When the counts are not known yet the
 * agent's lane is the guess, and the first answer corrects it.
 */
export function defaultCaseLane(remembered: CaseLaneChoice | undefined, counts: CaseLaneCounts | undefined): CaseLaneChoice {
  if (remembered !== undefined) return remembered;
  if (counts === undefined) return "agent";
  return (counts.agent ?? 0) > 0 ? "agent" : "host";
}

export const CASE_LANE_STORAGE_KEY = "innerwarden.cases-lane";

type LaneStorage = Pick<Storage, "getItem" | "setItem">;

function browserStorage(): LaneStorage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}

/**
 * The lane this viewer last opened, remembered in this browser only.
 *
 * Storage can be missing, blocked or throwing (a private window, an embedded
 * view), and each of those reads as "nothing remembered": the default rule
 * above then applies, which is a fine first visit, never a broken screen.
 */
export function rememberedCaseLane(storage: LaneStorage | undefined = browserStorage()): CaseLaneChoice | undefined {
  try {
    const value = storage?.getItem(CASE_LANE_STORAGE_KEY);
    return isCaseLaneChoice(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

export function rememberCaseLane(lane: CaseLaneChoice, storage: LaneStorage | undefined = browserStorage()): void {
  try {
    storage?.setItem(CASE_LANE_STORAGE_KEY, lane);
  } catch {
    // Not remembering costs the viewer one click next time; nothing else.
  }
}
