/**
 * Every closed word table the Community pages print from.
 *
 * Typed as `Record<Key, string>` over the key sets the CLI sends, so a key the
 * CLI starts sending that has no words here fails the build rather than
 * printing a token. Sentences about what HAPPENED are the CLI's (`story`,
 * lane sentences, next steps); these are labels.
 */

/** What finally happened to one flagged decision (`outcome_key`). */
export const DECISION_OUTCOMES = [
  "refused_before_run",
  "unsafe_may_have_run",
  "would_have_refused",
  "flagged_ran",
  "allowed",
  "checked_only",
  "unplaced",
] as const;
export type DecisionOutcomeKey = (typeof DECISION_OUTCOMES)[number];

/**
 * What finally happened to one message someone sent the agent. `not_seen` is
 * an outcome the record could not see (a chat that does not report the
 * agent's reply), never a recording fault, so it has its own words rather
 * than borrowing a decision's "not recorded". `unplaced` is still read, from
 * a CLI that predates `not_seen`.
 */
export const MESSAGE_OUTCOMES = ["stopped_by_innerwarden", "declined_by_agent", "answered", "not_seen", "unplaced"] as const;
export type MessageOutcomeKey = (typeof MESSAGE_OUTCOMES)[number];

export const OUTCOME_WORDS: Record<DecisionOutcomeKey | MessageOutcomeKey, string> = {
  refused_before_run: "Refused before it ran",
  would_have_refused: "Would have been refused",
  flagged_ran: "Flagged, and it ran",
  unsafe_may_have_run: "Judged unsafe, and it ran",
  allowed: "Allowed",
  checked_only: "Checked by hand",
  unplaced: "Outcome not recorded",
  stopped_by_innerwarden: "Stopped by InnerWarden",
  declined_by_agent: "Declined by your agent",
  answered: "Answered",
  not_seen: "Outcome not seen",
};

export function isDecisionOutcome(value: unknown): value is DecisionOutcomeKey {
  return typeof value === "string" && (DECISION_OUTCOMES as readonly string[]).includes(value);
}

export function isMessageOutcome(value: unknown): value is MessageOutcomeKey {
  return typeof value === "string" && (MESSAGE_OUTCOMES as readonly string[]).includes(value);
}

/**
 * Who made the decision (`decided_by`). A token this table does not know has
 * no words in the plain view; the technical view prints the token.
 */
export const DECIDER_WORDS: Record<string, string> = {
  rules: "InnerWarden's rules",
  graph: "a pattern across the session",
  warden: "the local model",
  llm: "your model's second opinion",
  user: "you",
};

export const CHANNELS = ["hook", "mcp", "check", "unknown"] as const;
export type Channel = (typeof CHANNELS)[number];

export function asChannel(value: unknown): Channel {
  return typeof value === "string" && (CHANNELS as readonly string[]).includes(value) ? (value as Channel) : "unknown";
}

/** What kind of thing was screened, for a case's eyebrow. */
export const CHANNEL_WORDS: Record<Channel, string> = {
  hook: "Shell command",
  mcp: "MCP tool call",
  check: "Checked by hand",
  unknown: "Command",
};

/** Who asked, when the record names no agent. Never a session id. */
export const WHO_WORDS: Record<Channel, string> = {
  hook: "An agent's shell hook",
  mcp: "An MCP connection",
  check: "You",
  unknown: "An agent",
};

/** One agent's state, or one control's. */
export const AGENT_STATES = ["refusing", "watching", "partial", "not_connected", "unsupported", "unknown"] as const;
export type AgentState = (typeof AGENT_STATES)[number];

export const STATE_WORDS: Record<AgentState, string> = {
  refusing: "Refusing",
  watching: "Watching only",
  partial: "Partly connected",
  not_connected: "Not connected",
  unsupported: "Cannot be connected yet",
  unknown: "Status unknown",
};

/** The host-wide mode in the header (`guard/meta`). */
export const MODE_WORDS: Record<"enforce" | "monitor" | "mixed" | "partial" | "not_configured" | "unknown", string> = {
  enforce: "Refusing",
  monitor: "Watching only",
  mixed: "Mixed modes",
  partial: "Partly connected",
  not_configured: "Not connected",
  unknown: "Status unknown",
};

export type PlatformOs = "macos" | "linux" | "windows" | "other";

export const PLATFORM_WORDS: Record<PlatformOs, string> = {
  macos: "this Mac",
  linux: "this machine",
  windows: "this PC",
  other: "this machine",
};

export function asPlatform(value: unknown): PlatformOs {
  return value === "macos" || value === "linux" || value === "windows" ? value : "other";
}

/** A session label, at most its first eight characters: never a whole UUID. */
export function shortSession(label: string): string {
  const clean = label.replace(/^session:/, "");
  return clean.length <= 8 ? clean : clean.slice(0, 8);
}
