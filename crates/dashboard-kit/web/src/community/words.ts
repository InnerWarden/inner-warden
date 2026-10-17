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

// ---------------------------------------------------------------------------
// Agent identity: how far an agent's own word is backed, and what was decided
// ---------------------------------------------------------------------------

/**
 * How much stands behind who an agent says it is. One set of words on every
 * screen: `host_verified` (a jail it cannot leave, checked from inside the
 * jail), `observed` (in a jail whose launcher could be replaced) and
 * `declared` (only its own word).
 */
export const TRUSTS = ["declared", "observed", "host_verified"] as const;
export type Trust = (typeof TRUSTS)[number];

/** Worst first, so `TRUSTS.indexOf` orders them. */
export function worseTrust(a: Trust, b: Trust): Trust {
  return TRUSTS.indexOf(a) <= TRUSTS.indexOf(b) ? a : b;
}

export type TrustWord = { label: string; tooltip: string; tone: "watch" };

/**
 * Keyed `${trust}:${source}`. This page checks from inside the jail, so its
 * source is always `jail`; `declared` has the same words from any source.
 * Typed as a `Record` over the keys: a key with no words fails the build.
 */
export type TrustWordKey = "host_verified:jail" | "observed:jail" | "declared:jail" | "declared:sensor";

export const TRUST_WORDS: Record<TrustWordKey, TrustWord> = {
  "host_verified:jail": {
    label: "Confined",
    tooltip: "Runs inside a jail it cannot leave, checked from inside the jail.",
    tone: "watch",
  },
  "observed:jail": {
    label: "Observed",
    tooltip: "Runs in a jail, but its launcher could be replaced.",
    tone: "watch",
  },
  "declared:jail": { label: "Declared only", tooltip: "Only its own word says what it is.", tone: "watch" },
  "declared:sensor": { label: "Declared only", tooltip: "Only its own word says what it is.", tone: "watch" },
};

/**
 * Why an instance has the trust it has, by the code the hook wrote. The
 * trust each code can support is the ceiling: a payload that pairs a higher
 * trust with a code is read at the code's trust, and a code this table does
 * not know reads as `declared` with `UNKNOWN_REASON_WORDS`.
 */
export const REASON_CODES = [
  "confined_by_namespace",
  "launcher_not_trusted",
  "no_record",
  "record_unreadable",
  "record_writable",
  "no_namespace_on_backend",
  "host_namespace_recorded",
  "own_namespace_unreadable",
  "namespace_mismatch",
  "no_instance",
  "not_checked_yet",
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export const REASON_TRUST: Record<ReasonCode, Trust> = {
  confined_by_namespace: "host_verified",
  launcher_not_trusted: "observed",
  no_record: "declared",
  record_unreadable: "declared",
  record_writable: "declared",
  no_namespace_on_backend: "declared",
  host_namespace_recorded: "declared",
  own_namespace_unreadable: "declared",
  namespace_mismatch: "declared",
  no_instance: "declared",
  not_checked_yet: "declared",
};

export const REASON_WORDS: Record<ReasonCode, string> = {
  confined_by_namespace: "Runs in a jail it cannot leave, checked from inside the jail.",
  launcher_not_trusted: "The launcher is installed in your home folder, so any program you run could replace it: install it system-wide.",
  no_record: "Started without a jail: only its own word says what it is.",
  record_unreadable: "Its jail record could not be read, so it counts as unverified.",
  record_writable: "Its jail record could be changed from inside the jail, so it proves nothing.",
  no_namespace_on_backend: "A jail on macOS has no process namespace to check, so only its own word says what it is.",
  host_namespace_recorded: "Its jail record names the host's own namespace, so it describes no jail.",
  own_namespace_unreadable: "The hook could not read its own namespace, so it counts as unverified.",
  namespace_mismatch: "Its jail record belongs to another jail.",
  no_instance: "Started without a jail: only its own word says what it is.",
  not_checked_yet: "Not checked yet: nothing was screened since it started.",
};

export const UNKNOWN_REASON_WORDS = "Why it is unverified was not recorded.";

export function isReasonCode(value: unknown): value is ReasonCode {
  return typeof value === "string" && (REASON_CODES as readonly string[]).includes(value);
}

/** The trust a payload may be shown at: never above what its reason supports. */
export function effectiveTrust(claimed: Trust, reason: unknown): Trust {
  return isReasonCode(reason) ? worseTrust(claimed, REASON_TRUST[reason]) : "declared";
}

export function reasonWords(reason: unknown): string {
  return isReasonCode(reason) ? REASON_WORDS[reason] : UNKNOWN_REASON_WORDS;
}

/** The second axis: what the person decided about a type of agent. */
export const LIFECYCLES = ["discovered", "approved", "revoked"] as const;
export type Lifecycle = (typeof LIFECYCLES)[number];

/** `approved` has no chip: it is a line, "Approved by {who}, {when}". */
export const LIFECYCLE_WORDS: Record<Lifecycle, string | undefined> = {
  discovered: "Waits for your approval",
  approved: undefined,
  revoked: "Revoked",
};

export function asLifecycle(value: unknown): Lifecycle | undefined {
  return typeof value === "string" && (LIFECYCLES as readonly string[]).includes(value) ? (value as Lifecycle) : undefined;
}

/** How a launched agent's guard answers: `LaunchRecord.mode`. */
export const LAUNCH_MODES = ["monitor", "enforce", "block-review"] as const;
export type LaunchMode = (typeof LAUNCH_MODES)[number];

export const LAUNCH_MODE_WORDS: Record<LaunchMode, string> = {
  monitor: "Records only",
  enforce: "Refuses",
  "block-review": "Refuses, reviews too",
};

export function asLaunchMode(value: unknown): LaunchMode | undefined {
  return typeof value === "string" && (LAUNCH_MODES as readonly string[]).includes(value) ? (value as LaunchMode) : undefined;
}

/** Which rule layer decided, and its verdict. */
export const LAYERS = ["hard", "general", "agent_type", "instance"] as const;
export type Layer = (typeof LAYERS)[number];
export const VERDICTS = ["allow", "review", "deny"] as const;
export type Verdict = (typeof VERDICTS)[number];

export function asLayer(value: unknown): Layer | undefined {
  return typeof value === "string" && (LAYERS as readonly string[]).includes(value) ? (value as Layer) : undefined;
}

export function asVerdict(value: unknown): Verdict | undefined {
  return typeof value === "string" && (VERDICTS as readonly string[]).includes(value) ? (value as Verdict) : undefined;
}

export type LayerKey = "hard:deny" | "general:deny" | "general:review" | "general:allow" | "agent_type:allow" | "agent_type:deny" | "instance:allow" | "instance:deny";

/** `{agent}` is the agent's name as the page shows it. A pair not listed has no words. */
export const LAYER_WORDS: Record<LayerKey, string> = {
  "hard:deny": "Refused by a product rule no setting changes. Nothing to change here.",
  "general:deny": "Refused by your general rules.",
  "general:review": "Sent for review by your general rules.",
  "general:allow": "Allowed by your general rules.",
  "agent_type:allow": "Allowed by the {agent} profile, because this instance runs confined.",
  "agent_type:deny": "Refused by the {agent} profile.",
  "instance:allow": "Allowed by an exception for this instance only.",
  "instance:deny": "Refused by an exception for this instance.",
};

export const WITHHELD_WORDS =
  "The {agent} profile would allow this, but this instance does not run confined, so your general rules decided.";

export function layerWords(layer: Layer, verdict: Verdict, agent: string, withheld: boolean): string | undefined {
  const base = (LAYER_WORDS as Record<string, string | undefined>)[`${layer}:${verdict}`];
  if (base === undefined) return undefined;
  const text = base.replace("{agent}", agent);
  return withheld ? `${text} ${WITHHELD_WORDS.replace("{agent}", agent)}` : text;
}

/** One line in the Changes list (P6), by what was done. */
export const AGENT_DECISION_ACTIONS = ["approve", "profile", "allow", "revoke"] as const;
export type AgentDecisionAction = (typeof AGENT_DECISION_ACTIONS)[number];

export function asDecisionAction(value: unknown): AgentDecisionAction | undefined {
  return typeof value === "string" && (AGENT_DECISION_ACTIONS as readonly string[]).includes(value) ? (value as AgentDecisionAction) : undefined;
}

/** What the page says about the agent count: "3 agents on this machine." */
export type TrustCounts = { total: number; confined: number; observed: number; declared: number };

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/**
 * The Overview's one sentence about how far the agents are backed. Pure:
 * counts in, words out. Parts that are zero are left out.
 */
export function agentTrustSentence(counts: TrustCounts, place: string): string {
  const head = `${counts.total} ${plural(counts.total, "agent", "agents")} on ${place}.`;
  const parts: string[] = [];
  if (counts.confined > 0) parts.push(`${counts.confined} ${plural(counts.confined, "runs", "run")} confined`);
  if (counts.observed > 0) {
    parts.push(`${counts.observed} ${plural(counts.observed, "runs", "run")} in a jail whose launcher could be replaced`);
  }
  if (counts.declared > 0) {
    const its = counts.declared === 1 ? "its" : "their";
    const it = counts.declared === 1 ? "it is" : "they are";
    parts.push(`${counts.declared} ${plural(counts.declared, "runs", "run")} as you, and only ${its} own word says what ${it}`);
  }
  return parts.length === 0 ? head : `${head} ${parts.join("; ")}.`;
}

export const CONFLICT_WORDS =
  "Its hook says the {agent} profile allowed this, but its jail could not be confirmed from inside, so this is not taken as an allowance.";

/**
 * The "Decided by" line of a case. A layer that allows only because an
 * instance runs confined is never worded as such for an instance that does
 * not: the label is untrusted, so the line says it could not be confirmed.
 */
export function layerLine(
  layer: Layer,
  verdict: Verdict,
  trust: Trust,
  agent: string,
  withheld: boolean,
): { text: string; conflict: boolean } | undefined {
  if ((layer === "agent_type" || layer === "instance") && verdict === "allow" && trust !== "host_verified") {
    return { text: CONFLICT_WORDS.replace("{agent}", agent), conflict: true };
  }
  const text = layerWords(layer, verdict, agent, withheld);
  return text === undefined ? undefined : { text, conflict: false };
}
