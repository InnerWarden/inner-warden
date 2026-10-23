import { formatCount } from "../presentation";
import type { AgentFacts, AgentNextStep, History, McpCounts, Protection } from "./api";
import { gatewayRestart, restartFor, type RestartWords } from "./restart";
import { shortDay } from "./words";

// ---------------------------------------------------------------------------
// One agent's screening, in six states (spec 6.2). "Connected" is the config;
// "screened" is what was seen; the two are never merged, so nothing here
// says an agent refuses anything until a screening came through the guard
// after its settings last changed.
// ---------------------------------------------------------------------------

/**
 * Whether the guard has seen an agent working since its settings changed.
 *
 * `not_reported`: no screening names it, and one on its channel names nobody
 * (or the CLI did not say), so it could be this agent's: nothing is said
 * either way. `nothing_to_screen`: a proxy with no local MCP server, which is
 * a fact about the agent, not a fault.
 */
export type Seen = "seen" | "not_seen" | "not_reported" | "nothing_to_screen";

type SeenFacts = Pick<AgentFacts, "mechanism" | "lastObservedAt" | "configChangedAt" | "mcp">;

/**
 * Connected: wired to the guard (the config), whatever was seen. Monitor,
 * enforce, partly connected, or mixed (its own hooks or servers differ).
 */
export function isConnected(agent: Pick<AgentFacts, "mode">): boolean {
  return agent.mode === "monitor" || agent.mode === "enforce" || agent.mode === "partial" || agent.mode === "mixed";
}

function later(a: string, b: string): boolean {
  return Date.parse(a) > Date.parse(b);
}

export function agentSeen(agent: SeenFacts, unnamed: { hook?: string; mcp?: string } | undefined): Seen {
  if (agent.mechanism === "mcp" && agent.mcp?.stdio === 0) return "nothing_to_screen";
  if (agent.lastObservedAt !== undefined) {
    return agent.configChangedAt === undefined || later(agent.lastObservedAt, agent.configChangedAt) ? "seen" : "not_seen";
  }
  if (agent.mechanism === undefined || unnamed === undefined) return "not_reported";
  const unnamedAt = unnamed[agent.mechanism];
  if (unnamedAt === undefined) return "not_seen";
  // A decision that names nobody, made before the settings changed, cannot
  // show the new settings working.
  if (agent.configChangedAt !== undefined && !later(unnamedAt, agent.configChangedAt)) return "not_seen";
  return "not_reported";
}

/** The six states one agent's screening can be in. */
export const SCREENING_STATES = ["refusing", "monitor", "needs_you", "unknown", "off", "not_available"] as const;
export type ScreeningState = (typeof SCREENING_STATES)[number];

/**
 * - `refusing`: Enforce, and seen working since its settings changed.
 * - `monitor`: Monitor, and seen working since. Monitor never refuses.
 * - `needs_you`: partly connected, or a proxy with a local server not wrapped.
 * - `unknown`: connected but not seen since its settings changed, or a row
 *   that could not be read. Never-screened is unknown, never "on".
 * - `off`: not connected. Neutral: off by choice is not a problem.
 * - `not_available`: the guard cannot wire this agent.
 */
export function screeningState(agent: AgentFacts | undefined, unnamed: { hook?: string; mcp?: string } | undefined): ScreeningState {
  if (agent === undefined) return "unknown";
  if (!agent.supported) return "not_available";
  if (agent.mode === "not_configured") return "off";
  if (agent.mode === "unknown") return "unknown";
  if (agent.mode === "partial" || (agent.mcp !== undefined && agent.mcp.wrapped < agent.mcp.stdio)) return "needs_you";
  if (agentSeen(agent, unnamed) !== "seen") return "unknown";
  // A mixed agent refuses some calls and not others: it is not counted as refusing.
  return agent.mode === "enforce" ? "refusing" : "monitor";
}

/** The pill each state is drawn with. */
export const SCREENING_PILL: Record<ScreeningState, "enforce" | "monitor" | "needs" | "unknown" | "off" | "not_available"> = {
  refusing: "enforce",
  monitor: "monitor",
  needs_you: "needs",
  unknown: "unknown",
  off: "off",
  not_available: "not_available",
};

/** The words on that pill. */
export const SCREENING_WORDS: Record<ScreeningState, string> = {
  refusing: "Refusing a deny",
  monitor: "Monitor",
  needs_you: "Needs you",
  unknown: "Unknown",
  off: "Not connected",
  not_available: "Not available",
};

/** Whether a state counts as refusing a deny: only `refusing`, never monitor. */
export function countsAsRefusing(state: ScreeningState): boolean {
  return state === "refusing";
}

// ---------------------------------------------------------------------------
// The Protection page's screening rows (spec 6.2, section 2).
// ---------------------------------------------------------------------------

/** One connected agent as Protection lists it: its state, what was seen, and the one step for it. */
export type ScreeningRow = {
  agent: AgentFacts;
  state: ScreeningState;
  seen: Seen;
  /** A step for this agent only, or the step that finishes connecting it. */
  step?: AgentNextStep;
  /** The agent's restart words: every row step changes this agent's config, so they follow it. */
  restart: RestartWords;
};

/**
 * The step a row offers: a switch for this agent only when the CLI sends one
 * (it does so only where the switch is proven), the step that finishes
 * connecting a partly connected agent, or none. Never a guess.
 */
function rowStep(agent: AgentFacts, state: ScreeningState): AgentNextStep | undefined {
  if (agent.mode === "enforce") return agent.modeSteps?.monitor;
  if (agent.mode === "monitor") return agent.modeSteps?.enforce;
  if (agent.mode === "mixed") return agent.modeSteps?.enforce ?? agent.modeSteps?.monitor;
  if (agent.mode === "partial" || state === "needs_you") return agent.nextStep;
  return undefined;
}

/** One row per connected or partly connected agent, in the order the CLI sent them. */
export function screeningRows(agents: readonly AgentFacts[], unnamed: { hook?: string; mcp?: string } | undefined): ScreeningRow[] {
  return agents.filter(isConnected).map((agent) => {
    const state = screeningState(agent, unnamed);
    const step = rowStep(agent, state);
    return {
      agent,
      state,
      seen: agentSeen(agent, unnamed),
      ...(step === undefined ? {} : { step }),
      restart: restartFor(agent.id, agent.name, agent.restart),
    };
  });
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/**
 * How a proxy agent's MCP servers are wrapped, in lines: "2 of 3 local servers
 * wrapped." and, where some are remote, that Community does not screen those.
 */
export function mcpLines(mcp: McpCounts | undefined): string[] {
  if (mcp === undefined) return [];
  const lines: string[] = [];
  lines.push(
    mcp.stdio === 0
      ? "No local MCP server to wrap."
      : `${formatCount(mcp.wrapped)} of ${formatCount(mcp.stdio)} local ${plural(mcp.stdio, "server", "servers")} wrapped.`,
  );
  if (mcp.remote > 0) {
    lines.push(`${formatCount(mcp.remote)} remote ${plural(mcp.remote, "server is", "servers are")} not screened (Community wraps local servers only).`);
  }
  return lines;
}

const SUMMARY_PARTS: { state: ScreeningState; words: (n: number) => string }[] = [
  { state: "refusing", words: () => "refusing a deny" },
  { state: "monitor", words: () => "in monitor" },
  { state: "needs_you", words: (n) => plural(n, "needs you", "need you") },
  { state: "unknown", words: () => "not yet seen working" },
];

/**
 * The screening half of Protection's summary sentence, counted by state:
 * "Screening: 1 agent refusing a deny, 1 in monitor, 1 not yet seen working."
 * `undefined` rows: the agents were not read, which is said, never a zero.
 */
export function screeningSummary(rows: readonly ScreeningRow[] | undefined): string {
  if (rows === undefined) return "Screening: not read.";
  if (rows.length === 0) return "Screening: no agent is connected yet.";
  const parts: string[] = [];
  for (const { state, words } of SUMMARY_PARTS) {
    const n = rows.filter((row) => row.state === state).length;
    if (n === 0) continue;
    parts.push(parts.length === 0 ? `${formatCount(n)} ${plural(n, "agent", "agents")} ${words(n)}` : `${formatCount(n)} ${words(n)}`);
  }
  return `Screening: ${parts.join(", ")}.`;
}

// ---------------------------------------------------------------------------
// The optional defences (spec 6.2, section 4). Each is off until the person
// turns it on, and each says its one step. What could not be read is "Not
// read", never off.
// ---------------------------------------------------------------------------

export type OptionalKey = "jail" | "alerts" | "second-opinion" | "messages";
/** The pill an optional defence is drawn with: off is neutral, never a warning. */
export type OptionalPill = "on" | "needs" | "unknown" | "off" | "not_available";

export type OptionalStep = { label: string; command: string; line?: string };

export type OptionalControl = {
  key: OptionalKey;
  name: string;
  pill: OptionalPill;
  /** The words on the pill. */
  words: string;
  /** What it does here now, in one sentence. */
  line: string;
  /** More lines from the CLI, as sent (the jail's advice). */
  more: string[];
  /** How the summary sentence names it. */
  summary: string;
  step?: OptionalStep;
  /** Whoever must be restarted after the step, with the words for it. */
  restarts: { agent: string; words: RestartWords }[];
  /** A tip below the step (the alias that starts Claude Code in the jail). */
  tip?: string;
};

/**
 * The AI Jail's optional extra, off unless the person adds it: the alias that
 * starts Claude Code in the jail every time (the same line `innerwarden setup`
 * offers).
 */
export const JAIL_ALIAS_WORDS =
  "To start Claude Code in it every time, add alias claude='innerwarden contain --identity -- claude' to your shell.";

/** The jail's template step: drawn to fill in, never copied as it is. */
export const JAIL_STEP: OptionalStep = {
  label: "To start an agent in the jail:",
  command: "innerwarden contain -- <command>",
  line: "Put your agent's own command in place of <command>. The guard runs inside the jail for Claude Code; other agents get the jail's walls.",
};

function notRead(key: OptionalKey, name: string, summary: string): OptionalControl {
  return { key, name, pill: "unknown", words: "Not read", line: "Not read: the dashboard did not answer for it.", more: [], summary: `${summary} not read`, restarts: [] };
}

/**
 * The AI Jail. "Ready" only when the CLI ran the checks a jail needs and they
 * passed (`checks_pass === true`); not checked yet, or a CLI that does not
 * say, reads "Not checked here yet", never ready and never off.
 */
export function jailControl(jail: Protection["jail"] | undefined, claudeHere: boolean): OptionalControl {
  const name = "AI Jail";
  if (jail === undefined) return notRead("jail", name, "AI Jail");
  const base = { key: "jail" as const, name, more: [] as string[], restarts: [] };
  if (!jail.available) {
    return { ...base, pill: "not_available", words: "Not available", line: "Not available on this system.", summary: "AI Jail not available" };
  }
  const backend = jail.backend === undefined ? "" : ` (${jail.backend})`;
  const offered = { step: JAIL_STEP, ...(claudeHere ? { tip: JAIL_ALIAS_WORDS } : {}) };
  if (jail.checksPass === true) {
    return { ...base, ...offered, pill: "on", words: "Ready", line: `Ready: the checks a jail needs pass on this machine${backend}.`, summary: "AI Jail ready" };
  }
  if (jail.checksPass === false) {
    return {
      ...base,
      ...offered,
      pill: "needs",
      words: "Needs you",
      line: "Needs you: a jail does not start here yet.",
      more: jail.advice,
      summary: "AI Jail needs you",
    };
  }
  const found = jail.backend === undefined ? "" : ` (${jail.backend} found)`;
  return { ...base, ...offered, pill: "unknown", words: "Not checked here yet", line: `Not checked here yet${found}.`, summary: "AI Jail not checked here yet" };
}

/** Alerts, by how many channels are set up. Never a channel's name or address (CJC-090-J012). */
export function alertsControl(alerts: Protection["alerts"] | undefined): OptionalControl {
  const name = "Alerts";
  const channels = alerts?.channels;
  if (channels === undefined) return notRead("alerts", name, "alerts");
  const base = { key: "alerts" as const, name, more: [] as string[], restarts: [] };
  if (channels === 0) {
    return {
      ...base,
      pill: "off",
      words: "Off",
      line: "Off: no alert channel is set up.",
      summary: "alerts off",
      step: { label: "To turn them on:", command: "innerwarden notify", line: "Sets up a chat or webhook alert for a deny." },
    };
  }
  const set = `${formatCount(channels)} ${plural(channels, "channel", "channels")}`;
  return { ...base, pill: "on", words: "On", line: `On: ${set} set up. A deny is sent; reviews only if you set that up.`, summary: `alerts on (${set})` };
}

/** A second opinion from the person's own model. */
export function secondOpinionControl(second: Protection["secondOpinion"] | undefined): OptionalControl {
  const name = "Second opinion";
  if (second === undefined) return notRead("second-opinion", name, "second opinion");
  const base = { key: "second-opinion" as const, name, more: [] as string[], restarts: [] };
  if (second.configured) {
    const provider = second.provider === undefined ? "" : ` (${second.provider})`;
    return {
      ...base,
      pill: "on",
      words: "On",
      line: `On${provider}: your own model is asked about commands the rules cannot settle.`,
      summary: "second opinion on",
    };
  }
  return {
    ...base,
    pill: "off",
    words: "Off",
    line: "Off.",
    summary: "second opinion off",
    step: {
      label: "To set it up, with your model's address and name:",
      command: "innerwarden llm set --url <URL> --model <MODEL>",
      line: "Asks your own model about commands the rules cannot settle.",
    },
  };
}

/**
 * Messages people send the agent. Recording them goes through an OpenClaw
 * chat gateway: where there is none, `observe install` changes nothing, so it
 * is not offered. A count is said only when the guard's log was read.
 */
export function messagesControl(protection: Protection | undefined, history: History | undefined): OptionalControl {
  const name = "Messages to your agent";
  if (protection === undefined) return notRead("messages", name, "messages");
  const base = { key: "messages" as const, name, more: [] as string[], restarts: [] as OptionalControl["restarts"] };
  if (protection.observe.installed) {
    const since = history?.since === undefined ? undefined : shortDay(history.since);
    const recorded = history === undefined || !history.readable
      ? "Recording."
      : `Recording: ${formatCount(history.messages.recorded)} ${plural(history.messages.recorded, "message", "messages")}${since === undefined ? "" : ` since ${since}`}.`;
    return { ...base, pill: "on", words: "Recording", line: recorded, summary: "messages recording" };
  }
  if (!protection.observe.available) {
    return { ...base, pill: "not_available", words: "Not available", line: "Not available here: needs OpenClaw.", summary: "messages not available" };
  }
  return {
    ...base,
    pill: "off",
    words: "Off",
    line: "Off.",
    summary: "messages off",
    step: {
      label: "To turn it on:",
      command: "innerwarden observe install",
      line: "Records the risky messages people send your agent through OpenClaw. It does not block them.",
    },
    restarts: [gatewayRestart()],
  };
}

/**
 * The optional half of the summary sentence: "Optional: AI Jail not checked
 * here yet, alerts off, second opinion on." Messages are named only where
 * they can be recorded.
 */
export function optionalSummary(controls: readonly OptionalControl[]): string {
  const named = controls.filter((control) => control.key !== "messages" || control.pill !== "not_available");
  return `Optional: ${named.map((control) => control.summary).join(", ")}.`;
}
