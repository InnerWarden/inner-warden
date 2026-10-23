import { formatCount } from "../presentation";
import type { AgentFacts, AgentNextStep, RecordSpan, RefusalDay } from "./api";
import { agentSeen, isConnected } from "./controls";
import { nameList } from "./agentsView";
import { restartFor, type RestartWords } from "./restart";
import { ENFORCE_MEANS, MONITOR_MEANS, type DecisionOutcomeKey } from "./words";

/**
 * The Overview's verdict band, decided outside React: the facts the page
 * read go in, the one answer comes out. The first row that matches wins
 * (spec 6.1, rows 0 to 9).
 *
 * The rules it keeps:
 *  - "Connected" (the config) and "screened" (what was seen) are never
 *    merged: an agent is connected when its mode is monitor, enforce, partial
 *    or mixed, and seen only when a screening came through after its
 *    settings last changed.
 *  - What could not be read is said as such (rows 0 and 3), never as off and
 *    never as zero.
 *  - Monitor is a fine place to stay: row 8 never says "you should".
 *  - Row 9 says "set to refuse" (the config) beside a counted number, and
 *    never that anything is protected.
 *  - Every step that changes an agent's config is followed by that agent's
 *    restart words.
 */

export type VerdictRow = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
export type VerdictTone = "unknown" | "exposed" | "needs" | "watch" | "stopped";

/** One step in the band: what it is for, one command, and one line on what it does. */
export type BandStep = { label: string; command?: string; line?: string };

/** An agent to restart after a step, with the words for it. */
export type Restart = { agent: string; words: RestartWords };

export type VerdictAction = {
  /** Steps to take, each followed by the restarts it needs. */
  steps: { step: BandStep; restarts: Restart[] }[];
  /** Restarts that follow no command (row 6). */
  restarts: Restart[];
  /** A sentence after them (row 6). */
  after?: string;
  /** The way back (row 8). */
  back?: BandStep;
  /** Said when there is nothing to do (row 9). */
  nothing?: string;
  /** A link to the Agents page, when there is no command to give. */
  link?: "agents";
};

export type Verdict = {
  row: VerdictRow;
  tone: VerdictTone;
  /** Absent only for row 0, which draws a fixed-height skeleton. */
  headline?: string;
  lines: string[];
  action?: VerdictAction;
};

export type VerdictInput = {
  metaStatus: "loading" | "ready" | "error";
  meta?: { exposed?: boolean };
  /** `guard/record-health`, when it was read. */
  health?: { recording: boolean; summary?: string; sinceUnix?: number; lostActions?: number };
  /** `guard/agents`: `undefined` until read. */
  agents?: readonly AgentFacts[];
  /** The agents could not be read and nothing was ever read. */
  agentsFailed: boolean;
  unnamed?: { hook?: string; mcp?: string };
  /** The guard's log by day, oldest first; absent from an older CLI or when not read. */
  days?: readonly RefusalDay[];
  /** `false` when the guard's log could not be read: then no count comes from it. */
  logReadable?: boolean;
  /** The decision record's own counts, the fallback when the log's days are not there. */
  record?: RecordCounts;
  /** Alert channels set up; `undefined` when not read. */
  alertChannels?: number;
  now: number;
  /** A time of day, "14:02"; the reader's own clock by default. */
  clock?: (ms: number) => string;
};

export type RecordCounts = { refused: number; wouldHave: number; span: string };

/**
 * A time of day in the reader's own clock, "14:02". Built per call, so it
 * follows the zone the page runs in rather than the one it was loaded in.
 */
export function clockTime(ms: number): string {
  return new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
}

/** "about 18 hours": how long a span is, in words a sentence can carry. */
export function spanWords(fromMs: number, toMs: number): string {
  const minutes = Math.max(1, Math.round((toMs - fromMs) / 60_000));
  if (minutes < 90) return minutes === 1 ? "about a minute" : `about ${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  if (hours < 36) return `about ${hours} hours`;
  const days = Math.round(hours / 24);
  return `about ${days} days`;
}

/** The refused and would-have counts of the decision record, with the span they cover. */
export function recordCounts(
  record: RecordSpan | undefined,
  byOutcome: Partial<Record<DecisionOutcomeKey, number>> | undefined,
  now: number,
): RecordCounts | undefined {
  if (record === undefined || byOutcome === undefined || record.oldestAt === undefined) return undefined;
  const to = record.newestAt === undefined ? now : Date.parse(record.newestAt);
  return {
    refused: byOutcome.refused_before_run ?? 0,
    wouldHave: byOutcome.would_have_refused ?? 0,
    span: spanWords(Date.parse(record.oldestAt), to),
  };
}

/** The last `n` days of the guard's log, summed. */
export function lastDays(days: readonly RefusalDay[], n = 7): { blocked: number; wouldBlock: number } {
  return days.slice(-n).reduce(
    (sum, day) => ({ blocked: sum.blocked + day.blocked, wouldBlock: sum.wouldBlock + day.wouldBlock }),
    { blocked: 0, wouldBlock: 0 },
  );
}

export { isConnected };

/** The shared switch's line, as the CLI words it, for a CLI that sends no step with it. */
export const SHARED_ENFORCE_LINE = "Switches every connected agent from Monitor to Enforce: a deny is refused before it runs.";

const STATUS_STEP: BandStep = { label: "To see why:", command: "innerwarden status", line: "Says why, and what to do." };

function restartOf(agent: AgentFacts): Restart {
  return { agent: agent.name, words: restartFor(agent.id, agent.name, agent.restart) };
}

function bandStep(step: AgentNextStep, label = step.label): BandStep {
  return { label, command: step.command, line: step.line };
}

function emptyAction(): VerdictAction {
  return { steps: [], restarts: [] };
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

export function overviewVerdict(input: VerdictInput): Verdict {
  const clock = input.clock ?? clockTime;

  // 0: nothing read yet.
  if (input.metaStatus === "loading" && input.meta === undefined) return { row: 0, tone: "unknown", lines: [] };

  // 1: open to the network.
  if (input.meta?.exposed === true) {
    return {
      row: 1,
      tone: "exposed",
      headline: "This dashboard is open to the network",
      lines: ["Anyone who can reach this machine can read your agents' commands here."],
      action: {
        ...emptyAction(),
        steps: [{
          step: {
            label: "To close it, stop the dashboard where it runs and start it again with:",
            command: "innerwarden dashboard",
            line: "Without --expose it answers on this machine only.",
          },
          restarts: [],
        }],
      },
    };
  }

  // 2: not recording.
  const health = input.health;
  if (health?.recording === false) {
    const lines: string[] = [];
    if (health.summary !== undefined) lines.push(health.summary);
    if (health.lostActions !== undefined) {
      const lost = `${formatCount(health.lostActions)} ${plural(health.lostActions, "action was", "actions were")} not recorded.`;
      lines.push(health.sinceUnix === undefined ? lost.charAt(0).toUpperCase() + lost.slice(1) : `Since ${clock(health.sinceUnix * 1_000)}, ${lost}`);
    }
    return {
      row: 2,
      tone: "needs",
      headline: "Decisions are not being recorded",
      lines,
      action: { ...emptyAction(), steps: [{ step: STATUS_STEP, restarts: [] }] },
    };
  }

  // 0 again: the agents have not answered yet.
  if (input.agents === undefined && !input.agentsFailed) return { row: 0, tone: "unknown", lines: [] };

  // 3: could not read.
  if ((input.agents === undefined && input.agentsFailed) || (input.metaStatus === "error" && input.meta === undefined)) {
    return {
      row: 3,
      tone: "unknown",
      headline: "Could not read whether your agents are connected",
      lines: [`The dashboard did not answer at ${clock(input.now)}. Nothing on this page is counted as zero.`],
      action: { ...emptyAction(), steps: [{ step: STATUS_STEP, restarts: [] }] },
    };
  }

  const agents = input.agents ?? [];
  const connected = agents.filter(isConnected);

  // 4: no agent connected.
  if (connected.length === 0) {
    const found = agents.filter((agent) => agent.mode === "not_configured" && agent.supported && agent.present);
    if (found.length === 0) {
      return {
        row: 4,
        tone: "needs",
        headline: "No AI agent is connected yet",
        lines: ["No supported agent was found on this machine."],
        action: { ...emptyAction(), link: "agents" },
      };
    }
    const first = found.find((agent) => agent.nextStep !== undefined);
    return {
      row: 4,
      tone: "needs",
      headline: "No AI agent is connected yet",
      lines: [`Found here: ${found.map((agent) => agent.name).join(", ")}.`],
      action: first?.nextStep === undefined
        ? { ...emptyAction(), link: "agents" }
        : { ...emptyAction(), steps: [{ step: bandStep(first.nextStep), restarts: [restartOf(first)] }] },
    };
  }

  // 5: one is only partly connected.
  const partial = connected.find((agent) => agent.mode === "partial");
  if (partial !== undefined) {
    return {
      row: 5,
      tone: "needs",
      headline: `${partial.name} is only partly connected`,
      lines: partial.nextStep === undefined ? [] : [partial.nextStep.line],
      action: partial.nextStep === undefined
        ? { ...emptyAction(), link: "agents" }
        : { ...emptyAction(), steps: [{ step: bandStep(partial.nextStep), restarts: [restartOf(partial)] }] },
    };
  }

  // 6: connected, and nothing seen since the settings changed.
  const considered = connected.filter((agent) => agentSeen(agent, input.unnamed) !== "nothing_to_screen");
  if (considered.length > 0 && considered.every((agent) => agentSeen(agent, input.unnamed) === "not_seen")) {
    return {
      row: 6,
      tone: "unknown",
      headline: "Connected, but nothing screened yet",
      lines: considered.map((agent) =>
        agent.configChangedAt === undefined
          ? `Nothing has come through the guard from ${agent.name} yet.`
          : `Nothing has come through the guard since ${agent.name}'s settings changed at ${clock(Date.parse(agent.configChangedAt))}.`,
      ),
      action: {
        ...emptyAction(),
        restarts: considered.map(restartOf),
        after: "Then ask it to run any command. It shows here within seconds.",
      },
    };
  }

  const refusing = connected.filter((agent) => agent.mode === "enforce");
  const recording = connected.filter((agent) => agent.mode !== "enforce");
  const useDays = input.days !== undefined && input.logReadable !== false;
  const sums = useDays ? lastDays(input.days ?? []) : undefined;
  const sharedServed = connected.find((agent) => agent.nextStep?.command === "innerwarden enforce")?.nextStep;
  const sharedStep = (label: string): BandStep => ({
    label,
    command: "innerwarden enforce",
    line: sharedServed?.line ?? SHARED_ENFORCE_LINE,
  });

  // 7: different modes. An agent whose own servers or hooks differ ("mixed")
  // refuses some calls and not others, so it is never counted as either.
  const mixed = connected.filter((agent) => agent.mode === "mixed");
  if ((refusing.length > 0 && recording.length > 0) || mixed.length > 0) {
    const monitorOnly = connected.filter((agent) => agent.mode === "monitor");
    const parts: string[] = [];
    if (refusing.length > 0) {
      parts.push(`${formatCount(refusing.length)} of ${formatCount(connected.length)} agents ${plural(refusing.length, "is", "are")} set to refuse a deny.`);
    }
    if (monitorOnly.length > 0) {
      parts.push(`${nameList(monitorOnly.map((agent) => agent.name))} only ${plural(monitorOnly.length, "records", "record")}.`);
    }
    if (mixed.length > 0) {
      parts.push(`${nameList(mixed.map((agent) => agent.name))} ${plural(mixed.length, "refuses", "refuse")} a deny for some calls only.`);
    }
    const perAgent = recording.every((agent) => agent.modeSteps?.enforce !== undefined);
    return {
      row: 7,
      tone: "watch",
      headline: parts.join(" "),
      lines: [MONITOR_MEANS],
      action: perAgent
        ? {
            ...emptyAction(),
            steps: recording.map((agent) => ({ step: bandStep(agent.modeSteps!.enforce!), restarts: [restartOf(agent)] })),
          }
        : { ...emptyAction(), steps: [{ step: sharedStep("When you want a deny refused:"), restarts: connected.map(restartOf) }] },
    };
  }

  const n = connected.length;

  // 8: every connected agent in monitor.
  if (refusing.length === 0) {
    const lines = [MONITOR_MEANS];
    if (sums !== undefined) lines.push(`Last 7 days: ${formatCount(sums.wouldBlock)} would have been refused.`);
    else if (input.record !== undefined) lines.push(`In the record (${input.record.span}): ${formatCount(input.record.wouldHave)} would have been refused.`);
    return {
      row: 8,
      tone: "watch",
      headline: n === 1
        ? "Your AI agent is connected. Monitor: nothing is refused."
        : `Your ${formatCount(n)} AI agents are connected. Monitor: nothing is refused.`,
      lines,
      action: {
        ...emptyAction(),
        steps: [{ step: sharedStep("When you want a deny refused:"), restarts: connected.map(restartOf) }],
        back: { label: "Back to monitor any time:", command: "innerwarden dry-run" },
      },
    };
  }

  // 9: every connected agent set to refuse a deny.
  const lines = [ENFORCE_MEANS];
  if (sums !== undefined) {
    lines.push(sums.blocked === 0 ? "None refused in the last 7 days." : `Last 7 days: ${formatCount(sums.blocked)} refused before they ran.`);
  } else if (input.record !== undefined) {
    lines.push(`In the record (${input.record.span}): ${formatCount(input.record.refused)} refused before they ran.`);
  }
  return {
    row: 9,
    tone: "stopped",
    headline: n === 1
      ? "Your AI agent is connected and set to refuse a deny."
      : `Your ${formatCount(n)} AI agents are connected and set to refuse a deny.`,
    lines,
    action: input.alertChannels === 0
      ? {
          ...emptyAction(),
          steps: [{
            step: { label: "To hear about a refusal:", command: "innerwarden notify", line: "Sets up a chat or webhook alert for a deny." },
            restarts: [],
          }],
        }
      : { ...emptyAction(), nothing: "Nothing to do." },
  };
}

// ---------------------------------------------------------------------------
// Protection's mode box (spec 6.2, section 1): the same band, compact, about
// the mode alone. Both definitions are always beside it (the page draws them).
// ---------------------------------------------------------------------------

/** The way back from Enforce, in the CLI's own terms, for a CLI that sends no step for it. */
export const SHARED_DRY_RUN_LINE = "Switches every connected agent from Enforce to Monitor: every command is checked and recorded, and none is stopped.";

export type ModeBoxInput = {
  /** `guard/agents`: `undefined` until read. */
  agents?: readonly AgentFacts[];
  /** The agents could not be read and nothing was ever read. */
  failed: boolean;
  now: number;
  clock?: (ms: number) => string;
};

/**
 * The mode the connected agents are set to, and the one switch: Monitor for
 * all, Enforce for all, or mixed, each with every connected agent's restart
 * words and the way back. A partly connected agent is named; its step is its
 * own row's. What could not be read is said, never counted as monitor.
 */
export function modeBox(input: ModeBoxInput): Verdict {
  const clock = input.clock ?? clockTime;
  if (input.agents === undefined && !input.failed) return { row: 0, tone: "unknown", lines: [] };
  if (input.agents === undefined) {
    return {
      row: 3,
      tone: "unknown",
      headline: "The mode could not be read",
      lines: [`The dashboard did not answer at ${clock(input.now)}. No agent is counted as in monitor or enforce.`],
      action: { ...emptyAction(), steps: [{ step: STATUS_STEP, restarts: [] }] },
    };
  }
  const connected = input.agents.filter(isConnected);
  if (connected.length === 0) {
    return {
      row: 4,
      tone: "needs",
      headline: "No AI agent is connected yet",
      lines: ["Connect one on Agents. It joins in monitor."],
      action: { ...emptyAction(), link: "agents" },
    };
  }
  const enforce = connected.filter((agent) => agent.mode === "enforce");
  const monitor = connected.filter((agent) => agent.mode === "monitor");
  const mixed = connected.filter((agent) => agent.mode === "mixed");
  const partial = connected.filter((agent) => agent.mode === "partial");
  const restarts = connected.map(restartOf);
  const partialLines = partial.map((agent) => `${agent.name} is only partly connected. Its step is under Screening.`);
  const sharedServed = connected.find((agent) => agent.nextStep?.command === "innerwarden enforce")?.nextStep;
  const toEnforce: BandStep = { label: "When you want a deny refused:", command: "innerwarden enforce", line: sharedServed?.line ?? SHARED_ENFORCE_LINE };
  const toMonitor: BandStep = { label: "To go back to monitor:", command: "innerwarden dry-run", line: SHARED_DRY_RUN_LINE };
  const forAll = (set: readonly AgentFacts[], word: string) =>
    partial.length === 0 && set.length > 1
      ? `${word} for all ${formatCount(set.length)} agents.`
      : `${word} for ${nameList(set.map((agent) => agent.name))}.`;

  if (enforce.length + monitor.length + mixed.length === 0) {
    // Only partly connected agents: the mode is not theirs to say yet.
    return {
      row: 5,
      tone: "needs",
      headline: partial.length === 1 ? `${partial[0].name} is only partly connected` : `${nameList(partial.map((agent) => agent.name))} are only partly connected`,
      lines: ["Its step is under Screening. Once connected, it runs in the mode it was connected in."],
    };
  }
  if (enforce.length === 0 && mixed.length === 0) {
    return {
      row: 8,
      tone: "watch",
      headline: forAll(monitor, "Monitor"),
      lines: partialLines,
      action: {
        ...emptyAction(),
        steps: [{ step: toEnforce, restarts }],
        back: { label: "Back to monitor any time:", command: "innerwarden dry-run" },
      },
    };
  }
  if (monitor.length === 0 && mixed.length === 0) {
    return {
      row: 9,
      tone: "stopped",
      headline: forAll(enforce, "Enforce"),
      lines: partialLines,
      action: {
        ...emptyAction(),
        steps: [{ step: toMonitor, restarts }],
        back: { label: "Back to enforce any time:", command: "innerwarden enforce" },
      },
    };
  }
  const parts: string[] = [];
  if (enforce.length > 0) parts.push(`${nameList(enforce.map((agent) => agent.name))} ${plural(enforce.length, "is", "are")} set to refuse a deny`);
  if (monitor.length > 0) parts.push(`${nameList(monitor.map((agent) => agent.name))} ${plural(monitor.length, "is", "are")} in monitor`);
  if (mixed.length > 0) parts.push(`${nameList(mixed.map((agent) => agent.name))} ${plural(mixed.length, "refuses", "refuse")} a deny for some calls only`);
  const recording = [...monitor, ...mixed];
  const perAgent = recording.every((agent) => agent.modeSteps?.enforce !== undefined);
  return {
    row: 7,
    tone: "watch",
    headline: `Mixed: ${parts.join(", ")}.`,
    lines: partialLines,
    // A switch for one agent restarts that agent; the way back for every
    // agent restarts them all, so it is a step with its own restart words.
    action: perAgent
      ? {
          ...emptyAction(),
          steps: [
            ...recording.map((agent) => ({ step: bandStep(agent.modeSteps!.enforce!), restarts: [restartOf(agent)] })),
            { step: { ...toMonitor, label: "Back to monitor for every agent:" }, restarts },
          ],
        }
      : { ...emptyAction(), steps: [{ step: toEnforce, restarts }], back: { label: "Back to monitor for every agent:", command: "innerwarden dry-run" } },
  };
}
