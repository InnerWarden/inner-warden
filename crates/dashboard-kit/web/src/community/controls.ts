import type { Part, Step } from "../components/viz";
import type { Protection, RecordHealth, RecordSpan } from "./api";
import { nameList, type AgentRow } from "./agentsView";

/**
 * What Community covers on this machine, control by control, and the ring
 * that counts them.
 *
 * Four states, each with one colour job: refusing (the accent: InnerWarden
 * acts), on (slate: working as set up, watching, recording), needs you
 * (amber: a person has to do something) and off (the faint track: off by
 * choice is not a problem, and the ring says "off", never "missing").
 *
 * A screening control is ONE row over several agents, so its state is one
 * word while its agents can differ: Tool-call screening is "needs you"
 * because Codex is partly connected, while Cursor and Gemini CLI refuse. The
 * control carries the agents that refuse (`refusingAgents`), so neither its
 * line, nor its ladder, nor the ring's legend can say nothing refuses while
 * something does.
 */
export type ControlState = "refusing" | "on" | "needs" | "off";

export type Control = {
  key: string;
  glyph?: "prompt" | "plug" | "file" | "cage" | "chat" | "bell" | "person";
  name: string;
  /** Words on the chip. */
  status: string;
  state: ControlState | "none";
  /** One plain line on what it does here. */
  line: string;
  /**
   * A command the CLI or the product documents, and what it is for. A
   * `template` holds a `<placeholder>` to fill in: shown, never copied.
   */
  command?: { label: string; command: string; template?: boolean };
  /** The four-step ladder, for the two screening controls. */
  ladder?: Step[];
  /** The agents this control refuses a deny for, whatever its one state says. */
  refusingAgents?: string[];
};

const SEEN_WITHIN_MS = 24 * 3_600_000;

function recent(at: string | undefined, now: number): boolean {
  return at !== undefined && Number.isFinite(Date.parse(at)) && now - Date.parse(at) <= SEEN_WITHIN_MS;
}

/**
 * The four steps of one screening control, per agent where they differ.
 *
 * "Seen working" reads the decision record, not only the agents that name
 * themselves in it: a hook written before hooks named their agent still
 * screens, and the channel's newest decision (`channelSeenAt`) says so.
 */
function screeningLadder(rows: readonly AgentRow[], channelSeenAt: string | undefined, now: number): Step[] {
  const connected = rows.some((row) => row.state === "refusing" || row.state === "watching" || row.state === "partial");
  const refusing = rows.filter((row) => row.state === "refusing");
  const others = rows.filter((row) => row.state !== "refusing");
  const seen = recent(channelSeenAt, now) || rows.some((row) => recent(row.lastScreenedAt, now));
  const everSeen = channelSeenAt !== undefined || rows.some((row) => row.lastScreenedAt !== undefined);
  const refusingWords = refusing.length === 0
    ? "watching only: nothing is refused"
    : others.length === 0
      ? "a deny is refused before it runs"
      : `${nameList(refusing.map((row) => row.name))} ${refusing.length === 1 ? "refuses" : "refuse"} a deny; ${nameList(others.map((row) => row.name))} ${others.length === 1 ? "does" : "do"} not`;
  return [
    { key: "connected", label: "Connected", mark: connected ? "done" : "not_applicable", words: connected ? "the guard is wired in" : "no agent is connected" },
    {
      key: "seen",
      label: "Seen working",
      mark: seen ? "done" : "unknown",
      words: seen ? "screened in the last 24 hours" : everSeen ? "nothing screened in the last 24 hours" : "nothing screened yet",
    },
    { key: "refusing", label: "Refusing", mark: refusing.length > 0 ? "done" : "not_applicable", words: refusingWords },
    { key: "checked", label: "Checked after", mark: "unknown", words: "not checked by a second part of InnerWarden" },
  ];
}

function screening(
  key: string,
  glyph: "prompt" | "plug",
  name: string,
  through: string,
  rows: readonly AgentRow[],
  channelSeenAt: string | undefined,
  now: number,
): Control {
  // What the rows count as agents here: not one the guard cannot wire, and
  // not a configuration left behind by an agent that is not on this machine.
  const present = rows.filter((row) => row.state !== "unsupported" && !(row.state === "not_connected" && !row.needsYou));
  if (present.length === 0) {
    return { key, glyph, name, status: "No agent found", state: "none", line: `No agent on this machine is screened ${through}.` };
  }
  const needs = present.filter((row) => row.needsYou);
  const refusing = present.filter((row) => row.state === "refusing");
  const watching = present.filter((row) => row.state === "watching");
  const names = nameList(present.map((row) => row.name));
  const firstNext = [...needs, ...watching, ...present].find((row) => row.next !== undefined)?.next;
  const command = firstNext === undefined ? undefined : { label: firstNext.label, command: firstNext.command };
  const ladder = screeningLadder(present, channelSeenAt, now);
  const refusingAgents = refusing.map((row) => row.name);
  const refuses = (list: readonly AgentRow[]) => `${nameList(list.map((row) => row.name))} ${list.length === 1 ? "refuses" : "refuse"} a deny.`;
  if (needs.length > 0) {
    const who = nameList(needs.map((row) => row.name));
    const notBehind = `${who} ${needs.length === 1 ? "is" : "are"} not fully behind the guard.`;
    const rest = present.filter((row) => !row.needsYou && row.state !== "refusing");
    const restWords = rest.length === 0 ? "" : ` ${nameList(rest.map((row) => row.name))} ${rest.length === 1 ? "watches" : "watch"} only.`;
    return {
      key, glyph, name,
      status: needs.every((row) => row.state === "partial") ? "Partly connected" : "Not connected",
      state: "needs",
      line: `${refusing.length === 0 ? "" : `${refuses(refusing)} `}${notBehind}${restWords}`,
      ...(command === undefined ? {} : { command }),
      ladder,
      refusingAgents,
    };
  }
  if (refusing.length === present.length) {
    return { key, glyph, name, status: "Refusing", state: "refusing", line: `${names}, ${through}. A deny is refused before it runs.`, ladder, refusingAgents };
  }
  if (watching.length === present.length) {
    return {
      key, glyph, name, status: "Watching only", state: "on",
      line: `${names}, ${through}. Every command is recorded; none is refused.`,
      ...(command === undefined ? {} : { command }),
      ladder,
      refusingAgents,
    };
  }
  const rest = present.filter((row) => row.state !== "refusing");
  return {
    key, glyph, name, status: "Some refuse", state: "on",
    line: `${refuses(refusing)} ${nameList(rest.map((row) => row.name))} ${rest.length === 1 ? "watches" : "watch"} only.`,
    ...(command === undefined ? {} : { command }),
    ladder,
    refusingAgents,
  };
}

export type ControlsInput = {
  agents: readonly AgentRow[];
  protection?: Protection;
  health?: RecordHealth;
  record?: RecordSpan;
  sinceWords?: string;
  /** `undefined` when the event log was not read: then no count is said. */
  messagesRecorded?: number;
  /** The newest decision each channel screened, named or not (`screened_by_channel`). */
  channelSeen?: { hook?: string; mcp?: string };
  now: number;
};

export function communityControls(input: ControlsInput): Control[] {
  const { agents, protection, health, now } = input;
  // An agent found here with no connection at all has no mechanism to sort it
  // by. It is not behind the guard, and that is said once, under Command
  // screening, rather than left out of both.
  const unwired = (row: AgentRow) => row.mechanism === undefined && row.needsYou;
  const controls: Control[] = [
    screening("command_screening", "prompt", "Command screening", "through its shell hook", agents.filter((row) => row.mechanism === "hook" || unwired(row)), input.channelSeen?.hook, now),
    screening("tool_call_screening", "plug", "Tool-call screening", "through the MCP proxy", agents.filter((row) => row.mechanism === "mcp"), input.channelSeen?.mcp, now),
  ];
  const recording = health?.recording ?? protection?.record.recording;
  controls.push({
    key: "decision_record",
    glyph: "file",
    name: "Decision record",
    status: recording === false ? "Not recording" : recording === true ? "Recording" : "Not read",
    state: recording === false ? "needs" : recording === true ? "on" : "none",
    line: recording === false
      ? "Decisions are not being written down. innerwarden status says why."
      : input.record === undefined
        ? "Every decision the guard makes is written to a local record."
        : `${input.record.decisions.toLocaleString("en-GB")} decisions${input.sinceWords === undefined ? "" : ` since ${input.sinceWords}`}. It keeps the newest and drops the oldest.`,
  });
  if (protection !== undefined) {
    controls.push({
      key: "ai_jail",
      glyph: "cage",
      name: "AI Jail",
      status: protection.jail.available ? "Ready" : "Not available here",
      state: protection.jail.available ? "on" : "off",
      line: protection.jail.available
        ? "Runs an agent in a jail when you ask for one, with the guard inside it for Claude Code; other agents get the walls."
        : "This machine has no sandbox the jail trusts.",
      ...(protection.jail.available
        ? { command: { label: "To start one, with your agent's own command in place of <command>:", command: "innerwarden contain -- <command>", template: true } }
        : {}),
    });
    controls.push(messagesControl(protection, input.messagesRecorded));
    controls.push({
      key: "alerts",
      glyph: "bell",
      name: "Alerts",
      status: protection.alerts.channels > 0 ? `On, ${protection.alerts.channels} ${protection.alerts.channels === 1 ? "channel" : "channels"}` : "Off",
      state: protection.alerts.channels > 0 ? "on" : "off",
      line: protection.alerts.channels > 0
        ? "A deny is sent where you asked: Telegram, Slack, Discord or a webhook."
        : "Sends a deny to Telegram, Slack, Discord or a webhook.",
      ...(protection.alerts.channels > 0 ? {} : { command: { label: "To turn them on:", command: "innerwarden notify" } }),
    });
    controls.push({
      key: "second_opinion",
      glyph: "person",
      name: "Second opinion",
      status: protection.secondOpinion.configured ? "On" : "Off",
      state: protection.secondOpinion.configured ? "on" : "off",
      line: protection.secondOpinion.configured
        ? "Your own model is asked about commands the rules cannot settle."
        : "Asks your own model about commands the rules cannot settle.",
      ...(protection.secondOpinion.configured
        ? {}
        : { command: { label: "To set it up, with your model's address and name:", command: "innerwarden llm set --url <URL> --model <MODEL>", template: true } }),
    });
    const suppress = protection.suppress;
    const mutes = suppress.muteRules + suppress.muteCategories;
    controls.push({
      key: "allow_list",
      name: "Allow and mute list",
      status: `${suppress.allow} ${suppress.allow === 1 ? "pattern" : "patterns"}, ${mutes} ${mutes === 1 ? "rule" : "rules"}`,
      state: "none",
      line: suppress.allow + mutes === 0 ? "Nothing is let through by hand." : "Commands they cover are not flagged.",
    });
  }
  return controls;
}

/**
 * Messages to the agent. Recording them goes through an OpenClaw chat
 * gateway: where there is none, `observe install` changes nothing and exits
 * 1, so it is not offered, and the control is not counted as "off" in a ring
 * that could never turn it on.
 */
function messagesControl(protection: Protection, recorded: number | undefined): Control {
  const base = { key: "messages", glyph: "chat" as const, name: "Messages to your agent" };
  if (protection.observe.installed) {
    return {
      ...base,
      status: "Recording",
      state: "on",
      line: `${recorded === undefined ? "" : `${recorded.toLocaleString("en-GB")} recorded. `}Records the risky ones; it does not block them.`,
    };
  }
  if (!protection.observe.available) {
    return {
      ...base,
      status: "Needs OpenClaw",
      state: "none",
      line: "Records the risky messages people send your agent through OpenClaw, a chat gateway. None is set up here.",
    };
  }
  return {
    ...base,
    status: "Off",
    state: "off",
    line: "Records the risky messages people send your agent through OpenClaw. It does not block them.",
    command: { label: "To turn it on:", command: "innerwarden observe install" },
  };
}

export type ControlCounts = Record<ControlState, number>;

export function controlCounts(controls: readonly Control[]): ControlCounts {
  const counts: ControlCounts = { refusing: 0, on: 0, needs: 0, off: 0 };
  for (const control of controls) if (control.state !== "none") counts[control.state] += 1;
  return counts;
}

/**
 * Whether some agent refuses a deny under a control whose one state is not
 * "refusing": the ring's legend then says "Some refuse" rather than
 * "0 Refusing" beside agents that refuse.
 */
export function someRefuse(controls: readonly Control[]): boolean {
  return controls.some((control) => control.state !== "refusing" && (control.refusingAgents?.length ?? 0) > 0);
}

/** The ring's parts, in reading order, each with its count in its label. */
export function controlRing(counts: ControlCounts): Part[] {
  return [
    { key: "refusing", value: counts.refusing, tone: "accent", label: `Refusing: ${counts.refusing}` },
    { key: "on", value: counts.on, tone: "watch", label: `On: ${counts.on}` },
    { key: "needs", value: counts.needs, tone: "attention", label: `Needs you: ${counts.needs}` },
    { key: "off", value: counts.off, tone: "off", label: `Off: ${counts.off}` },
  ];
}
