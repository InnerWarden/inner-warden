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
  /** A command the CLI or the product documents, and what it is for. */
  command?: { label: string; command: string };
  /** The four-step ladder, for the two screening controls. */
  ladder?: Step[];
};

const SEEN_WITHIN_MS = 24 * 3_600_000;

function screeningLadder(rows: readonly AgentRow[], now: number): Step[] {
  const connected = rows.some((row) => row.state === "refusing" || row.state === "watching" || row.state === "partial");
  const refusing = rows.length > 0 && rows.every((row) => row.state === "refusing");
  const seen = rows.some((row) => row.lastScreenedAt !== undefined && now - Date.parse(row.lastScreenedAt) <= SEEN_WITHIN_MS);
  return [
    { key: "connected", label: "Connected", mark: connected ? "done" : "not_applicable", words: connected ? "the guard is wired in" : "no agent is connected" },
    { key: "seen", label: "Seen working", mark: seen ? "done" : "unknown", words: seen ? "screened a command in the last 24 hours" : "not reported by this build" },
    { key: "refusing", label: "Refusing", mark: refusing ? "done" : "not_applicable", words: refusing ? "a deny is refused before it runs" : "watching only: nothing is refused" },
    { key: "checked", label: "Checked after", mark: "unknown", words: "not checked by a second part of InnerWarden" },
  ];
}

function screening(
  key: string,
  glyph: "prompt" | "plug",
  name: string,
  through: string,
  rows: readonly AgentRow[],
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
  const behind = present.filter((row) => !row.needsYou);
  const firstNext = [...needs, ...watching, ...present].find((row) => row.next !== undefined)?.next;
  const command = firstNext === undefined ? undefined : { label: firstNext.label, command: firstNext.command };
  if (needs.length > 0) {
    const who = nameList(needs.map((row) => row.name));
    return {
      key, glyph, name,
      status: needs.every((row) => row.state === "partial") ? "Partly connected" : "Not connected",
      state: "needs",
      line: `${who} ${needs.length === 1 ? "is" : "are"} not fully behind the guard.${behind.length === 0 ? "" : ` ${nameList(behind.map((row) => row.name))} ${behind.length === 1 ? "is" : "are"}.`}`,
      ...(command === undefined ? {} : { command }),
      ladder: screeningLadder(present, now),
    };
  }
  if (refusing.length === present.length) {
    return { key, glyph, name, status: "Refusing", state: "refusing", line: `${names}, ${through}. A deny is refused before it runs.`, ladder: screeningLadder(present, now) };
  }
  if (watching.length === present.length) {
    return {
      key, glyph, name, status: "Watching only", state: "on",
      line: `${names}, ${through}. Every command is recorded; none is refused.`,
      ...(command === undefined ? {} : { command }),
      ladder: screeningLadder(present, now),
    };
  }
  return {
    key, glyph, name, status: "Some refuse", state: "on",
    line: `${names}, ${through}. ${nameList(refusing.map((row) => row.name))} ${refusing.length === 1 ? "refuses" : "refuse"} a deny; the rest watch.`,
    ...(command === undefined ? {} : { command }),
    ladder: screeningLadder(present, now),
  };
}

export type ControlsInput = {
  agents: readonly AgentRow[];
  protection?: Protection;
  health?: RecordHealth;
  record?: RecordSpan;
  sinceWords?: string;
  messagesRecorded?: number;
  now: number;
};

export function communityControls(input: ControlsInput): Control[] {
  const { agents, protection, health, now } = input;
  // An agent found here with no connection at all has no mechanism to sort it
  // by. It is not behind the guard, and that is said once, under Command
  // screening, rather than left out of both.
  const unwired = (row: AgentRow) => row.mechanism === undefined && row.needsYou;
  const controls: Control[] = [
    screening("command_screening", "prompt", "Command screening", "through its shell hook", agents.filter((row) => row.mechanism === "hook" || unwired(row)), now),
    screening("tool_call_screening", "plug", "Tool-call screening", "through the MCP proxy", agents.filter((row) => row.mechanism === "mcp"), now),
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
        ? "Runs an agent in a jail with the guard inside it, when you ask for one."
        : "This machine has no sandbox the jail trusts.",
      ...(protection.jail.available ? { command: { label: "To start one:", command: "innerwarden contain -- <command>" } } : {}),
    });
    controls.push({
      key: "messages",
      glyph: "chat",
      name: "Messages to your agent",
      status: protection.observe.installed ? "Recording" : "Off",
      state: protection.observe.installed ? "on" : "off",
      line: protection.observe.installed
        ? `${(input.messagesRecorded ?? 0).toLocaleString("en-GB")} recorded. Records the risky ones; it does not block them.`
        : "Records the risky messages people send your agent. It does not block them.",
      ...(protection.observe.installed ? {} : { command: { label: "To turn it on:", command: "innerwarden observe install" } }),
    });
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
      ...(protection.secondOpinion.configured ? {} : { command: { label: "To set it up:", command: "innerwarden llm set" } }),
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

export type ControlCounts = Record<ControlState, number>;

export function controlCounts(controls: readonly Control[]): ControlCounts {
  const counts: ControlCounts = { refusing: 0, on: 0, needs: 0, off: 0 };
  for (const control of controls) if (control.state !== "none") counts[control.state] += 1;
  return counts;
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
