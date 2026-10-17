import type { AgentsResponse, LocalAgent } from "../api";
import { guardrailIsConfiguredButUnobserved } from "../components/MachineIntelligence";
import { readAgentIdentity, readAgentNextStep, type AgentDecisionLine, type AgentIdentity, type AgentNextStep } from "./api";
import type { AgentState, TrustCounts } from "./words";

/**
 * One agent as a row: its state in one word, how the guard is wired to it,
 * and the one command the CLI says changes its state.
 *
 * The state is read from the same fields `MachineIntelligence` reads
 * (`guardrail.mode`, `setup_support`), and a configured-but-never-seen
 * guardrail is `unknown` here exactly as it is not an assurance there, so the
 * plain row and the technical card can never disagree.
 */
export type AgentRow = {
  id: string;
  name: string;
  mechanism: "hook" | "mcp" | undefined;
  state: AgentState;
  /** A person is needed: it is not, or only partly, behind the guard. */
  needsYou: boolean;
  next?: AgentNextStep;
  /**
   * For wiring whose decisions do not name this agent (a hook written before
   * hooks named their agent, or MCP servers wrapped before wrappers did): the
   * reconnect, in the wiring's own mode, that adds the name (the CLI's
   * `identity_step`).
   */
  identity?: AgentNextStep;
  /** `null` where the platform does not check (macOS). */
  running: boolean | null;
  lastScreenedAt?: string;
  /**
   * Who this agent is and what was decided about it. Absent unless the CLI
   * sent identity fields for it, and then the row is what it always was.
   */
  who?: AgentIdentity;
};

export function agentState(agent: LocalAgent): AgentState {
  const mode = agent.guardrail.mode;
  if (guardrailIsConfiguredButUnobserved(agent.guardrail)) return "unknown";
  if (mode === "enforce") return "refusing";
  if (mode === "monitor" || mode === "mixed") return "watching";
  if (mode === "partial") return "partial";
  if (mode === "not_configured") return agent.guardrail.setup_support === "unsupported" ? "unsupported" : "not_connected";
  return "unknown";
}

function mechanismOf(agent: LocalAgent): AgentRow["mechanism"] {
  if (agent.guardrail.mechanism === "pretooluse_hook") return "hook";
  if (agent.guardrail.mechanism === "mcp_proxy") return "mcp";
  return undefined;
}

/**
 * Whether an unconnected agent is really here. Only leftover files or a
 * borrowed MCP config is not an agent a person uses, and it must not turn
 * the page amber.
 */
function presentHere(agent: LocalAgent): boolean {
  if (agent.installed) return true;
  return agent.detected_by.some((evidence) => evidence === "process" || evidence === "executable_on_path");
}

export function agentRows(response: AgentsResponse | undefined): AgentRow[] {
  if (response === undefined) return [];
  return response.agents.map((agent) => {
    const state = agentState(agent);
    const next = readAgentNextStep((agent as LocalAgent & { next_step?: unknown }).next_step);
    const identity = readAgentNextStep((agent as LocalAgent & { identity_step?: unknown }).identity_step);
    const lastScreened = (agent.guardrail as { last_observed_at?: unknown }).last_observed_at;
    const who = readAgentIdentity(agent);
    return {
      id: agent.id,
      name: agent.display_name,
      mechanism: mechanismOf(agent),
      state,
      needsYou: state === "partial" || (state === "not_connected" && presentHere(agent)),
      ...(next === undefined ? {} : { next }),
      ...(identity === undefined ? {} : { identity }),
      running: agent.running,
      ...(typeof lastScreened === "string" && Number.isFinite(Date.parse(lastScreened)) ? { lastScreenedAt: lastScreened } : {}),
      ...(who === undefined ? {} : { who }),
    };
  });
}

export type AgentsSummary = {
  /**
   * Agents on this machine the guard could stand in front of: not the
   * unsupported, and not a configuration left behind by an agent that is not
   * here (its row says so; it is not one more agent to connect).
   */
  total: number;
  refusing: number;
  watching: number;
  needsYou: AgentRow[];
  /** Connectable, neither connected nor needing a person: a status not confirmed. */
  unconfirmed: AgentRow[];
};

export function agentsSummary(rows: readonly AgentRow[]): AgentsSummary {
  const connectable = rows.filter((row) => row.state !== "unsupported" && !(row.state === "not_connected" && !row.needsYou));
  const refusing = connectable.filter((row) => row.state === "refusing").length;
  const watching = connectable.filter((row) => row.state === "watching").length;
  const needsYou = connectable.filter((row) => row.needsYou);
  return {
    total: connectable.length,
    refusing,
    watching,
    needsYou,
    unconfirmed: connectable.filter((row) => row.state !== "refusing" && row.state !== "watching" && !row.needsYou),
  };
}

/** Names in a list the way a sentence says them: "A", "A and B", "A, B and C". */
export function nameList(names: readonly string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/**
 * The mode in one word, from the connected agents' own states: "Refusing"
 * when every one refuses, "Watching only" when none does, "Mixed modes" when
 * some do. `undefined` when no agent is connected: the host's own word
 * stands then.
 */
export function modeWord(rows: readonly AgentRow[]): "Refusing" | "Watching only" | "Mixed modes" | undefined {
  const refusing = rows.filter((row) => row.state === "refusing").length;
  const watching = rows.filter((row) => row.state === "watching").length;
  if (refusing + watching === 0) return undefined;
  if (watching === 0) return "Refusing";
  if (refusing === 0) return "Watching only";
  return "Mixed modes";
}

/**
 * Who refuses and who only watches, in one line, from the agents' own
 * states: "Claude Code watches only; Cursor and Gemini CLI refuse."
 */
export function modeLine(rows: readonly AgentRow[]): string | undefined {
  const refusing = rows.filter((row) => row.state === "refusing").map((row) => row.name);
  const watching = rows.filter((row) => row.state === "watching").map((row) => row.name);
  if (refusing.length === 0 && watching.length === 0) return undefined;
  if (refusing.length === 0) return "Every command is recorded; nothing is refused.";
  if (watching.length === 0) return `${nameList(refusing)} ${refusing.length === 1 ? "refuses" : "refuse"} a deny before it runs.`;
  return `${nameList(watching)} ${watching.length === 1 ? "watches" : "watch"} only; ${nameList(refusing)} ${refusing.length === 1 ? "refuses" : "refuse"}.`;
}

const DAY_MS = 86_400_000;

/**
 * How far the agents on this machine are backed, counted: one for each live
 * instance, and one for each agent with none that ran or was screened in the
 * last 24 hours (it counts as declared: only its own word says what it is).
 * `undefined` unless some agent has an instance at all, so a CLI that sends
 * no instances adds nothing to the Overview.
 */
export function trustCounts(rows: readonly AgentRow[], now: number): TrustCounts | undefined {
  if (!rows.some((row) => (row.who?.instances.length ?? 0) > 0)) return undefined;
  const counts: TrustCounts = { total: 0, confined: 0, observed: 0, declared: 0 };
  for (const row of rows) {
    const live = (row.who?.instances ?? []).filter((instance) => instance.live === true);
    for (const instance of live) {
      counts.total += 1;
      if (instance.trust === "host_verified") counts.confined += 1;
      else if (instance.trust === "observed") counts.observed += 1;
      else counts.declared += 1;
    }
    const active = row.running === true
      || (row.lastScreenedAt !== undefined && now - Date.parse(row.lastScreenedAt) <= DAY_MS);
    if (live.length === 0 && active) {
      counts.total += 1;
      counts.declared += 1;
    }
  }
  return counts.total === 0 ? undefined : counts;
}

/** Agents the person has not decided about yet, when the CLI says so. */
export function awaitingApproval(rows: readonly AgentRow[]): AgentRow[] {
  return rows.filter((row) => row.who?.lifecycle === "discovered");
}

function instances(n: number | undefined): string {
  return n === undefined ? "" : ` ${n === 1 ? "instance" : "instances"}`;
}

/**
 * One line of the Changes list, in words, from what the CLI wrote down. `name`
 * is the agent as the page shows it. A refused change is a line too.
 */
export function decisionSentence(line: AgentDecisionLine, name: string): string {
  const target = line.instanceId === undefined ? name : `instance ${line.instanceId.slice(0, 8)}`;
  if (line.result !== "success") {
    const code = line.result.replace(/^failure:\s*/, "") || "unknown";
    const did = {
      approve: `approve ${name}`,
      profile: `change the ${name} profile`,
      allow: `allow ${line.rule ?? "a rule"} for ${name}`,
      revoke: `revoke ${target}`,
    }[line.action];
    return `${line.by} tried to ${did}. Refused: ${code.replace(/_/g, " ")}.`;
  }
  switch (line.action) {
    case "approve":
      return `${line.by} approved ${name}${line.owner === undefined ? "" : `, owner ${line.owner}`}${line.profileAfter === undefined ? "" : `, profile ${line.profileAfter}`}.`;
    case "profile": {
      const change = line.profileBefore === undefined || line.profileAfter === undefined
        ? `changed the ${name} profile`
        : `changed the ${name} profile from ${line.profileBefore} to ${line.profileAfter}`;
      const applies = line.confined === undefined ? "" : ` Applies to ${line.confined} confined${instances(line.confined)}.`;
      return `${line.by} ${change}.${applies}`;
    }
    case "allow":
      return `${line.by} allowed ${line.rule ?? "a rule"} for ${name} (${line.instanceId === undefined ? "confined instances" : "this instance only"}).`;
    case "revoke":
      return `${line.by} revoked ${target}. Its history stays.`;
  }
}
