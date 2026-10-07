import type { AgentsResponse, LocalAgent } from "../api";
import { guardrailIsConfiguredButUnobserved } from "../components/MachineIntelligence";
import { readAgentNextStep, type AgentNextStep } from "./api";
import type { AgentState } from "./words";

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
