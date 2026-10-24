import type { AgentsResponse, LocalAgent } from "../api";
import { guardrailIsConfiguredButUnobserved } from "../components/MachineIntelligence";
import { readAgentIdentity, readAgentNextStep, readAgentsFacts, type AgentDecisionLine, type AgentFacts, type AgentIdentity, type AgentNextStep, type AgentsFacts } from "./api";
import { agentSeen, isConnected } from "./controls";
import { atWords, type AgentState, type PlatformOs, type TrustCounts } from "./words";

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

/** Names in a list the way a sentence says them: "A", "A and B", "A, B and C". */
export function nameList(names: readonly string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
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

// ---------------------------------------------------------------------------
// The Agents page (spec 6.4), decided outside React.
// ---------------------------------------------------------------------------

/** The agents' answer, read; `undefined` while none came, and an answer that cannot be read counts as failed. */
export function factsOf(data: unknown): { facts?: AgentsFacts; unreadable: boolean; loading: boolean } {
  if (data === undefined) return { unreadable: false, loading: false };
  // The CLI answers while its first look at this machine is still running.
  if ((data as { availability?: unknown }).availability === "loading") return { unreadable: false, loading: true };
  try {
    return { facts: readAgentsFacts(data), unreadable: false, loading: false };
  } catch {
    return { unreadable: true, loading: false };
  }
}

export type AgentGroups = {
  /** Wired to the guard, or set up with a mode that could not be read. */
  connected: AgentFacts[];
  /** Found here and not connected; a configuration whose agent is not here is listed too, and says so. */
  found: AgentFacts[];
  /** Found, with no hook or MCP configuration the guard can use: only the jail's walls are on offer. */
  jailOnly: AgentFacts[];
};

/** The page's three groups, each in the order the CLI sent. */
export function agentGroups(agents: readonly AgentFacts[]): AgentGroups {
  const jailOnly = agents.filter((agent) => !agent.supported);
  const connected = agents.filter((agent) => agent.supported && (isConnected(agent) || agent.mode === "unknown"));
  const found = agents.filter((agent) => agent.supported && agent.mode === "not_configured");
  return { connected, found, jailOnly };
}

/** What automatic setup is doing, in one line, from the policy the CLI read; `undefined` when it did not say. */
export function autoSetupLine(auto: AgentsFacts["autoConnect"]): string | undefined {
  if (auto === undefined) return undefined;
  if (!auto.enabled) return "Automatic setup is off.";
  const every = auto.everySeconds === undefined ? "" : `, checked every ${auto.everySeconds} s`;
  return `Automatic setup is on: a new agent joins in monitor${every}.`;
}

/** The step that turns automatic setup on, in monitor (a command the CLI answers). */
export const AUTO_SETUP_STEP: AgentNextStep = {
  label: "To turn it on, in monitor:",
  command: "innerwarden agents auto-connect --monitor",
  line: "While this dashboard runs, each new agent it finds is connected in monitor.",
};

/**
 * Said when an agent's settings changed and nothing came through the guard
 * since: the person restarts it (only they can), and the page says so. Never
 * where a screening that names nobody could be this agent's (`not_reported`),
 * and never for a proxy with no local server to screen.
 */
export function restartPrompt(agent: AgentFacts, unnamed: { hook?: string; mcp?: string } | undefined, now: number): string | undefined {
  if (!isConnected(agent) || agent.configChangedAt === undefined) return undefined;
  if (agentSeen(agent, unnamed) !== "not_seen") return undefined;
  return `Its settings changed ${atWords(Date.parse(agent.configChangedAt), now)} and nothing has come through since.`;
}

/**
 * Whether the agent's program is on this machine, for the technical view.
 * A configuration found without its program says so.
 */
export function programWords(agent: Pick<AgentFacts, "installed" | "detectedBy">): string {
  if (agent.installed) return "Program on PATH: found";
  const configuration = (agent.detectedBy ?? []).some((evidence) => evidence.includes("configuration"));
  return configuration ? "Program on PATH: not found (its configuration file was found)" : "Program on PATH: not found";
}

const PLATFORM_NAME: Record<PlatformOs, string> = { macos: "macOS", linux: "Linux", windows: "Windows", other: "this platform" };

/** Whether the agent runs, for the technical view: `null` is not read here, never "not running". */
export function runningWords(running: boolean | null, os: PlatformOs): string {
  if (running === null) return `Running: not read on ${PLATFORM_NAME[os]}`;
  return running ? "Running: yes" : "Running: no";
}
