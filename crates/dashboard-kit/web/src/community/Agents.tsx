import { fetchAgents, type AgentsResponse } from "../api";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { agentRows, type AgentRow } from "./agentsView";
import { readUnnamedByChannel } from "./api";
import { CARD, Chip, CopyCommand, PageHeader, Skeleton, StaleLine, Unreadable, type ChipTone } from "./parts";
import { usePolled } from "./poll";
import { STATE_WORDS, type AgentState } from "./words";

export const AGENTS_PAGE_POLL_MS = 30_000;

const STATE_TONE: Record<AgentState, ChipTone> = {
  refusing: "accent",
  watching: "watch",
  partial: "needs",
  not_connected: "needs",
  unsupported: "off",
  unknown: "watch",
};

const MECHANISM_WORDS = { hook: "Shell hook", mcp: "MCP proxy" } as const;

/** What automatic setup is doing, in one line, from the policy the CLI read. */
export function autoConnectLine(response: AgentsResponse | undefined): { text: string; command?: string } | undefined {
  const auto = response?.auto_connect;
  if (auto === undefined || auto.status === "unavailable" || auto.enabled === null) return undefined;
  if (auto.enabled) {
    return { text: "Automatic setup is on: while this dashboard runs, it connects new agents in monitor mode, checking every minute." };
  }
  return { text: "Automatic setup is off. This turns it on, in monitor mode:", command: "innerwarden agents auto-connect --monitor" };
}

function rowLine(row: AgentRow): string | undefined {
  if (row.state === "unsupported") return "This agent has no hook or MCP configuration the guard can use yet.";
  if (row.state === "not_connected" && !row.needsYou) return "Found a configuration for it; the agent itself was not found on this machine.";
  return undefined;
}

const CONNECTED: readonly AgentRow["state"][] = ["refusing", "watching", "partial"];

/**
 * When the guard last screened something for this agent, by what it screens
 * (a shell hook screens commands, the MCP proxy tool calls), or that nothing
 * has been screened yet. Said only from facts: "nothing yet" only where the
 * channel holds no decision that names nobody (`unnamed`), since such a
 * decision could be this agent's; otherwise no line.
 */
export function screenedLine(row: AgentRow, unnamed: { hook?: string; mcp?: string } | undefined): { at?: string; words: string } | undefined {
  if (!CONNECTED.includes(row.state) || row.mechanism === undefined) return undefined;
  const thing = row.mechanism === "mcp" ? "tool call" : "command";
  if (row.lastScreenedAt !== undefined) return { at: row.lastScreenedAt, words: `Last screened a ${thing}` };
  if (unnamed !== undefined && unnamed[row.mechanism] === undefined) return { words: `No ${thing} screened yet.` };
  return undefined;
}

/**
 * Community's Agents: one row per AI agent on this machine, whether the guard
 * is in front of it, and the one command (the CLI's, printed as sent) that
 * changes that. The spec sheet of each agent is the technical view's.
 */
export function CommunityAgents() {
  const agents = usePolled(fetchAgents, AGENTS_PAGE_POLL_MS, "agents");
  const rows = agentRows(agents.data);
  const auto = autoConnectLine(agents.data);
  const unnamed = readUnnamedByChannel(agents.data);
  return (
    <div className="min-w-0 space-y-5" data-tour="agents">
      <PageHeader
        eyebrow="Agents"
        title="Agents"
        titleId="agents-title"
        description="AI agents on this machine, and whether the guard is in front of each one."
      />
      {auto === undefined ? null : (
        <div className="text-sm leading-6 text-slate-600">
          <p>{auto.text}</p>
          {auto.command === undefined ? null : <CopyCommand command={auto.command} className="mt-1 max-w-xl" />}
        </div>
      )}
      {agents.stale ? <StaleLine onRetry={agents.refresh} /> : null}
      {agents.data === undefined ? (
        agents.error === undefined ? <Skeleton className="h-48" /> : <Unreadable title="Agents did not answer" onRetry={agents.refresh} />
      ) : agents.data.availability === "loading" ? (
        <Skeleton className="h-48" />
      ) : rows.length === 0 ? (
        <div className={CARD}>
          <p className="text-sm font-semibold text-slate-900">No AI agent found on this machine</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">When one is installed, this finds it and connects it:</p>
          <CopyCommand command="innerwarden agents connect --all --monitor" className="mt-2 max-w-xl" />
        </div>
      ) : (
        <section aria-labelledby="agents-list-title" className={CARD}>
          <h2 id="agents-list-title" className="sr-only">Agents on this machine</h2>
          <ul className="divide-y divide-slate-100">
            {rows.map((row) => (
              <li key={row.id} data-agent={row.id} data-agent-state={row.state} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0 sm:flex-row sm:gap-6">
                <div className="min-w-0 sm:w-56 sm:shrink-0">
                  <p className="text-sm font-semibold text-slate-950">{row.name}</p>
                  <p className="text-xs text-slate-500">{row.mechanism === undefined ? "No connection it can use" : MECHANISM_WORDS[row.mechanism]}</p>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <Chip tone={row.state === "not_connected" && !row.needsYou ? "off" : STATE_TONE[row.state]} label={STATE_WORDS[row.state]} />
                    {(() => {
                      const screened = screenedLine(row, unnamed);
                      if (screened === undefined) return null;
                      return (
                        <span data-screened className="text-xs text-slate-600">
                          {screened.words}
                          {screened.at === undefined ? null : <> <When at={screened.at} relative /></>}
                        </span>
                      );
                    })()}
                    {row.running === true ? <span className="text-xs text-slate-600">Running now</span> : null}
                  </div>
                  {rowLine(row) === undefined ? null : <p className="mt-1 text-sm leading-6 text-slate-600">{rowLine(row)}</p>}
                  {[row.next, row.identity].map((step) =>
                    step === undefined ? null : (
                      <div key={step.command} className="mt-2 max-w-xl">
                        <p className="text-xs font-semibold text-slate-700">{step.label}</p>
                        <CopyCommand command={step.command} className="mt-1" />
                        <p className="mt-1 text-xs leading-5 text-slate-600">{step.line}</p>
                      </div>
                    ),
                  )}
                </div>
              </li>
            ))}
          </ul>
          {rows.some((row) => row.running === null) ? (
            <TechnicalOnly>
              <p className="mt-3 text-xs text-slate-500">Whether an agent is running is not checked on this platform.</p>
            </TechnicalOnly>
          ) : null}
        </section>
      )}
      <TechnicalOnly>
        <MachineIntelligence edition="community" showAgents showTokens={false} tones="neutral" />
      </TechnicalOnly>
    </div>
  );
}
