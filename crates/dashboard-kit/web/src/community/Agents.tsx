import type { CommunityScreenContext } from "../App";
import { fetchAgents, type AgentsResponse } from "../api";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { agentRows, decisionSentence, type AgentRow } from "./agentsView";
import { fetchHistory, readProfilesFile, readUnnamedByChannel, type AgentNextStep, type LocalInstance } from "./api";
import { OfferLine } from "./Offer";
import { agentsOffer } from "./offers";
import { CARD, Chip, CopyCommand, PageHeader, Skeleton, StaleLine, Unreadable, type ChipTone } from "./parts";
import { usePolled } from "./poll";
import { LAUNCH_MODE_WORDS, LIFECYCLE_WORDS, reasonWords, STATE_WORDS, TRUST_WORDS, type AgentState, type Trust } from "./words";

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
export function CommunityAgents({ context }: { context?: CommunityScreenContext } = {}) {
  const agents = usePolled(fetchAgents, AGENTS_PAGE_POLL_MS, "agents");
  const rows = agentRows(agents.data);
  const auto = autoConnectLine(agents.data);
  const unnamed = readUnnamedByChannel(agents.data);
  const profilesFile = readProfilesFile(agents.data);
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
      {profilesFile === undefined ? null : (
        <div data-profiles-invalid className={CARD}>
          <Chip tone="needs" label="Invalid profiles file" />
          <p className="mt-2 text-sm leading-6 text-slate-700">{profilesFile.sentence}</p>
        </div>
      )}
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
                    {row.who?.trust === undefined ? null : <TrustChip trust={row.who.trust} />}
                    {row.who?.lifecycle === undefined || LIFECYCLE_WORDS[row.who.lifecycle] === undefined ? null : (
                      <span data-lifecycle={row.who.lifecycle}>
                        <Chip tone={row.who.lifecycle === "discovered" ? "needs" : "off"} label={LIFECYCLE_WORDS[row.who.lifecycle] ?? ""} />
                      </span>
                    )}
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
                  {row.who === undefined ? null : <WhoBlock row={row} context={context} />}
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
      {rows.some((row) => (row.who?.instances.length ?? 0) > 0) ? (
        <OfferLine offer={agentsOffer()} installed={context?.meta?.active_defence_installed === true} />
      ) : null}
      {rows.some((row) => row.who !== undefined) ? <AgentChanges names={new Map(rows.map((row) => [row.id, row.name]))} /> : null}
      <TechnicalOnly>
        <MachineIntelligence edition="community" showAgents showTokens={false} tones="neutral" />
      </TechnicalOnly>
    </div>
  );
}

/** The trust chip: the words and the tooltip are the closed table's, the tone the page's grey. */
function TrustChip({ trust }: { trust: Trust }) {
  const word = TRUST_WORDS[`${trust}:jail`];
  return (
    <span data-trust={trust} title={word.tooltip}>
      <Chip tone={word.tone} label={word.label} />
    </span>
  );
}

function StepBlock({ step }: { step: AgentNextStep }) {
  return (
    <div className="mt-2 max-w-xl">
      <p className="text-xs font-semibold text-slate-700">{step.label}</p>
      <CopyCommand command={step.command} className="mt-1" />
      <p className="mt-1 text-xs leading-5 text-slate-600">{step.line}</p>
    </div>
  );
}

/**
 * What the CLI says about who one agent is: its profile and owner, why it is
 * or is not confined and how to start it in a jail, what was decided about it,
 * and its instances. Every part is drawn only from a field that was sent.
 */
function WhoBlock({ row, context }: { row: AgentRow; context?: CommunityScreenContext }) {
  const who = row.who;
  if (who === undefined) return null;
  const approvedBy = who.lifecycle === "approved" && who.lifecycleBy !== undefined;
  return (
    <div data-agent-identity className="mt-2 space-y-2">
      {who.profile === undefined && who.owner === undefined && !approvedBy ? null : (
        <p className="text-xs leading-5 text-slate-600">
          {who.profile === undefined ? null : <span data-profile>Profile: {who.profile.label}</span>}
          {who.owner === undefined ? null : <span data-owner>{who.profile === undefined ? "" : " · "}Owner: {who.owner}</span>}
          {approvedBy ? (
            <span data-approved>
              {who.profile === undefined && who.owner === undefined ? "" : " · "}Approved by {who.lifecycleBy}
              {who.lifecycleAt === undefined ? null : <>, <When at={who.lifecycleAt} relative /></>}
            </span>
          ) : null}
        </p>
      )}
      {who.trust !== undefined && who.trust !== "host_verified" ? (
        <p data-trust-reason className="text-xs leading-5 text-slate-600">{reasonWords(who.trustReason)}</p>
      ) : null}
      {who.confine === undefined ? null : <div data-confine-step><StepBlock step={who.confine} /></div>}
      {who.decisionSteps.map((step) => (
        <StepBlock key={`${step.label}${step.command}`} step={step} />
      ))}
      {who.instances.length > 0 ? (
        <ul data-instances className="divide-y divide-slate-100 rounded-lg border border-slate-100">
          {who.instances.map((instance) => (
            <InstanceRow key={instance.instanceId} instance={instance} profileLabel={who.profile?.label} context={context} />
          ))}
        </ul>
      ) : who.trust !== undefined ? (
        <p data-no-instance className="text-xs leading-5 text-slate-500">No instance started in a jail yet.</p>
      ) : null}
      {who.moreInstances > 0 ? (
        <p className="text-xs text-slate-500">{who.moreInstances} more {who.moreInstances === 1 ? "instance" : "instances"} not listed.</p>
      ) : null}
    </div>
  );
}

function InstanceRow({ instance, profileLabel, context }: { instance: LocalInstance; profileLabel?: string; context?: CommunityScreenContext }) {
  const place = [
    instance.user === undefined ? undefined : instance.project === undefined ? instance.user : `${instance.user} in ${instance.project}`,
    instance.user === undefined ? instance.project : undefined,
  ].find((part) => part !== undefined);
  const when = instance.live === false ? "Ended" : "Last active";
  const at = instance.lastActivityAt ?? (instance.live === false ? undefined : instance.startedAt);
  return (
    <li data-instance={instance.instanceId} data-instance-trust={instance.trust} data-live={instance.live === undefined ? undefined : String(instance.live)} className="px-3 py-2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-600">
        <TrustChip trust={instance.trust} />
        {place === undefined ? null : <span>{place}</span>}
        {instance.mode === undefined ? null : <span>· {LAUNCH_MODE_WORDS[instance.mode]}</span>}
        {profileLabel === undefined ? null : <span>· {profileLabel}</span>}
        {at === undefined ? null : <span>· {when} <When at={at} relative /></span>}
      </div>
      {instance.trust === "host_verified" ? null : (
        <p className="mt-1 text-xs leading-5 text-slate-600">{reasonWords(instance.trustReason)}</p>
      )}
      {instance.sessions.length === 0 ? null : (
        <p className="mt-1 flex flex-wrap items-center gap-x-2 text-xs text-slate-600">
          <span>Sessions:</span>
          {instance.sessions.map((session) =>
            session.caseId !== undefined && context !== undefined ? (
              <button
                key={session.session}
                type="button"
                onClick={() => context.navigate("activity", { decision: session.caseId ?? "" })}
                className="font-semibold text-cyan-700 hover:text-cyan-900"
              >
                {session.session} (open case)
              </button>
            ) : (
              <span key={session.session}>{session.session}{session.caseId === undefined ? "" : " (open case)"}</span>
            ),
          )}
        </p>
      )}
      <TechnicalOnly>
        <dl className="mt-1 space-y-0.5 text-[11px] leading-4 text-slate-500 [overflow-wrap:anywhere]">
          <div>Instance {instance.instanceId}</div>
          {instance.technical.jailPid === undefined ? null : (
            <div>Jail pid {instance.technical.jailPid}{instance.technical.jailStartTicks === undefined ? "" : `, started at tick ${instance.technical.jailStartTicks}`}</div>
          )}
          {instance.technical.pidNs === undefined ? null : <div>PID namespace {instance.technical.pidNs}</div>}
          {instance.technical.scopeUnit === undefined ? null : <div>Scope {instance.technical.scopeUnit}</div>}
          {instance.technical.launcherPath === undefined ? null : (
            <div>
              Launcher {instance.technical.launcherPath}
              {instance.technical.launcherRootOwned === undefined ? "" : `, owned by root: ${instance.technical.launcherRootOwned ? "yes" : "no"}`}
            </div>
          )}
          <div>Trust decided by: the hook inside the jail ({instance.trustReason === "" ? "no reason recorded" : instance.trustReason})</div>
        </dl>
      </TechnicalOnly>
    </li>
  );
}

/** What people decided about agents, most recent first (P6). Read only when the page has identity fields. */
function AgentChanges({ names }: { names: ReadonlyMap<string, string> }) {
  const history = usePolled(fetchHistory, AGENTS_PAGE_POLL_MS, "history");
  const lines = history.data?.agentDecisions;
  if (lines === undefined || lines.length === 0) return null;
  return (
    <section aria-labelledby="agent-changes-title" data-agent-changes className={CARD}>
      <h2 id="agent-changes-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Changes</h2>
      <ul className="mt-2 divide-y divide-slate-100">
        {lines.map((line) => (
          <li key={`${line.at}${line.action}${line.agent}${line.instanceId ?? ""}`} className="py-1.5 text-sm leading-6 text-slate-700">
            {decisionSentence(line, names.get(line.agent) ?? line.agent)}{" "}
            <span className="text-xs text-slate-500"><When at={line.at} relative /></span>
            <TechnicalOnly>
              <span className="block font-mono text-[11px] text-slate-500 [overflow-wrap:anywhere]">
                {line.action} {line.agent}{line.instanceId === undefined ? "" : ` ${line.instanceId}`}: {line.result}
              </span>
            </TechnicalOnly>
          </li>
        ))}
      </ul>
    </section>
  );
}
