import { useMemo, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import type { AgentsResponse } from "../api";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { formatAbsolute } from "../presentation";
import {
  agentGroups,
  agentRows,
  AUTO_SETUP_STEP,
  autoSetupLine,
  decisionSentence,
  factsOf,
  programWords,
  restartPrompt,
  runningWords,
  type AgentRow,
} from "./agentsView";
import { readProfilesFile, type AgentFacts, type AgentNextStep, type LocalInstance } from "./api";
import { JAIL_STEP, mcpLines, screeningState } from "./controls";
import { CONNECT_ALL } from "./Overview";
import { StaleLine } from "./parts";
import { restartFor } from "./restart";
import { useSource } from "./store";
import { BODY_TEXT, H2, H3, LINK_TEXT, META_TEXT, NotRead, onPlainClick, PAGE_TITLE, PANEL, Pending, ReadAt, RestartNote, SMALL_TEXT, StepBlock } from "./ui/blocks";
import { Icon } from "./ui/Icon";
import { StatusPill } from "./ui/marks";
import { AgentModePill, MECHANISM_WORDS, SeenCell } from "./ui/rows";
import type { Restart } from "./verdict";
import {
  asPlatform,
  LAUNCH_MODE_WORDS,
  LIFECYCLE_WORDS,
  MONITOR_MEANS,
  reasonWords,
  trustWord,
  USERNS_CLOSED_WORDS,
  type PlatformOs,
  type Trust,
  type TrustSource,
} from "./words";

/**
 * Community's Agents (spec 6.4): the AI agents on this machine and how each
 * one reaches the guard. Connected (the config) and screened (what was seen)
 * stay apart on every card; a change the person makes is followed by how to
 * restart that agent and why, because only they can; the technical view adds
 * evidence and never a different claim.
 */
export function CommunityAgents({ context }: { context?: CommunityScreenContext } = {}) {
  const agents = useSource("agents");
  const protection = useSource("protection");
  const read = useMemo(() => factsOf(agents.data), [agents.data]);
  const facts = read.facts;
  const rows = useMemo(() => new Map(agentRows(facts === undefined ? undefined : (agents.data as AgentsResponse)).map((row) => [row.id, row])), [agents.data, facts]);
  const profilesFile = readProfilesFile(agents.data);
  const os = asPlatform(protection.data?.os ?? context?.bootstrap?.platform.os);
  const now = Date.now();
  const openProtectionMode = () => {
    context?.navigate("posture");
    setTimeout(() => document.getElementById("mode")?.scrollIntoView({ block: "start" }), 0);
  };
  const openDecision = (id: string) => context?.navigate("activity", { decision: id });
  const auto = autoSetupLine(facts?.autoConnect);
  const groups = facts === undefined ? undefined : agentGroups(facts.agents);
  const anyConnected = (groups?.connected.length ?? 0) > 0;

  let body: ReactNode;
  if (facts === undefined) {
    body = read.unreadable || agents.error !== undefined ? (
      <NotRead alert onRetry={agents.refresh}>
        {read.unreadable ? "Not read: the agents' answer could not be read." : "Not read: the dashboard did not answer for the agents."} Nothing here is counted as not connected.
      </NotRead>
    ) : (
      <Pending label="Reading the agents on this machine" className="h-48" />
    );
  } else if (facts.agents.length === 0) {
    body = (
      <section aria-labelledby="agents-none-title" className={`${PANEL} space-y-3`}>
        <h2 id="agents-none-title" className={H2}>No AI agent found on this machine</h2>
        <StepBlock
          step={{ label: "When one is installed, this finds it and connects it:", command: CONNECT_ALL, line: "Connects every agent it finds, in monitor: it records and refuses nothing." }}
          restarts={[{ agent: "your agent", words: restartFor("", "your agent", undefined) }]}
        />
      </section>
    );
  } else {
    body = (
      <>
        {groups!.connected.length === 0 ? null : (
          <ul data-agents-connected className="min-w-0 space-y-6">
            {groups!.connected.map((agent) => (
              <AgentCard
                key={agent.id}
                agent={agent}
                row={rows.get(agent.id)}
                unnamed={facts.unnamed}
                os={os}
                now={now}
                onProtectionMode={openProtectionMode}
                onDecision={openDecision}
              />
            ))}
          </ul>
        )}
        {groups!.found.length === 0 ? null : <FoundHere agents={groups!.found} rows={rows} os={os} />}
        {groups!.jailOnly.length === 0 ? null : <JailOnly agents={groups!.jailOnly} rows={rows} os={os} jailAvailable={protection.data?.jail.available} />}
      </>
    );
  }

  return (
    <div data-agents className="min-w-0 space-y-8" data-tour="agents">
      <div className="space-y-2">
        <h1 id="agents-title" tabIndex={-1} className={PAGE_TITLE}>Agents</h1>
        <p className={BODY_TEXT}>The AI agents on this machine and how each one reaches the guard.</p>
        {auto === undefined ? null : <p data-auto-setup className={BODY_TEXT}>{auto}</p>}
        {facts?.autoConnect?.enabled === false ? (
          <div className="max-w-xl">
            <StepBlock step={AUTO_SETUP_STEP} />
            <p className={`mt-2 ${META_TEXT}`}>An agent it connects reads the change when it next starts.</p>
          </div>
        ) : null}
        {anyConnected ? <p data-monitor-means className={META_TEXT}>{MONITOR_MEANS}</p> : null}
      </div>
      {agents.stale ? <StaleLine onRetry={agents.refresh} /> : null}
      {profilesFile === undefined ? null : (
        <div data-profiles-invalid className={`${PANEL} space-y-2`}>
          <StatusPill state="needs" words="Invalid profiles file" />
          <p className={BODY_TEXT}>{profilesFile.sentence}</p>
        </div>
      )}
      {body}
      <TechnicalOnly>
        <div data-agents-technical className="space-y-4">
          {facts?.discoveryLimited === true ? (
            <p className={META_TEXT}>Discovery stopped at its local safety limit: an agent may be missing from this list.</p>
          ) : null}
          {rows.size === 0 ? null : <AgentChanges names={new Map([...rows.values()].map((row) => [row.id, row.name]))} />}
        </div>
      </TechnicalOnly>
      <ReadAt data={agents.data} path="/api/guard/agents" />
    </div>
  );
}

function restartOf(agent: AgentFacts): Restart {
  return { agent: agent.name, words: restartFor(agent.id, agent.name, agent.restart) };
}

/** The one step that changes this agent: its own switch when the CLI sends one, or the step that finishes connecting it. */
function changeStep(agent: AgentFacts): AgentNextStep | undefined {
  if (agent.mode === "partial") return agent.nextStep;
  if (agent.mode === "enforce") return agent.modeSteps?.monitor;
  if (agent.mode === "monitor") return agent.modeSteps?.enforce;
  if (agent.mode === "mixed") return agent.modeSteps?.enforce ?? agent.modeSteps?.monitor;
  return undefined;
}

function AgentCard({
  agent,
  row,
  unnamed,
  os,
  now,
  onProtectionMode,
  onDecision,
}: {
  agent: AgentFacts;
  row?: AgentRow;
  unnamed: { hook?: string; mcp?: string } | undefined;
  os: PlatformOs;
  now: number;
  onProtectionMode: () => void;
  onDecision: (id: string) => void;
}) {
  const state = screeningState(agent, unnamed);
  const prompt = restartPrompt(agent, unnamed, now);
  const step = changeStep(agent);
  const restart = restartOf(agent);
  const titleId = `agent-${agent.id}-title`;
  return (
    <li data-agent={agent.id} data-agent-state={row?.state ?? "unknown"} data-control-state={state}>
      <article id={`agent-${agent.id}`} aria-labelledby={titleId} className={`${PANEL} space-y-3`}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <h2 id={titleId} className={H2}>{agent.name}</h2>
          {agent.mechanism === undefined ? null : <span className={META_TEXT}>{MECHANISM_WORDS[agent.mechanism]}</span>}
          <AgentModePill agent={agent} />
          {row?.who?.trust === undefined ? null : <TrustTag trust={row.who.trust} />}
          {row?.who?.lifecycle === undefined || LIFECYCLE_WORDS[row.who.lifecycle] === undefined ? null : (
            <span data-lifecycle={row.who.lifecycle}>
              <StatusPill state={row.who.lifecycle === "discovered" ? "needs" : "off"} words={LIFECYCLE_WORDS[row.who.lifecycle] ?? ""} />
            </span>
          )}
        </div>
        {agent.judgesLine === undefined ? null : (
          <p data-judges className={BODY_TEXT}>
            <span className="font-medium text-(--iw-ink)">Judges before it runs: </span>
            {agent.judgesLine}
          </p>
        )}
        {mcpLines(agent.mcp).map((line) => (
          <p key={line} data-mcp className={`${SMALL_TEXT} text-(--iw-ink-2)`}>{line}</p>
        ))}
        <p><SeenCell agent={agent} unnamed={unnamed} screened="Last screened" /></p>
        {prompt === undefined ? null : (
          <div data-restart-prompt className="space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
            <p className="text-sm leading-[21px] font-medium text-(--iw-ink)">{prompt}</p>
            <RestartNote agent={restart.agent} words={restart.words} />
          </div>
        )}
        {step !== undefined ? (
          <div data-agent-change className="max-w-xl space-y-2">
            {agent.mode === "partial" ? null : <p className={META_TEXT}>Change this agent only:</p>}
            <StepBlock step={step} restarts={[restart]} />
          </div>
        ) : agent.mode === "monitor" || agent.mode === "enforce" || agent.mode === "mixed" ? (
          <a href="?view=posture#mode" data-agent-change onClick={onPlainClick(onProtectionMode)} className={`inline-flex min-h-9 items-center gap-1 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
            Switch every connected agent at once on Protection. <Icon name="arrow-right" className="h-3.5 w-3.5" />
          </a>
        ) : null}
        {row?.identity === undefined ? null : (
          <div className="max-w-xl">
            <StepBlock step={row.identity} restarts={[restart]} />
          </div>
        )}
        {row?.who === undefined ? null : <WhoBlock row={row} onDecision={onDecision} />}
        <TechnicalOnly>
          <AgentTechnical agent={agent} os={os} connected />
        </TechnicalOnly>
      </article>
    </li>
  );
}

/** Agents found here and not connected: each with the CLI's step to connect it and the restart it needs. */
function FoundHere({ agents, rows, os }: { agents: readonly AgentFacts[]; rows: ReadonlyMap<string, AgentRow>; os: PlatformOs }) {
  return (
    <section id="agents-found" aria-labelledby="agents-found-title" className={`${PANEL} space-y-3`}>
      <h2 id="agents-found-title" className={H2}>Found here, not connected</h2>
      <ul className="divide-y divide-(--iw-line)">
        {agents.map((agent) => (
          <li key={agent.id} data-agent={agent.id} data-agent-state={rows.get(agent.id)?.state ?? "not_connected"} className="space-y-2 py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h3 className={H3}>{agent.name}</h3>
              <StatusPill state="off" words="Not connected" />
            </div>
            {agent.present ? null : <p className={BODY_TEXT}>Found a configuration for it; the agent itself was not found on this machine.</p>}
            {agent.nextStep === undefined ? null : (
              <div className="max-w-xl">
                <StepBlock step={agent.nextStep} restarts={[restartOf(agent)]} />
              </div>
            )}
            <TechnicalOnly>
              <AgentTechnical agent={agent} os={os} />
            </TechnicalOnly>
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * Agents the guard cannot connect to: no hook or MCP configuration it can
 * use. The jail's walls are on offer (a template, never copied as it is);
 * the guard runs inside the jail for Claude Code only.
 */
function JailOnly({
  agents,
  rows,
  os,
  jailAvailable,
}: {
  agents: readonly AgentFacts[];
  rows: ReadonlyMap<string, AgentRow>;
  os: PlatformOs;
  jailAvailable: boolean | undefined;
}) {
  return (
    <section id="agents-jail-only" aria-labelledby="agents-jail-only-title" className={`${PANEL} space-y-3`}>
      <h2 id="agents-jail-only-title" className={H2}>Can only run inside AI Jail</h2>
      <ul className="divide-y divide-(--iw-line)">
        {agents.map((agent) => (
          <li key={agent.id} data-agent={agent.id} data-agent-state={rows.get(agent.id)?.state ?? "unsupported"} className="space-y-2 py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h3 className={H3}>{agent.name}</h3>
              <StatusPill state="not_available" words="Cannot be connected yet" />
            </div>
            <p className={BODY_TEXT}>It has no hook or MCP configuration the guard can use yet.</p>
            {jailAvailable === false ? (
              <p className={BODY_TEXT}>AI Jail is not available on this system either.</p>
            ) : (
              <div className="max-w-xl">
                <StepBlock step={JAIL_STEP} />
              </div>
            )}
            <TechnicalOnly>
              <AgentTechnical agent={agent} os={os} />
            </TechnicalOnly>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** The evidence behind one agent, as sent: more evidence than the plain view, never a different claim. */
function AgentTechnical({ agent, os, connected = false }: { agent: AgentFacts; os: PlatformOs; connected?: boolean }) {
  const lines = [
    programWords(agent),
    runningWords(agent.running, os),
    `Connection: ${agent.mechanismId ?? "none"}`,
    `Mode as sent: ${agent.modeId ?? "not sent"}`,
    `Setup: ${agent.setupSupport ?? "not sent"}`,
    `Found by: ${(agent.detectedBy ?? []).join(", ") || "not sent"}`,
  ];
  if (connected && agent.judgesLine === undefined) lines.push("Judges before it runs: Not read");
  if (agent.configChangedAt !== undefined) lines.push(`Settings changed: ${formatAbsolute(agent.configChangedAt) ?? agent.configChangedAt}`);
  if (agent.lastObservedAt !== undefined) lines.push(`Last screened: ${formatAbsolute(agent.lastObservedAt) ?? agent.lastObservedAt}`);
  return (
    <ul data-agent-evidence className={`space-y-0.5 border-t border-(--iw-line) pt-2 font-mono text-[12px] leading-[18px] text-(--iw-ink-3) [overflow-wrap:anywhere]`}>
      {lines.map((line) => <li key={line}>{line}</li>)}
    </ul>
  );
}

/** How far an agent's own word is backed, in the closed table's words: neutral, never green. */
function TrustTag({ trust, source }: { trust: Trust; source?: TrustSource }) {
  const word = trustWord(trust, source);
  return (
    <span
      data-trust={trust}
      title={word.tooltip}
      className="inline-flex items-center rounded-full border border-(--iw-line) bg-(--iw-surface-2) px-2 py-0.5 text-xs font-semibold text-(--iw-ink-2)"
    >
      {word.label}
    </span>
  );
}

/**
 * What the CLI says about who one agent is: its profile and owner, why it is
 * or is not confined and how to start it in a jail, what was decided about it,
 * and its instances. Every part is drawn only from a field that was sent.
 */
function WhoBlock({ row, onDecision }: { row: AgentRow; onDecision: (id: string) => void }) {
  const who = row.who;
  if (who === undefined) return null;
  const approvedBy = who.lifecycle === "approved" && who.lifecycleBy !== undefined;
  const facts: ReactNode[] = [];
  if (who.profile !== undefined) facts.push(<span key="profile" data-profile>Profile: {who.profile.label}</span>);
  if (who.owner !== undefined) facts.push(<span key="owner" data-owner>Owner: {who.owner}</span>);
  if (approvedBy) {
    facts.push(
      <span key="approved" data-approved>
        Approved by {who.lifecycleBy}
        {who.lifecycleAt === undefined ? null : <>, <When at={who.lifecycleAt} relative /></>}
      </span>,
    );
  }
  return (
    <div data-agent-identity className="space-y-2">
      {facts.length === 0 ? null : (
        <p className={`flex flex-wrap gap-x-3 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>{facts}</p>
      )}
      {who.trust !== undefined && who.trust !== "host_verified" ? (
        <p data-trust-reason className={`${SMALL_TEXT} text-(--iw-ink-2)`}>{reasonWords(who.trustReason)}</p>
      ) : null}
      {who.confine === undefined ? null : (
        <div data-confine-step className="max-w-xl">
          <StepBlock step={who.confine} />
        </div>
      )}
      {who.decisionSteps.map((step) => (
        <div key={`${step.label}${step.command}`} className="max-w-xl">
          <StepBlock step={step} />
        </div>
      ))}
      {who.instances.length > 0 ? (
        <ul data-instances className="divide-y divide-(--iw-line) rounded-lg border border-(--iw-line)">
          {who.instances.map((instance) => (
            <InstanceRow key={instance.instanceId} instance={instance} profileLabel={who.profile?.label} onDecision={onDecision} />
          ))}
        </ul>
      ) : who.trust !== undefined ? (
        <p data-no-instance className={META_TEXT}>No instance started in a jail yet.</p>
      ) : null}
      {who.moreInstances > 0 ? (
        <p className={META_TEXT}>{who.moreInstances} more {who.moreInstances === 1 ? "instance" : "instances"} not listed.</p>
      ) : null}
    </div>
  );
}

function InstanceRow({ instance, profileLabel, onDecision }: { instance: LocalInstance; profileLabel?: string; onDecision: (id: string) => void }) {
  const place = [
    instance.user === undefined ? undefined : instance.project === undefined ? instance.user : `${instance.user} in ${instance.project}`,
    instance.user === undefined ? instance.project : undefined,
  ].find((part) => part !== undefined);
  const when = instance.live === false ? "Ended" : "Last active";
  const at = instance.lastActivityAt ?? (instance.live === false ? undefined : instance.startedAt);
  return (
    <li data-instance={instance.instanceId} data-instance-trust={instance.trust} data-live={instance.live === undefined ? undefined : String(instance.live)} className="space-y-1 px-3 py-2">
      <div className={`flex flex-wrap items-center gap-x-2 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
        <TrustTag trust={instance.trust} source={instance.trustSource} />
        {place === undefined ? null : <span>{place}</span>}
        {instance.mode === undefined ? null : <span>{LAUNCH_MODE_WORDS[instance.mode]}</span>}
        {profileLabel === undefined ? null : <span>{profileLabel}</span>}
        {at === undefined ? null : <span>{when} <When at={at} relative /></span>}
      </div>
      {instance.trust === "host_verified" ? null : <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>{reasonWords(instance.trustReason)}</p>}
      {instance.sessions.length === 0 ? null : (
        <p className={`flex flex-wrap items-center gap-x-2 ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <span>Sessions:</span>
          {instance.sessions.map((session) =>
            session.caseId !== undefined ? (
              <a
                key={session.session}
                href={`?view=activity&decision=${encodeURIComponent(session.caseId)}`}
                onClick={onPlainClick(() => onDecision(session.caseId ?? ""))}
                className={`inline-flex min-h-9 items-center pointer-coarse:min-h-11 ${LINK_TEXT}`}
              >
                {session.session} (open decision)
              </a>
            ) : (
              <span key={session.session}>{session.session}</span>
            ),
          )}
        </p>
      )}
      <TechnicalOnly>
        <dl className="mt-1 space-y-0.5 text-[11px] leading-4 text-(--iw-ink-3) [overflow-wrap:anywhere]">
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
          {instance.technical.usernsClosed === true ? <div>{USERNS_CLOSED_WORDS}</div> : null}
          <div>Trust read by: the hook inside the jail ({instance.trustReason === "" ? "no reason recorded" : instance.trustReason})</div>
        </dl>
      </TechnicalOnly>
    </li>
  );
}

/** What people decided about agents, most recent first; read only in the technical view, and only when the log holds any. */
function AgentChanges({ names }: { names: ReadonlyMap<string, string> }) {
  const history = useSource("history");
  const lines = history.data?.agentDecisions;
  if (lines === undefined || lines.length === 0) return null;
  return (
    <section aria-labelledby="agent-changes-title" data-agent-changes className={`${PANEL} space-y-2`}>
      <h2 id="agent-changes-title" className={H2}>Changes</h2>
      <ul className="divide-y divide-(--iw-line)">
        {lines.map((line) => (
          <li key={`${line.at}${line.action}${line.agent}${line.instanceId ?? ""}`} className={`py-1.5 ${BODY_TEXT}`}>
            {decisionSentence(line, names.get(line.agent) ?? line.agent)}{" "}
            <span className={META_TEXT}><When at={line.at} relative /></span>
            <span className="block font-mono text-[11px] text-(--iw-ink-3) [overflow-wrap:anywhere]">
              {line.action} {line.agent}{line.instanceId === undefined ? "" : ` ${line.instanceId}`}: {line.result}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
