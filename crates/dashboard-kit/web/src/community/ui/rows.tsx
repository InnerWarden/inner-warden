import { formatCount } from "../../presentation";
import type { AgentFacts, Decision, Reason, SessionSummary } from "../api";
import { commandSegments } from "../commandDisplay";
import { agentSeen } from "../controls";
import { dominantOutcome, SEVERITY_ORDER, type OutcomeKey } from "../outcomeStyle";
import { Ago, HiddenChip } from "../parts";
import { clockTime, isConnected } from "../verdict";
import { MODE_WORDS, OUTCOME_WORDS, WHO_WORDS } from "../words";
import { LINK_TEXT, META_TEXT, onPlainClick, SMALL_TEXT } from "./blocks";
import { Icon } from "./Icon";
import { OutcomeMark, StatusPill, type PillState } from "./marks";

/**
 * The rows Community lists things in. A row that opens something is a real
 * link (`<a href="?view=...">`), so a middle click and the back button work;
 * a plain click is handled in the page (`onOpen`).
 */

const ROW_LINK = "block min-h-9 rounded-lg px-3 py-2 hover:bg-(--iw-surface-2) pointer-coarse:min-h-11";

/**
 * A command as a row draws it (T7): every character, clamped from the end
 * at two lines, a plain leading `cd <folder> && ` in muted ink. The whole
 * command is in the title.
 */
export function CommandText({ command, className = "" }: { command: string; className?: string }) {
  return (
    <code title={command} data-command-text className={`line-clamp-2 min-w-0 break-all font-mono text-[12.5px] leading-[18px] text-(--iw-ink) ${className}`}>
      {commandSegments(command).map((segment, index) =>
        segment.muted ? (
          <span key={index} data-muted className="text-(--iw-ink-3)">{segment.text}</span>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </code>
  );
}

/** One flagged decision: what ran, what happened, who asked and where. */
export function DecisionRow({ decision, href, onOpen, current = false }: { decision: Decision; href: string; onOpen?: () => void; current?: boolean }) {
  return (
    <li data-decision-row={decision.id}>
      <a href={href} onClick={onPlainClick(onOpen)} aria-current={current ? "true" : undefined} className={`${ROW_LINK} ${current ? "bg-(--iw-surface-2)" : ""}`}>
        <span className="flex min-w-0 items-start gap-2">
          <OutcomeMark outcome={decision.outcomeKey} className="mt-1" />
          <CommandText command={decision.command} className="flex-1" />
          {decision.recordedAt === undefined ? null : <Ago at={decision.recordedAt} className={`shrink-0 whitespace-nowrap ${META_TEXT}`} />}
        </span>
        <span className={`mt-1 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 pl-[18px] ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <span className="font-medium">{OUTCOME_WORDS[decision.outcomeKey]}</span>
          <span>{decision.agent ?? WHO_WORDS[decision.channel]}</span>
          {decision.project === undefined ? null : (
            <span data-folder className="rounded border border-(--iw-line) px-1">
              in <span className="font-mono">{decision.project}</span>
            </span>
          )}
          <span className="min-w-0 text-(--iw-ink-3)">{decision.reason.short}</span>
          {decision.hiddenCharacters ? <HiddenChip compact /> : null}
        </span>
      </a>
    </li>
  );
}

/** One reason commands were flagged: the outcome most of them reached, the words, how many. */
export function ReasonRow({ reason, href, onOpen }: { reason: Reason; href: string; onOpen?: () => void }) {
  const dominant = reason.byOutcome === undefined ? undefined : dominantOutcome(reason.byOutcome);
  return (
    <li data-reason-row={reason.key}>
      <a href={href} onClick={onPlainClick(onOpen)} className={ROW_LINK}>
        <span className="flex min-w-0 items-start gap-2">
          {dominant === undefined ? <span className="h-2.5 w-2.5 shrink-0" /> : <OutcomeMark outcome={dominant} className="mt-1.5" />}
          <span className="min-w-0 flex-1">
            <span className="block text-sm leading-[21px] font-medium text-(--iw-ink)">{reason.short}</span>
            {reason.detail === undefined ? null : <span className={`block break-all font-mono ${META_TEXT}`}>{reason.detail}</span>}
          </span>
          <span className="shrink-0 text-right">
            <span className="block text-sm font-semibold tabular-nums text-(--iw-ink)">{formatCount(reason.count)}</span>
            {dominant === undefined ? null : <span className={`block ${META_TEXT}`}>{OUTCOME_WORDS[dominant]}</span>}
          </span>
        </span>
      </a>
    </li>
  );
}

/** One session with decisions still in the record. */
export function SessionRow({ session, href, onOpen }: { session: SessionSummary; href: string; onOpen?: () => void }) {
  const outcomes = SEVERITY_ORDER.filter((key): key is OutcomeKey => (session.byOutcome[key as keyof typeof session.byOutcome] ?? 0) > 0);
  const from = session.firstAt === undefined ? undefined : clockTime(Date.parse(session.firstAt));
  const to = session.lastAt === undefined ? undefined : clockTime(Date.parse(session.lastAt));
  return (
    <li data-session-row={session.id}>
      <a href={href} onClick={onPlainClick(onOpen)} className={ROW_LINK}>
        <span className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-3">
          <span className="text-sm leading-[21px] font-medium text-(--iw-ink)">
            {session.agent ?? WHO_WORDS[session.channel]}
            {session.project === undefined ? null : <span className="font-normal text-(--iw-ink-2)"> in <span className="font-mono">{session.project}</span></span>}
          </span>
          {from === undefined || to === undefined ? null : <span className={`tabular-nums ${META_TEXT}`}>{from === to ? from : `${from} to ${to}`}</span>}
        </span>
        <span className={`mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <span className="tabular-nums">{formatCount(session.decisions)} {session.decisions === 1 ? "decision" : "decisions"}, {formatCount(session.flagged)} flagged</span>
          {outcomes.map((key) => (
            <span key={key} className="inline-flex items-center gap-1" title={OUTCOME_WORDS[key]}>
              <OutcomeMark outcome={key} />
              <span className="tabular-nums">{formatCount(session.byOutcome[key as keyof typeof session.byOutcome] ?? 0)}</span>
              <span className="sr-only">{OUTCOME_WORDS[key]}</span>
            </span>
          ))}
        </span>
      </a>
    </li>
  );
}

/** An agent's mode as a pill: the config, never what was seen. */
const MODE_PILL: Record<AgentFacts["mode"], PillState> = {
  enforce: "enforce",
  monitor: "monitor",
  mixed: "mixed",
  partial: "needs",
  not_configured: "off",
  unknown: "unknown",
};

export function AgentModePill({ agent }: { agent: AgentFacts }) {
  return <StatusPill state={MODE_PILL[agent.mode]} words={MODE_WORDS[agent.mode]} />;
}

export const MECHANISM_WORDS: Record<"hook" | "mcp", string> = { hook: "Shell hook", mcp: "MCP proxy" };

/** What a connection judges, short, for a row; the full sentence is the CLI's `judges_line`. */
export const JUDGES_SHORT: Record<NonNullable<AgentFacts["judges"]>, string> = {
  shell_and_privileged_files: "Shell commands and privileged files",
  shell_only: "Shell commands",
  mcp_server_calls: "Calls to its MCP servers",
};

/**
 * Whether the guard was seen working for an agent, in one line: when it last
 * screened something, or dashed when nothing was seen or it cannot be told.
 */
export function SeenCell({ agent, unnamed }: { agent: AgentFacts; unnamed: { hook?: string; mcp?: string } | undefined }) {
  const seen = agentSeen(agent, unnamed);
  if (seen === "nothing_to_screen") {
    return (
      <span data-seen="nothing_to_screen" className={`inline-flex items-center gap-1.5 ${META_TEXT}`}>
        <span className="text-(--iw-ink-3)"><Icon name="hollow-circle" className="h-3 w-3" /></span>No MCP server to screen
      </span>
    );
  }
  if (agent.lastObservedAt !== undefined) {
    return (
      <span data-seen="screened" className={`inline-flex items-center gap-1.5 ${SMALL_TEXT} text-(--iw-ink-2)`}>
        <span className="h-2 w-2 shrink-0 rounded-full bg-(--iw-ink-3)" aria-hidden="true" />
        Screened <Ago at={agent.lastObservedAt} />
      </span>
    );
  }
  return (
    <span data-seen={seen} className={`inline-flex items-center gap-1.5 ${SMALL_TEXT} text-(--iw-ink-2)`}>
      <span className="h-2 w-2 shrink-0 rounded-full border border-dashed border-(--iw-unknown)" aria-hidden="true" />
      {seen === "not_reported" ? "Not reported" : "Nothing screened yet"}
    </span>
  );
}

/** One agent: its name and mode, how it is connected and what it judges, whether it was seen working. */
export function AgentRow({
  agent,
  unnamed,
  onOpenAgents,
}: {
  agent: AgentFacts;
  unnamed: { hook?: string; mcp?: string } | undefined;
  onOpenAgents?: () => void;
}) {
  const connected = isConnected(agent);
  return (
    <li data-agent-row={agent.id} className="min-w-0 space-y-1 py-2">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-sm leading-[21px] font-semibold text-(--iw-ink)">{agent.name}</span>
        {connected ? <AgentModePill agent={agent} /> : null}
      </p>
      {connected ? (
        <>
          <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>
            {agent.mechanism === undefined ? null : MECHANISM_WORDS[agent.mechanism]}
            {agent.mechanism !== undefined && agent.judges !== undefined ? ": " : null}
            {agent.judges === undefined ? null : JUDGES_SHORT[agent.judges]}
          </p>
          <p><SeenCell agent={agent} unnamed={unnamed} /></p>
        </>
      ) : (
        <p className={`flex flex-wrap items-center gap-x-3 ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <span>Not connected</span>
          <a href="?view=agents" onClick={onPlainClick(onOpenAgents)} className={`inline-flex min-h-9 items-center gap-1 pointer-coarse:min-h-11 ${LINK_TEXT}`}>
            See Agents <Icon name="arrow-right" className="h-3.5 w-3.5" />
          </a>
        </p>
      )}
    </li>
  );
}

/**
 * The agents in a short list: connected first, then those found here and not
 * connected, at most `max`, then "+N more on Agents". An agent the guard
 * cannot wire, or a configuration left behind by an agent that is not here,
 * is the Agents page's to list.
 */
export function AgentStrip({
  agents,
  unnamed,
  max = 4,
  onOpenAgents,
}: {
  agents: readonly AgentFacts[];
  unnamed: { hook?: string; mcp?: string } | undefined;
  max?: number;
  onOpenAgents?: () => void;
}) {
  const connected = agents.filter(isConnected);
  const found = agents.filter((agent) => !isConnected(agent) && agent.supported && agent.present);
  const listed = [...connected, ...found];
  const shown = listed.slice(0, max);
  const more = listed.length - shown.length;
  return (
    <div data-agent-strip className="min-w-0">
      <ul className="divide-y divide-(--iw-line)">
        {shown.map((agent) => <AgentRow key={agent.id} agent={agent} unnamed={unnamed} onOpenAgents={onOpenAgents} />)}
      </ul>
      {more > 0 ? (
        <a href="?view=agents" onClick={onPlainClick(onOpenAgents)} className={`mt-2 inline-flex min-h-9 items-center gap-1 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
          +{formatCount(more)} more on Agents <Icon name="arrow-right" className="h-3.5 w-3.5" />
        </a>
      ) : null}
    </div>
  );
}
