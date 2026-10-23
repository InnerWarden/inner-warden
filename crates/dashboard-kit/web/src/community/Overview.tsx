import { useMemo, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import type { AgentsResponse, Overview as OverviewPayload } from "../api";
import { useTechnicalDetail } from "../components/TechnicalDetail";
import { formatAbsolute, formatCount, humanizeToken } from "../presentation";
import { agentRows, awaitingApproval, nameList } from "./agentsView";
import {
  fetchDecisions,
  readAgentsFacts,
  readLaneNextStep,
  readOverviewRecord,
  type AgentFacts,
  type AgentsFacts,
  type DecisionsPage,
  type History,
  type Protection,
  type RecordHealth,
  type RecordSpan,
  type RefusalDay,
} from "./api";
import { StaleLine } from "./parts";
import { usePolled, type Polled } from "./poll";
import { restartFor, restartWords } from "./restart";
import { useSource } from "./store";
import {
  BODY_TEXT,
  CountStat,
  LINK_TEXT,
  META_TEXT,
  NotRead,
  onPlainClick,
  PANEL,
  ReadAt,
  RestartNote,
  Section,
  SMALL_TEXT,
  SourceLine,
  StepBlock,
  VerdictBand,
} from "./ui/blocks";
import { DayBars } from "./ui/charts";
import { Icon } from "./ui/Icon";
import { AgentStrip, DecisionRow, ReasonRow } from "./ui/rows";
import { isConnected, lastDays, overviewVerdict, recordCounts, spanWords, type BandStep, type Restart } from "./verdict";

/** The newest denies and the reasons are read on their own, every 30 s. */
export const DECISIONS_POLL_MS = 30_000;
/** At most this many denies, and this many reasons, under Needs a look. */
export const DENIES_SHOWN = 3;
export const REASONS_SHOWN = 4;
/** At most this many agents in the strip; the rest are on the Agents page. */
export const STRIP_MAX = 4;

/** The first step when no agent can be named: connect every agent found, in monitor. */
export const CONNECT_ALL = "innerwarden agents connect --all --monitor";

const SHORT_DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });

/** "30 Jul", for the day the guard's log starts (a UTC date). */
export function shortDay(iso: string): string | undefined {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? SHORT_DAY.format(ms) : undefined;
}

/**
 * What the decision record holds, as the line every count from it carries
 * (T6): "From the decision record: newest 96 decisions, about 4 days." The
 * span runs from the oldest decision kept to the newest.
 */
export function recordSourceLine(record: RecordSpan, now: number): string {
  const decisions = `newest ${formatCount(record.decisions)} ${record.decisions === 1 ? "decision" : "decisions"}`;
  const span = record.oldestAt === undefined
    ? ""
    : `, ${spanWords(Date.parse(record.oldestAt), record.newestAt === undefined ? now : Date.parse(record.newestAt))}`;
  return `From the decision record: ${decisions}${span}.`;
}

/** The exact span behind `recordSourceLine`, for its title. */
function recordSpanTitle(record: RecordSpan): string | undefined {
  if (record.oldestAt === undefined) return undefined;
  const from = formatAbsolute(record.oldestAt);
  const to = record.newestAt === undefined ? "now" : formatAbsolute(record.newestAt);
  return from === undefined || to === undefined ? undefined : `${from} to ${to}`;
}

/** The guard's log by day, summed over the last week, and today so far. */
export function refusalSums(days: readonly RefusalDay[]): { blocked: number; wouldBlock: number; today?: RefusalDay } {
  const week = lastDays(days, 7);
  const last = days.at(-1);
  return { ...week, ...(last?.partial === true ? { today: last } : {}) };
}

/** The agents' answer, read; `undefined` while none came, and an answer that cannot be read counts as failed. */
function readFacts(data: unknown): { facts?: AgentsFacts; unreadable: boolean } {
  if (data === undefined) return { unreadable: false };
  try {
    return { facts: readAgentsFacts(data), unreadable: false };
  } catch {
    return { unreadable: true };
  }
}

/** A fixed-height block while the first answer is on its way: never a zero, never an empty list. */
function Pending({ className = "h-24" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-lg bg-(--iw-surface-2) ${className}`} />;
}

/**
 * Community's Overview (spec 6.1). Without scrolling, at a desk or on a
 * phone, it answers three questions: are my agents connected and in which
 * mode (the band and the header), what was refused or would have been (two
 * numbers and fourteen days), and what is the one next step (the band's
 * command, what it does, and the restart it needs).
 *
 * It reads seven sources: five shared ones (the record's health, the agents,
 * the guard's log, the controls and the overview) and two of its own (the
 * three newest denies, and the reasons). What could not be read is said in
 * its own place and never as a zero; the rest of the page still renders.
 */
export function CommunityOverview({ context }: { context: CommunityScreenContext }) {
  const health = useSource("record-health");
  const agents = useSource("agents");
  const history = useSource("history");
  const protection = useSource("protection");
  const overview = useSource("overview");
  const denies = usePolled(() => fetchDecisions({ verdict: "deny", limit: DENIES_SHOWN }), DECISIONS_POLL_MS, "overview-denies");
  const flagged = usePolled(() => fetchDecisions({ limit: 1 }), DECISIONS_POLL_MS, "overview-flagged");
  const read = useMemo(() => readFacts(agents.data), [agents.data]);
  const facts = read.facts;
  const now = Date.now();
  const page = flagged.data;
  const verdict = overviewVerdict({
    metaStatus: context.metaStatus,
    meta: context.meta,
    health: health.data,
    agents: facts?.agents,
    agentsFailed: facts === undefined && (read.unreadable || agents.error !== undefined),
    unnamed: facts?.unnamed,
    days: history.data?.refusals.days,
    logReadable: history.data?.readable,
    record: recordCounts(page?.record, page?.byOutcome, now),
    alertChannels: protection.data?.alerts.channels,
    now,
  });
  const openDecisions = (params?: Record<string, string>) => context.navigate("activity", params);
  const openAgents = () => context.navigate("agents");
  const connected = facts?.agents.some(isConnected) === true;

  return (
    <div data-overview className="min-w-0 space-y-8">
      <div>
        <VerdictBand verdict={verdict} page="Overview" tour="overview-verdict" onOpenAgents={openAgents} />
        <ReadAt data={agents.data} path="/api/guard/agents" />
      </div>
      <div className="grid min-w-0 grid-cols-1 gap-8 lg:grid-cols-12 lg:gap-6">
        <Refused history={history} flagged={flagged} now={now} className="lg:col-span-5 lg:col-start-8 lg:row-start-1" />
        <NeedsALook
          denies={denies}
          flagged={flagged}
          facts={facts}
          connected={connected}
          agentsPending={facts === undefined && !read.unreadable && agents.error === undefined}
          now={now}
          onOpen={(id) => openDecisions({ decision: id })}
          onReason={(reason) => openDecisions({ reason })}
          onAll={() => openDecisions()}
          className="lg:col-span-12 lg:row-start-2"
        />
        <AgentsStrip agents={agents} facts={facts} unreadable={read.unreadable} onOpenAgents={openAgents} className="lg:col-span-7 lg:col-start-1 lg:row-start-1" />
      </div>
      <FooterLine
        health={health}
        protection={protection}
        history={history}
        navigate={context.navigate}
      />
      <MessagesStep overview={overview.data} />
      {overview.data === undefined ? null : <OverviewRecords overview={overview.data} />}
    </div>
  );
}

function AgentsStrip({
  agents,
  facts,
  unreadable,
  onOpenAgents,
  className,
}: {
  agents: Polled<unknown>;
  facts?: AgentsFacts;
  unreadable: boolean;
  onOpenAgents: () => void;
  className: string;
}) {
  let body: ReactNode;
  if (facts !== undefined) {
    const listed = facts.agents.filter((agent) => isConnected(agent) || (agent.supported && agent.present));
    const unsupported = facts.agents.filter((agent) => !agent.supported);
    body = listed.length > 0 ? (
      <AgentStrip agents={facts.agents} unnamed={facts.unnamed} max={STRIP_MAX} onOpenAgents={onOpenAgents} />
    ) : (
      <p className={BODY_TEXT}>
        {unsupported.length > 0
          ? `${nameList(unsupported.map((agent) => agent.name))} cannot be connected yet.`
          : "No supported agent was found on this machine."}
      </p>
    );
  } else if (unreadable || agents.error !== undefined) {
    body = (
      <NotRead onRetry={agents.refresh}>
        {unreadable ? "Not read: the agents' answer could not be read." : "Not read: the dashboard did not answer for the agents."}
      </NotRead>
    );
  } else {
    body = <Pending className="h-40" />;
  }
  // A new agent the person has not approved yet is theirs to decide, on Agents.
  const waiting = facts === undefined ? [] : awaitingApproval(agentRows(agents.data as AgentsResponse));
  return (
    <Section id="overview-agents" title="Agents" className={`${PANEL} ${className}`}>
      {agents.stale ? <StaleLine onRetry={agents.refresh} /> : null}
      {body}
      {waiting.length === 0 ? null : (
        <p data-agents-waiting className={`flex flex-wrap items-center gap-x-2 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <span className="text-(--iw-review)"><Icon name="triangle" className="h-3.5 w-3.5" /></span>
          <span>{formatCount(waiting.length)} new {waiting.length === 1 ? "agent waits" : "agents wait"} for your approval.</span>
          <a href="?view=agents" onClick={onPlainClick(onOpenAgents)} className={`inline-flex min-h-9 items-center pointer-coarse:min-h-11 ${LINK_TEXT}`}>See Agents</a>
        </p>
      )}
    </Section>
  );
}

/**
 * Refused, or would have been: two numbers for the last 7 days and the
 * fourteen days behind them, from the guard's log. An older CLI sends no
 * days: the two numbers then come from the decision record, said as such,
 * with no bars. A log that could not be read draws no number at all.
 */
function Refused({
  history,
  flagged,
  now,
  className,
}: {
  history: Polled<History>;
  flagged: Polled<DecisionsPage>;
  now: number;
  className: string;
}) {
  const data = history.data;
  let body: ReactNode;
  if (data === undefined) {
    body = history.error === undefined
      ? <Pending className="h-48" />
      : <NotRead at={now} onRetry={history.refresh}>Not read: the dashboard did not answer for the guard's log.</NotRead>;
  } else if (!data.readable) {
    body = <NotRead>Not read: the guard's log could not be read.</NotRead>;
  } else if (data.refusals.days !== undefined) {
    const sums = refusalSums(data.refusals.days);
    const since = data.since === undefined ? undefined : shortDay(data.since);
    body = (
      <>
        <div className="grid grid-cols-2 gap-4">
          <CountStat value={sums.blocked} label="Refused before they ran" tone="stopped" fill="solid" />
          <CountStat value={sums.wouldBlock} label="Would have been refused" tone="deny" fill="hatched" />
        </div>
        <DayBars days={data.refusals.days} />
        {sums.today === undefined ? null : (
          <p data-today className={`${SMALL_TEXT} text-(--iw-ink-2)`}>
            Today so far: {formatCount(sums.today.blocked)} refused, {formatCount(sums.today.wouldBlock)} would have.
          </p>
        )}
        <SourceLine>
          From the guard's log, last 7 days (UTC).{since === undefined ? "" : ` It keeps refusals since ${since}.`}
        </SourceLine>
      </>
    );
  } else {
    const page = flagged.data;
    body = page === undefined ? (
      flagged.error === undefined ? <Pending className="h-24" /> : <NotRead onRetry={flagged.refresh}>Not read: the decision record could not be read.</NotRead>
    ) : (
      <>
        <div className="grid grid-cols-2 gap-4">
          <CountStat value={page.byOutcome.refused_before_run ?? 0} label="Refused before they ran" tone="stopped" fill="solid" />
          <CountStat value={page.byOutcome.would_have_refused ?? 0} label="Would have been refused" tone="deny" fill="hatched" />
        </div>
        <SourceLine>
          {page.record.decisions === 0
            ? "From the decision record: nothing recorded yet."
            : <span title={recordSpanTitle(page.record)}>{recordSourceLine(page.record, now)}</span>}
        </SourceLine>
      </>
    );
  }
  return (
    <Section id="refused" title="Refused, or would have been" tour="overview-lanes" className={`${PANEL} ${className}`}>
      {history.stale ? <StaleLine onRetry={history.refresh} /> : null}
      {body}
      <ReadAt data={data} path="/api/guard/history" />
    </Section>
  );
}

/** The agent Getting started names: the first one found here and not connected, with a step the CLI sent. */
function firstFound(facts: AgentsFacts | undefined): AgentFacts | undefined {
  return facts?.agents.find((agent) => !isConnected(agent) && agent.supported && agent.present && agent.nextStep !== undefined);
}

/**
 * The first run, in place of Needs a look: three steps, each a thing to do
 * on THIS machine. With no supported agent here, the first step asks for
 * one: connecting would connect nothing.
 */
function GettingStarted({ facts }: { facts?: AgentsFacts }) {
  const agent = firstFound(facts);
  const none = facts !== undefined && !facts.agents.some((candidate) => candidate.supported && candidate.present);
  const connect: BandStep = none
    ? { label: "Install a supported agent (Claude Code, Codex, Cursor, Gemini CLI), then connect it." }
    : agent?.nextStep !== undefined
      ? { label: "Connect your agent:", command: agent.nextStep.command, line: agent.nextStep.line }
      : { label: "Connect your agent:", command: CONNECT_ALL, line: "Connects every agent it finds, in monitor: it records and refuses nothing." };
  const restart: Restart = agent === undefined
    ? { agent: "your agent", words: restartWords("", "your agent") }
    : { agent: agent.name, words: restartFor(agent.id, agent.name, agent.restart) };
  return (
    <Section id="getting-started" title="Getting started" className={PANEL}>
      <ol data-get-started className="space-y-3">
        <li className="flex gap-3">
          <StepNumber n={1} />
          <div className="min-w-0 flex-1"><StepBlock step={connect} /></div>
        </li>
        <li className="flex gap-3">
          <StepNumber n={2} />
          <div className="min-w-0 flex-1 space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
            <p className="text-sm leading-[21px] font-medium text-(--iw-ink)">Restart it:</p>
            <RestartNote agent={restart.agent} words={restart.words} />
          </div>
        </li>
        <li className="flex gap-3">
          <StepNumber n={3} />
          <p className={`min-w-0 flex-1 pt-0.5 ${BODY_TEXT}`}>Ask it to run any command. The decision shows here within seconds.</p>
        </li>
      </ol>
    </Section>
  );
}

function StepNumber({ n }: { n: number }) {
  return (
    <span aria-hidden="true" className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-(--iw-line-strong) text-xs font-semibold tabular-nums text-(--iw-ink-2)">
      {n}
    </span>
  );
}

/**
 * Needs a look: the three newest denies and why commands were flagged, from
 * the decision record, said with the span it covers. No Hide here: hiding a
 * reason is a view of the Decisions list, done there.
 */
function NeedsALook({
  denies,
  flagged,
  facts,
  connected,
  agentsPending,
  now,
  onOpen,
  onReason,
  onAll,
  className,
}: {
  denies: Polled<DecisionsPage>;
  flagged: Polled<DecisionsPage>;
  facts?: AgentsFacts;
  connected: boolean;
  /** The agents have not answered yet, and have not failed. */
  agentsPending: boolean;
  now: number;
  onOpen: (id: string) => void;
  onReason: (reason: string) => void;
  onAll: () => void;
  className: string;
}) {
  const page = flagged.data;
  if (page === undefined) {
    return (
      <Section id="needs-a-look" title="Needs a look" className={`${PANEL} ${className}`}>
        {flagged.error === undefined ? (
          <Pending className="h-48" />
        ) : (
          <NotRead alert at={now} onRetry={flagged.refresh}>
            The decision record could not be read. <code className="font-mono">innerwarden status</code> says why.
          </NotRead>
        )}
      </Section>
    );
  }
  const record = page.record;
  // A first run: nothing recorded, and no agent connected to record anything.
  // Until the agents answer, it is not yet known which of the two it is.
  if (record.decisions === 0 && facts === undefined && agentsPending) {
    return (
      <Section id="needs-a-look" title="Needs a look" className={`${PANEL} ${className}`}>
        <Pending className="h-32" />
      </Section>
    );
  }
  if (record.decisions === 0 && !connected) {
    return <div className={className}><GettingStarted facts={facts} /></div>;
  }
  const source = record.decisions === 0 ? null : (
    <SourceLine>
      <span title={recordSpanTitle(record)}>{recordSourceLine(record, now)}</span>
      {record.capped === true ? " Older ones are dropped as new ones arrive." : null}
    </SourceLine>
  );
  let body: ReactNode;
  if (record.decisions === 0) {
    body = <p className={BODY_TEXT}>Nothing recorded yet. Ask your agent to run any command. The decision shows here within seconds.</p>;
  } else if (page.flaggedTotal === 0) {
    const from = record.oldestAt === undefined ? undefined : shortStamp(record.oldestAt);
    body = <p className={BODY_TEXT}>Nothing flagged in the record{from === undefined ? "" : ` (${from} to now)`}.</p>;
  } else {
    const reasons = page.reasons.slice(0, REASONS_SHOWN);
    body = (
      <div className="space-y-6">
        <div className="space-y-2">
          <h3 className="text-sm leading-[21px] font-semibold text-(--iw-ink)">Newest denies</h3>
          {denies.stale ? <StaleLine onRetry={denies.refresh} /> : null}
          {denies.data === undefined ? (
            denies.error === undefined ? <Pending className="h-28" /> : <NotRead onRetry={denies.refresh}>Not read: the dashboard did not answer for the newest denies.</NotRead>
          ) : denies.data.items.length === 0 ? (
            <p className={BODY_TEXT}>
              {denies.data.total > 0 ? `${formatCount(denies.data.total)} denied could not be shown.` : "No command was denied in the record."}
            </p>
          ) : (
            <ul className="-mx-3 divide-y divide-(--iw-line)">
              {denies.data.items.slice(0, DENIES_SHOWN).map((decision) => (
                <DecisionRow
                  key={decision.id}
                  decision={decision}
                  href={`?view=activity&decision=${encodeURIComponent(decision.id)}`}
                  onOpen={() => onOpen(decision.id)}
                />
              ))}
            </ul>
          )}
        </div>
        <div className="space-y-2">
          <h3 className="text-sm leading-[21px] font-semibold text-(--iw-ink)">Why commands were flagged</h3>
          {reasons.length === 0 ? (
            <p className={BODY_TEXT}>{formatCount(page.flaggedTotal)} flagged could not be shown.</p>
          ) : (
            <ul className="-mx-3 divide-y divide-(--iw-line)">
              {reasons.map((reason) => (
                <ReasonRow
                  key={reason.key}
                  reason={reason}
                  href={`?view=activity&reason=${encodeURIComponent(reason.key)}`}
                  onOpen={() => onReason(reason.key)}
                />
              ))}
            </ul>
          )}
        </div>
        <a
          href="?view=activity"
          data-see-all
          onClick={onPlainClick(onAll)}
          className={`inline-flex min-h-9 items-center gap-1 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}
        >
          See all {formatCount(page.flaggedTotal)} flagged in Decisions <Icon name="arrow-right" className="h-3.5 w-3.5" />
        </a>
      </div>
    );
  }
  return (
    <Section id="needs-a-look" title="Needs a look" className={`${PANEL} ${className}`}>
      {flagged.stale ? <StaleLine onRetry={flagged.refresh} /> : null}
      {source}
      {body}
      <ReadAt data={page} path="/api/guard/decisions" />
    </Section>
  );
}

/** "25 Sept, 17:34" in the reader's own clock, built per call so it follows the zone the page runs in. */
function stamp(ms: number): string {
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
}

/** "25 Sept, 17:34", in the reader's own clock. */
function shortStamp(iso: string): string | undefined {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? stamp(ms) : undefined;
}

type FooterItem = { key: string; words: string; section?: string; route?: "posture" | "activity" | "tokens"; params?: Record<string, string> };

/** The footer's words for each control, from what was read; never a guess for what was not. */
export function footerItems(
  health: RecordHealth | undefined,
  protection: Protection | undefined,
  history: History | undefined,
): FooterItem[] {
  const items: FooterItem[] = [];
  items.push({
    key: "record",
    words: health === undefined ? "Record: not read." : health.recording ? "Record: recording." : "Record: not recording.",
    section: "record",
  });
  if (protection === undefined) {
    items.push({ key: "alerts", words: "Alerts: not read.", section: "alerts" });
    items.push({ key: "jail", words: "AI Jail: not read.", section: "jail" });
    items.push({ key: "second-opinion", words: "Second opinion: not read.", section: "second-opinion" });
  } else {
    const channels = protection.alerts.channels;
    items.push({
      key: "alerts",
      words: channels === 0 ? "Alerts: off." : `Alerts: ${formatCount(channels)} ${channels === 1 ? "channel" : "channels"}.`,
      section: "alerts",
    });
    const jail = protection.jail;
    items.push({
      key: "jail",
      words: !jail.available
        ? "AI Jail: not available."
        : jail.checksPass === true
          ? "AI Jail: ready."
          : jail.checksPass === false
            ? "AI Jail: needs you."
            : "AI Jail: not checked here yet.",
      section: "jail",
    });
    items.push({ key: "second-opinion", words: protection.secondOpinion.configured ? "Second opinion: on." : "Second opinion: off.", section: "second-opinion" });
  }
  const messages = history?.messages.recorded ?? 0;
  if (protection?.observe.available === true || messages > 0) {
    items.push(
      history === undefined
        ? { key: "messages", words: "Messages: not read.", route: "activity", params: { lane: "agent_messages" } }
        : { key: "messages", words: `Messages: ${formatCount(messages)} recorded.`, route: "activity", params: { lane: "agent_messages" } },
    );
  }
  items.push({ key: "tokens", words: "Tokens", route: "tokens" });
  return items;
}

/** Scroll to a section of the page just opened, once it is drawn; a page that never draws it is left as it is. */
function scrollWhenDrawn(id: string, tries = 20) {
  const element = document.getElementById(id);
  if (element !== null) {
    element.scrollIntoView({ block: "start" });
    return;
  }
  if (tries > 0) setTimeout(() => scrollWhenDrawn(id, tries - 1), 100);
}

/** One line: the rest of what is on this machine, each item a link to where it is set. */
function FooterLine({
  health,
  protection,
  history,
  navigate,
}: {
  health: Polled<RecordHealth>;
  protection: Polled<Protection>;
  history: Polled<History>;
  navigate: CommunityScreenContext["navigate"];
}) {
  const items = footerItems(health.data, protection.data, history.data);
  return (
    <section aria-labelledby="overview-footer-title" data-overview-footer className="rounded-[10px] bg-(--iw-surface-2) px-4 py-3">
      <h2 id="overview-footer-title" className="sr-only">The rest of this machine</h2>
      <ul className={`flex flex-wrap gap-x-4 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
        {items.map((item) => {
          const route = item.route ?? "posture";
          const query = new URLSearchParams({ view: route, ...(item.params ?? {}) }).toString();
          const href = `?${query}${item.section === undefined ? "" : `#${item.section}`}`;
          const open = () => {
            navigate(route, item.params);
            if (item.section !== undefined) setTimeout(() => scrollWhenDrawn(item.section!), 0);
          };
          return (
            <li key={item.key} data-footer-item={item.key}>
              <a href={href} onClick={onPlainClick(open)} className="inline-flex min-h-9 items-center underline-offset-2 hover:text-(--iw-accent) hover:underline pointer-coarse:min-h-11">
                {item.words}
              </a>
            </li>
          );
        })}
      </ul>
      <ReadAt data={protection.data} path="/api/guard/protection" />
    </section>
  );
}

/**
 * A message hook an earlier version wrote keeps running after an upgrade.
 * The CLI names it, with the command that fixes it, beside the messages it
 * still records; the step is printed as sent. Nothing when it sends none.
 */
function MessagesStep({ overview }: { overview?: OverviewPayload }) {
  const lanes = (overview as (OverviewPayload & { lanes?: unknown }) | undefined)?.lanes;
  const lane = (lanes as Record<string, { availability?: unknown }> | undefined)?.agent_messages;
  const step = lane?.availability === "available" ? readLaneNextStep(lanes, "agent_messages") : undefined;
  if (step === undefined) return null;
  return (
    <div data-lane-step className="max-w-xl">
      <StepBlock step={{ label: "Messages to your agent:", command: step.command, line: step.line }} />
    </div>
  );
}

/** The numbers behind the page, for whoever asks: technical view only. */
function OverviewRecords({ overview }: { overview: OverviewPayload }) {
  const [technical] = useTechnicalDetail();
  if (!technical) return null;
  const record = readOverviewRecord((overview as OverviewPayload & { record?: unknown }).record);
  const verdicts: [string, number][] = [
    ["deny", overview.deny_verdicts ?? overview.blocked],
    ["review", overview.review_verdicts ?? overview.review],
    ["allow", overview.allow_verdicts ?? overview.allowed],
    ["unknown", overview.unknown_verdicts ?? 0],
  ];
  const refused = overview.actual_blocks ?? 0;
  const would = overview.would_block ?? 0;
  const checked = overview.screened ?? 0;
  const unknown = overview.outcomes_unknown ?? 0;
  const outcomes: [string, number][] = [
    ["refused before it ran", refused],
    ["would have been refused", would],
    ["checked by hand", checked],
    ["ran", Math.max(0, overview.commands - refused - would - checked - unknown)],
    ["outcome not recorded", unknown],
  ];
  const list = (rows: [string, number][]) => (
    <dl className={`space-y-1 ${SMALL_TEXT}`}>
      {rows.map(([name, value]) => (
        <div key={name} className="flex justify-between gap-3">
          <dt className="text-(--iw-ink-3)">{name}</dt>
          <dd className="font-semibold tabular-nums text-(--iw-ink)">{formatCount(value)}</dd>
        </div>
      ))}
    </dl>
  );
  return (
    <Section id="overview-records" title="The records behind these numbers" className="border-t border-(--iw-line) pt-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div className={PANEL}><p className="mb-2 text-xs font-medium text-(--iw-ink-3)">By verdict</p>{list(verdicts)}</div>
        <div className={PANEL}><p className="mb-2 text-xs font-medium text-(--iw-ink-3)">By outcome</p>{list(outcomes)}</div>
        <div className={PANEL}>
          <p className="mb-2 text-xs font-medium text-(--iw-ink-3)">The record</p>
          <dl className={`space-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
            <div><dt className="inline text-(--iw-ink-3)">Decisions kept: </dt><dd className="inline tabular-nums">{formatCount(record?.decisions ?? overview.commands)}</dd></div>
            {record?.oldestAt === undefined ? null : <div><dt className="inline text-(--iw-ink-3)">Oldest: </dt><dd className="inline">{formatAbsolute(record.oldestAt)}</dd></div>}
            {record?.newestAt === undefined ? null : <div><dt className="inline text-(--iw-ink-3)">Newest: </dt><dd className="inline">{formatAbsolute(record.newestAt)}</dd></div>}
            {record?.capped === undefined ? null : <div><dt className="inline text-(--iw-ink-3)">Full: </dt><dd className="inline">{record.capped ? "yes, the oldest are dropped as new ones arrive" : "no"}</dd></div>}
          </dl>
        </div>
      </div>
      {overview.top_categories.length === 0 ? null : (
        <div className={PANEL}>
          <p className="text-sm font-semibold text-(--iw-ink)">Rule categories matched</p>
          <p className={`mt-1 ${META_TEXT}`}>These count categories matched, not decisions: one decision can match several.</p>
          <ul className="mt-2 flex flex-wrap gap-2 text-xs">
            {overview.top_categories.slice(0, 8).map((category) => (
              <li key={category.name} className="rounded-full border border-(--iw-line) bg-(--iw-surface-2) px-2.5 py-0.5 text-(--iw-ink-2)">
                {humanizeToken(category.name)} <span className="font-semibold tabular-nums">{formatCount(category.count)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <ReadAt data={overview} path="/api/guard/overview" />
    </Section>
  );
}
