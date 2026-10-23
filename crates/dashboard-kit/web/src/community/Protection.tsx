import { useMemo, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import type { Overview as OverviewPayload } from "../api";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { formatAbsolute, formatCount } from "../presentation";
import { factsOf } from "./agentsView";
import { readOverviewRecord, type AllowEntry, type History, type Protection, type RecordHealth, type RecordSpan, type SuppressCounts, type SuppressList } from "./api";
import {
  alertsControl,
  jailControl,
  mcpLines,
  messagesControl,
  optionalSummary,
  screeningRows,
  screeningSummary,
  secondOpinionControl,
  type OptionalControl,
  type ScreeningRow,
} from "./controls";
import { FooterOffer } from "./Offer";
import { CopyCommand, HiddenChip, StaleLine } from "./parts";
import type { Polled } from "./poll";
import { useSource } from "./store";
import { BODY_TEXT, Code, H3, LINK_TEXT, META_TEXT, NotRead, onPlainClick, PAGE_TITLE, PANEL, Pending, ReadAt, Section, SMALL_TEXT, SourceLine, StepBlock, VerdictBand } from "./ui/blocks";
import { WeekBars } from "./ui/charts";
import { StatusPill } from "./ui/marks";
import { AgentModePill, MECHANISM_WORDS, SeenCell } from "./ui/rows";
import { modeBox, spanWords } from "./verdict";
import { asPlatform, atWords, dayAndTime, ENFORCE_MEANS, MONITOR_MEANS, PLATFORM_WORDS, shortDay } from "./words";

/** The page's lead: what Community does, and how the page reads. */
export const PROTECTION_LEAD =
  "Community checks what your AI agents ask to run. Each line is one control, what it does here now, and the one command that changes it.";

/** The three lines every reader of the exceptions is told, once (CJC-090-J006). */
export const EXCEPTION_RULES = [
  "An allow pattern lets through only the commands it matches, and the record says you allowed it.",
  "A mute clears a flag only when every rule behind it is muted and no other danger signal remains.",
  "These change only from a terminal you type in. An agent that runs them is refused.",
] as const;

const STATUS_STEP = { label: "To see why:", command: "innerwarden status", line: "Says why, and what to do." };

/**
 * Community's Protection (spec 6.2): the mode the agents are set to and what
 * each mode means, each agent's screening, the decision record, the optional
 * defences (each off until the person turns it on, in one step the page
 * names), and the exceptions the person made. No ring and no score: a count
 * is said with its source, and what could not be read is said as such.
 */
export function CommunityProtection({ context }: { context: CommunityScreenContext }) {
  const agents = useSource("agents");
  const protection = useSource("protection");
  const health = useSource("record-health");
  const history = useSource("history");
  const overview = useSource("overview");
  const read = useMemo(() => factsOf(agents.data), [agents.data]);
  const facts = read.facts;
  const agentsFailed = facts === undefined && (read.unreadable || agents.error !== undefined);
  const now = Date.now();
  const os = asPlatform(protection.data?.os ?? context.bootstrap?.platform.os);
  const rows = facts === undefined ? undefined : screeningRows(facts.agents, facts.unnamed);
  const claudeHere = facts?.agents.some((agent) => agent.id === "claude-code" && (agent.present || agent.mode !== "not_configured")) === true;
  const optional: OptionalControl[] = [
    jailControl(protection.data?.jail, claudeHere),
    alertsControl(protection.data?.alerts),
    secondOpinionControl(protection.data?.secondOpinion),
    messagesControl(protection.data, history.data),
  ];
  const summary = `${agentsFailed || facts !== undefined ? screeningSummary(rows) : "Screening: checking."} ${protection.data === undefined ? (protection.error === undefined ? "Optional: checking." : "Optional: not read.") : optionalSummary(optional)}`;
  const verdict = modeBox({ agents: facts?.agents, failed: agentsFailed, now });
  const installed = context.meta?.active_defence_installed === true;

  return (
    <div data-protection className="min-w-0 space-y-8">
      <div className="space-y-2">
        <h1 id="protection-title" tabIndex={-1} className={PAGE_TITLE}>
          Protection on {PLATFORM_WORDS[os]}
        </h1>
        <p className={BODY_TEXT}>{PROTECTION_LEAD}</p>
        <p data-protection-summary className={`${BODY_TEXT} font-medium`}>{summary}</p>
      </div>

      <div>
        <VerdictBand
          verdict={verdict}
          compact
          id="mode"
          tour="community-protection"
          onOpenAgents={() => context.navigate("agents")}
          extra={
            <div data-mode-means className="space-y-1 border-t border-(--iw-line) pt-2">
              <p className={BODY_TEXT}>{MONITOR_MEANS}</p>
              <p className={BODY_TEXT}>{ENFORCE_MEANS}</p>
            </div>
          }
        />
        <ReadAt data={agents.data} path="/api/guard/agents" />
      </div>

      <Screening rows={rows} failed={agentsFailed} unnamed={facts?.unnamed} agents={agents} />

      <RecordSection health={health} protection={protection} history={history} overview={overview.data} now={now} />

      <Section id="optional" title="Optional defences" className={PANEL}>
        <p className={META_TEXT}>Each is off until you turn it on.</p>
        {protection.stale ? <StaleLine onRetry={protection.refresh} /> : null}
        <ul className="divide-y divide-(--iw-line)">
          {optional.map((control) => (
            <OptionalRow
              key={control.key}
              control={control}
              onMessages={control.key === "messages" && control.pill === "on" ? () => context.navigate("activity", { lane: "agent_messages" }) : undefined}
              jail={control.key === "jail" ? protection.data?.jail : undefined}
            />
          ))}
        </ul>
        <ReadAt data={protection.data} path="/api/guard/protection" />
      </Section>

      <Exceptions protection={protection.data} history={history.data} now={now} />

      <FooterOffer installed={installed} />
    </div>
  );
}

/**
 * One row per connected agent: how it reaches the guard, what it judges
 * before a call runs, its mode (the config) and whether it was seen working
 * (what came through), kept apart, and the one step for this agent.
 */
function Screening({
  rows,
  failed,
  unnamed,
  agents,
}: {
  rows: ScreeningRow[] | undefined;
  failed: boolean;
  unnamed: { hook?: string; mcp?: string } | undefined;
  agents: Polled<unknown>;
}) {
  let body: ReactNode;
  if (rows === undefined) {
    body = failed ? (
      <NotRead onRetry={agents.refresh}>Not read: the dashboard did not answer for the agents.</NotRead>
    ) : (
      <Pending label="Reading the agents" className="h-32" />
    );
  } else if (rows.length === 0) {
    body = (
      <p className={BODY_TEXT}>
        No agent is connected yet.{" "}
        <a href="?view=agents" className={LINK_TEXT}>See Agents</a>
      </p>
    );
  } else {
    body = (
      <ul className="divide-y divide-(--iw-line)">
        {rows.map((row) => <ScreeningItem key={row.agent.id} row={row} unnamed={unnamed} />)}
      </ul>
    );
  }
  return (
    <Section id="screening" title="Screening" className={PANEL}>
      {agents.stale ? <StaleLine onRetry={agents.refresh} /> : null}
      {body}
    </Section>
  );
}

const CELL_LABEL = "text-xs leading-4 font-medium text-(--iw-ink-3)";

function ScreeningItem({ row, unnamed }: { row: ScreeningRow; unnamed: { hook?: string; mcp?: string } | undefined }) {
  const { agent } = row;
  const how = agent.mechanism === undefined ? "Not read" : MECHANISM_WORDS[agent.mechanism];
  return (
    <li data-screening={agent.id} data-control-state={row.state} className="space-y-3 py-4 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 className={H3}>{agent.name}</h3>
        <AgentModePill agent={agent} />
      </div>
      <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
        <div className="min-w-0">
          <dt className={CELL_LABEL}>How</dt>
          <dd className={`${SMALL_TEXT} text-(--iw-ink-2)`}>
            {how}
            {mcpLines(agent.mcp).map((line) => <span key={line} data-mcp className="block">{line}</span>)}
          </dd>
        </div>
        {agent.judgesLine === undefined ? (
          <TechnicalOnly>
            <div className="min-w-0">
              <dt className={CELL_LABEL}>Judges before it runs</dt>
              <dd className={`${SMALL_TEXT} text-(--iw-ink-2)`}>Not read</dd>
            </div>
          </TechnicalOnly>
        ) : (
          <div className="min-w-0 lg:col-span-1">
            <dt className={CELL_LABEL}>Judges before it runs</dt>
            <dd data-judges className={`${SMALL_TEXT} text-(--iw-ink-2)`}>{agent.judgesLine}</dd>
          </div>
        )}
        <div className="min-w-0">
          <dt className={CELL_LABEL}>Seen working</dt>
          <dd><SeenCell agent={agent} unnamed={unnamed} /></dd>
        </div>
      </dl>
      {row.step === undefined ? null : (
        <div className="max-w-xl">
          <StepBlock step={row.step} restarts={[{ agent: agent.name, words: row.restart }]} />
        </div>
      )}
    </li>
  );
}

/** The decision record's span, in words: "from 25 Sept, 17:34 to now (about 4 days)". */
export function recordSpanLine(record: RecordSpan, now: number): string {
  if (record.decisions === 0) return "Recording. Nothing recorded yet.";
  const count = `The newest ${formatCount(record.decisions)} ${record.decisions === 1 ? "decision" : "decisions"}`;
  if (record.oldestAt === undefined) return `Recording. ${count}.`;
  const from = Date.parse(record.oldestAt);
  return `Recording. ${count}, from ${dayAndTime(from)} to now (${spanWords(from, now)}).`;
}

/**
 * The decision record: whether it is recording, what it holds, and the
 * guard's log by week, the week under way outlined and said as so far.
 */
function RecordSection({
  health,
  protection,
  history,
  overview,
  now,
}: {
  health: Polled<RecordHealth>;
  protection: Polled<Protection>;
  history: Polled<History>;
  overview?: OverviewPayload;
  now: number;
}) {
  const recording = health.data?.recording ?? protection.data?.record.recording;
  const record = readOverviewRecord((overview as (OverviewPayload & { record?: unknown }) | undefined)?.record);
  let state: ReactNode;
  if (recording === undefined) {
    state = health.error !== undefined && protection.error !== undefined ? (
      <div className="space-y-3">
        <NotRead onRetry={health.refresh}>The decision record could not be read.</NotRead>
        <StepBlock step={STATUS_STEP} />
      </div>
    ) : (
      <Pending label="Reading the decision record" className="h-12" />
    );
  } else if (!recording) {
    state = (
      <div data-record-state="not_recording" className="space-y-3">
        <p className="flex flex-wrap items-center gap-2">
          <StatusPill state="needs" words="Needs you" />
          <span className={BODY_TEXT}>Decisions are not being recorded.</span>
        </p>
        {health.data?.summary === undefined ? null : <p className={BODY_TEXT}>{health.data.summary}</p>}
        <StepBlock step={STATUS_STEP} />
      </div>
    );
  } else {
    state = (
      <div data-record-state="recording" className="space-y-1">
        <p className="flex flex-wrap items-center gap-2">
          <StatusPill state="on" words="Recording" />
        </p>
        {record === undefined ? null : (
          <p className={BODY_TEXT} title={record.oldestAt === undefined ? undefined : `${formatAbsolute(record.oldestAt) ?? ""} to now`}>
            {recordSpanLine(record, now)}
          </p>
        )}
        {record?.capped === true ? <p className={BODY_TEXT}>The record is full: the oldest are dropped as new ones arrive.</p> : null}
      </div>
    );
  }
  const log = history.data;
  let weeks: ReactNode;
  if (log === undefined) {
    weeks = history.error === undefined ? (
      <Pending label="Reading the guard's log" className="h-40" />
    ) : (
      <NotRead onRetry={history.refresh}>Not read: the dashboard did not answer for the guard's log.</NotRead>
    );
  } else if (!log.readable) {
    weeks = <NotRead>Not read: the guard's log could not be read.</NotRead>;
  } else {
    const since = log.since === undefined ? undefined : shortDay(log.since);
    const n = log.refusals.weeks.length;
    weeks = (
      <div className="space-y-3">
        <SourceLine>
          The guard's log keeps refusals and list changes{since === undefined ? "" : ` since ${since}`}
          {n === 0 ? "" : ` (${formatCount(n)} ${n === 1 ? "week" : "weeks"})`}.
        </SourceLine>
        {n === 0 ? null : <WeekBars weeks={log.refusals.weeks} />}
      </div>
    );
  }
  return (
    <Section id="record" title="Decision record" className={PANEL}>
      {health.stale ? <StaleLine onRetry={health.refresh} /> : null}
      {state}
      {weeks}
      <ReadAt data={log} path="/api/guard/history" />
    </Section>
  );
}

/** One optional defence: its state in words, what it does here now, and its one step. */
function OptionalRow({ control, onMessages, jail }: { control: OptionalControl; onMessages?: () => void; jail?: Protection["jail"] }) {
  return (
    <li id={control.key} data-control={control.key} data-control-state={control.pill} className="scroll-mt-4 space-y-2 py-4 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 className={H3}>{control.name}</h3>
        <StatusPill state={control.pill} words={control.words} />
      </div>
      <p className={BODY_TEXT}>{control.line}</p>
      {control.more.length === 0 ? null : (
        <ul data-advice className={`list-disc space-y-0.5 pl-5 ${SMALL_TEXT} text-(--iw-ink-2)`}>
          {control.more.map((line) => <li key={line}>{line}</li>)}
        </ul>
      )}
      {onMessages === undefined ? null : (
        <a href="?view=activity&lane=agent_messages" onClick={onPlainClick(onMessages)} className={`inline-flex min-h-9 items-center text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
          See them in Decisions
        </a>
      )}
      {control.step === undefined ? null : (
        <div className="max-w-xl">
          <StepBlock step={control.step} restarts={control.restarts} />
        </div>
      )}
      {control.tip === undefined ? null : <p className={META_TEXT}>{control.tip}</p>}
      {jail === undefined ? null : (
        <TechnicalOnly>
          <p className={META_TEXT}>
            Commands run in the jail are recorded in that project's own record.
            {jail.checkedAt === undefined ? " The checks have not run yet." : ` Checked ${formatAbsolute(jail.checkedAt) ?? jail.checkedAt}.`}
          </p>
        </TechnicalOnly>
      )}
    </li>
  );
}

function countsLine(counts: SuppressCounts): string {
  const plural = (n: number, one: string, many: string) => `${formatCount(n)} ${n === 1 ? one : many}`;
  return `${plural(counts.allow, "allow pattern", "allow patterns")}, ${plural(counts.muteRules, "muted rule", "muted rules")}, ${plural(counts.muteCategories, "muted category", "muted categories")}.`;
}

/**
 * Your exceptions: the allow patterns and mutes, read only while this section
 * is on screen. A pattern that held a secret, or a character a reader cannot
 * see, has no remove step here: the step would not remove it. When this
 * dashboard is open to the network the lists stay in the terminal. An older
 * InnerWarden that does not serve them is said, with the counts it does send.
 */
function Exceptions({ protection, history, now }: { protection?: Protection; history?: History; now: number }) {
  const suppress = useSource("suppress");
  const answer = suppress.data;
  let body: ReactNode;
  if (answer === undefined) {
    body = suppress.error === undefined ? (
      <Pending label="Reading your exceptions" className="h-24" />
    ) : protection === undefined ? (
      <NotRead onRetry={suppress.refresh}>Not read: the dashboard did not answer for your exceptions.</NotRead>
    ) : (
      <>
        <p data-exception-counts className={BODY_TEXT}>{countsLine(protection.suppress)}</p>
        <NotRead onRetry={suppress.refresh}>Not read: the list itself did not answer. These are the counts.</NotRead>
      </>
    );
  } else if (!answer.supported) {
    body = protection === undefined ? (
      <NotRead>This InnerWarden lists only the counts, and they were not read.</NotRead>
    ) : (
      <div data-exceptions-older className="space-y-2">
        <p data-exception-counts className={BODY_TEXT}>{countsLine(protection.suppress)}</p>
        <p className={BODY_TEXT}>
          This InnerWarden lists only the counts. Run <Code>innerwarden allow --list</Code> to see them.
        </p>
        {history === undefined || !history.readable || history.suppressionChanges === 0 ? null : (
          <p className={BODY_TEXT}>
            {formatCount(history.suppressionChanges)} {history.suppressionChanges === 1 ? "change" : "changes"}
            {history.since === undefined ? "" : ` since ${shortDay(history.since)}`}.
          </p>
        )}
      </div>
    );
  } else {
    body = <ExceptionLists list={answer.value} now={now} />;
  }
  return (
    <Section id="exceptions" title="Your exceptions" className={PANEL}>
      {suppress.stale ? <StaleLine onRetry={suppress.refresh} /> : null}
      {body}
      <ul data-exception-rules className={`space-y-1 border-t border-(--iw-line) pt-3 ${SMALL_TEXT} text-(--iw-ink-2)`}>
        {EXCEPTION_RULES.map((line) => <li key={line}>{line}</li>)}
      </ul>
      <ReadAt data={answer} path="/api/guard/suppress" />
    </Section>
  );
}

/** "Remove it from a terminal": the one way to remove a pattern this page will not print whole. */
function FromTerminal() {
  return (
    <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>
      Remove it from a terminal: <Code>innerwarden allow --list</Code> shows it.
    </p>
  );
}

function AllowRow({ entry }: { entry: AllowEntry }) {
  return (
    <li data-allow={entry.redacted ? "redacted" : entry.hiddenCharacters ? "hidden" : "plain"} className="space-y-2 py-3 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-2">
        <code className="min-w-0 break-all font-mono text-[12.5px] leading-[18px] text-(--iw-ink)">{entry.pattern}</code>
        {entry.unanchored ? <span data-unanchored><StatusPill state="needs" words="Matches more than one command" /></span> : null}
        {entry.hiddenCharacters ? <HiddenChip compact /> : null}
      </div>
      {entry.redacted ? <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>Contains a secret, hidden here.</p> : null}
      {entry.redacted || entry.hiddenCharacters ? (
        <FromTerminal />
      ) : entry.remove === undefined ? null : (
        <RemoveStep step={entry.remove} />
      )}
    </li>
  );
}

function RemoveStep({ step }: { step: { label: string; command: string; line: string } }) {
  return (
    <div data-remove className="max-w-xl space-y-1">
      <p className={`${SMALL_TEXT} text-(--iw-ink-3)`}>{step.label}</p>
      <CopyCommand command={step.command} />
      <p className={META_TEXT}>{step.line}</p>
    </div>
  );
}

function MoreLine({ n, step }: { n: number; step?: { label: string; command: string; line: string } }) {
  if (n === 0) return null;
  return (
    <div className="space-y-1">
      <p className={BODY_TEXT}>And {formatCount(n)} more.</p>
      {step === undefined ? null : <RemoveStep step={step} />}
    </div>
  );
}

function ExceptionLists({ list, now }: { list: SuppressList; now: number }) {
  const changes = list.changes;
  const changesLine = changes.count === 0
    ? "No change to these lists in the guard's log."
    : `${formatCount(changes.count)} ${changes.count === 1 ? "change" : "changes"}${changes.since === undefined ? "" : ` since ${shortDay(changes.since)}`}${changes.lastAt === undefined ? "" : `, the last ${atWords(Date.parse(changes.lastAt), now)}`}.`;
  return (
    <div className="space-y-5">
      <p data-exception-counts className={BODY_TEXT}>{countsLine(list.counts)}</p>
      {list.withheld ? (
        <p data-withheld className={BODY_TEXT}>
          Hidden because this dashboard is open to the network. See them in a terminal:{" "}
          <Code>innerwarden allow --list</Code>.
        </p>
      ) : (
        <>
          <div className="space-y-2">
            <h3 className={H3}>Allow list</h3>
            {list.allow.length === 0 ? (
              <p className={BODY_TEXT}>No allow pattern.</p>
            ) : (
              <ul data-allow-list className="divide-y divide-(--iw-line)">
                {list.allow.map((entry) => <AllowRow key={entry.pattern} entry={entry} />)}
              </ul>
            )}
            <MoreLine n={list.more.allow} step={list.listSteps.allow} />
          </div>
          {list.dropped.length === 0 ? null : (
            <div className="space-y-2">
              <h3 className={H3}>Ignored patterns</h3>
              <ul data-dropped className="space-y-2">
                {list.dropped.map((pattern) => (
                  <li key={pattern} className="space-y-1">
                    <code className="break-all font-mono text-[12.5px] leading-[18px] text-(--iw-ink)">{pattern}</code>
                    <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>
                      Ignored: matches every command. Use <Code>innerwarden dry-run</Code> instead.
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="space-y-2">
            <h3 className={H3}>Muted rules and categories</h3>
            {list.muteRules.length + list.muteCategories.length === 0 ? (
              <p className={BODY_TEXT}>Nothing muted.</p>
            ) : (
              <ul data-mute-list className="divide-y divide-(--iw-line)">
                {list.muteRules.map((rule) => (
                  <li key={`rule:${rule.id}`} data-mute={rule.id} className="space-y-2 py-3 first:pt-0 last:pb-0">
                    <p className={BODY_TEXT}>
                      <code className="font-mono text-[12.5px] text-(--iw-ink)">{rule.id}</code>
                      {rule.title === undefined ? null : <>: {rule.title}</>}
                    </p>
                    {rule.remove === undefined ? null : <RemoveStep step={rule.remove} />}
                  </li>
                ))}
                {list.muteCategories.map((category) => (
                  <li key={`category:${category.id}`} data-mute={category.id} className="space-y-2 py-3 first:pt-0 last:pb-0">
                    <p className={BODY_TEXT}>
                      Category <code className="font-mono text-[12.5px] text-(--iw-ink)">{category.id}</code>
                    </p>
                    {category.remove === undefined ? null : <RemoveStep step={category.remove} />}
                  </li>
                ))}
              </ul>
            )}
            <MoreLine n={list.more.muteRules + list.more.muteCategories} step={list.listSteps.mute} />
          </div>
        </>
      )}
      <p data-exception-changes className={BODY_TEXT}>{changesLine}</p>
    </div>
  );
}
