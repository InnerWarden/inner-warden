import { Fragment, useState, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import { fetchAgents, fetchOverview, fetchTokenIntelligence, type Overview as OverviewPayload } from "../api";
import { LaneCards } from "../components/LaneCards";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { TechnicalOnly, useTechnicalDetail } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { Ring, type Part } from "../components/viz";
import { overviewLaneCards, type LaneCard } from "../lanes";
import { compactCount, formatCount, formatDay, humanizeToken, normaliseMode } from "../presentation";
import { agentRows, agentsSummary, modeLine, modeWord, nameList, type AgentRow } from "./agentsView";
import { fetchDecisions, fetchHistory, fetchRecordHealth, readLaneNextStep, readOverviewRecord, type Decision, type DecisionsPage, type History, type Reason, type RecordSpan } from "./api";
import { CaseRow } from "./CaseRow";
import { OfferBox } from "./Offer";
import { serverOffer, type RanHere } from "./offers";
import { CARD, CopyCommand, Go, Skeleton, StaleLine, Unreadable } from "./parts";
import { usePolled } from "./poll";
import { rowRuns, type Run } from "./rows";
import { tokenRows, tokenTotal } from "./tokensView";
import { asPlatform, MODE_WORDS, OUTCOME_WORDS, type PlatformOs } from "./words";

export const OVERVIEW_POLL_MS = 10_000;
export const AGENTS_POLL_MS = 30_000;
export const TOKENS_POLL_MS = 300_000;
export const HISTORY_POLL_MS = 60_000;
/** Recently flagged shows this many situations, runs of one reason folded into one. */
export const RECENT_SHOWN = 5;
/**
 * Read enough to fill five situations when the newest are one long run (an
 * agent looping on one script), and ask less often than the cards: this list
 * is the newest flagged, not a live feed.
 */
const RECENT_READ = 30;
const RECENT_POLL_MS = 30_000;

/** Community's order: what the agent did leads, the card with the offer is last. */
const LANE_ORDER = ["agent_actions", "agent_messages", "server_attacks"] as const;

export function orderedCards(cards: readonly LaneCard[]): LaneCard[] {
  return [...cards].sort((a, b) => LANE_ORDER.indexOf(a.lane) - LANE_ORDER.indexOf(b.lane));
}

/**
 * The cards with each part of a split in the words the Cases page prints the
 * same outcome in (`OUTCOME_WORDS`): one count, one name, on every page. A
 * key the table does not know keeps the CLI's own words.
 */
export function communityCards(cards: readonly LaneCard[]): LaneCard[] {
  return cards.map((card) =>
    card.state !== "available" || card.breakdown === undefined
      ? card
      : {
          ...card,
          breakdown: card.breakdown.map((part) =>
            Object.prototype.hasOwnProperty.call(OUTCOME_WORDS, part.key)
              ? { ...part, label: OUTCOME_WORDS[part.key as keyof typeof OUTCOME_WORDS] }
              : part,
          ),
        },
  );
}

/** A part of a card's split, by key, or 0. */
function partCount(card: LaneCard | undefined, key: string): number {
  if (card === undefined || card.state !== "available") return 0;
  return card.breakdown?.find((part) => part.key === key)?.count ?? 0;
}

/** The span a card counted, in the words a sentence ends with. */
function spanWords(card: LaneCard | undefined): string {
  if (card === undefined || card.state !== "available" || card.since === undefined) return "in the last 7 days";
  return `since ${formatDay(card.since)}`;
}

/**
 * The flagged commands that ran here in a way Community's own refusing mode
 * does not stop (the rules asked for a review, or a deny went through an MCP
 * connection that only warns): the reader's own number the offer leads with.
 */
export function ranHere(card: LaneCard | undefined): RanHere {
  return { count: partCount(card, "flagged_ran") + partCount(card, "unsafe_may_have_run"), span: spanWords(card) };
}

/**
 * The reason that is more than half of everything flagged, when one is: an
 * agent's own scratch scripts can be three quarters of a real record, and a
 * list of the newest would then show nothing else.
 */
export function dominantReason(page: DecisionsPage | undefined): Reason | undefined {
  const top = page?.reasons[0];
  if (page === undefined || top === undefined || page.flaggedTotal === 0) return undefined;
  return top.count * 2 > page.flaggedTotal ? top : undefined;
}

/**
 * The guard's long log in one slate line: what Community refused for this
 * reader since the log began. The proof it is worth keeping, on the page
 * people open first; Protection has it week by week.
 */
export function valueProofLine(history: History | undefined): string | undefined {
  if (history === undefined || !history.readable) return undefined;
  const since = history.since === undefined ? "" : ` since ${formatDay(history.since)}`;
  if (history.refusals.blocked > 0) return `${formatCount(history.refusals.blocked)} refused before they ran${since}, from the guard's log.`;
  if (history.refusals.wouldBlock > 0) return `${formatCount(history.refusals.wouldBlock)} would have been refused${since}, from the guard's log.`;
  return undefined;
}

/**
 * Community's Overview: what the agents did, what people asked them, and
 * what Community does not watch, then what is on this machine, then the
 * newest flagged commands. Every figure is the CLI's, from this machine's
 * own records; a source that could not be read says so in its own place and
 * the rest of the page still renders. A machine with nothing connected yet
 * gets its first steps FIRST, under the heading, before any card.
 */
export function CommunityOverview({ context }: { context: CommunityScreenContext }) {
  const overview = usePolled(fetchOverview, OVERVIEW_POLL_MS, "overview");
  const recent = usePolled(() => fetchDecisions({ limit: RECENT_READ }), RECENT_POLL_MS, "recent-flagged");
  const agents = usePolled(fetchAgents, AGENTS_POLL_MS, "agents");
  const tokens = usePolled(fetchTokenIntelligence, TOKENS_POLL_MS, "tokens");
  const health = usePolled(fetchRecordHealth, AGENTS_POLL_MS, "record-health");
  const history = usePolled(fetchHistory, HISTORY_POLL_MS, "history");
  const [showDominant, setShowDominant] = useState(false);
  const dominant = dominantReason(recent.data);
  const hiding = dominant !== undefined && !showDominant;
  const withoutDominant = usePolled(
    () => (dominant === undefined ? Promise.resolve(undefined) : fetchDecisions({ limit: RECENT_READ, reasonNot: dominant.key })),
    hiding ? RECENT_POLL_MS : 0,
    hiding ? `recent-without:${dominant.key}` : "recent-without:",
  );
  const os = asPlatform(context.bootstrap?.platform.os);
  const installed = context.meta?.active_defence_installed === true;
  const openCases = (params?: Record<string, string>) => context.navigate("activity", params);
  const data = overview.data;
  const parsed = data === undefined ? undefined : overviewLaneCards(data.lanes);
  const cards = parsed === undefined ? undefined : communityCards(parsed);
  const agentCard = cards?.find((card) => card.lane === "agent_actions");
  const record = readOverviewRecord((data as (OverviewPayload & { record?: unknown }) | undefined)?.record);
  const rows = agentRows(agents.data);
  const nothingYet = agentCard?.state === "no_source";
  const shown = hiding ? withoutDominant.data : recent.data;
  const shownFailed = hiding ? withoutDominant.data === undefined && withoutDominant.error !== undefined : false;

  return (
    <div className="min-w-0 space-y-8">
      {overview.stale ? <StaleLine onRetry={overview.refresh} /> : null}
      {data === undefined ? (
        overview.error === undefined ? (
          <Skeleton className="h-80" />
        ) : (
          <section aria-labelledby="lanes-title" className="space-y-3">
            <h1 id="lanes-title" className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">What is happening here</h1>
            <Unreadable
              title="The decision record could not be read"
              body={<><code className="font-mono">innerwarden status</code> says why. Agents and tokens below still come from their own sources.</>}
              onRetry={overview.refresh}
            />
          </section>
        )
      ) : cards === undefined ? (
        <Unreadable title="This InnerWarden sends no summary this page can read" body="Update InnerWarden, or run innerwarden status." />
      ) : (
        <LaneCards
          cards={orderedCards(cards)}
          edition="community"
          intro="From this machine's own records."
          beforeCards={nothingYet ? <GetStarted rows={rows} agentsLoaded={agents.data !== undefined} connect={readLaneNextStep(data.lanes, "agent_actions")?.command} /> : undefined}
          onOpenLane={(lane) => openCases(lane === "agent_messages" ? { lane } : {})}
          onOpenCase={(caseId, lane) => openCases(lane === "agent_messages" ? { lane, decision: caseId } : { decision: caseId })}
          linkLabel={(lane) => (lane === "agent_actions" ? "See the flagged commands" : lane === "agent_messages" ? "See the messages" : undefined)}
          title={(lane) => (lane === "server_attacks" && os !== "linux" ? "Attacks on this machine" : undefined)}
          blurb={(lane) =>
            lane !== "server_attacks"
              ? undefined
              : os === "linux"
                ? "Community does not watch this. Active Defence does."
                : "Community does not watch this. Active Defence does, on Linux servers."
          }
          footer={(card) =>
            laneFooter(card, {
              overview: data,
              os,
              installed,
              nothingYet,
              record,
              history: history.data,
              ran: ranHere(agentCard),
              onProtection: () => context.navigate("posture"),
            })
          }
          align={cards.some((card) => card.lane !== "server_attacks" && card.state === "no_source") ? "start" : undefined}
        />
      )}

      <OnThisMachine
        context={context}
        agentsLoaded={agents.data !== undefined}
        agentsFailed={agents.data === undefined && agents.error !== undefined}
        rows={rows}
        record={record}
        recordFailed={data === undefined && overview.error !== undefined}
        recording={health.data?.recording}
        outageSince={health.data?.sinceUnix}
        wouldHaveRefused={partCount(agentCard, "would_have_refused")}
        wouldSpan={spanWords(agentCard)}
        tokens={tokens.data === undefined ? undefined : tokenTotal(tokenRows(tokens.data))}
        tokensFailed={tokens.data === undefined && tokens.error !== undefined}
        tokensRead={tokens.data !== undefined && tokens.data.availability !== "loading"}
      />

      {nothingYet ? null : (
        <RecentFlagged
          loading={(recent.data === undefined && recent.error === undefined) || (shown === undefined && !shownFailed && recent.error === undefined)}
          failed={(recent.data === undefined && recent.error !== undefined) || shownFailed}
          runs={rowRuns(shown?.items ?? []).slice(0, RECENT_SHOWN)}
          total={recent.data?.flaggedTotal}
          sinceWords={record?.oldestAt === undefined ? undefined : formatDay(record.oldestAt)}
          screened={record?.decisions}
          dominant={dominant}
          hidingDominant={hiding}
          onToggleDominant={() => setShowDominant((value) => !value)}
          onOpen={(id) => openCases({ decision: id })}
          onAll={() => openCases()}
          onReason={(reason) => openCases({ reason })}
        />
      )}

      {data === undefined ? null : <OverviewRecords overview={data} />}
    </div>
  );
}

type FooterFacts = {
  overview: OverviewPayload;
  os: PlatformOs;
  installed: boolean;
  nothingYet: boolean;
  record?: RecordSpan;
  history?: History;
  ran: RanHere;
  onProtection: () => void;
};

function laneFooter(card: LaneCard, facts: FooterFacts): ReactNode {
  if (card.lane === "server_attacks") {
    // No offer on a machine with nothing recorded yet: a new reader's first
    // need is their own first step, and an offer never comes before the
    // page's first real figure.
    if (facts.record === undefined || facts.record.decisions === 0) return undefined;
    return <OfferBox offer={serverOffer(facts.os, facts.ran)} installed={facts.installed} />;
  }
  if (card.lane === "agent_actions" && card.state === "available") {
    const proof = valueProofLine(facts.history);
    if (proof === undefined) return undefined;
    return (
      <p data-value-proof className="text-xs leading-5 text-slate-600">
        {proof}{" "}
        <button type="button" onClick={facts.onProtection} className="font-semibold text-cyan-700 hover:text-cyan-900">
          Protection <span aria-hidden="true">→</span>
        </button>
      </p>
    );
  }
  if (card.state !== "no_source") return undefined;
  // The first run's steps sit above the cards; the card does not repeat them.
  if (card.lane === "agent_actions" && facts.nothingYet) {
    return <p className="text-sm leading-6 text-slate-600">No agent is connected yet. Start above.</p>;
  }
  const step = readLaneNextStep(facts.overview.lanes, card.lane);
  if (step === undefined) return undefined;
  return (
    <div>
      <CopyCommand command={step.command} />
      <p className="mt-1.5 text-xs leading-5 text-slate-600">{step.line}</p>
    </div>
  );
}

function Tile({ label, children, link }: { label: string; children: ReactNode; link?: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col rounded-2xl border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <div className="mt-2 min-w-0">{children}</div>
      {link === undefined ? null : <div className="mt-auto pt-3">{link}</div>}
    </div>
  );
}

/** The four tiles: two across on a phone, four across on a desk. */
export const TILES = "mt-3 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4";

function OnThisMachine({
  context,
  agentsLoaded,
  agentsFailed,
  rows,
  record,
  recordFailed,
  recording,
  outageSince,
  wouldHaveRefused,
  wouldSpan,
  tokens,
  tokensFailed,
  tokensRead,
}: {
  context: CommunityScreenContext;
  agentsLoaded: boolean;
  agentsFailed: boolean;
  rows: AgentRow[];
  record?: RecordSpan;
  recordFailed: boolean;
  recording?: boolean;
  outageSince?: number;
  /** Commands the agent card counts as "would have been refused" (monitor mode). */
  wouldHaveRefused: number;
  wouldSpan: string;
  tokens?: { total: bigint; agents: number };
  tokensFailed: boolean;
  /** The history was read and holds no counters: said, never left "reading". */
  tokensRead: boolean;
}) {
  const summary = agentsSummary(rows);
  const connected = summary.refusing + summary.watching;
  const ringParts: Part[] = [
    { key: "refusing", value: summary.refusing, tone: "accent", label: `Refusing: ${summary.refusing}` },
    { key: "watching", value: summary.watching, tone: "watch", label: `Watching only: ${summary.watching}` },
    { key: "needs", value: summary.needsYou.length, tone: "attention", label: `Need you: ${summary.needsYou.length}` },
    { key: "other", value: summary.unconfirmed.length, tone: "off", label: `Status not confirmed: ${summary.unconfirmed.length}` },
  ];
  const mode = normaliseMode(context.meta);
  const line = modeLine(rows);
  // The CLI's own step for an agent that only watches (`innerwarden enforce`),
  // printed as sent: the kit never builds it.
  const enforceStep = rows.find((row) => row.state === "watching" && row.next !== undefined)?.next;
  const watching = rows.some((row) => row.state === "watching");
  return (
    <section aria-labelledby="on-machine-title">
      <h2 id="on-machine-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">On this machine</h2>
      <div className={TILES}>
        <Tile label="Agents" link={<Go onClick={() => context.navigate("agents")}>Agents</Go>}>
          {agentsFailed ? (
            <p className="text-sm text-slate-600">Agents did not answer.</p>
          ) : !agentsLoaded ? (
            <p className="text-sm text-slate-500">Looking for agents</p>
          ) : summary.total === 0 ? (
            <p className="text-sm leading-6 text-slate-600">
              {rows.some((row) => row.state === "unsupported")
                ? `${nameList(rows.filter((row) => row.state === "unsupported").map((row) => row.name))} cannot be connected yet.`
                : "No AI agent found on this machine."}
            </p>
          ) : (
            <div className="flex items-center gap-2.5 sm:gap-3">
              <Ring parts={ringParts} size={44} stroke={6} label={`${connected} of ${summary.total} agents connected`} />
              <div className="min-w-0">
                <p className="flex flex-wrap items-baseline gap-x-1.5">
                  <span className="text-xl font-semibold text-slate-950 sm:text-2xl">{connected} of {summary.total}</span>{" "}
                  <span className="text-sm text-slate-600">connected</span>
                </p>
                {summary.needsYou.length > 0 ? (
                  <p data-needs-you="" className="mt-0.5 text-xs font-semibold leading-5 text-amber-900">
                    <span aria-hidden="true">! </span>
                    {summary.needsYou.length} {summary.needsYou.every((row) => row.state === "partial") ? "partly connected" : "not connected"}: {nameList(summary.needsYou.map((row) => row.name))}
                  </p>
                ) : summary.unconfirmed.length > 0 ? (
                  <p className="mt-0.5 text-xs leading-5 text-slate-600">
                    {nameList(summary.unconfirmed.map((row) => row.name))}: status not confirmed.
                  </p>
                ) : (
                  <p className="mt-0.5 text-xs leading-5 text-slate-600">Every agent found is connected.</p>
                )}
              </div>
            </div>
          )}
        </Tile>
        <Tile label="Mode" link={<Go onClick={() => context.navigate("posture")}>Protection</Go>}>
          <p className="text-xl font-semibold text-slate-950 sm:text-2xl">{modeWord(rows) ?? MODE_WORDS[mode]}</p>
          {line === undefined ? null : <p className="mt-1 text-xs leading-5 text-slate-600">{line}</p>}
          {watching && wouldHaveRefused > 0 ? (
            <p data-mode-step className="mt-1 text-xs leading-5 text-slate-700">
              {formatCount(wouldHaveRefused)} {wouldHaveRefused === 1 ? "command" : "commands"} would have been refused {wouldSpan}.
              {enforceStep === undefined ? null : (
                <> <code className="font-mono text-slate-900">{enforceStep.command}</code> refuses them.</>
              )}
            </p>
          ) : null}
        </Tile>
        <Tile label="Decision record" link={<Go onClick={() => context.navigate("activity")}>Cases</Go>}>
          {record === undefined ? (
            <p className="text-sm text-slate-600">{recordFailed ? "Could not be read." : "Reading the record"}</p>
          ) : (
            <>
              <p className="flex flex-wrap items-baseline gap-x-1.5">
                <span className="text-xl font-semibold text-slate-950 sm:text-2xl">{formatCount(record.decisions)}</span>{" "}
                <span className="text-sm text-slate-600">
                  {record.decisions === 1 ? "decision" : "decisions"}
                  {record.oldestAt === undefined ? "" : ` since ${formatDay(record.oldestAt)}`}
                </span>
              </p>
              {record.checked > 0 ? (
                <p data-record-checked className="mt-0.5 text-xs leading-5 text-slate-600">
                  {formatCount(record.checked)} of them {record.checked === 1 ? "a check" : "checks"} by hand.
                </p>
              ) : null}
            </>
          )}
          {recording === false ? (
            <p data-needs-you="" className="mt-1 text-xs font-semibold leading-5 text-amber-900">
              <span aria-hidden="true">! </span>Not recording{outageSince === undefined ? "" : " since "}
              {outageSince === undefined ? null : <When at={outageSince * 1_000} />}
            </p>
          ) : recording === true && record !== undefined ? (
            <p className="mt-1 text-xs leading-5 text-slate-600">Recording.</p>
          ) : null}
        </Tile>
        <Tile label="Tokens" link={<Go onClick={() => context.navigate("tokens")}>Tokens</Go>}>
          {tokens === undefined ? (
            <p className="text-sm leading-6 text-slate-600">
              {tokensFailed ? "Token history did not answer." : tokensRead ? "No agent here keeps a token history this can read." : "Reading local history"}
            </p>
          ) : (
            <>
              <p className="flex flex-wrap items-baseline gap-x-1.5">
                <span className="text-xl font-semibold text-slate-950 sm:text-2xl">{compactCount(tokens.total)}</span>{" "}
                <span className="text-sm text-slate-600">tokens</span>
              </p>
              <p className="mt-1 text-xs leading-5 text-slate-600">
                {tokens.agents === 1 ? "From 1 agent's own history" : `From ${tokens.agents} agents' own history`}
              </p>
            </>
          )}
        </Tile>
      </div>
    </section>
  );
}

function RecentFlagged({
  loading,
  failed,
  runs,
  total,
  sinceWords,
  screened,
  dominant,
  hidingDominant,
  onToggleDominant,
  onOpen,
  onAll,
  onReason,
}: {
  loading: boolean;
  failed: boolean;
  /** The newest flagged situations: a run of one reason in one session is one. */
  runs: Run<Decision>[];
  /** Every flagged decision in the record: what "nothing flagged" is decided by, never the rows drawn. */
  total?: number;
  sinceWords?: string;
  screened?: number;
  /** A reason that is more than half of everything flagged, when one is. */
  dominant?: Reason;
  hidingDominant: boolean;
  onToggleDominant: () => void;
  onOpen: (id: string) => void;
  onAll: () => void;
  onReason: (reason: string) => void;
}) {
  return (
    <section aria-labelledby="recent-flagged-title">
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
        <h2 id="recent-flagged-title" className="text-lg font-semibold text-slate-950">Recently flagged</h2>
        {total !== undefined && total > 0 ? <Go onClick={onAll}>See all {formatCount(total)} in Cases</Go> : null}
      </div>
      <div className="mt-3">
        {loading ? (
          <Skeleton className="h-40" />
        ) : failed ? (
          <Unreadable title="The flagged commands could not be read" />
        ) : total === 0 ? (
          <p className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">
            {screened === undefined || screened === 0
              ? "Nothing flagged yet."
              : `Nothing flagged${sinceWords === undefined ? "" : ` since ${sinceWords}`}. Every command was screened and allowed.`}
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            {dominant === undefined ? null : (
              <li data-dominant-reason={dominant.key} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 bg-slate-50 px-4 py-2 text-xs text-slate-600">
                <span>
                  {hidingDominant
                    ? `${formatCount(dominant.count)} from the ${dominant.short} rule, hidden here.`
                    : `Showing the ${formatCount(dominant.count)} from the ${dominant.short} rule.`}
                </span>
                <button type="button" onClick={onToggleDominant} aria-pressed={!hidingDominant} className="font-semibold text-cyan-700 hover:text-cyan-900">
                  {hidingDominant ? "Show" : "Hide"}
                </button>
              </li>
            )}
            {runs.length === 0 ? (
              <li className="px-4 py-3 text-sm text-slate-600">
                {hidingDominant ? "Nothing else was flagged." : `${formatCount(total ?? 0)} flagged could not be shown.`}
              </li>
            ) : null}
            {runs.map((run) => (
              <Fragment key={run.first.id}>
                <CaseRow item={run.first} open={false} onOpen={onOpen} />
                {run.folded.length === 0 ? null : (
                  <li className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-l-2 border-dashed border-slate-300 bg-slate-50 py-2 pl-8 pr-4 text-xs text-slate-600">
                    <span>{formatCount(run.folded.length)} more in a row, flagged for the same reason</span>
                    <button type="button" onClick={() => onReason(run.first.reason.key)} className="font-semibold text-cyan-700 hover:text-cyan-900">
                      See them <span aria-hidden="true">→</span>
                    </button>
                  </li>
                )}
              </Fragment>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

/**
 * A first run's steps, where a new reader sees them first: under the page's
 * heading, before any card. Only commands that do something on THIS machine
 * are offered: connecting when an agent is here, installing one when none is.
 * The page they are reading is not a step.
 */
function GetStarted({ rows, agentsLoaded, connect }: { rows: readonly AgentRow[]; agentsLoaded: boolean; connect?: string }) {
  const found = rows.filter((row) => row.state !== "unsupported");
  const steps: { title: string; command?: string; line: string }[] = [
    agentsLoaded && found.length === 0
      ? {
          title: "Install a supported agent (Claude Code, Codex, Cursor, Gemini CLI), then connect it",
          line: "Once one is installed, this step shows the command that connects it.",
        }
      : {
          title: "Connect your agents in monitor mode",
          command: connect ?? "innerwarden agents connect --all --monitor",
          line: "Every command they try is recorded and nothing is refused.",
        },
    { title: "Use your agent as usual", line: "Flagged commands appear under Cases, one case each." },
    { title: "Refuse a deny when you are ready", command: "innerwarden enforce", line: "A deny is then refused before it runs." },
  ];
  return (
    <section aria-labelledby="get-started-title" data-get-started="" className={CARD}>
      <h2 id="get-started-title" className="text-lg font-semibold text-slate-950">Getting started</h2>
      <ol className="mt-3 space-y-4">
        {steps.map((step, index) => (
          <li key={step.title} className="flex gap-3">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white">{index + 1}</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-slate-900">{step.title}</p>
              {step.command === undefined ? null : <CopyCommand command={step.command} className="mt-1.5 max-w-xl" />}
              <p className="mt-1 text-xs leading-5 text-slate-600">{step.line}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** The numbers behind the cards, for whoever asks: technical view only. */
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
  return (
    <TechnicalOnly>
      <section aria-labelledby="overview-records-title" className="space-y-6 border-t border-slate-200 pt-6">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Technical detail</p>
          <h2 id="overview-records-title" className="mt-1 text-lg font-semibold text-slate-950">The records behind these cards</h2>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 sm:gap-4 lg:grid-cols-3">
          <Tile label="By verdict">
            <dl className="space-y-1 text-sm">
              {verdicts.map(([name, count]) => (
                <div key={name} className="flex justify-between gap-3"><dt className="text-slate-600">{name}</dt><dd className="font-semibold tabular-nums text-slate-950">{formatCount(count)}</dd></div>
              ))}
            </dl>
          </Tile>
          <Tile label="By outcome">
            <dl className="space-y-1 text-sm">
              {outcomes.map(([name, count]) => (
                <div key={name} className="flex justify-between gap-3"><dt className="text-slate-600">{name}</dt><dd className="font-semibold tabular-nums text-slate-950">{formatCount(count)}</dd></div>
              ))}
            </dl>
          </Tile>
          <Tile label="The record">
            <dl className="space-y-1 text-sm text-slate-700">
              <div><dt className="inline text-slate-500">Decisions kept: </dt><dd className="inline tabular-nums">{formatCount(record?.decisions ?? overview.commands)}</dd></div>
              {record?.oldestAt === undefined ? null : <div><dt className="inline text-slate-500">Oldest: </dt><dd className="inline"><When at={record.oldestAt} /></dd></div>}
              {record?.newestAt === undefined ? null : <div><dt className="inline text-slate-500">Newest: </dt><dd className="inline"><When at={record.newestAt} /></dd></div>}
            </dl>
            <p className="mt-2 text-xs leading-5 text-slate-500">InnerWarden keeps the newest decisions; older ones are dropped.</p>
          </Tile>
        </div>
        {overview.top_categories.length === 0 ? null : (
          <div className={CARD}>
            <p className="text-sm font-semibold text-slate-900">Rule categories matched</p>
            <p className="mt-1 text-xs leading-5 text-slate-500">These count categories matched, not decisions: one decision can match several.</p>
            <ul className="mt-2 flex flex-wrap gap-2 text-xs">
              {overview.top_categories.slice(0, 8).map((category) => (
                <li key={category.name} className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-slate-700">
                  {humanizeToken(category.name)} <span className="font-semibold tabular-nums">{formatCount(category.count)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <MachineIntelligence edition="community" showAgents showTokens tones="neutral" />
      </section>
    </TechnicalOnly>
  );
}
