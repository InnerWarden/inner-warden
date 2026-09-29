import { Fragment, type ReactNode } from "react";
import type { CommunityScreenContext } from "../App";
import { fetchAgents, fetchOverview, fetchTokenIntelligence, type Overview as OverviewPayload } from "../api";
import { LaneCards } from "../components/LaneCards";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { TechnicalOnly, useTechnicalDetail } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { Ring, type Part } from "../components/viz";
import { overviewLaneCards, type LaneCard } from "../lanes";
import { compactCount, formatCount, formatDay, humanizeToken, normaliseMode } from "../presentation";
import { agentRows, agentsSummary, modeLine, modeWord, nameList } from "./agentsView";
import { fetchDecisions, fetchRecordHealth, readLaneNextStep, readOverviewRecord, type Decision } from "./api";
import { CaseRow } from "./CaseRow";
import { OfferBox } from "./Offer";
import { serverOffer } from "./offers";
import { CARD, CopyCommand, Go, Skeleton, StaleLine, Unreadable } from "./parts";
import { usePolled } from "./poll";
import { rowRuns, type Run } from "./rows";
import { tokenRows, tokenTotal } from "./tokensView";
import { asPlatform, MODE_WORDS } from "./words";

export const OVERVIEW_POLL_MS = 10_000;
export const AGENTS_POLL_MS = 30_000;
export const TOKENS_POLL_MS = 300_000;
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
 * Community's Overview: what the agents did, what people asked them, and
 * what Community does not watch, then what is on this machine, then the
 * newest flagged commands. Every figure is the CLI's, from this machine's
 * own records; a source that could not be read says so in its own place and
 * the rest of the page still renders.
 */
export function CommunityOverview({ context }: { context: CommunityScreenContext }) {
  const overview = usePolled(fetchOverview, OVERVIEW_POLL_MS, "overview");
  const recent = usePolled(() => fetchDecisions({ limit: RECENT_READ }), RECENT_POLL_MS, "recent-flagged");
  const agents = usePolled(fetchAgents, AGENTS_POLL_MS, "agents");
  const tokens = usePolled(fetchTokenIntelligence, TOKENS_POLL_MS, "tokens");
  const health = usePolled(fetchRecordHealth, AGENTS_POLL_MS, "record-health");
  const os = asPlatform(context.bootstrap?.platform.os);
  const installed = context.meta?.active_defence_installed === true;
  const openCases = (params?: Record<string, string>) => context.navigate("activity", params);
  const data = overview.data;
  const cards = data === undefined ? undefined : overviewLaneCards(data.lanes);
  const record = readOverviewRecord((data as (OverviewPayload & { record?: unknown }) | undefined)?.record);
  const rows = agentRows(agents.data);
  const nothingYet = cards?.some((card) => card.lane === "agent_actions" && card.state === "no_source") === true;

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
          onOpenLane={(lane) => openCases(lane === "agent_messages" ? { lane } : {})}
          onOpenCase={(caseId, lane) => openCases(lane === "agent_messages" ? { lane, decision: caseId } : { decision: caseId })}
          linkLabel={(lane) => (lane === "agent_actions" ? "See the flagged commands" : lane === "agent_messages" ? "See the messages" : undefined)}
          footer={(card) => laneFooter(card, data, os, installed)}
          align={cards.some((card) => card.lane !== "server_attacks" && card.state === "no_source") ? "start" : undefined}
        />
      )}

      <OnThisMachine
        context={context}
        agentsLoaded={agents.data !== undefined}
        agentsFailed={agents.data === undefined && agents.error !== undefined}
        rows={rows}
        record={record}
        recording={health.data?.recording}
        outageSince={health.data?.sinceUnix}
        tokens={tokens.data === undefined ? undefined : tokenTotal(tokenRows(tokens.data))}
        tokensFailed={tokens.data === undefined && tokens.error !== undefined}
        tokensRead={tokens.data !== undefined && tokens.data.availability !== "loading"}
      />

      {nothingYet ? <GetStarted /> : null}

      {nothingYet ? null : (
        <RecentFlagged
          loading={recent.data === undefined && recent.error === undefined}
          failed={recent.data === undefined && recent.error !== undefined}
          runs={rowRuns(recent.data?.items ?? []).slice(0, RECENT_SHOWN)}
          total={recent.data?.flaggedTotal}
          sinceWords={record?.oldestAt === undefined ? undefined : formatDay(record.oldestAt)}
          screened={record?.decisions}
          onOpen={(id) => openCases({ decision: id })}
          onAll={() => openCases()}
          onReason={(reason) => openCases({ reason })}
        />
      )}

      {data === undefined ? null : <OverviewRecords overview={data} />}
    </div>
  );
}

function laneFooter(card: LaneCard, overview: OverviewPayload, os: ReturnType<typeof asPlatform>, installed: boolean): ReactNode {
  if (card.lane === "server_attacks") return <OfferBox offer={serverOffer(os)} installed={installed} />;
  if (card.state !== "no_source") return undefined;
  const step = readLaneNextStep(overview.lanes, card.lane);
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
    <div className="flex min-w-0 grow basis-[15rem] flex-col rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <div className="mt-2 min-w-0">{children}</div>
      {link === undefined ? null : <div className="mt-auto pt-3">{link}</div>}
    </div>
  );
}

function OnThisMachine({
  context,
  agentsLoaded,
  agentsFailed,
  rows,
  record,
  recording,
  outageSince,
  tokens,
  tokensFailed,
  tokensRead,
}: {
  context: CommunityScreenContext;
  agentsLoaded: boolean;
  agentsFailed: boolean;
  rows: ReturnType<typeof agentRows>;
  record?: ReturnType<typeof readOverviewRecord>;
  recording?: boolean;
  outageSince?: number;
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
  return (
    <section aria-labelledby="on-machine-title">
      <h2 id="on-machine-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">On this machine</h2>
      <div className="mt-3 flex flex-wrap gap-4">
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
            <div className="flex items-center gap-3">
              <Ring parts={ringParts} size={56} stroke={7} label={`${connected} of ${summary.total} agents connected`} />
              <div className="min-w-0">
                <p className="flex flex-wrap items-baseline gap-x-1.5">
                  <span className="text-2xl font-semibold text-slate-950">{connected} of {summary.total}</span>{" "}
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
          <p className="text-2xl font-semibold text-slate-950">{modeWord(rows) ?? MODE_WORDS[mode]}</p>
          {line === undefined ? null : <p className="mt-1 text-xs leading-5 text-slate-600">{line}</p>}
          {modeWord(rows) === "Watching only" ? (
            <p className="mt-1 text-xs leading-5 text-slate-600">
              <code className="font-mono text-slate-800">innerwarden enforce</code> turns refusing on.
            </p>
          ) : null}
        </Tile>
        <Tile label="Decision record" link={<Go onClick={() => context.navigate("activity")}>Cases</Go>}>
          {record === undefined ? (
            <p className="text-sm text-slate-600">Not read yet.</p>
          ) : (
            <p className="flex flex-wrap items-baseline gap-x-1.5">
              <span className="text-2xl font-semibold text-slate-950">{formatCount(record.decisions)}</span>{" "}
              <span className="text-sm text-slate-600">
                {record.decisions === 1 ? "decision" : "decisions"}
                {record.oldestAt === undefined ? "" : ` since ${formatDay(record.oldestAt)}`}
              </span>
            </p>
          )}
          {recording === false ? (
            <p data-needs-you="" className="mt-1 text-xs font-semibold leading-5 text-amber-900">
              <span aria-hidden="true">! </span>Not recording{outageSince === undefined ? "" : " since "}
              {outageSince === undefined ? null : <When at={outageSince * 1_000} />}
            </p>
          ) : recording === true ? (
            <p className="mt-1 text-xs leading-5 text-slate-600">Recording every decision.</p>
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
                <span className="text-2xl font-semibold text-slate-950">{compactCount(tokens.total)}</span>{" "}
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
  onOpen,
  onAll,
  onReason,
}: {
  loading: boolean;
  failed: boolean;
  /** The newest flagged situations: a run of one reason in one session is one. */
  runs: Run<Decision>[];
  total?: number;
  sinceWords?: string;
  screened?: number;
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
        ) : runs.length === 0 ? (
          <p className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">
            {screened === undefined || screened === 0
              ? "Nothing flagged yet."
              : `Nothing flagged${sinceWords === undefined ? "" : ` since ${sinceWords}`}. Every command was screened and allowed.`}
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
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

function GetStarted() {
  const steps: [string, string, string][] = [
    ["Connect your agents in monitor mode", "innerwarden agents connect --all --monitor", "Every command they try is recorded and nothing is refused."],
    ["Watch what they do", "innerwarden dashboard", "Flagged commands appear under Cases, one case each."],
    ["Refuse a deny when you are ready", "innerwarden enforce", "A deny is then refused before it runs."],
  ];
  return (
    <section aria-labelledby="get-started-title" className={CARD}>
      <h2 id="get-started-title" className="text-lg font-semibold text-slate-950">Getting started</h2>
      <ol className="mt-3 space-y-4">
        {steps.map(([title, command, line], index) => (
          <li key={title} className="flex gap-3">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white">{index + 1}</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-slate-900">{title}</p>
              <CopyCommand command={command} className="mt-1.5" />
              <p className="mt-1 text-xs leading-5 text-slate-600">{line}</p>
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
        <div className="flex flex-wrap gap-4">
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
        <MachineIntelligence edition="community" showAgents showTokens />
      </section>
    </TechnicalOnly>
  );
}
