import { useEffect, useState, type ReactNode } from "react";
import { headline, type Headline } from "../components/HeadlineAnswer";
import { TechnicalOnly, useTechnicalDetail } from "../components/TechnicalDetail";
import {
  fetchOverview,
  type DashboardMeta,
  type DecisionSummary,
  type GuardrailMode,
  type Overview,
} from "../api";
import type { CaseLane } from "../api/cases";
import { DecidedBy } from "../components/DecidedBy";
import { LaneCards, type LaneOpenOptions } from "../components/LaneCards";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { Outcome } from "../components/Outcome";
import { SensorActivity } from "../components/SensorActivity";
import { Verdict } from "../components/Verdict";
import { overviewLaneCards, type LaneCard } from "../lanes";
import { formatTimestamp, humanizeToken, normaliseMode } from "../presentation";

type ActivityLink = { id?: string; session?: string; verdict?: string; action?: string };

/**
 * Where one recorded decision on this screen leads when clicked.
 *
 * - `case`: the server named the unified case this decision belongs to, and the
 *   shell can open the Cases screen, so the entry deep-links to that case.
 * - `activity`: Community's decision record IS its case surface (one place per
 *   product, not two screens over the same graph), so the entry opens Activity
 *   with this decision selected.
 * - `none`: there is nowhere real to go. The entry must then not look
 *   clickable, because a link that bounces back to Overview teaches the
 *   operator that clicking is pointless. This is what every Enterprise entry
 *   did before the server sent `case_id`.
 */
export type DecisionEntryLink =
  | { kind: "case"; caseId: string }
  | { kind: "activity" }
  | { kind: "none" };

export function decisionEntryLink(
  caseId: string | undefined,
  edition: "community" | "enterprise" | undefined,
  canOpenCase: boolean,
): DecisionEntryLink {
  if (caseId && canOpenCase) return { kind: "case", caseId };
  if (edition === "community") return { kind: "activity" };
  return { kind: "none" };
}

/**
 * The "view everything" step out of the Decision record section.
 *
 * Community goes to Activity, its decision record. Enterprise goes to Cases
 * when the shell offers it; when it does not, the button is hidden rather than
 * rendered as a link that silently lands back on Overview.
 *
 * On a host that files cases into lanes it goes to the agent's lane (`lane`),
 * where these decisions are, instead of the whole case list: the button used
 * to open every case on the host, thousands of them, beside a record counting
 * a handful of agent decisions, and told the reader to find them with a
 * filter. A host that does not serve lanes keeps the old destination, because
 * its Cases screen cannot open a lane.
 */
export function decisionRecordCta(
  edition: "community" | "enterprise" | undefined,
  canOpenCase: boolean,
  lanesServed = false,
): { kind: "cases" | "lane" | "activity" | "hidden"; label: string } {
  if (edition === "community") return { kind: "activity", label: "View all activity" };
  if (canOpenCase && lanesServed) return { kind: "lane", label: "View all in Cases" };
  if (canOpenCase) return { kind: "cases", label: "View all in Cases" };
  return { kind: "hidden", label: "" };
}

/**
 * What the Decision record section says: its "view everything" button, the
 * headline above the tiles, and the three verdict counts the tiles show.
 *
 * One function decides all of it from what the host sent, so the headline's
 * remedy and the button beside it read ONE decision about where "everything"
 * lives and can never name different screens. This was once two calls in the
 * render, and nothing checked that the remedy followed the button: hardcoding
 * the remedy back to "activity" sent every paid reader to an Activity tab their
 * shell does not have, and every test stayed green. Being a pure function of
 * its inputs is what lets a test hand it a paid shell and read the answer.
 */
export function decisionRecord(
  overview: Overview,
  edition: "community" | "enterprise" | undefined,
  canOpenCase: boolean,
  mode: GuardrailMode,
  lanesServed = false,
): {
  cta: ReturnType<typeof decisionRecordCta>;
  summary: Headline;
  denyVerdicts: number;
  reviewVerdicts: number;
  allowVerdicts: number;
} {
  const denyVerdicts = overview.deny_verdicts ?? overview.blocked;
  const reviewVerdicts = overview.review_verdicts ?? overview.review;
  const allowVerdicts = overview.allow_verdicts ?? overview.allowed;
  const cta = decisionRecordCta(edition, canOpenCase, lanesServed);
  // Computed from what the host already sent: no new field, no extra request.
  const summary = headline({
    needsReview: reviewVerdicts,
    reviewListedIn: cta.kind,
    // Recent activity lists verdicts only from `recent_decisions`; the older
    // `recent_blocks` fallback holds denies alone. See `recentShowsDecisions`.
    recentShowsDecisions: (overview.recent_decisions?.length ?? 0) > 0,
    denyVerdicts,
    // `?? null`, never `?? 0`: a host that sends no outcome figures has not
    // said it stopped nothing, and the headline must not read it as if it had.
    blockedBeforeExecution: overview.actual_blocks ?? null,
    wouldBlock: overview.would_block ?? null,
    screened: overview.screened ?? null,
    outcomesUnknown: overview.outcomes_unknown ?? null,
    deniesWithoutBlock: overview.denies_without_block ?? null,
    monitorOnly: mode === "monitor",
    unprovenAgents: 0,
  });
  return { cta, summary, denyVerdicts, reviewVerdicts, allowVerdicts };
}

/**
 * What the "Recorded decisions" tile is a count OF, and over what span.
 *
 * The number is `Overview.commands`: every decision node in the guard graph, for
 * the whole life of that file, ungrouped and unwindowed. The screen its CTA
 * opens counts CASES, and counts them inside a window that defaults to the last
 * 24 hours. An operator read 17 here and 1 there and reasonably took it for
 * data loss, because neither screen said what it was counting or over how long.
 *
 * Stating the span is the fix. Making the two numbers equal is not available:
 * they are different units, and the honest move when a screen cannot compare is
 * to say what each figure means rather than to bend one into the other.
 */
export function recordedDecisionsDetail(sessions: number): string {
  // NOT "all time". `Graph::prune` drops the oldest nodes past MAX_NODES and
  // sheds another tenth on top, so the store is bounded and the oldest
  // decisions are gone. Saying "all time" over a pruned record is the same
  // class of claim this whole pass is removing.
  return `No time window, across ${sessions} session${sessions === 1 ? "" : "s"}`;
}

/**
 * The footnote under Risk signals, which says what those bars count.
 *
 * They count rule CATEGORIES matched, never decisions. One decision can match
 * several categories at once, and a decision whose rule carries no category
 * matches none at all (every built-in MCP rule is in that state today), so the
 * column does not and cannot add up to the deny count printed beside it. An
 * operator compared "3" here with "11 deny verdicts" there and read the gap as
 * missing signal.
 *
 * The card also shows only the most frequent few of what the host sent, so it
 * says when it is not showing everything. Neither half may be fixed by making
 * the numbers match: they are different units, and forcing them together would
 * print a figure no rule match supports.
 */
export function riskSignalsFootnote(shown: number, sent: number): string {
  const unit = "These count rule categories matched, not decisions: one decision can match several, "
    + "and a decision whose rule carries no category matches none, so they do not add up to the "
    + "verdict counts above.";
  const truncated = sent > shown ? ` Showing the ${shown} most frequent.` : "";
  return `${unit}${truncated} A match is not a confirmed attack; a user or model decision may still `
    + "allow a matched action.";
}

export function Home({
  meta,
  onOpenActivity,
  onOpenCase,
  onOpenQueue,
  onOpenLane,
  machinePanels,
  edition,
}: {
  meta?: DashboardMeta;
  onOpenActivity: (target?: ActivityLink) => void;
  /**
   * Opens the Cases screen, optionally with one case selected, and with the
   * lane it belongs to when the link came from a lane card. Provided only
   * when the shell actually has a Cases screen to open; its absence makes
   * every case link degrade per `decisionEntryLink`.
   */
  onOpenCase?: (caseId?: string, lane?: CaseLane) => void;
  /**
   * Opens the Cases screen on one lane. Provided only when the shell has a
   * Cases screen; a lane card without it links nowhere (`laneLink`).
   */
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  /** Which of the agent and token panels the shell offers; see `LanesOverview`. */
  machinePanels?: MachinePanels;
  /**
   * Opens the Cases screen on the queue of what is waiting for a decision.
   * The "waiting on you" line is a dead end without it: a number, and no way
   * to get to the cases it counts.
   */
  onOpenQueue?: () => void;
  /**
   * Drives whether the Active Defence card is an offer or noise. Absent means
   * the edition has not resolved yet, which is treated as "do not offer" --
   * an upsell is the wrong thing to guess about.
   */
  edition?: "community" | "enterprise";
}) {
  const [overview, setOverview] = useState<Overview>();
  const [error, setError] = useState<string>();
  const [fetching, setFetching] = useState(true);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      setFetching(true);
      fetchOverview()
        .then((data) => {
          if (!active) return;
          setOverview(data);
          setError(undefined);
        })
        .catch((reason) => {
          if (active) setError(String(reason));
        })
        .finally(() => {
          inFlight = false;
          if (active) setFetching(false);
        });
    };
    load();
    const timer = setInterval(load, 4_000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  if (!overview && error) return <FullError message={error} />;
  if (!overview) return <OverviewSkeleton />;

  // A producer that omits a required field is a stated fault, not a blank page.
  //
  // `top_categories` and `recent_blocks` are non-optional in the Overview
  // contract, so the code below indexed and sliced them directly. When a server
  // answered without them the screen threw
  // `Cannot read properties of undefined (reading 'slice')` during render and the
  // whole dashboard went WHITE -- no message, no partial render, nothing in the
  // UI to say which side was at fault. Defaulting to `[]` would be worse: it
  // would report "no recent activity" for a host whose activity was simply never
  // sent.
  const missing = missingOverviewFields(overview);
  if (missing.length > 0) {
    return (
      <FullError
        message={`This dashboard asked the local InnerWarden process for the overview and got a \
reply with no ${missing.join(" and no ")} in it, so the figures below cannot be shown. The reply \
was incomplete; it does not mean this host is idle.`}
      />
    );
  }

  return (
    <OverviewScreen
      overview={overview}
      meta={meta}
      edition={edition}
      fetching={fetching}
      reconnecting={error !== undefined}
      onOpenActivity={onOpenActivity}
      onOpenCase={onOpenCase}
      onOpenQueue={onOpenQueue}
      onOpenLane={onOpenLane}
      machinePanels={machinePanels}
    />
  );
}

/**
 * The Overview once the host has answered, with nothing fetched here, so a
 * test can render every branch from a payload it hands in.
 *
 * Two layouts, chosen by what the HOST sent, never by the edition:
 *
 *  - No `lanes` (every Community host, and every paid host older than the
 *    field): exactly the page this was before lanes existed, element for
 *    element. `Home.lanes.render.test.tsx` pins that markup.
 *  - `lanes`: the three questions lead, one card each. What the page used to
 *    lead with (the posture hero, the agent and token panels, the sensor
 *    chart, the decision tiles, "What the guardrail actually did" and the
 *    risk signals) is still here, whole, behind the technical switch for
 *    whoever wants the numbers behind the cards. What changes what a reader
 *    should DO stays visible in both views: the host's waiting line, a
 *    decision record that is flagging something, and the recent decisions.
 */
export function OverviewScreen({
  overview,
  meta,
  edition,
  fetching = false,
  reconnecting = false,
  onOpenActivity,
  onOpenCase,
  onOpenQueue,
  onOpenLane,
  machinePanels,
}: {
  overview: Overview;
  meta?: DashboardMeta;
  edition?: "community" | "enterprise";
  fetching?: boolean;
  reconnecting?: boolean;
  onOpenActivity: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string, lane?: CaseLane) => void;
  onOpenQueue?: () => void;
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  machinePanels?: MachinePanels;
}) {
  const [technical] = useTechnicalDetail();
  const mode = normaliseMode(meta);
  const guardedAgents = meta?.guardrail?.guarded_agents;
  const laneCards = overviewLaneCards(overview.lanes);

  if (laneCards !== undefined) {
    return (
      <LanesOverview
        overview={overview}
        laneCards={laneCards}
        technical={technical}
        mode={mode}
        edition={edition}
        guardedAgents={guardedAgents}
        fetching={fetching}
        reconnecting={reconnecting}
        onOpenActivity={onOpenActivity}
        onOpenCase={onOpenCase}
        onOpenQueue={onOpenQueue}
        onOpenLane={onOpenLane}
        machinePanels={machinePanels}
        // `?? false` reads an older server the way the layout without lanes
        // reads it: as an offer.
        activeDefenceInstalled={meta?.active_defence_installed ?? false}
      />
    );
  }

  return (
    <div className="min-w-0 space-y-6 sm:space-y-8" aria-busy={fetching}>
      {reconnecting && <ReconnectingNotice />}

      <PostureHero mode={mode} edition={edition} decisions={overview.commands} sessions={overview.sessions} guardedAgents={guardedAgents} hostHeadline={overview.headline} />

      <MachineIntelligence edition={edition} />

      {/* Renders nothing at all where `/api/sensors` is not served, which is
          every Community host. It is mounted unconditionally rather than gated
          on `edition` so the panel appears from the endpoint that actually has
          the data, not from a label the shell resolved separately. */}
      <SensorActivity />

      <OverviewRecord
        overview={overview}
        mode={mode}
        edition={edition}
        guardedAgents={guardedAgents}
        onOpenActivity={onOpenActivity}
        onOpenCase={onOpenCase}
        onOpenQueue={onOpenQueue}
      />

      {edition === "enterprise" ? null : <CommunityIncluded />}
      {/* `?? false` reads an older server, which does not send the field, the
          way it always read it: as an offer. Being wrong toward offering is
          recoverable; being wrong toward silence hides the product. */}
      {edition === "community" ? (
        <ActiveDefenceCard installed={meta?.active_defence_installed ?? false} />
      ) : null}
    </div>
  );
}

/** Which of the agent and token panels this shell may show; see `LanesOverview`. */
export type MachinePanels = { agents: boolean; tokens: boolean };

function ReconnectingNotice() {
  return (
    <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
      <span>Reconnecting to the local dashboard. The figures below may be slightly out of date.</span>
      <span className="text-xs font-medium text-amber-700">Last good response retained</span>
    </div>
  );
}

/**
 * The Overview on a host that answers the three questions.
 *
 * The decision record keeps its place in the plain view only while it is
 * flagging something (`tone === "attention"`): agent actions flagged for a
 * person, or verdicts whose outcome was never recorded. A calm record is the
 * agent card's evidence, and moves behind the switch with its tiles.
 *
 * The agent and token panels follow the shell: on a paid host whose bootstrap
 * says the source is `not_configured`, the nav already offers no tab for it,
 * and the panel here said "none wired to a guardrail" about an agent the host
 * was screening through another path. On this layout they render only where
 * the source is configured, and only in the technical view. The layout
 * without lanes keeps them as they were.
 */
function LanesOverview({
  overview,
  laneCards,
  technical,
  mode,
  edition,
  guardedAgents,
  fetching,
  reconnecting,
  onOpenActivity,
  onOpenCase,
  onOpenQueue,
  onOpenLane,
  machinePanels,
  activeDefenceInstalled,
}: {
  overview: Overview;
  laneCards: LaneCard[];
  technical: boolean;
  activeDefenceInstalled: boolean;
  mode: GuardrailMode;
  edition?: "community" | "enterprise";
  guardedAgents?: number;
  fetching: boolean;
  reconnecting: boolean;
  onOpenActivity: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string, lane?: CaseLane) => void;
  onOpenQueue?: () => void;
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  machinePanels?: MachinePanels;
}) {
  const hasDecisions = overview.commands > 0;
  const record = hasDecisions
    ? decisionRecord(overview, edition, onOpenCase !== undefined, mode, onOpenLane !== undefined)
    : undefined;
  const showRecord = record !== undefined && (technical || record.summary.tone === "attention");
  const recent = (overview.recent_decisions ?? overview.recent_blocks).slice(0, 5);
  const agents = machinePanels?.agents ?? true;
  const tokens = machinePanels?.tokens ?? true;
  return (
    <div className="min-w-0 space-y-6 sm:space-y-8" aria-busy={fetching}>
      {reconnecting && <ReconnectingNotice />}

      <LaneCards
        cards={laneCards}
        edition={edition}
        onOpenLane={onOpenLane}
        onOpenCase={onOpenCase === undefined ? undefined : (caseId, lane) => onOpenCase(caseId, lane)}
        onOpenActivity={() => onOpenActivity()}
      />

      <HostAttention waiting={overview.host_attention} onOpen={onOpenQueue} />

      {showRecord && record !== undefined ? (
        <DecisionRecordSection
          record={record}
          overview={overview}
          tiles={technical}
          onOpenActivity={onOpenActivity}
          onOpenCase={onOpenCase}
          onOpenLane={onOpenLane}
        />
      ) : null}

      {recent.length > 0 || technical ? (
        <div className={technical ? "grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(280px,.65fr)]" : ""}>
          <RecentActivity items={recent} edition={edition} onOpen={onOpenActivity} onOpenCase={onOpenCase} />
          {technical ? (
            <RiskSignals items={overview.top_categories.slice(0, 6)} sent={overview.top_categories.length} max={overview.top_categories[0]?.count ?? 0} />
          ) : null}
        </div>
      ) : null}

      <TechnicalOnly>
        <section aria-labelledby="overview-technical-title" className="space-y-6 border-t border-slate-200 pt-6 sm:space-y-8">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Technical detail</p>
            <h2 id="overview-technical-title" className="mt-1 text-lg font-semibold text-slate-950">The records behind these cards</h2>
          </div>
          <PostureHero
            mode={mode}
            edition={edition}
            decisions={overview.commands}
            sessions={overview.sessions}
            guardedAgents={guardedAgents}
            hostHeadline={overview.headline}
            headingLevel="h2"
          />
          {agents || tokens ? <MachineIntelligence edition={edition} showAgents={agents} showTokens={tokens} /> : null}
          <SensorActivity />
          {hasDecisions ? null : <ZeroState guardedAgents={guardedAgents} edition={edition} />}
        </section>
      </TechnicalOnly>

      {edition === "enterprise" ? null : <CommunityIncluded />}
      {edition === "community" ? (
        <ActiveDefenceCard installed={activeDefenceInstalled} />
      ) : null}
    </div>
  );
}

/**
 * The guardrail's decision record, or its onboarding when it has none, and
 * the host's waiting line beside either.
 *
 * The host line used to render only in the branch for a guardrail that had
 * recorded decisions. A paid host whose agent guardrail had recorded none took
 * the onboarding branch and never said "8 addresses are waiting on you", the
 * first thing a reader who does not know the product needs from this screen.
 * That line reads the HOST layer (`host_attention`), not the guardrail, so it
 * now renders whenever the host sent it, whatever the guardrail recorded.
 * Absent, which is every Community host, it still renders nothing.
 *
 * With no decisions it sits above the onboarding steps: something waiting on
 * the host now matters more than connecting an agent later. With decisions it
 * keeps its place under the decision record.
 */
export function OverviewRecord({
  overview,
  mode,
  edition,
  guardedAgents,
  onOpenActivity,
  onOpenCase,
  onOpenQueue,
}: {
  overview: Overview;
  mode: GuardrailMode;
  edition?: "community" | "enterprise";
  guardedAgents?: number;
  onOpenActivity: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string) => void;
  onOpenQueue?: () => void;
}) {
  const hostAttention = <HostAttention waiting={overview.host_attention} onOpen={onOpenQueue} />;
  if (overview.commands === 0) {
    return (
      <>
        {hostAttention}
        <ZeroState guardedAgents={guardedAgents} edition={edition} />
      </>
    );
  }

  // One decision about where "everything" lives, read by both the button and
  // the headline's remedy, so the sentence never names a screen the button
  // beside it does not open.
  const record = decisionRecord(overview, edition, onOpenCase !== undefined, mode);
  const recent = (overview.recent_decisions ?? overview.recent_blocks).slice(0, 5);
  const maxSignal = overview.top_categories[0]?.count ?? 0;

  return (
    <>
      <DecisionRecordSection
        record={record}
        overview={overview}
        tiles
        onOpenActivity={onOpenActivity}
        onOpenCase={onOpenCase}
      />

      {hostAttention}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(280px,.65fr)]">
        <RecentActivity items={recent} edition={edition} onOpen={onOpenActivity} onOpenCase={onOpenCase} />
        <RiskSignals items={overview.top_categories.slice(0, 6)} sent={overview.top_categories.length} max={maxSignal} />
      </div>
    </>
  );
}

/**
 * The Decision record's headline, its "view everything" button and, with
 * `tiles`, the counters under it and what the guardrail actually did. The
 * layout without lanes always shows the tiles; the lanes layout shows them in
 * the technical view only (see `LanesOverview`).
 */
function DecisionRecordSection({
  record,
  overview,
  tiles,
  onOpenActivity,
  onOpenCase,
  onOpenLane,
}: {
  record: ReturnType<typeof decisionRecord>;
  overview: Overview;
  tiles: boolean;
  onOpenActivity: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string, lane?: CaseLane) => void;
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
}) {
  const { cta, summary, denyVerdicts, reviewVerdicts, allowVerdicts } = record;
  const openAll = () => {
    if (cta.kind === "cases") onOpenCase?.();
    else if (cta.kind === "lane") onOpenLane?.("agent", { window: "all" });
    else onOpenActivity();
  };
  return (
    <>
      <section aria-labelledby="decision-summary-title">
        <div className="mb-3 flex flex-col items-start gap-2 sm:flex-row sm:items-end sm:justify-between sm:gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Decision record</p>
            {/* THE ANSWER FIRST, the counters underneath as its evidence.
              * Five numbers and no conclusion left the reader to work out
              * whether they were safe, and the pairing of "252 classified
              * as unsafe" with "3 blocked before execution" reads as a
              * confession unless something explains monitor mode. */}
            <h2 id="decision-summary-title" className="mt-1 text-lg font-semibold text-slate-950">{summary.answer}</h2>
            {summary.next ? (
              <p className="mt-1 text-sm text-slate-600">{summary.next}</p>
            ) : null}
            <TechnicalOnly>
              <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">What the guardrail saw</p>
            </TechnicalOnly>
          </div>
          {cta.kind === "hidden" ? null : (
            <button
              type="button"
              onClick={openAll}
              className="text-sm font-semibold text-cyan-700 hover:text-cyan-900"
            >
              {cta.label} <span aria-hidden="true">→</span>
            </button>
          )}
        </div>
        {tiles ? (
          <DecisionCounts
            commands={overview.commands}
            sessions={overview.sessions}
            denyVerdicts={denyVerdicts}
            reviewVerdicts={reviewVerdicts}
            allowVerdicts={allowVerdicts}
            unknownVerdicts={overview.unknown_verdicts}
          />
        ) : null}
      </section>

      {tiles && (overview.actual_blocks != null || overview.would_block != null || overview.screened != null || overview.outcomes_unknown != null) && (
        <OperationalEvidence overview={overview} />
      )}
    </>
  );
}

/// What the `unknown` posture means on a paid host: the guardrail hook reports
/// nothing because it is not the mechanism here, and enforcement posture has a
/// screen of its own. It does NOT mean nothing is being protected.
/// Which posture copy the hero shows.
///
/// Pure so the CHOICE is testable: this package has no jsdom, and a test that
/// only compares the two constants passes even when the component picks the
/// wrong one -- which is exactly what a first attempt at this test did.
/// The product name the operator is actually looking at.
///
/// Hardcoded as "InnerWarden Community" until now, on every host. A paid box
/// therefore announced itself as the free product -- and an operator who
/// upgraded saw no change at all, which reads as the upgrade not having taken.
/// `edition` already reaches this screen; it just was not used here.
///
/// Unknown edition keeps the neutral brand rather than guessing: claiming
/// either tier before the bootstrap resolves would be a claim we cannot back.
export function editionLabel(edition?: "community" | "enterprise"): string {
  if (edition === "enterprise") return "InnerWarden Enterprise";
  if (edition === "community") return "InnerWarden Community";
  return "InnerWarden";
}

export function postureFor(mode: GuardrailMode, edition?: "community" | "enterprise") {
  return mode === "unknown" && edition === "enterprise"
    ? ENTERPRISE_UNKNOWN_POSTURE
    : POSTURES[mode];
}

export const ENTERPRISE_UNKNOWN_POSTURE = {
  label: "Guardrail decisions not recorded here",
  title: "Enforcement is reported on Posture, not by decision count.",
  body: "The agent-guard hook that records per-action decisions is not running on this host, so that counter reads zero. It is not a measure of what the host is protected by. See Posture for the enforcement layers actually in effect.",
  badge: "border-slate-300 bg-white text-slate-700",
  panel: "border-slate-200 from-white to-slate-100",
};

export const POSTURES: Record<GuardrailMode, { label: string; title: string; body: string; badge: string; panel: string }> = {
  not_configured: {
    label: "Setup needed",
    title: "Connect an agent to start screening its actions.",
    body: "Guided setup starts in monitor mode. Captured shell actions, MCP tool calls and one-off checks build the local decision record.",
    badge: "border-slate-300 bg-white text-slate-700",
    panel: "border-slate-200 from-white to-slate-100",
  },
  monitor: {
    label: "Monitor configured",
    title: "Build confidence before you turn on blocking.",
    body: "Once an agent reloads this wiring, the integrations you configured screen its activity without blocking any of it. Review the local evidence before enforcing.",
    badge: "border-blue-200 bg-blue-50 text-blue-700",
    panel: "border-blue-200 from-blue-50 to-white",
  },
  enforce: {
    label: "Enforce configured",
    title: "Blocking is configured for screened agent actions.",
    body: "After agents reload this wiring, enforce-capable hooks and request/response MCP calls refuse deny decisions before execution. Outcomes show what actually happened.",
    badge: "border-blue-200 bg-blue-50 text-blue-700",
    panel: "border-blue-200 from-blue-50 to-white",
  },
  mixed: {
    label: "Mixed configuration",
    title: "Some integrations monitor; others are configured to enforce.",
    body: "Restart changed agents, then use per-decision outcomes to distinguish observed risk from actions actually blocked.",
    badge: "border-amber-200 bg-amber-50 text-amber-800",
    panel: "border-amber-200 from-amber-50 to-white",
  },
  partial: {
    label: "Partial coverage",
    title: "Some local MCP servers are not wired through the guardrail.",
    body: "Reconnect that agent to apply one mode to every configured local server. The cards below report saved configuration separately from confirmed runtime state.",
    badge: "border-orange-200 bg-orange-50 text-orange-800",
    panel: "border-orange-200 from-orange-50 to-white",
  },
  unknown: {
    label: "Status unavailable",
    title: "Agent action security, with evidence.",
    body: "This version records guardrail decisions but does not report a reliable global enforcement posture.",
    badge: "border-slate-300 bg-white text-slate-700",
    panel: "border-slate-200 from-white to-slate-100",
  },
};

// Exported so a test can RENDER it and read the words it actually prints.
// The first version of this test rebuilt the merge expression inline and
// asserted on its own object, so it passed with the fix reverted: it proved
// that spreading two objects works, not that this screen honours the host.
export function PostureHero({ mode, edition, decisions, sessions, guardedAgents, hostHeadline, headingLevel = "h1" }: { mode: GuardrailMode; edition?: "community" | "enterprise"; decisions: number; sessions: number; guardedAgents?: number; hostHeadline?: { label: string; title: string; body: string }; /** `h2` where the page already has its `h1` (the lanes layout). */ headingLevel?: "h1" | "h2" }) {
  const Heading = headingLevel;
  // The `unknown` copy is written for Community: "this version records guardrail
  // decisions" describes the free hook, and the decision count is the free
  // product's headline. On an Enterprise host that hook is often not installed
  // at all -- the paid stack is what protects it -- so the same words turn a
  // correct zero into a claim that the product is idle. Observed on the
  // production box: 0 decisions on screen while 6,047 incidents sat in its
  // graph. The number was right; the sentence around it was not.
  // The HOST decides the sentence when it offers one.
  //
  // `postureFor` picks from a table keyed on the guardrail mode, and on a paid
  // host that mode is `unknown`, which selected a constant stating the decision
  // counter reads zero. The host computes the real sentence from the same
  // counters it just sent (`agent/src/dashboard/guard_headline.rs`), and the
  // screen ignored it. Measured on live.innerwarden.com 2026-08-31: the page
  // said the counter reads zero beside a payload carrying 8 screened commands
  // and 5 deny verdicts.
  //
  // Colours stay local because they are presentation; only the words come from
  // the host, and only when it sent them.
  const posture = { ...postureFor(mode, edition), ...(hostHeadline ?? {}) };
  return (
    <section className={`overflow-hidden rounded-2xl border bg-gradient-to-br ${posture.panel}`} aria-labelledby="posture-title">
      <div className="grid gap-6 px-5 py-6 sm:px-7 sm:py-8 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-center">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${posture.badge}`}>
              <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" aria-hidden="true" />
              {posture.label}
            </span>
            {guardedAgents != null && (
              <span className="text-xs font-medium text-slate-600">
                {guardedAgents} agent integration{guardedAgents === 1 ? "" : "s"} configured
              </span>
            )}
          </div>
          <p className="mt-5 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">{editionLabel(edition)}</p>
          <Heading id="posture-title" className="mt-2 max-w-3xl text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
            {posture.title}
          </Heading>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600 sm:text-base">{posture.body}</p>
          {/* These three lines were a permanent strip across the hero. They are
              true, and they are the same three sentences on every load of every
              host forever, which is the definition of copy an operator stops
              reading. The facts stay, one click down, where somebody who wants
              them can find them. */}
          <details className="mt-5 max-w-2xl">
            <summary className="cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-700">
              How this dashboard handles your data
            </summary>
            <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs font-medium text-slate-600">
              <TrustItem>Rules are evaluated on this machine</TrustItem>
              <TrustItem>This dashboard only reads; it changes nothing</TrustItem>
              <TrustItem>Common secret patterns are redacted before storage</TrustItem>
            </ul>
          </details>
        </div>
        <div className="grid grid-cols-2 gap-3 rounded-xl border border-white/80 bg-white/75 p-4 shadow-sm backdrop-blur">
          <HeroNumber label="Decisions recorded" value={decisions} />
          <HeroNumber label="Sessions" value={sessions} />
        </div>
      </div>
    </section>
  );
}

function TrustItem({ children }: { children: ReactNode }) {
  return (
    <li className="flex items-center gap-2">
      <span className="flex h-4 w-4 items-center justify-center rounded-full bg-cyan-100 text-[10px] font-bold text-cyan-800" aria-hidden="true">✓</span>
      {children}
    </li>
  );
}

function HeroNumber({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-2xl font-semibold tabular-nums text-slate-950">{value.toLocaleString()}</div>
      <div className="mt-0.5 text-xs font-medium text-slate-500">{label}</div>
    </div>
  );
}

/**
 * The tile that counts the agent guardrail's `review` verdicts.
 *
 * It was labelled "Needs review" / "Requires human judgement". The number is
 * graph decisions the agent guardrail answered `review` on. A paid host's
 * Cases screen offers a "Needs review" status too, and that is a case status,
 * not a guardrail verdict: a different count, so one paid Overview read 0 here
 * while Cases listed hundreds of rows under the same two words. A reader with
 * no way to know the two are different took it for a contradiction,
 * reasonably.
 *
 * The label says whose verdict this is and about what, in words that are true
 * on Community (no host layer, no Cases screen) and on Enterprise alike.
 * "flagged", not "held": a `review` verdict only stops the action where the
 * hook runs in block-review mode, and this count does not know which ran.
 */
export const REVIEW_VERDICTS_TILE = {
  label: "Agent actions flagged for review",
  detail: "The agent guardrail asked for a person's judgement",
} as const;

/**
 * The chip a `review` verdict wears in this page's Recent activity.
 *
 * Everywhere else the chip reads "Needs review" (`verdictLabel`), which is
 * also the name of Activity's verdict filter, and the Community remedy tells
 * its reader to press that filter, so the shared label stays. On THIS page it
 * cannot: a paid Overview sits one click from a Cases status of the same two
 * words, and the tile above says "flagged for review". The chip here uses the
 * tile's word, so the page does not name one verdict two ways.
 */
export const REVIEW_VERDICT_CHIP = "Flagged for review";

/**
 * The Decision record's tiles. Exported so a test can RENDER them and read
 * the words the screen prints, not a copy of them.
 */
export function DecisionCounts({ commands, sessions, denyVerdicts, reviewVerdicts, allowVerdicts, unknownVerdicts }: {
  commands: number;
  sessions: number;
  denyVerdicts: number;
  reviewVerdicts: number;
  allowVerdicts: number;
  /** Absent on an older host, which then gets no tile rather than a zero. */
  unknownVerdicts?: number;
}) {
  const hasUnknownVerdicts = unknownVerdicts != null;
  return (
    <div className={hasUnknownVerdicts ? "grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5" : "grid grid-cols-2 gap-3 lg:grid-cols-4"}>
      <Stat label="Recorded decisions" value={commands} detail={recordedDecisionsDetail(sessions)} />
      <Stat label="Deny verdicts" value={denyVerdicts} detail="Classified as unsafe" tone={denyVerdicts > 0 ? "danger" : undefined} />
      <Stat label={REVIEW_VERDICTS_TILE.label} value={reviewVerdicts} detail={REVIEW_VERDICTS_TILE.detail} tone={reviewVerdicts > 0 ? "attention" : undefined} />
      <Stat label="Allowed" value={allowVerdicts} detail="No blocking verdict" tone="positive" />
      {hasUnknownVerdicts && <Stat label="Unknown verdicts" value={unknownVerdicts ?? 0} detail="Could not be classified" tone={(unknownVerdicts ?? 0) > 0 ? "attention" : undefined} />}
    </div>
  );
}

function Stat({ label, value, detail, tone }: { label: string; value: number; detail: string; tone?: "danger" | "attention" | "positive" }) {
  const number = tone === "danger" ? "text-red-700" : tone === "attention" ? "text-amber-700" : tone === "positive" ? "text-emerald-700" : "text-slate-950";
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`text-2xl font-semibold tabular-nums ${number}`}>{value.toLocaleString()}</div>
      <div className="mt-1 text-sm font-semibold text-slate-800">{label}</div>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </article>
  );
}

function OperationalEvidence({ overview }: { overview: Overview }) {
  const items = [
    { label: "Blocked before execution", value: overview.actual_blocks, cls: "text-red-700" },
    { label: "Would block in monitor mode", value: overview.would_block, cls: "text-blue-700" },
    { label: "Screened by one-off check", value: overview.screened, cls: "text-cyan-700" },
    { label: "Outcome not recorded", value: overview.outcomes_unknown, cls: "text-slate-700" },
  ].filter((item) => item.value != null);
  return (
    <section className="rounded-xl border border-slate-200 bg-white px-4 py-3" aria-labelledby="outcome-evidence-title">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="mr-auto">
          {/* "Outcomes reported by newer guardrail integrations" sat under this
              heading on every load. Which integrations are new is our
              bookkeeping; the four labels beside it already say what each
              number counts. */}
          <h2 id="outcome-evidence-title" className="text-sm font-semibold text-slate-900">What the guardrail actually did</h2>
        </div>
        {items.map((item) => (
          <div key={item.label} className="min-w-28">
            <div className={`text-lg font-semibold tabular-nums ${item.cls}`}>{item.value?.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500">{item.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

/** Exported so a test can RENDER the entries and read the words they print. */
export function RecentActivity({ items, edition, onOpen, onOpenCase }: {
  items: DecisionSummary[];
  edition?: "community" | "enterprise";
  onOpen: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string) => void;
}) {
  return (
    <section className="min-w-0" aria-labelledby="recent-activity-title">
      <div className="mb-3">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Evidence</p>
        <h2 id="recent-activity-title" className="mt-1 text-lg font-semibold text-slate-950">Recent activity</h2>
      </div>
      {items.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600">No recent decisions are available yet.</div>
      ) : (
        <ul className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          {items.map((item, index) => {
            const recommendation = item.recommendation ?? "unknown";
            const link = decisionEntryLink(item.case_id, edition, onOpenCase !== undefined);
            const body = <RecentActivityEntry item={item} clickable={link.kind !== "none"} />;
            return (
              <li key={item.id ?? `${item.session}-${item.command}-${index}`} className="border-b border-slate-100 last:border-0">
                {link.kind === "none" ? (
                  // No case to open: plain text, no hover, no affordance. A row
                  // that looks clickable and lands nowhere is worse than one
                  // that says it is a record.
                  <div className="grid w-full min-w-0 grid-cols-[7rem_minmax(0,1fr)] items-start gap-x-3 gap-y-2 px-3 py-3 text-left sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:px-4">
                    {body}
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() =>
                      link.kind === "case"
                        ? onOpenCase?.(link.caseId)
                        : onOpen({ id: item.id, session: item.session, verdict: recommendation, action: item.command })
                    }
                    className="group grid w-full min-w-0 grid-cols-[7rem_minmax(0,1fr)] items-start gap-x-3 gap-y-2 px-3 py-3 text-left transition-colors hover:bg-slate-50 focus-visible:-outline-offset-2 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:px-4"
                    aria-label={
                      link.kind === "case"
                        ? `Open the case for ${item.command}`
                        : `Open ${recommendation} decision for ${item.command}`
                    }
                  >
                    {body}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/**
 * The program the kernel refused to start during this decision, when the host
 * sent one (`kernel_stopped`). Anything that is not a short printable path or
 * name is read as not sent: the chip must not print a value it cannot vouch
 * for.
 */
export function kernelStopped(item: Pick<DecisionSummary, "kernel_stopped">): string | undefined {
  const value = item.kernel_stopped;
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 512 || /[\u0000-\u001f\u007f]/.test(trimmed)) return undefined;
  return trimmed;
}

/** "The kernel stopped sudo": the program's own name, not its path. */
export function kernelStoppedLabel(program: string): string {
  const name = program.split("/").filter((part) => part.length > 0).pop() ?? program;
  return `The kernel stopped ${name}`;
}

function RecentActivityEntry({ item, clickable }: { item: DecisionSummary; clickable: boolean }) {
  const recommendation = item.recommendation ?? "unknown";
  const when = formatTimestamp(item.recorded_at_ms);
  const sessionLabel = item.session === "local" ? "Local session" : item.session;
  return (
    <>
      <Verdict rec={recommendation} reviewLabel={REVIEW_VERDICT_CHIP} />
      <div className="min-w-0 flex-1">
        <code className="block truncate text-sm font-medium text-slate-900">{item.command}</code>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <DecidedBy by={item.decided_by} />
          <Outcome value={item.outcome ?? "unknown"} />
          {kernelStopped(item) ? (
            <span className="max-w-full break-words rounded-md border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-semibold text-rose-800 [overflow-wrap:anywhere]">
              {kernelStoppedLabel(kernelStopped(item) as string)}
            </span>
          ) : null}
          {item.categories.slice(0, 2).map((category) => (
            <span key={category} className="max-w-full truncate rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600">
              {humanizeToken(category)}
            </span>
          ))}
        </div>
      </div>
      <div className="col-span-2 flex min-w-0 items-center justify-between gap-3 text-xs text-slate-500 sm:col-span-1 sm:block sm:max-w-28 sm:shrink-0 sm:text-right">
        {when && <div className="shrink-0">{when}</div>}
        <div className="min-w-0 flex-1 truncate sm:mt-1 sm:max-w-28" title={sessionLabel}>{sessionLabel}</div>
        {clickable && (
          <span className="mt-2 hidden font-semibold text-cyan-700 opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100 sm:inline-block">Open →</span>
        )}
      </div>
    </>
  );
}

/**
 * What the HOST has waiting, or nothing at all.
 *
 * This page is the agent layer's and said nothing about the host, so an
 * operator reading a healthy agent picture had no way to know the host side
 * was holding anything.
 *
 * Three rules, and each of them is the operator's standing instruction that
 * this dashboard must not fill with warnings that mean nothing:
 *
 *  * ABSENT is not zero. A build with no host layer omits the field and this
 *    renders nothing, rather than a zero that would claim knowledge of
 *    something it cannot see.
 *  * Zero waiting is GOOD news and is said in one calm line, not as a tile
 *    competing for attention.
 *  * The number counts distinct ADDRESSES, not rows, and says so on the
 *    screen. Measured on a production host: 851 incidents in a day, 42
 *    undecided, behind eight addresses. Eight is actionable; 851 is a wall.
 *
 * The addresses are not everything the host has waiting. A finding that
 * names no outside address (a privilege escalation, a lateral movement to an
 * internal one) has nothing for an address count to count, and a high one
 * nothing has decided on is in the waiting queue all the same. The line read
 * "Nothing on the host is waiting for you" over a queue holding it, and hid
 * the way to that queue. The paid host now serves those beside the addresses
 * (`findings_waiting_off_the_line`, by the queue's own rule), and the title
 * counts both: "8 addresses, and 3 findings the address count leaves out, are
 * waiting on you". The findings are named as the ones the address count
 * leaves out, not as "other findings": an address is not a finding, and a
 * finding counted here can stand behind one of the eight addresses (a
 * critical the product only watched, on an address that also has an
 * undecided finding). An older host does not send the findings, and the line
 * then reads the addresses alone, as it did.
 *
 * Both numbers are TODAY's; the queue is every day's. So zero today is not
 * zero in the queue: a finding from yesterday that is still waiting on a
 * person (an undecided privilege escalation that arrived at 23:30 and was
 * parked for review at 00:30) is in the queue while both of today's counts
 * read 0. The calm line therefore says TODAY, "Nothing new on the host today
 * is waiting for you", and the way to the queue stays offered under it, in
 * calmer words, because the queue can still hold something. Saying "nothing
 * is waiting" and hiding the link there was the defect one day later.
 *
 * What each number counts is the producer's own sentence, and it is long and
 * exact because it is the definition a reader checks the number against. It is
 * not the answer, and it is written in the producer's terms. So it sits behind
 * "What these numbers count", closed: the title and the link are the plain
 * answer, and the definition is one click away for whoever wants to check it.
 *
 * `through` is the way to the list, and it must not promise the list is the
 * number. The line counts ADDRESSES and findings seen TODAY; the link opens
 * CASES of ALL time with status `waiting` (the contract with the paid server,
 * which this wording does not change). The list will not match an address
 * count in either direction: one address can own several cases, and one case
 * (a distributed SSH attack) can name several addresses. A finding is one
 * case, so the note speaks of addresses only when the title counted them.
 *
 * The note also says the list is not only the host's, because on the paid
 * server it is not: an agent session a person must look at (a deny the guard
 * did not stop, a verdict it cannot read) waits there too, and so does a
 * response that failed on any day. The link is deliberately NOT narrowed to
 * the host with `capability=host_visibility`: that filter keeps only cases
 * with host SQLite evidence, and would drop a standalone response case whose
 * reversal failed (`NeedsReview`, response-lifecycle evidence only), which is
 * a host problem a person must act on. The filter takes one value, so "host
 * OR response" cannot be asked for. Saying what the list holds hides nothing;
 * a narrower list would.
 */
export function hostAttentionLine(
  waiting: Overview["host_attention"],
): {
  tone: "quiet" | "waiting";
  title: string;
  /** One plain sentence under the calm title. The waiting title needs none. */
  body?: string;
  /** What each number the title names counts, in the producer's words, in
   * the order the title names them. Shown behind a disclosure, not as the
   * answer. Empty under the calm line. */
  definitions: { label: string; text: string }[];
  /** The link to the waiting queue, and what it opens. */
  through: { label: string; note: string };
} | undefined {
  if (waiting === undefined) return undefined;
  const addresses = wholeCount(waiting.addresses_waiting);
  // The line's own number is not a count: say nothing rather than a guess.
  if (addresses === undefined) return undefined;
  // Not sent by an older host, and not trusted when it is not a count: either
  // way the line reads the addresses alone, as it always did.
  const sentFindings = wholeCount(waiting.findings_waiting_off_the_line);
  const findings = sentFindings ?? 0;
  if (addresses === 0 && findings === 0) {
    return {
      tone: "quiet",
      title: "Nothing new on the host today is waiting for you",
      // A host that counts findings too can say that nothing it found today
      // asks for a person. An older one counted addresses only, and its zero
      // says no more than that.
      body: sentFindings === undefined
        ? "Every address this host saw today has been decided on."
        : "Nothing the host found today is asking for a person.",
      definitions: [],
      through: {
        label: "See the waiting queue, from any day",
        note: "This line counts today only. The queue also keeps what earlier days left waiting, and the agent's cases as well as the host's, so it may not be empty.",
      },
    };
  }
  const definitions: { label: string; text: string }[] = [];
  if (addresses > 0) definitions.push({ label: "Addresses", text: asSentence(waiting.counts) });
  if (findings > 0) {
    const counts = waiting.findings_waiting_off_the_line_counts;
    definitions.push({
      label: "Findings",
      text: asSentence(typeof counts === "string" && counts.trim() !== "" ? counts : FINDINGS_OFF_THE_LINE_FALLBACK),
    });
  }
  return {
    tone: "waiting",
    title: waitingTitle(addresses, findings),
    definitions,
    through: {
      label: "See all waiting cases, from any day",
      note: throughNote(addresses, findings),
    },
  };
}

/** A count this line can print: a non-negative whole number, nothing else. */
function wholeCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/** The producer writes its definitions as clauses ("distinct outside
 * addresses, today, ..."). Under a label they read as sentences: capital
 * first, full stop last. The words are the producer's, unchanged. */
function asSentence(text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return trimmed;
  const capital = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

/** Said when a host sends the findings count without its definition. */
const FINDINGS_OFF_THE_LINE_FALLBACK =
  "host findings from today that wait in Cases and that a count of addresses cannot include, one per finding";

function waitingTitle(addresses: number, findings: number): string {
  const addressPart = `${addresses.toLocaleString()} ${addresses === 1 ? "address" : "addresses"}`;
  if (findings === 0) return `${addressPart} ${addresses === 1 ? "is" : "are"} waiting on you`;
  const findingPart = `${findings.toLocaleString()} ${findings === 1 ? "finding" : "findings"}`;
  if (addresses === 0) return `${findingPart} ${findings === 1 ? "is" : "are"} waiting on you`;
  // Not "other findings": an address is not a finding, and these are the
  // findings the address count left out, never the same waiting twice.
  return `${addressPart}, and ${findingPart} the address count leaves out, are waiting on you`;
}

function throughNote(addresses: number, findings: number): string {
  const span = "every day rather than only today, and the agent's cases as well as the host's";
  if (addresses === 0) {
    return `That list holds ${span}, so it can be longer than this number.`;
  }
  const these = findings === 0 ? "this number" : "these numbers";
  return `That list shows cases rather than addresses, so it will not match ${these}: one address can have several cases, and one case can name several addresses. It also holds ${span}.`;
}

export function HostAttention({ waiting, onOpen }: { waiting: Overview["host_attention"]; onOpen?: () => void }) {
  const line = hostAttentionLine(waiting);
  if (line === undefined) return null;
  const quiet = line.tone === "quiet";
  // The way through is offered whenever there is somewhere to go: under the
  // calm line too, because today's zero does not empty a queue that keeps
  // every day. Without a Cases screen there is nothing to open, and the note,
  // which explains the link, goes with it.
  const through = onOpen !== undefined ? line.through : undefined;
  return (
    <section
      aria-labelledby="host-attention-title"
      className={`rounded-xl border p-4 shadow-sm ${quiet ? "border-slate-200 bg-white" : "border-amber-200 bg-amber-50"}`}
    >
      <h2
        id="host-attention-title"
        className={`text-sm font-semibold ${quiet ? "text-slate-950" : "text-amber-900"}`}
      >
        {line.title}
      </h2>
      {line.body !== undefined && (
        <p className={`mt-1 text-sm leading-6 ${quiet ? "text-slate-600" : "text-amber-900"}`}>{line.body}</p>
      )}
      {through && (
        <div className="mt-3">
          <button
            type="button"
            onClick={onOpen}
            className={quiet
              ? "text-sm font-semibold text-slate-700 underline decoration-slate-300 underline-offset-4 hover:text-slate-950"
              : "text-sm font-semibold text-amber-900 underline decoration-amber-400 underline-offset-4 hover:text-amber-950"}
          >
            {through.label} <span aria-hidden="true">→</span>
          </button>
          <p className={`mt-1 text-xs leading-5 ${quiet ? "text-slate-500" : "text-amber-800"}`}>{through.note}</p>
        </div>
      )}
      {line.definitions.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs font-semibold text-amber-800 hover:text-amber-950">
            {line.definitions.length === 1 ? "What this number counts" : "What these numbers count"}
          </summary>
          <dl className="mt-2 space-y-2 text-xs leading-5 text-amber-900">
            {line.definitions.map((definition) => (
              <div key={definition.label}>
                <dt className="font-semibold">{definition.label}</dt>
                <dd>{definition.text}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </section>
  );
}

function RiskSignals({ items, sent, max }: { items: Overview["top_categories"]; sent: number; max: number }) {
  return (
    <section className="min-w-0" aria-labelledby="risk-signals-title">
      <div className="mb-3">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Patterns</p>
        <h2 id="risk-signals-title" className="mt-1 text-lg font-semibold text-slate-950">Risk signals</h2>
      </div>
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        {items.length === 0 ? (
          <p className="text-sm text-slate-600">No rule categories have been triggered.</p>
        ) : (
          <ul className="space-y-4">
            {items.map((item) => (
              <li key={item.name}>
                <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-slate-700" title={item.name}>{humanizeToken(item.name)}</span>
                  <span className="tabular-nums text-slate-500">{item.count}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-slate-100" aria-hidden="true">
                  <div
                    className="h-full rounded-full bg-cyan-600"
                    style={{ width: `${max > 0 ? Math.min(100, Math.max(0, (item.count / max) * 100)) : 0}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-4 border-t border-slate-100 pt-3 text-xs leading-5 text-slate-500">
          {riskSignalsFootnote(items.length, sent)}
        </p>
      </div>
    </section>
  );
}

/**
 * The command that actually flips enforcement on, for the product being shown.
 *
 * REGRESSION ANCHOR. Step 3 hardcoded `innerwarden enforce`. That command is
 * real in Community and DOES NOT EXIST in Enterprise, where enforcement is the
 * kernel exec-gate -- so the final step of the paid onboarding told the
 * operator to run a command that exits with an error. This file is shared by
 * both products, which is exactly why the string cannot be a constant.
 *
 * Both were verified against the shipped CLIs rather than assumed.
 */
export function enforceCommand(edition?: "community" | "enterprise"): string {
  return edition === "enterprise" ? "innerwarden exec-gate enforce" : "innerwarden enforce";
}

export function enforceHint(edition?: "community" | "enterprise"): string {
  return edition === "enterprise"
    // The paid gate refuses a blind flip: it enforces only after an
    // observe-armed, scoped, zero-would-block rehearsal.
    ? "Flip the kernel gate to deny, after a clean rehearsal."
    : "Block deny decisions on supported integrations.";
}

/**
 * The onboarding panel for an agent guardrail that has recorded nothing.
 *
 * The heading names whose decisions it means. On a paid host the host line
 * ("8 addresses are waiting on you ... latest decision is absent or awaiting
 * confirmation") sits directly above it, and a bare "No decisions recorded
 * yet" under that reads as a statement about the host's decisions, which the
 * line above has just contradicted.
 */
function ZeroState({ guardedAgents, edition }: { guardedAgents?: number; edition?: "community" | "enterprise" }) {
  const hasConfiguredAgent = guardedAgents != null && guardedAgents > 0;
  return (
    <section className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 sm:p-8" aria-labelledby="zero-state-title">
      <div className="mx-auto max-w-3xl text-center">
        <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-50 text-lg font-bold text-cyan-800" aria-hidden="true">IW</div>
        <h2 id="zero-state-title" className="mt-4 text-xl font-semibold text-slate-950">No agent guardrail decisions recorded yet</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-600">
          {hasConfiguredAgent
            ? "The guardrail is configured. Captured shell actions, MCP tool calls and one-off checks appear here as a local activity record."
            : "Connect a detected agent in monitor mode to build a local decision record without blocking its work."}
        </p>
      </div>
      <ol className="mx-auto mt-7 grid max-w-3xl gap-3 sm:grid-cols-3">
        <OnboardingStep number="1" title="Connect safely" command="innerwarden setup">Detect agents and begin in monitor mode.</OnboardingStep>
        <OnboardingStep number="2" title="Review evidence" command="innerwarden dashboard">Inspect captured shell, MCP and one-off decisions here.</OnboardingStep>
        <OnboardingStep number="3" title="Enforce when ready" command={enforceCommand(edition)}>{enforceHint(edition)}</OnboardingStep>
      </ol>
    </section>
  );
}

function OnboardingStep({ number, title, command, children }: { number: string; title: string; command: string; children: ReactNode }) {
  return (
    <li className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-left">
      <div className="flex items-center gap-2">
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-900 text-xs font-semibold text-white">{number}</span>
        <span className="font-semibold text-slate-900">{title}</span>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-600">{children}</p>
      <code className="mt-3 block overflow-x-auto rounded-md bg-white px-2.5 py-2 text-[11px] text-slate-800 ring-1 ring-slate-200">{command}</code>
    </li>
  );
}

const COMMUNITY_FEATURES = [
  "Pre-execution screening",
  "Monitor and enforce modes",
  "Agent hooks and MCP guard",
  "Agent and token visibility",
  "Monitor-only automatic setup",
  "Local action decision record",
  "User allow and mute controls",
  "Second opinion with your model",
];

/**
 * The feature list, collapsed.
 *
 * Eight bullets in a coloured panel on every single load of the Overview, and
 * not one of them tells an operator anything about THIS host: it is a brochure
 * printed on the instrument. The list is worth keeping for somebody new, so it
 * stays, closed, at the bottom of the page.
 */
function CommunityIncluded() {
  return (
    <details className="rounded-2xl border border-slate-200 bg-white px-5 py-4 sm:px-6">
      <summary className="cursor-pointer text-sm font-semibold text-slate-700 hover:text-slate-950">
        What Community includes
      </summary>
      <ul className="mt-3 grid gap-x-6 gap-y-2 text-sm text-slate-700 sm:grid-cols-2 lg:grid-cols-3">
        {COMMUNITY_FEATURES.map((feature) => (
          <li key={feature} className="flex items-center gap-2">
            <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-cyan-700 text-[10px] font-bold text-white" aria-hidden="true">✓</span>
            {feature}
          </li>
        ))}
      </ul>
    </details>
  );
}

/**
 * The Active Defence slot at the foot of the Community Overview.
 *
 * THE DEFECT. This card rendered unconditionally for the Community edition. On
 * `iw-challenge` -- sensor, watchdog and DNS guard all running, Execution Gate
 * `Armed` with 1387 entries, Secret Read Guard in `ENFORCE` with a canary
 * proving the denial -- it told the operator to go and acquire what was already
 * running underneath the page, beneath a header reading "Setup needed". The
 * honest reading of that screen was "you are not protected", on a host that was.
 *
 * `installed` comes from the server, which looks for the host CLI on disk: the
 * same check the Community binary already uses to decide whether to delegate a
 * host command. One definition, so the dashboard cannot disagree with the CLI
 * about the machine they are both standing on.
 *
 * What the installed variant may NOT say is that anything is armed. This
 * dashboard runs unprivileged and cannot read `LSM_POLICY`. It knows a binary
 * is on disk, it says exactly that, and it points at the command that does
 * know. Understating is recoverable; claiming protection we cannot see is not.
 */
/**
 * The wording for each state, as data rather than as JSX only.
 *
 * There is no DOM in this test suite, so copy that lives solely inside a
 * component can only be asserted by grepping the file that declares it -- a
 * test that matches its own source and passes whatever the component renders.
 * Exporting the sentences lets the test read the same strings the screen does.
 */
export const ACTIVE_DEFENCE_COPY = {
  offer: {
    badge: "Host protection",
    title: "Extend protection from agent intent to the host.",
    body: "Community screens supported agent actions before execution. On supported Linux hosts, Active Defence adds independent host telemetry, incident triage and evidence-backed response, including eBPF enforcement and the kernel Execution Gate. macOS and Windows host protection is planned, not implied by this dashboard.",
  },
  installed: {
    badge: "Installed on this host",
    title: "Active Defence is installed on this host.",
    body: "This page covers the agent layer only. Host telemetry, incident triage and the kernel Execution Gate belong to Active Defence, and this dashboard runs unprivileged, so it cannot read kernel state and does not report here what is running or what is turned on. Ask the host itself:",
    /**
     * Verified against a real installation before being written down: on
     * `iw-challenge`, `innerwarden get status` exits 0 and lists the host
     * services. The Community binary delegates any verb it does not know to
     * `innerwarden-ctl`, which is why the plain `innerwarden` spelling is the
     * right one to print for somebody already reading a Community dashboard.
     */
    command: "innerwarden get status",
  },
} as const;

/**
 * Which state the card is in. Trivial today, and named anyway: it is the seam
 * the tests assert through, and it is where a third state would land if one
 * ever arrives (installed-but-unlicensed, say).
 */
export function activeDefenceCardState(installed: boolean): "installed" | "offer" {
  return installed ? "installed" : "offer";
}

function ActiveDefenceCard({ installed }: { installed: boolean }) {
  if (activeDefenceCardState(installed) === "installed") {
    const copy = ACTIVE_DEFENCE_COPY.installed;
    return (
      <aside
        data-ad-state="installed"
        className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6"
        aria-labelledby="active-defence-title"
      >
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">InnerWarden Active Defence</p>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold text-slate-600">{copy.badge}</span>
        </div>
        <h2 id="active-defence-title" className="mt-2 text-lg font-semibold text-slate-950">{copy.title}</h2>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{copy.body}</p>
        <code className="mt-3 inline-block rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-sm text-slate-800">{copy.command}</code>
      </aside>
    );
  }
  return (
    <aside data-tour="upgrade" data-ad-state="offer" className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6" aria-labelledby="active-defence-title">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">InnerWarden Active Defence</p>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold text-slate-600">{ACTIVE_DEFENCE_COPY.offer.badge}</span>
          </div>
          <h2 id="active-defence-title" className="mt-2 text-lg font-semibold text-slate-950">{ACTIVE_DEFENCE_COPY.offer.title}</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{ACTIVE_DEFENCE_COPY.offer.body}</p>
        </div>
        <a
          href="https://innerwarden.com/enterprise#enterprise-install"
          target="_blank"
          rel="noreferrer"
          className="inline-flex shrink-0 items-center justify-center rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 shadow-sm hover:border-slate-400 hover:bg-slate-50"
        >
          Explore Active Defence <span className="ml-1" aria-hidden="true">↗</span>
        </a>
      </div>
    </aside>
  );
}

/// Required Overview fields the producer did not send.
///
/// Typed as non-optional in `api.ts`, which is a claim about the producer rather
/// than a guarantee about the bytes. Checking at the boundary keeps a contract
/// violation legible instead of turning it into a render crash.
export function missingOverviewFields(overview: Overview): string[] {
  const missing: string[] = [];
  if (!Array.isArray(overview.top_categories)) missing.push("top_categories");
  if (!Array.isArray(overview.recent_decisions) && !Array.isArray(overview.recent_blocks)) {
    missing.push("recent_decisions/recent_blocks");
  }
  return missing;
}

function OverviewSkeleton() {
  return (
    <div role="status" aria-live="polite" aria-label="Loading overview" className="space-y-6">
      <div className="h-64 animate-pulse rounded-2xl border border-slate-200 bg-white" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[0, 1, 2, 3].map((item) => <div key={item} className="h-28 animate-pulse rounded-xl border border-slate-200 bg-white" />)}
      </div>
      <span className="sr-only">Loading overview…</span>
    </div>
  );
}

function FullError({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-2xl border border-amber-200 bg-amber-50 p-6 text-amber-950">
      <h1 className="text-lg font-semibold">The local dashboard is unavailable</h1>
      <p className="mt-2 text-sm">Check that the InnerWarden process is still running, then reload this page.</p>
      <details className="mt-4 text-xs text-amber-900"><summary className="cursor-pointer font-semibold">Technical detail</summary><code className="mt-2 block break-all">{message}</code></details>
    </div>
  );
}
