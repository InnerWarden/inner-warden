import { useEffect, useState, type ReactNode } from "react";
import {
  fetchAgents,
  fetchTokenIntelligence,
  type AgentGuardrail,
  type AgentsResponse,
  type LocalAgent,
  type TokenAgent,
  type TokenIntelligenceResponse,
} from "../api";
import { gridColumnsClass, gridSpanClass, joinClasses } from "./cardGrid";

type PollState<T> = {
  data?: T;
  error: boolean;
  loading: boolean;
  refreshing: boolean;
};

const INITIAL_POLL_STATE = { error: false, loading: true, refreshing: false };
const agentsAreLoading = (data: AgentsResponse) => data.availability === "loading";
const tokensAreLoading = (data: TokenIntelligenceResponse) => data.availability === "loading";
const PRODUCT_LABELS: Record<string, string> = {
  mcp_proxy: "MCP proxy",
  pretooluse_hook: "PreToolUse hook",
  local_session_log: "Local session log",
};

export function MachineIntelligence({ edition }: { edition?: "community" | "enterprise" } = {}) {
  const agents = usePollingResource(fetchAgents, 30_000, agentsAreLoading);
  const tokens = usePollingResource(fetchTokenIntelligence, 60_000, tokensAreLoading);

  return (
    <div className="space-y-6">
      <AgentsPanel state={agents} edition={edition} />
      <TokenPanel state={tokens} />
    </div>
  );
}

/// A poll the operator does not see.
///
/// Refreshing is background work; it is not news. The previous version told the
/// user about every cycle: it set `refreshing` before each request and, on
/// failure, replaced a populated panel with "unavailable". Against an endpoint
/// that answers 404 the retry was a flat 5s, so the whole panel flipped between
/// content and an error box roughly every five seconds, forever. That reads as a
/// system malfunctioning in front of you.
///
/// Four rules, and each one removes a visible event:
///
/// 1. Announce the FIRST load only. Once there is data on screen, a refresh
///    starts silently: no state write, so no re-render.
/// 2. Keep the last good data through a failure. A transient error must not
///    empty a panel that is still showing true, if slightly older, information.
///    `error` only reaches the UI when there has never been data to show.
/// 3. Back off. Repeated failures double the delay up to a minute, so a
///    permanently broken endpoint costs one request a minute instead of twelve.
/// 4. Do not re-render for an unchanged payload. Most cycles return exactly what
///    is already on screen.
export const ERROR_BACKOFF_START_MS = 5_000;
export const ERROR_BACKOFF_MAX_MS = 60_000;

/// How long to wait after a FAILED poll, and what the next backoff becomes.
///
/// Pure so it can be tested: this file has no jsdom, and the kit's convention is
/// that the decision lives outside the React shell.
export function nextErrorDelay(backoff: number): { delay: number; next: number } {
  return {
    delay: Math.min(backoff, ERROR_BACKOFF_MAX_MS),
    next: Math.min(backoff * 2, ERROR_BACKOFF_MAX_MS),
  };
}

/// Whether a failure should reach the operator.
///
/// Only when there is nothing already on screen. Replacing real, slightly older
/// data with an error box is the flicker the user reported.
export function shouldSurfaceError(haveData: boolean): boolean {
  return !haveData;
}

function usePollingResource<T>(load: () => Promise<T>, intervalMs: number, retrySoon: (data: T) => boolean): PollState<T> {
  const [state, setState] = useState<PollState<T>>(INITIAL_POLL_STATE);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let timer: number | undefined;
    let backoff = ERROR_BACKOFF_START_MS;
    let lastSerialised: string | undefined;
    let haveData = false;

    const refresh = () => {
      if (inFlight) return;
      inFlight = true;
      let nextDelay = intervalMs;
      // Rule 1: only the first load is worth telling the user about. With data
      // already on screen this writes nothing, so React does not re-render.
      if (!haveData) setState((current) => ({ ...current, loading: true, refreshing: false }));
      load()
        .then((data) => {
          if (!active) return;
          backoff = ERROR_BACKOFF_START_MS;
          nextDelay = retrySoon(data) ? 750 : intervalMs;
          // Rule 4: an identical payload is not an update.
          const serialised = JSON.stringify(data);
          if (haveData && serialised === lastSerialised) return;
          lastSerialised = serialised;
          haveData = true;
          setState({ data, error: false, loading: false, refreshing: false });
        })
        .catch(() => {
          if (!active) return;
          // Rule 3: a broken endpoint should get quieter, not louder.
          const step = nextErrorDelay(backoff);
          nextDelay = step.delay;
          backoff = step.next;
          // Rule 2: stale truth beats an empty panel. Surface the error only
          // when there is nothing already on screen to keep.
          if (!shouldSurfaceError(haveData)) return;
          setState((current) => ({ ...current, error: true, loading: false, refreshing: false }));
        })
        .finally(() => {
          inFlight = false;
          if (active) timer = window.setTimeout(refresh, nextDelay);
        });
    };

    refresh();
    return () => {
      active = false;
      if (timer != null) window.clearTimeout(timer);
    };
  }, [intervalMs, load, retrySoon]);

  return state;
}

// Internal bookkeeping stays out of the user's face. Two lines used to render
// as prominent chrome on every affected load: an amber role="status" banner for
// the discovery safety limit (a permanent producer bound, not an event), and an
// "Automatic setup is unavailable" header announcement on hosts where the
// free-tier mechanism simply does not run. Both truths are preserved, one
// interaction or one glance lower: a collapsed disclosure and a grey footnote.
export const DISCOVERY_LIMIT_DISCLOSURE = {
  kind: "disclosure",
  summary: "Some integrations may not be listed",
  body: "Agent discovery reached its local safety limit. Reviewed integrations remain visible, but some generic MCP configurations may be omitted to keep the dashboard responsive.",
} as const;

export const AUTO_SETUP_UNKNOWN_FOOTNOTE =
  "Automatic setup policy is not reported here. Check it with the CLI if you need it.";

/** The privacy fact about token counts: worth stating, not worth a banner. */
export const TOKEN_PRIVACY_FOOTNOTE =
  "Counts only, not a security score. Prompts, responses and tool content never reach this dashboard, and these are not billing figures.";

/** Where the automatic-setup line belongs: a header strip only when the policy
 * is actually known; otherwise a quiet footnote. */
export function autoSetupPlacement(known: boolean): "header" | "footnote" {
  return known ? "header" : "footnote";
}

/** The discovery-limit truth as a quiet disclosure; null when discovery is not
 * limited. Never a banner: the limit is permanent producer bookkeeping. */
export function discoveryLimitNotice(limited: boolean): typeof DISCOVERY_LIMIT_DISCLOSURE | null {
  return limited ? DISCOVERY_LIMIT_DISCLOSURE : null;
}

function AgentsPanel({ state, edition }: { state: PollState<AgentsResponse>; edition?: "community" | "enterprise" }) {
  const { data, error, loading } = state;
  const scanning = loading || data?.availability === "loading";
  // `unavailable` arrives WITH data, so it renders through the data branch and
  // gets its own honest message there rather than falling through to the
  // no-response panel below.
  const couldNotEnumerate = data?.availability === "unavailable";
  const autoConnectKnown = data?.auto_connect.status === "available"
    && data.auto_connect.enabled != null
    && data.auto_connect.mode != null;
  return (
    <section aria-labelledby="local-agents-title" aria-busy={scanning}>
      <SectionHeading
        // The eyebrow said "Community visibility" on every host, paid ones
        // included. Local agent detection is not a Community feature -- it is
        // the same view in both tiers -- so naming a tier here was both wrong
        // and, on a paid box, a quiet contradiction of the header above it.
        eyebrow={edition === "enterprise" ? "Local visibility" : "Community visibility"}
        title="Agents on this machine"
        // Was: "Local detection and guardrail setup are shown as separate
        // signals, so presence is never presented as proof of active
        // protection." That is a description of our own rendering rule. The
        // rule still holds; each card states its own guardrail evidence, which
        // is where an operator reads it.
        description="Which agents are here, whether they are running, and whether a guardrail has been seen working on each one."
        aside={data ? <GeneratedAt value={data.generated_at_ms} /> : undefined}
      />
      {error && data && <StaleNotice />}
      {scanning ? (
        <PanelSkeleton cards={3} label="Loading locally detected agents" />
      ) : data ? (
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          {autoConnectKnown && (
            // A KNOWN automatic-setup policy is a user fact worth a header line.
            // The unknown case is producer bookkeeping (on the paid tier the
            // free-tier mechanism simply is not a thing) and renders as a quiet
            // footnote below instead of a permanent header announcement.
            <div className="flex flex-col gap-2 border-b border-slate-100 bg-slate-50/70 px-4 py-3 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between sm:px-5">
              <span>
                Automatic setup is <strong className="font-semibold text-slate-800">{data.auto_connect.enabled ? "enabled" : "disabled"}</strong>
                {data.auto_connect.enabled ? ` in ${humanise(data.auto_connect.mode!)} mode` : ""}.
              </span>
              <span className="tabular-nums">
                {data.auto_connect.enabled
                  ? `Checks every ${formatInterval(data.auto_connect.refresh_interval_secs)}`
                  : "Enable from setup or the CLI"}
              </span>
            </div>
          )}
          {data.agents.length === 0 ? (
            couldNotEnumerate ? (
              <EmptyPanel title="Agent detection could not run" body="The host answered but could not enumerate agents, so none are listed. On the paid tier this is an absent or unreadable agent registry; nothing is being inferred from the gap." />
            ) : (
              <EmptyPanel title="No compatible agents detected" body="Install or launch an agent, or configure a standard MCP client, then keep the InnerWarden dashboard process running while it checks again." />
            )
          ) : (
            <ul className={agentGridClass(data.agents.length)}>
              {data.agents.map((agent, index) => (
                <AgentCard key={agent.id} agent={agent} spanClass={agentCardSpanClass(index, data.agents.length)} />
              ))}
            </ul>
          )}
          {(data.discovery_limited || !autoConnectKnown) && (
            <div className="border-t border-slate-100 px-4 py-2.5 sm:px-5">
              {data.discovery_limited && (
                <details className="text-xs leading-5 text-slate-500">
                  <summary className="cursor-pointer font-medium hover:text-slate-700">{DISCOVERY_LIMIT_DISCLOSURE.summary}</summary>
                  <p className="mt-1">{DISCOVERY_LIMIT_DISCLOSURE.body}</p>
                </details>
              )}
              {!autoConnectKnown && (
                <p className="text-xs leading-5 text-slate-500">{AUTO_SETUP_UNKNOWN_FOOTNOTE}</p>
              )}
            </div>
          )}
        </div>
      ) : (
        // Two different facts, and saying the wrong one sends the operator to
        // check the wrong thing. No data at all means the request never landed.
        // Data that says `unavailable` means it DID land and the host could not
        // enumerate agents -- on the paid side, an absent or unreadable agent
        // registry. Reporting that as "did not respond" is the product
        // describing a state it is not in.
        <UnavailablePanel
          title="Agent detection is unavailable"
          body="The local endpoint did not respond. InnerWarden will keep trying; automatic setup continues to follow the policy shown when the endpoint is available."
        />
      )}
    </section>
  );
}

/**
 * The grid class for a given number of agent cards.
 *
 * Two across is the ceiling: each card carries a heading, six detail cells and
 * a detection-evidence list, and at three the detail grid collapses to one
 * column per card and the headings wrap mid-word. `pair-md` is that ceiling.
 *
 * REGRESSION ANCHOR. This was a flat `md:grid-cols-2`. The cards sit in a
 * `gap-px` grid over a `bg-slate-200` parent (the hairline-divider trick),
 * which means any cell the cards do not fill shows that parent through. On the
 * common case of exactly ONE agent, the second column was an empty grey panel
 * sitting beside the single card on every screen wider than `md`, which reads as
 * a card that failed to load rather than as a host with one agent.
 */
export function agentGridClass(count: number): string {
  return joinClasses("grid gap-px bg-slate-200", gridColumnsClass("pair-md", count));
}

/**
 * Whether a card should span the full row.
 *
 * The odd one out. Two columns leave the same grey hole beside the last card at
 * three, five, seven agents that one column left at one; widening the trailing
 * card closes it at every count instead of only the count someone tested.
 */
export function agentCardSpanClass(index: number, count: number): string {
  return gridSpanClass("pair-md", index, count);
}

function AgentCard({ agent, spanClass = "" }: { agent: LocalAgent; spanClass?: string }) {
  const running = runningStatus(agent.running);
  const view = guardrailView(agent.guardrail);
  return (
    <li className={`min-w-0 bg-white p-4 sm:p-5 ${spanClass}`}>
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-base font-semibold text-slate-950" title={agent.display_name}>{agent.display_name}</h3>
          <p className="mt-1 text-xs text-slate-500">{agentPresence(agent)}</p>
        </div>
        <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${running.cls}`}>
          <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
          {running.label}
        </span>
      </div>

      {/* The whole point of the liveness half. An agent with a policy row and no
          observation used to render as a normal, healthy card; the sentence has
          to be on the card, not inferable from it. */}
      {view.notice && (
        <p role="status" className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5 text-xs leading-5 text-amber-950">
          {view.notice}
        </p>
      )}

      <dl className="mt-4 grid grid-cols-1 gap-3 text-xs min-[380px]:grid-cols-2">
        <Detail label="Guardrail">
          <span className={`font-semibold ${view.tone}`}>{view.label}</span>
          {view.intent && <span className="mt-0.5 block text-[11px] font-normal text-slate-500">{view.intent}</span>}
        </Detail>
        <Detail label="Setup support">{humanise(agent.guardrail.setup_support)}</Detail>
        <Detail label="Mechanism">{agent.guardrail.mechanism ? humanise(agent.guardrail.mechanism) : "Not available"}</Detail>
        <Detail label="Automatic setup">{automaticSetupLabel(agent)}</Detail>
        {view.lastObserved && <Detail label="Last observed">{view.lastObserved}</Detail>}
        {view.recordedActivity && <Detail label="Recorded activity">{view.recordedActivity}</Detail>}
      </dl>

      {agent.detected_by.length > 0 && (
        <div className="mt-4 border-t border-slate-100 pt-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-500">Detected by</p>
          <ul className="mt-2 flex flex-wrap gap-1.5" aria-label={`Detection evidence for ${agent.display_name}`}>
            {agent.detected_by.map((method, index) => (
              <li key={`${method}-${index}`} className="max-w-full truncate rounded-full bg-slate-100 px-2 py-1 text-[11px] font-medium text-slate-600" title={method}>
                {humanise(method)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

/// Modes that positively mean a guardrail IS in place. Anything outside this
/// set has not told us that, and must not be reported as though it had.
const CONFIGURED_MODES = new Set(["monitor", "enforce", "mixed"]);

/// The mode a producer sends when a policy row exists and NOTHING has been seen
/// going through it. Deliberately outside [`CONFIGURED_MODES`] so it can never
/// be rendered as an assurance -- but it still has to be rendered as SOMETHING,
/// which is what everything below exists to do.
const CONFIGURED_NOT_OBSERVED = "configured_not_observed";

function readString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function readCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/**
 * Does the payload positively say a guardrail is in place AND working?
 *
 * Two conditions, and both are required. A positive mode is the intent half; an
 * `observation` other than `observed` is the live half CONTRADICTING it, and the
 * contradiction wins. A producer that ships the live half therefore gets to veto
 * its own positive mode, so a build that downgrades `mode` in one code path and
 * forgets it in another still cannot print an assurance here.
 *
 * A producer that sends no `observation` at all (the free CLI) is not treated as
 * having said "not observed" -- it has said nothing, and the old card is the
 * honest rendering of that.
 */
export function guardrailIsProtecting(guardrail: AgentGuardrail): boolean {
  if (!CONFIGURED_MODES.has(guardrail.mode)) return false;
  const observation = readString(guardrail.observation);
  return observation === undefined || observation === "observed";
}

/**
 * Is this the state the whole card had no words for: configured, never seen?
 *
 * Recognised two ways, because the truth must not depend on one field arriving.
 * Explicitly, when the producer already downgraded `mode` to
 * `configured_not_observed`; and structurally, when a positive intent is
 * contradicted by the live half.
 */
export function guardrailIsConfiguredButUnobserved(guardrail: AgentGuardrail): boolean {
  if (guardrail.mode === CONFIGURED_NOT_OBSERVED) return true;
  const observation = readString(guardrail.observation);
  if (observation === undefined || observation === "observed") return false;
  const intent = readString(guardrail.configured_mode) ?? guardrail.mode;
  return CONFIGURED_MODES.has(intent);
}

/// Everything the agent card needs to say about one guardrail, decided outside
/// React so the wording is testable without a DOM.
export type GuardrailView = {
  /// Whether the card is allowed to read as protection. Nothing else may set a
  /// positive tone.
  protecting: boolean;
  /// A policy row exists and nothing has been seen going through it.
  unobserved: boolean;
  label: string;
  tone: string;
  /// The recorded intent, when the rendered verdict is not it.
  intent?: string;
  lastObserved?: string;
  recordedActivity?: string;
  /// The sentence the amber notice prints. Set only when `unobserved`.
  notice?: string;
};

/**
 * REGRESSION ANCHOR.
 *
 * The producer started sending an honest payload -- `configured_not_observed`
 * plus dates, counters and prose -- and the card rendered none of it. The mode
 * fell through `humanise` to the words "Configured not observed" beside
 * "Eligibility unavailable", with no date, no age, and nothing to distinguish it
 * from a card that had simply failed to load. Honest and useless is still a
 * broken surface: the operator could not tell WHEN it was last seen, so the only
 * available action was to ignore it.
 */
export function guardrailView(guardrail: AgentGuardrail): GuardrailView {
  const protecting = guardrailIsProtecting(guardrail);
  const unobserved = guardrailIsConfiguredButUnobserved(guardrail);
  return {
    protecting,
    unobserved,
    label: unobserved ? "Configured, not observed" : humanise(guardrail.mode),
    tone: guardrailTone(guardrail),
    intent: unobserved ? configuredIntentLabel(guardrail) : undefined,
    lastObserved: lastObservedLabel(guardrail),
    recordedActivity: recordedActivityLabel(guardrail),
    notice: unobserved ? unobservedNotice(guardrail) : undefined,
  };
}

/// Colour is a claim too. Only a guardrail that has been observed working earns
/// the positive tone; the unobserved state gets the warning one, and anything
/// unrecognised stays neutral rather than borrowing either.
export function guardrailTone(guardrail: AgentGuardrail): string {
  if (guardrailIsConfiguredButUnobserved(guardrail)) return "text-amber-800";
  if (guardrailIsProtecting(guardrail)) return guardrail.mode === "mixed" ? "text-amber-700" : "text-blue-700";
  if (guardrail.mode.toLowerCase().includes("partial")) return "text-amber-700";
  return "text-slate-700";
}

/// What the policy row records, kept beside the verdict so nothing is hidden:
/// the operator still sees what was configured, it just no longer arrives as an
/// assurance the evidence does not support.
export function configuredIntentLabel(guardrail: AgentGuardrail): string | undefined {
  const intent = readString(guardrail.configured_mode);
  if (intent === undefined || intent === guardrail.mode) return undefined;
  return `Policy row records ${humanise(intent).toLowerCase()}`;
}

/// The date half, and the age beside it. An operator looking at a silent agent
/// needs to know HOW silent; a bare date makes them do the subtraction.
export function lastObservedLabel(guardrail: AgentGuardrail): string | undefined {
  const observation = readString(guardrail.observation);
  const age = formatUnobservedAge(guardrail.unobserved_for_seconds);
  const observed = formatDate(guardrail.last_observed_at);
  if (observed) return age ? `${observed} (${age} ago)` : observed;
  // Below here nothing was ever observed, so the cell only exists when the
  // producer sent the live half at all. Otherwise it says nothing.
  if (observation === undefined) return undefined;
  if (observation === "never_observed") {
    const configured = formatDate(guardrail.configured_at);
    if (configured && age) return `Never, ${age} since ${configured}`;
    if (age) return `Never, ${age} and counting`;
    return "Never";
  }
  return age ? `Not recorded (${age} since configuration)` : "Not recorded";
}

/// The row's own counters. Zero is a fact worth printing, so it is never elided
/// into an empty cell.
export function recordedActivityLabel(guardrail: AgentGuardrail): string | undefined {
  const count = readCount(guardrail.recorded_activity);
  if (count === undefined) return undefined;
  if (count <= 0) return "None recorded";
  return `${count.toLocaleString()} recorded, undated`;
}

/**
 * The sentence on the amber notice.
 *
 * The producer's own `summary` is preferred when it sent one -- it is written
 * against the same evidence and adds the reason ("a policy row is intent, not a
 * running guardrail"). The derived fallback exists because the free product
 * serves this endpoint too and sends none of these fields, and because a partial
 * payload must still produce a sentence rather than a blank.
 */
export function unobservedNotice(guardrail: AgentGuardrail): string {
  const summary = readString(guardrail.summary);
  if (summary) return summary;
  const since = formatDate(guardrail.last_observed_at) ?? formatDate(guardrail.configured_at);
  const age = formatUnobservedAge(guardrail.unobserved_for_seconds);
  const when = since && age
    ? `not observed since ${since} (${age})`
    : since
      ? `not observed since ${since}`
      : age
        ? `not observed for ${age}`
        : "not observed, and no observation has been recorded";
  return `Configured, ${when}. A policy row is intent, not a running guardrail.`;
}

/// A duration in words, coarse on purpose: the point is the ORDER of magnitude
/// ("16 days"), not a precise interval. Mirrors the producer's own wording so
/// the derived fallback and the sent summary do not read as two different
/// products.
export function formatUnobservedAge(seconds: number | null | undefined): string | undefined {
  const value = readCount(seconds);
  if (value === undefined) return undefined;
  const secs = Math.max(0, Math.floor(value));
  if (secs < 90) return "less than a minute";
  if (secs < 5_400) return `${Math.floor(secs / 60)} minutes`;
  if (secs < 172_800) return `${Math.floor(secs / 3_600)} hours`;
  const days = Math.floor(secs / 86_400);
  return `${days} day${days === 1 ? "" : "s"}`;
}

/// An RFC 3339 timestamp as a calendar day. Falls back to the leading `Y-m-d`
/// when the runtime cannot parse the string, and to nothing at all when it is
/// not shaped like a date -- a wrong date is worse than an absent one.
export function formatDate(value: string | null | undefined): string | undefined {
  const raw = readString(value);
  if (raw === undefined) return undefined;
  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(parsed);
  }
  const day = raw.slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : undefined;
}

/**
 * What to say about automatic setup for one agent.
 *
 * REGRESSION ANCHOR. This used to read `mode !== "not_configured"` and print
 * "Already configured" for everything else -- including `unknown`. An agent
 * whose guardrail state we could not determine was therefore reported to the
 * operator as configured. On a live host that produced a card claiming
 * "Already configured" beside "Mechanism: Not available" and "Setup support:
 * Unsupported", under a banner that said automatic setup was unavailable, for
 * an agent with no guardrail installed at all.
 *
 * "Already configured" is an assurance. It may only be derived from a mode that
 * positively says so, never from the absence of a negative -- and, since the
 * live half exists, never over the top of evidence that contradicts it.
 */
export function automaticSetupLabel(agent: LocalAgent): string {
  if (agent.guardrail.mode === "partial") return "Manual review required";
  // Ahead of the positive branch on purpose. This cell is one of the places an
  // operator reads for "am I covered", so the veto has to reach it too:
  // configured is not verified, and the words must not blur that.
  if (guardrailIsConfiguredButUnobserved(agent.guardrail)) return "Configured, not verified";
  if (guardrailIsProtecting(agent.guardrail)) return "Already configured";
  // `unknown` lands here rather than in the branch above: not knowing is not a
  // kind of being configured.
  if (agent.guardrail.mode === "unknown") return "Not determined";
  if (agent.auto_connect_eligible == null) return "Eligibility unavailable";
  if (agent.auto_connect_eligible) return "Eligible when enabled";
  if (agent.guardrail.setup_support === "manual") return "Manual setup";
  if (agent.guardrail.setup_support === "unsupported") return "Not available";
  return "Not eligible automatically";
}

function agentPresence(agent: LocalAgent): string {
  const evidence = new Set(agent.detected_by);
  if (evidence.has("executable_on_path") && evidence.has("process")) return "CLI available and running process detected";
  if (evidence.has("process")) return "Running process detected";
  if (evidence.has("executable_on_path") || agent.installed) return "CLI available on this PATH";
  if (evidence.has("configuration_file")) return "Configuration found; CLI not confirmed";
  if (evidence.has("compatible_mcp_configuration")) return "Compatible MCP configuration found";
  if (evidence.has("possible_leftover")) return "Possible leftover files; installation not confirmed";
  return "Local presence detected; installation not confirmed";
}

function TokenPanel({ state }: { state: PollState<TokenIntelligenceResponse> }) {
  const { data, error, loading } = state;
  return (
    <section aria-labelledby="token-intelligence-title" aria-busy={loading || data?.availability === "loading"}>
      <SectionHeading
        eyebrow="Local resource visibility"
        title="Token intelligence"
        description="How much each agent on this machine has consumed, read from the history it keeps locally."
        aside={data ? <AvailabilityBadge value={data.availability} /> : undefined}
      />

      {error && data && <StaleNotice />}
      {loading && !data ? (
        <PanelSkeleton cards={3} label="Loading token intelligence" lgColumns={3} />
      ) : data ? (
        data.agents.length === 0 ? (
          <EmptyPanel title="No local token history yet" body="No agent on this machine keeps a token history InnerWarden can read. Counts appear here once one does." />
        ) : (
          <ul className={joinClasses("grid gap-3", gridColumnsClass("trio", data.agents.length))}>
            {data.agents.map((agent, index) => (
              <TokenCard key={agent.agent_id} agent={agent} spanClass={gridSpanClass("trio", index, data.agents.length)} />
            ))}
          </ul>
        )
      ) : (
        <UnavailablePanel title="Token intelligence is unavailable" body="The local endpoint did not respond. No usage value is being inferred from the missing response." />
      )}
      {/* The privacy fact used to be a coloured banner ABOVE the counters, on
          every load, on every host. It is worth stating once and it is worth
          nobody's attention twice, so it sits under the numbers in grey. */}
      <p className="mt-3 text-xs leading-5 text-slate-500">{TOKEN_PRIVACY_FOOTNOTE}</p>
    </section>
  );
}

function TokenCard({ agent, spanClass = "" }: { agent: TokenAgent; spanClass?: string }) {
  const scanning = agent.availability === "loading";
  const unsupported = agent.availability.toLowerCase() === "unsupported";
  const metrics = [
    ["Input", agent.input_tokens],
    ["Output", agent.output_tokens],
    ["Cache read", agent.cache_read_input_tokens],
    ["Cached input", agent.cached_input_tokens],
    ["Cache creation", agent.cache_creation_input_tokens],
    ["Reasoning output", agent.reasoning_output_tokens],
    ["Sessions", agent.sessions],
  ] as const;

  return (
    <li className={joinClasses("min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5", spanClass)}>
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-base font-semibold text-slate-950" title={agent.display_name}>{agent.display_name}</h3>
          <p className="mt-1 text-xs text-slate-500">
            {unsupported ? "No supported local token source" : `Last observed: ${scanning ? "Scanning…" : formatObservedAt(agent.last_observed_at_ms)}`}
          </p>
        </div>
        <AvailabilityBadge value={agent.availability} />
      </div>

      {unsupported ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-4">
          <p className="text-sm font-semibold text-slate-800">Token usage is unavailable for this agent</p>
          <p className="mt-1 text-xs leading-5 text-slate-600">
            {agent.provenance.note || "InnerWarden does not infer usage from an unsupported local source."}
          </p>
        </div>
      ) : (
        <>
          <div className="mt-4 rounded-xl bg-slate-950 px-4 py-3 text-white">
            <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-300">Tokens observed</p>
            <p className="mt-1 truncate text-2xl font-semibold tabular-nums" title={formatNullableCount(agent.total_tokens, scanning)}>
              {formatNullableCount(agent.total_tokens, scanning)}
            </p>
          </div>

          <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-4">
            {metrics.map(([label, value]) => {
              const formatted = formatNullableCount(value, scanning);
              return (
                <div key={label} className="min-w-0">
                  <dt className="truncate text-[11px] text-slate-500" title={label}>{label}</dt>
                  <dd
                    className={`mt-0.5 truncate text-sm font-semibold tabular-nums ${value == null ? "text-slate-500" : "text-slate-900"}`}
                    title={formatted}
                  >
                    {formatted}
                  </dd>
                </div>
              );
            })}
          </dl>

          <div className="mt-4 border-t border-slate-100 pt-3 text-xs leading-5 text-slate-600">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-semibold text-slate-700">Provenance</span>
              <span>{humanise(agent.provenance.source)}</span>
              <span aria-hidden="true" className="text-slate-300">·</span>
              <span className="font-medium text-slate-700">{humanise(agent.provenance.quality)}</span>
            </div>
            {agent.provenance.note && <p className="mt-1 text-slate-500">{agent.provenance.note}</p>}
          </div>
        </>
      )}
    </li>
  );
}

function SectionHeading({ eyebrow, title, description, aside }: { eyebrow: string; title: string; description: string; aside?: ReactNode }) {
  const id = title === "Agents on this machine" ? "local-agents-title" : "token-intelligence-title";
  return (
    <div className="mb-3 flex flex-col items-start gap-2 sm:flex-row sm:items-end sm:justify-between sm:gap-4">
      <div className="min-w-0">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">{eyebrow}</p>
        <h2 id={id} className="mt-1 text-lg font-semibold text-slate-950">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-slate-600">{description}</p>
      </div>
      {aside && <div className="shrink-0">{aside}</div>}
    </div>
  );
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-words font-medium text-slate-800">{children}</dd>
    </div>
  );
}

function AvailabilityBadge({ value }: { value: string }) {
  const normalised = value.toLowerCase();
  const cls = normalised.includes("error") || normalised.includes("failed")
    ? "border-red-200 bg-red-50 text-red-700"
    : normalised.includes("loading")
      ? "border-blue-200 bg-blue-50 text-blue-700"
      : normalised.includes("partial") || normalised.includes("estimated")
    ? "border-amber-200 bg-amber-50 text-amber-800"
    : normalised.includes("available") && !normalised.includes("unavailable")
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : "border-slate-200 bg-slate-50 text-slate-600";
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${cls}`}>{humanise(value)}</span>;
}

function GeneratedAt({ value }: { value: number }) {
  return <span className="text-xs text-slate-500">Snapshot {formatObservedAt(value)}</span>;
}

function StaleNotice() {
  return (
    <div role="status" className="mb-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-900">
      Latest refresh failed. The last available local snapshot is retained.
    </div>
  );
}

function PanelSkeleton({ cards, label, lgColumns = 2 }: { cards: number; label: string; lgColumns?: 2 | 3 }) {
  return (
    <div
      role="status"
      aria-label={label}
      className={lgColumns === 3 ? "grid gap-3 md:grid-cols-2 lg:grid-cols-3" : "grid gap-3 md:grid-cols-2"}
    >
      {Array.from({ length: cards }, (_, index) => <div key={index} className="h-44 animate-pulse rounded-2xl border border-slate-200 bg-white" />)}
      <span className="sr-only">{label}…</span>
    </div>
  );
}

function EmptyPanel({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-white px-4 py-6 text-center sm:px-6">
      <h3 className="font-semibold text-slate-900">{title}</h3>
      <p className="mx-auto mt-1 max-w-xl text-sm leading-6 text-slate-600">{body}</p>
    </div>
  );
}

function UnavailablePanel({ title, body }: { title: string; body: string }) {
  return (
    <div role="alert" className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-5 text-amber-950 sm:px-5">
      <h3 className="font-semibold">{title}</h3>
      <p className="mt-1 text-sm leading-6">{body}</p>
    </div>
  );
}

function runningStatus(value: boolean | null): { label: string; cls: string } {
  if (value === true) return { label: "Running", cls: "border-emerald-200 bg-emerald-50 text-emerald-700" };
  if (value === false) return { label: "Not running", cls: "border-slate-200 bg-slate-50 text-slate-600" };
  return { label: "Runtime not confirmed", cls: "border-slate-200 bg-slate-50 text-slate-600" };
}

function humanise(value: string): string {
  const productLabel = PRODUCT_LABELS[value.toLowerCase()];
  if (productLabel) return productLabel;
  const label = value.replace(/[_-]+/g, " ").trim();
  return label ? label[0].toUpperCase() + label.slice(1) : "Unavailable";
}

function formatNullableCount(value: string | number | null, scanning = false): string {
  if (value == null) return scanning ? "Scanning…" : "Unavailable";
  if (typeof value === "number") return Number.isFinite(value) ? value.toLocaleString() : "Unavailable";
  try {
    return BigInt(value).toLocaleString();
  } catch {
    return "Unavailable";
  }
}

function formatObservedAt(value: number | null): string {
  if (value == null || !Number.isFinite(value)) return "Unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "the configured interval";
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.round(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}
