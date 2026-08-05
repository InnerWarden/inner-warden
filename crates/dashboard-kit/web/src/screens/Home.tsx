import { useEffect, useState, type ReactNode } from "react";
import {
  fetchOverview,
  type DashboardMeta,
  type DecisionSummary,
  type GuardrailMode,
  type Overview,
} from "../api";
import { DecidedBy } from "../components/DecidedBy";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { Outcome } from "../components/Outcome";
import { Verdict } from "../components/Verdict";
import { formatTimestamp, humanizeToken, normaliseMode } from "../presentation";

type ActivityLink = { id?: string; session?: string; verdict?: string; action?: string };

export function Home({
  meta,
  onOpenActivity,
  edition,
}: {
  meta?: DashboardMeta;
  onOpenActivity: (target?: ActivityLink) => void;
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
        message={`This dashboard's data source returned an overview without ${missing.join(", ")}. \
The Overview contract requires ${missing.length === 1 ? "that field" : "those fields"}, so the \
figures below cannot be shown. This is a producer fault, not an empty host.`}
      />
    );
  }

  const mode = normaliseMode(meta);
  const denyVerdicts = overview.deny_verdicts ?? overview.blocked;
  const reviewVerdicts = overview.review_verdicts ?? overview.review;
  const allowVerdicts = overview.allow_verdicts ?? overview.allowed;
  const hasUnknownVerdicts = overview.unknown_verdicts != null;
  const recent = (overview.recent_decisions ?? overview.recent_blocks).slice(0, 5);
  const maxSignal = overview.top_categories[0]?.count ?? 0;
  const guardedAgents = meta?.guardrail?.guarded_agents;

  return (
    <div className="min-w-0 space-y-6 sm:space-y-8" aria-busy={fetching}>
      {error && (
        <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <span>Reconnecting to the local dashboard. The figures below may be slightly out of date.</span>
          <span className="text-xs font-medium text-amber-700">Last good response retained</span>
        </div>
      )}

      <PostureHero mode={mode} edition={edition} decisions={overview.commands} sessions={overview.sessions} guardedAgents={guardedAgents} />

      <MachineIntelligence />

      {overview.commands === 0 ? (
        <ZeroState guardedAgents={guardedAgents} />
      ) : (
        <>
          <section aria-labelledby="decision-summary-title">
            <div className="mb-3 flex flex-col items-start gap-2 sm:flex-row sm:items-end sm:justify-between sm:gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Decision record</p>
                <h2 id="decision-summary-title" className="mt-1 text-lg font-semibold text-slate-950">What the guardrail saw</h2>
              </div>
              <button type="button" onClick={() => onOpenActivity()} className="text-sm font-semibold text-cyan-700 hover:text-cyan-900">
                View all activity <span aria-hidden="true">→</span>
              </button>
            </div>
            <div className={hasUnknownVerdicts ? "grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5" : "grid grid-cols-2 gap-3 lg:grid-cols-4"}>
              <Stat label="Recorded decisions" value={overview.commands} detail={`${overview.sessions} session${overview.sessions === 1 ? "" : "s"}`} />
              <Stat label="Deny verdicts" value={denyVerdicts} detail="Classified as unsafe" tone={denyVerdicts > 0 ? "danger" : undefined} />
              <Stat label="Needs review" value={reviewVerdicts} detail="Requires human judgement" tone={reviewVerdicts > 0 ? "attention" : undefined} />
              <Stat label="Allowed" value={allowVerdicts} detail="No blocking verdict" tone="positive" />
              {hasUnknownVerdicts && <Stat label="Unknown verdicts" value={overview.unknown_verdicts ?? 0} detail="Could not be classified" tone={(overview.unknown_verdicts ?? 0) > 0 ? "attention" : undefined} />}
            </div>
          </section>

          {(overview.actual_blocks != null || overview.would_block != null || overview.screened != null || overview.outcomes_unknown != null) && (
            <OperationalEvidence overview={overview} />
          )}

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(280px,.65fr)]">
            <RecentActivity items={recent} onOpen={onOpenActivity} />
            <RiskSignals items={overview.top_categories.slice(0, 6)} max={maxSignal} />
          </div>
        </>
      )}

      <CommunityIncluded />
      {edition === "community" ? <ActiveDefenceCard /> : null}
    </div>
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
export function postureFor(mode: GuardrailMode, edition?: "community" | "enterprise") {
  return mode === "unknown" && edition === "enterprise"
    ? ENTERPRISE_UNKNOWN_POSTURE
    : POSTURES[mode];
}

export const ENTERPRISE_UNKNOWN_POSTURE = {
  label: "Guardrail decisions not recorded here",
  title: "Enforcement is reported on Posture, not by decision count.",
  body: "The agent-guard hook that records per-action decisions is not running on this host, so that counter reads zero. It is not a measure of what the host is protected by \u2014 see Posture for the enforcement layers actually in effect.",
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
    body: "Configured integrations screen activity without blocking it after the agent reloads them. Review the local evidence before enforcing.",
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

function PostureHero({ mode, edition, decisions, sessions, guardedAgents }: { mode: GuardrailMode; edition?: "community" | "enterprise"; decisions: number; sessions: number; guardedAgents?: number }) {
  // The `unknown` copy is written for Community: "this version records guardrail
  // decisions" describes the free hook, and the decision count is the free
  // product's headline. On an Enterprise host that hook is often not installed
  // at all -- the paid stack is what protects it -- so the same words turn a
  // correct zero into a claim that the product is idle. Observed on the
  // production box: 0 decisions on screen while 6,047 incidents sat in its
  // graph. The number was right; the sentence around it was not.
  const posture = postureFor(mode, edition);
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
          <p className="mt-5 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">InnerWarden Community</p>
          <h1 id="posture-title" className="mt-2 max-w-3xl text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
            {posture.title}
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600 sm:text-base">{posture.body}</p>
          <ul className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs font-medium text-slate-600" aria-label="Trust properties">
            <TrustItem>Local rule analysis</TrustItem>
            <TrustItem>Read-only dashboard API</TrustItem>
            <TrustItem>Common secret patterns redacted before storage</TrustItem>
          </ul>
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
          <h2 id="outcome-evidence-title" className="text-sm font-semibold text-slate-900">Execution evidence</h2>
          <p className="text-xs text-slate-500">Outcomes reported by newer guardrail integrations</p>
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

function RecentActivity({ items, onOpen }: { items: DecisionSummary[]; onOpen: (target?: ActivityLink) => void }) {
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
            const when = formatTimestamp(item.recorded_at_ms);
            const sessionLabel = item.session === "local" ? "Local session" : item.session;
            return (
              <li key={item.id ?? `${item.session}-${item.command}-${index}`} className="border-b border-slate-100 last:border-0">
                <button
                  type="button"
                  onClick={() => onOpen({ id: item.id, session: item.session, verdict: recommendation, action: item.command })}
                  className="group grid w-full min-w-0 grid-cols-[7rem_minmax(0,1fr)] items-start gap-x-3 gap-y-2 px-3 py-3 text-left transition-colors hover:bg-slate-50 focus-visible:-outline-offset-2 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:px-4"
                  aria-label={`Open ${recommendation} decision for ${item.command}`}
                >
                  <Verdict rec={recommendation} />
                  <div className="min-w-0 flex-1">
                    <code className="block truncate text-sm font-medium text-slate-900">{item.command}</code>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <DecidedBy by={item.decided_by} />
                      <Outcome value={item.outcome ?? "unknown"} />
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
                    <span className="mt-2 hidden font-semibold text-cyan-700 opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100 sm:inline-block">Open →</span>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function RiskSignals({ items, max }: { items: Overview["top_categories"]; max: number }) {
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
          Categories show rule matches, not confirmed attacks. A user or model decision may still allow a matched action.
        </p>
      </div>
    </section>
  );
}

function ZeroState({ guardedAgents }: { guardedAgents?: number }) {
  const hasConfiguredAgent = guardedAgents != null && guardedAgents > 0;
  return (
    <section className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 sm:p-8" aria-labelledby="zero-state-title">
      <div className="mx-auto max-w-3xl text-center">
        <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-50 text-lg font-bold text-cyan-800" aria-hidden="true">IW</div>
        <h2 id="zero-state-title" className="mt-4 text-xl font-semibold text-slate-950">No decisions recorded yet</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-600">
          {hasConfiguredAgent
            ? "The guardrail is configured. Captured shell actions, MCP tool calls and one-off checks appear here as a local activity record."
            : "Connect a detected agent in monitor mode to build a local decision record without blocking its work."}
        </p>
      </div>
      <ol className="mx-auto mt-7 grid max-w-3xl gap-3 sm:grid-cols-3">
        <OnboardingStep number="1" title="Connect safely" command="innerwarden setup">Detect agents and begin in monitor mode.</OnboardingStep>
        <OnboardingStep number="2" title="Review evidence" command="innerwarden dashboard">Inspect captured shell, MCP and one-off decisions here.</OnboardingStep>
        <OnboardingStep number="3" title="Enforce when ready" command="innerwarden enforce">Block deny decisions on supported integrations.</OnboardingStep>
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

function CommunityIncluded() {
  return (
    <section className="rounded-2xl border border-cyan-200 bg-cyan-50/60 px-5 py-5 sm:px-6" aria-labelledby="community-included-title">
      <div className="grid gap-4 lg:grid-cols-[220px_1fr] lg:items-center">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-800">Community Edition</p>
          <h2 id="community-included-title" className="mt-1 text-lg font-semibold text-slate-950">Included, not gated</h2>
        </div>
        <ul className="grid gap-x-6 gap-y-2 text-sm text-slate-700 sm:grid-cols-2 lg:grid-cols-3">
          {COMMUNITY_FEATURES.map((feature) => (
            <li key={feature} className="flex items-center gap-2">
              <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-cyan-700 text-[10px] font-bold text-white" aria-hidden="true">✓</span>
              {feature}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function ActiveDefenceCard() {
  return (
    <aside className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6" aria-labelledby="active-defence-title">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">InnerWarden Active Defence</p>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold text-slate-600">Host protection</span>
          </div>
          <h2 id="active-defence-title" className="mt-2 text-lg font-semibold text-slate-950">Extend protection from agent intent to the host.</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
            Community screens supported agent actions before execution. On supported Linux hosts, Active Defence adds independent host telemetry, incident triage and evidence-backed response, including eBPF enforcement and the kernel Execution Gate. macOS and Windows host protection is planned, not implied by this dashboard.
          </p>
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
