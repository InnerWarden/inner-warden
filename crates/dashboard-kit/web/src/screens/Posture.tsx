import type {
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
} from "../api/v1";
import { StatusBadge } from "../components/StatusBadge";
import { layerAssuranceLabel } from "../posture/assurance";

// ─────────────────────────── user-facing projections ─────────────────────────
//
// This screen answers the operator's question: which host controls are on, are
// they working, and what needs my attention. The verification chain that backs
// each answer stays one interaction away in a per-control disclosure; it never
// renders as the screen's primary content.

const ARMED_MODES = ["enforce", "observe", "rehearse"];

/** Effective mode in plain words. Armed-but-unverified keeps the armed intent
 * visible ("Enforcing, verifying") without claiming verification. */
export function plainMode(layer: Pick<ProtectionLayer, "effective_mode" | "desired_mode">): string {
  const words: Record<string, string> = {
    enforce: "Enforcing",
    observe: "Watching",
    rehearse: "Rehearsing",
    learning: "Learning",
    disabled: "Off",
    mixed: "Mixed",
  };
  if (layer.effective_mode !== "unknown") return words[layer.effective_mode] ?? "Unknown";
  if (ARMED_MODES.includes(layer.desired_mode)) return `${words[layer.desired_mode]}, verifying`;
  if (layer.desired_mode !== "unknown") return words[layer.desired_mode] ?? "Unknown";
  return "Unknown";
}

/** Freshness as the user fact: when this control was last checked. The producer
 * budget is contract bookkeeping and lives in the disclosure only. */
export function checkedAgo(freshness: EvidenceFreshness): string {
  if (freshness.age_seconds === null) return "not checked yet";
  const secs = Math.max(0, freshness.age_seconds);
  if (secs < 90) return `checked ${secs}s ago`;
  if (secs < 5_400) return `checked ${Math.floor(secs / 60)}m ago`;
  if (secs < 172_800) return `checked ${Math.floor(secs / 3_600)}h ago`;
  return `checked ${Math.floor(secs / 86_400)}d ago`;
}

/** Scope as its display name only; kind and verification detail belong to the
 * disclosure, not to every summary row. */
export function scopeDisplay(scopes: ScopeRef[]): string {
  if (scopes.length === 0) return "No scope reported";
  return scopes.map((scope) => scope.display_name ?? scope.id).join("; ");
}

/** The full scope record, for the disclosure. */
export function scopeDetail(scopes: ScopeRef[]): string {
  if (scopes.length === 0) return "No effective scope reported";
  return scopes.map((scope) => `${scope.display_name ?? scope.id} (${scope.kind}; ${humanize(scope.verification)})`).join("; ");
}

/**
 * Which audience a coverage gap addresses.
 *
 * "operator": a control the user turned on is not doing what it says; there is
 * something to run or fix. These render amber, once, in the gaps section.
 *
 * "verification": the SYSTEM still owes its own proof chain (assurance-matrix
 * pinning, scope-membership evidence, producer timestamps). Nothing the
 * operator clicks resolves these; they render as quiet verification-pending
 * lines inside the owning control's disclosure, never as amber cards.
 */
export function gapAudience(gap: Pick<CoverageGap, "id" | "state">): "operator" | "verification" {
  if (/assurance|membership|temporal|scope-state/.test(gap.id)) return "verification";
  if (gap.state === "unknown" && !/effectiveness/.test(gap.id)) return "verification";
  return "operator";
}

export type ControlPill = {
  name: string;
  mode: string;
  scope: string;
  freshness: string;
  tone: "positive" | "attention" | "neutral";
  verified: boolean;
};

export function controlPill(
  layer: ProtectionLayer,
  bootstrap: DashboardBootstrap,
  generatedAt: string,
  current: boolean,
  evaluatedAt: string,
): ControlPill {
  const assurance = layerAssuranceLabel(
    layer,
    bootstrap.capabilities,
    bootstrap.assurance_matrix,
    generatedAt,
    bootstrap.generated_at,
    evaluatedAt,
    bootstrap.platform.os,
    current,
  );
  const operatorGaps = layer.known_gaps.filter((gap) => gapAudience(gap) === "operator");
  return {
    name: layer.label,
    mode: current ? plainMode(layer) : "Refreshing",
    scope: scopeDisplay(layer.effective_scope),
    freshness: current ? checkedAgo(layer.freshness) : "refreshing",
    tone: assurance.verifiedActive ? "positive" : operatorGaps.length > 0 ? "attention" : "neutral",
    verified: assurance.verifiedActive,
  };
}

/** The one-line verdict the screen leads with. */
export function postureHeadline(pills: ControlPill[]): string {
  const verified = pills.filter((pill) => pill.verified).length;
  return `${verified} of ${pills.length} host control${pills.length === 1 ? "" : "s"} verified active`;
}

/** The quiet line shown when no gap card needs to render. */
export function emptyGapsLine(totalGaps: number): string {
  return totalGaps === 0
    ? "No coverage gaps in this snapshot."
    : "No coverage gaps need attention in this snapshot.";
}

// ────────────────────────────────── screen ───────────────────────────────────

export function Posture({
  bootstrap,
  posture,
  current,
  evaluatedAt,
}: {
  bootstrap: DashboardBootstrap;
  posture: DashboardPosture;
  current: boolean;
  evaluatedAt: string;
}) {
  const pills = posture.layers.map((layer) => controlPill(layer, bootstrap, posture.generated_at, current, evaluatedAt));
  const operatorGaps = dedupeGaps(posture.gaps.filter((gap) => gapAudience(gap) === "operator"));

  return (
    <div className="space-y-8">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Protection posture</p>
        <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-950">Host controls</h2>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
          What is enforcing, what is watching, and where the gaps are.
        </p>
      </div>

      {posture.layers.length > 0 ? (
        <section aria-labelledby="posture-verdict-title" className="overflow-hidden rounded-2xl border border-slate-200 bg-gradient-to-br from-white to-slate-50">
          <div className="px-5 py-6 sm:px-7">
            <h3 id="posture-verdict-title" className="text-2xl font-semibold tracking-tight text-slate-950">
              {postureHeadline(pills)}
            </h3>
            <ul className="mt-4 flex flex-wrap gap-2" aria-label="Host controls">
              {pills.map((pill) => (
                <li
                  key={pill.name}
                  className={`inline-flex max-w-full items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${
                    pill.tone === "positive"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                      : pill.tone === "attention"
                        ? "border-amber-200 bg-amber-50 text-amber-900"
                        : "border-slate-200 bg-white text-slate-700"
                  }`}
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-70" aria-hidden="true" />
                  <span className="truncate">{pill.name}</span>
                  <span className="shrink-0 font-medium opacity-80">{pill.mode}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      ) : (
        <p className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm leading-6 text-slate-600">
          No host controls reported in this snapshot.
        </p>
      )}

      <section aria-labelledby="posture-controls-title">
        <h3 id="posture-controls-title" className="sr-only">Control details</h3>
        <div className="space-y-3">
          {posture.layers.map((layer) => (
            <ControlRow
              key={layer.id}
              layer={layer}
              bootstrap={bootstrap}
              generatedAt={posture.generated_at}
              current={current}
              evaluatedAt={evaluatedAt}
            />
          ))}
        </div>
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Host controls are evaluated from host evidence only; agent metadata never grants host trust.
        </p>
      </section>

      <section aria-labelledby="posture-gaps-title">
        <div className="mb-4">
          <h2 id="posture-gaps-title" className="text-xl font-semibold tracking-tight text-slate-950">Coverage gaps</h2>
        </div>
        {operatorGaps.length > 0 ? (
          <div className="space-y-3">{operatorGaps.map((gap) => <GapCard key={gap.id} gap={gap} />)}</div>
        ) : (
          <p className="text-sm leading-6 text-slate-600">{emptyGapsLine(posture.gaps.length)}</p>
        )}
      </section>
    </div>
  );
}

/** posture.gaps is the layers' known_gaps flattened by the producer, so a gap
 * must render once even if a future producer lists it twice. */
function dedupeGaps(gaps: CoverageGap[]): CoverageGap[] {
  const seen = new Set<string>();
  return gaps.filter((gap) => (seen.has(gap.id) ? false : (seen.add(gap.id), true)));
}

function ControlRow({
  layer,
  bootstrap,
  generatedAt,
  current,
  evaluatedAt,
}: {
  layer: ProtectionLayer;
  bootstrap: DashboardBootstrap;
  generatedAt: string;
  current: boolean;
  evaluatedAt: string;
}) {
  const assurance = layerAssuranceLabel(
    layer,
    bootstrap.capabilities,
    bootstrap.assurance_matrix,
    generatedAt,
    bootstrap.generated_at,
    evaluatedAt,
    bootstrap.platform.os,
    current,
  );
  const relevantCapabilities = layer.capability_ids
    .map((id) => bootstrap.capabilities.find((capability) => capability.id === id))
    .filter((capability): capability is CapabilityStatus => capability !== undefined);
  const verificationGaps = layer.known_gaps.filter((gap) => gapAudience(gap) === "verification");

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h3 className="min-w-0 flex-1 truncate text-base font-semibold text-slate-950">{layer.label}</h3>
        <StatusBadge
          status={current ? layer.effective_mode : "stale"}
          label={current ? plainMode(layer) : "Refreshing"}
          className="shrink-0"
        />
        <span className="[overflow-wrap:anywhere] text-sm text-slate-600">{scopeDisplay(layer.effective_scope)}</span>
        <span className="shrink-0 text-xs font-medium text-slate-500">{current ? checkedAgo(layer.freshness) : "refreshing"}</span>
      </div>

      <details className="mt-3 border-t border-slate-100 pt-3">
        <summary className="cursor-pointer text-xs font-semibold text-slate-500 hover:text-slate-700">How this was verified</summary>
        <div className="mt-3 space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status={current ? assurance.status : "stale"} label={current ? assurance.label : "Awaiting a current snapshot"} />
            <span className="text-xs text-slate-500">
              {layer.evidence.length} evidence record{layer.evidence.length === 1 ? "" : "s"} · freshness {humanize(layer.freshness.state)}
              {layer.freshness.age_seconds !== null ? `, ${layer.freshness.age_seconds}s old` : ""} · {layer.freshness.budget_seconds}s producer budget
            </span>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Runtime convergence</h4>
            <Convergence convergence={layer.convergence} current={current} />
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Effective scope</h4>
            <p className="mt-1 [overflow-wrap:anywhere] text-sm text-slate-700">{scopeDetail(layer.effective_scope)}</p>
            {layer.covered_action_classes.length > 0 ? (
              <p className="mt-1 text-xs text-slate-500">Covered actions: {layer.covered_action_classes.map(humanize).join(", ")}</p>
            ) : null}
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Declared capabilities</h4>
            {relevantCapabilities.length > 0 ? (
              <ul className="mt-2 space-y-2">
                {relevantCapabilities.map((capability) => (
                  <li key={capability.id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm">
                    <span className="[overflow-wrap:anywhere] font-medium text-slate-800">{humanize(capability.id)}</span>
                    <StatusBadge status={current ? capability.availability : "stale"} />
                  </li>
                ))}
              </ul>
            ) : <p className="mt-2 text-sm text-slate-600">No matching capability record was declared.</p>}
          </div>
          {verificationGaps.length > 0 ? (
            <ul className="space-y-1">
              {verificationGaps.map((gap) => (
                <li key={gap.id} className="text-xs leading-5 text-slate-500">Verification pending: {gap.next_step}</li>
              ))}
            </ul>
          ) : null}
        </div>
      </details>
    </article>
  );
}

function Convergence({ convergence, current }: { convergence: RuntimeConvergence; current: boolean }) {
  const stages = [
    ["Configured", convergence.configured],
    ["Loaded", convergence.loaded],
    ["Running", convergence.running],
    ["Enforcing", convergence.enforcing],
    ["Verified effective", convergence.verified_effective],
  ] as const;
  return (
    <ol className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
      {stages.map(([label, stage]) => (
        <li key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-2.5">
          <div className="text-[11px] font-semibold text-slate-600">{label}</div>
          <div className="mt-1"><StatusBadge status={current ? stage.state : "stale"} /></div>
          {stage.reason_code ? <div className="mt-1 [overflow-wrap:anywhere] text-[10px] text-slate-500">{humanize(stage.reason_code)}</div> : null}
        </li>
      ))}
    </ol>
  );
}

function GapCard({ gap }: { gap: CoverageGap }) {
  return (
    <article className="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <StatusBadge status={gap.state} />
          <h3 className="mt-2 [overflow-wrap:anywhere] font-semibold text-slate-950">{humanize(gap.capability_id)}</h3>
        </div>
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-800">{sentence(gap.next_step)}</p>
      <p className="mt-2 text-xs text-slate-600">
        {gap.action_classes.length > 0 ? `Affects ${gap.action_classes.map(humanize).join(", ").toLowerCase()}` : "Affected actions not reported"}
        {" · "}
        {scopeDisplay(gap.affected_scope)}
      </p>
    </article>
  );
}

function sentence(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  const capitalized = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(capitalized) ? capitalized : `${capitalized}.`;
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}
