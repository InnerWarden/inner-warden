import type {
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
} from "../api/v1";
import { StatusBadge } from "../components/StatusBadge";
import { layerAssuranceLabel } from "../posture/assurance";

type LayerBoundary = "agent" | "host";

export function classifyProtectionLayer(
  layer: ProtectionLayer,
  capabilities: CapabilityStatus[],
): LayerBoundary {
  const declared = layer.capability_ids
    .map((id) => capabilities.find((capability) => capability.id === id))
    .filter((capability): capability is CapabilityStatus => capability !== undefined);
  if (declared.length > 0 && declared.every((capability) => capability.tier === "community")) return "agent";
  if (declared.some((capability) => capability.tier === "enterprise_core")) return "host";
  return layer.id === "agent_layer" ? "agent" : "host";
}

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
  const agentLayers = posture.layers.filter((layer) => classifyProtectionLayer(layer, bootstrap.capabilities) === "agent");
  const hostLayers = posture.layers.filter((layer) => classifyProtectionLayer(layer, bootstrap.capabilities) === "host");

  return (
    <div className="space-y-8">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Protection posture</p>
        <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-950">Agent and host boundaries</h2>
        <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
          Effective mode, verified scope, producer freshness and known gaps stay separate. Agent metadata never grants host trust.
        </p>
      </div>

      <LayerSection
        id="agent-layer"
        eyebrow="Agent layer"
        title="Agent-boundary controls"
        description="Hooks, MCP mediation and related Community capabilities apply only to their evidenced interception surfaces."
        emptyTitle="Agent-layer posture not reported"
        emptyBody="This Enterprise adapter did not provide an agent-layer projection. Community data is not copied or relabelled as Enterprise evidence."
        layers={agentLayers}
        bootstrap={bootstrap}
        generatedAt={posture.generated_at}
        current={current}
        evaluatedAt={evaluatedAt}
      />

      <LayerSection
        id="host-layer"
        eyebrow="Host layer"
        title="Independent host controls"
        description="Host visibility and enforcement are evaluated independently of agent names, prompts, hooks or model cooperation."
        emptyTitle="Host-layer posture not reported"
        emptyBody="No host-layer adapter was present in this validated response. No independent host protection is implied."
        layers={hostLayers}
        bootstrap={bootstrap}
        generatedAt={posture.generated_at}
        current={current}
        evaluatedAt={evaluatedAt}
      />

      <section aria-labelledby="posture-gaps-title">
        <div className="mb-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Coverage gaps</p>
          <h2 id="posture-gaps-title" className="mt-1 text-xl font-semibold tracking-tight text-slate-950">Known limits in this snapshot</h2>
          <p className="mt-1 text-sm text-slate-600">Every gap retains its affected actions, scope and recorded next step.</p>
        </div>
        {posture.gaps.length > 0 ? (
          <div className="space-y-3">{posture.gaps.map((gap) => <GapCard key={gap.id} gap={gap} />)}</div>
        ) : (
          <EmptyState
            title="No gaps reported by this adapter"
            body="An empty gap list is not a universal coverage claim. Review each layer's scope, action classes and freshness."
          />
        )}
      </section>
    </div>
  );
}

function LayerSection({
  id,
  eyebrow,
  title,
  description,
  emptyTitle,
  emptyBody,
  layers,
  bootstrap,
  generatedAt,
  current,
  evaluatedAt,
}: {
  id: string;
  eyebrow: string;
  title: string;
  description: string;
  emptyTitle: string;
  emptyBody: string;
  layers: ProtectionLayer[];
  bootstrap: DashboardBootstrap;
  generatedAt: string;
  current: boolean;
  evaluatedAt: string;
}) {
  return (
    <section aria-labelledby={`${id}-title`}>
      <div className="mb-4">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">{eyebrow}</p>
        <h2 id={`${id}-title`} className="mt-1 text-xl font-semibold tracking-tight text-slate-950">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm text-slate-600">{description}</p>
      </div>
      {layers.length > 0 ? (
        <div className="space-y-4">
          {layers.map((layer) => (
            <LayerCard
              key={layer.id}
              layer={layer}
              bootstrap={bootstrap}
              generatedAt={generatedAt}
              current={current}
              evaluatedAt={evaluatedAt}
            />
          ))}
        </div>
      ) : <EmptyState title={emptyTitle} body={emptyBody} />}
    </section>
  );
}

function LayerCard({
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

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="[overflow-wrap:anywhere] text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{humanize(layer.id)}</p>
          <h3 className="mt-1 text-lg font-semibold text-slate-950">{layer.label}</h3>
        </div>
        <StatusBadge status={current ? assurance.status : "stale"} label={current ? assurance.label : "Snapshot not current"} className="shrink-0" />
      </div>

      <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 lg:grid-cols-4">
        <Datum label="Effective mode" value={current ? layerModeText(layer) : "Withheld; snapshot not current"} status={current ? layer.effective_mode : "stale"} />
        <Datum label="Freshness" value={freshnessText(layer)} status={current ? layer.freshness.state : "stale"} />
        <Datum label="Effective scope" value={scopeSummary(layer.effective_scope)} />
        <Datum label="Covered actions" value={layer.covered_action_classes.length > 0 ? layer.covered_action_classes.map(humanize).join(", ") : "None reported"} />
      </dl>

      <div className="mt-5 space-y-6 border-t border-slate-100 pt-5">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Runtime convergence</h4>
          <Convergence convergence={layer.convergence} current={current} />
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
      </div>

      {layer.known_gaps.length > 0 ? (
        <div className="mt-5 border-t border-slate-100 pt-5">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Layer gaps</h4>
          <div className="mt-2 space-y-2">{layer.known_gaps.map((gap) => <GapCard key={gap.id} gap={gap} compact />)}</div>
        </div>
      ) : null}
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

function Datum({ label, value, status }: { label: string; value: string; status?: string }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 [overflow-wrap:anywhere] text-sm font-semibold text-slate-900">
        {status ? <StatusBadge status={status} label={value} /> : value}
      </dd>
    </div>
  );
}

function GapCard({ gap, compact = false }: { gap: CoverageGap; compact?: boolean }) {
  return (
    <article className={`rounded-xl border border-amber-200 bg-amber-50/60 ${compact ? "p-3" : "p-4"}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <StatusBadge status={gap.state} />
          <h3 className="mt-2 [overflow-wrap:anywhere] font-semibold text-slate-950">{humanize(gap.capability_id)}</h3>
        </div>
        <span className="text-xs font-medium text-slate-500">{gap.evidence.length} evidence record{gap.evidence.length === 1 ? "" : "s"}</span>
      </div>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <Datum label="Affected actions" value={gap.action_classes.length > 0 ? gap.action_classes.map(humanize).join(", ") : "Not reported"} />
        <Datum label="Affected scope" value={scopeSummary(gap.affected_scope)} />
      </dl>
      <p className="mt-3 border-t border-amber-200/80 pt-3 text-sm text-slate-700"><span className="font-semibold">Recorded next step:</span> {gap.next_step}</p>
    </article>
  );
}

function scopeSummary(scopes: ScopeRef[]): string {
  if (scopes.length === 0) return "No effective scope reported";
  return scopes.map((scope) => `${scope.display_name ?? scope.id} (${scope.kind}; ${humanize(scope.verification)})`).join("; ");
}

function freshnessText(layer: ProtectionLayer): string {
  const age = layer.freshness.age_seconds === null ? "age unknown" : `${layer.freshness.age_seconds}s old`;
  return `${humanize(layer.freshness.state)}; ${age}; ${layer.freshness.budget_seconds}s budget`;
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}

// When a layer reads a definite armed mode (desired_mode) but active
// containment is not yet fully verified, effective_mode stays "unknown" by
// design. Reveal the armed intent in the label ("Enforce · verifying") while
// the badge colour still reflects the honest, unverified effective mode.
const ARMED_MODES = ["enforce", "observe", "rehearse"];
function layerModeText(layer: ProtectionLayer): string {
  if (layer.effective_mode !== "unknown") return humanize(layer.effective_mode);
  if (ARMED_MODES.includes(layer.desired_mode)) return `${humanize(layer.desired_mode)} · verifying`;
  if (layer.desired_mode !== "unknown") return humanize(layer.desired_mode);
  return humanize(layer.effective_mode);
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 bg-white px-5 py-8 text-center">
      <h3 className="font-semibold text-slate-900">{title}</h3>
      <p className="mx-auto mt-1 max-w-2xl text-sm leading-6 text-slate-600">{body}</p>
    </div>
  );
}
