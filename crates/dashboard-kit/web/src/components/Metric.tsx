import type { Metric as MetricProjection } from "../api/v1";
import { StatusBadge } from "./StatusBadge";

function groupDecimal(value: string): string {
  return /^(0|[1-9][0-9]*)$/.test(value) ? value.replace(/\B(?=(\d{3})+(?!\d))/g, ",") : value;
}

export function formatMetricValue(metric: Pick<MetricProjection, "availability" | "value" | "unit">): string {
  if (metric.value === null) return metric.availability.replaceAll("_", " ");
  const value = typeof metric.value === "string"
    ? groupDecimal(metric.value)
    : typeof metric.value === "number"
      ? new Intl.NumberFormat(undefined, { maximumFractionDigits: 4 }).format(metric.value)
      : metric.value ? "Yes" : "No";
  return metric.unit ? `${value} ${metric.unit}` : value;
}

function formatTime(value: string | null): string {
  if (value === null) return "Not reported";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function sourceLabel(metric: MetricProjection): string {
  if (metric.source === null) return "No source reported for this unavailable value";
  return `${metric.source.id} · ${metric.source.authority} · ${metric.source.completeness}`;
}

function scopeLabel(metric: MetricProjection): string {
  if (metric.scope.length === 0) return "No scope reported";
  return metric.scope.map((scope) => `${scope.display_name ?? scope.id} (${scope.kind}, ${scope.verification})`).join("; ");
}

export function Metric({ metric }: { metric: MetricProjection }) {
  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm" aria-labelledby={`metric-${metric.metric_id}`}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Metric</p>
          <h3 id={`metric-${metric.metric_id}`} className="mt-1 [overflow-wrap:anywhere] text-base font-semibold text-slate-950">{metric.metric_id}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-600">{metric.definition}</p>
        </div>
        <StatusBadge status={metric.availability} />
      </div>

      <div className="mt-5 border-y border-slate-100 py-4">
        <div className="[overflow-wrap:anywhere] text-2xl font-semibold tabular-nums text-slate-950">{formatMetricValue(metric)}</div>
        <div className="mt-1 text-xs text-slate-500">Generated {formatTime(metric.generated_at)}</div>
      </div>

      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
        <Datum label="Source" value={sourceLabel(metric)} />
        <Datum label="Scope" value={scopeLabel(metric)} />
        <Datum label="Window" value={`${formatTime(metric.window.started_at)} → ${formatTime(metric.window.ended_at)}`} />
        <Datum
          label="Freshness"
          value={`${metric.freshness.state}; age ${metric.freshness.age_seconds ?? "unknown"}s / budget ${metric.freshness.budget_seconds}s`}
        />
        <Datum label="Denominator" value={metric.denominator ?? "Not applicable or not reported"} />
        <Datum label="Reconciliation" value={metric.reconciliation.replaceAll("_", " ")} />
      </dl>

      <div className="mt-4 border-t border-slate-100 pt-4 text-xs text-slate-600">
        {metric.claim_ref ? (
          <a className="font-semibold text-cyan-800 hover:text-cyan-950" href={`#claim-${encodeURIComponent(metric.claim_ref)}`}>
            Claim record: {metric.claim_ref}
          </a>
        ) : (
          <span>Not used for a product claim in this projection.</span>
        )}
        <span className="ml-3">{metric.evidence.length} evidence record{metric.evidence.length === 1 ? "" : "s"}</span>
      </div>
    </article>
  );
}

function Datum({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 [overflow-wrap:anywhere] text-slate-800">{value}</dd>
    </div>
  );
}
