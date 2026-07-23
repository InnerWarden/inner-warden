import type { TokenCounterSet, TokenIntelligence as TokenIntelligenceContract, TokenProviderUsage } from "../api/v1";
import { StatusBadge } from "../components/StatusBadge";

export function TokenIntelligence({ report, stale = false }: { report: TokenIntelligenceContract; stale?: boolean }) {
  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Agent layer · local resource visibility</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Token intelligence</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Numeric counters from supported retained local histories. They are observability data, not billing data or a security score.
          </p>
        </div>
        <StatusBadge status={stale ? "stale" : report.availability} />
      </header>

      <div className="rounded-xl border border-cyan-200 bg-cyan-50/70 px-4 py-3 text-xs leading-5 text-cyan-950">
        <strong className="font-semibold">Privacy boundary:</strong> this projection contains numeric counters and provenance only. It does not contain prompts, responses, tool content or secrets.
      </div>

      {report.totals ? <Totals counters={report.totals} /> : (
        <section className="rounded-2xl border border-dashed border-slate-300 bg-white px-5 py-10 text-center">
          <h2 className="font-semibold text-slate-900">No aggregate token history is available</h2>
          <p className="mx-auto mt-1 max-w-xl text-sm leading-6 text-slate-600">
            Missing or unsupported counters remain unavailable; the dashboard never substitutes zero or an estimate.
          </p>
        </section>
      )}

      {report.providers.length > 0 ? (
        <section aria-labelledby="token-providers-title">
          <div className="mb-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Independent sources</p>
            <h2 id="token-providers-title" className="mt-1 text-lg font-semibold text-slate-950">Usage by observed agent source</h2>
          </div>
          <ul className="grid gap-4 lg:grid-cols-3">
            {report.providers.map((provider) => <ProviderCard key={provider.agent_id} provider={provider} stale={stale} />)}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function Totals({ counters }: { counters: TokenCounterSet }) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm" aria-labelledby="token-totals-title">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Available local history</p>
      <h2 id="token-totals-title" className="mt-1 text-lg font-semibold text-slate-950">Observed totals</h2>
      <dl className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        <Counter label="Total" value={counters.total} primary />
        <Counter label="Input" value={counters.input} />
        <Counter label="Output" value={counters.output} />
        <Counter label="Cache read" value={counters.cache_read_input} />
        <Counter label="Cached input" value={counters.cached_input} />
        <Counter label="Cache creation" value={counters.cache_creation_input} />
        <Counter label="Reasoning output" value={counters.reasoning_output} />
      </dl>
    </section>
  );
}

function ProviderCard({ provider, stale }: { provider: TokenProviderUsage; stale: boolean }) {
  const hasCounters = Object.values(provider.counters).some((value) => value !== null);
  return (
    <li className="min-w-0 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-base font-semibold text-slate-950" title={provider.display_name}>{provider.display_name}</h3>
          <p className="mt-1 truncate text-xs text-slate-500" title={provider.agent_id}>{provider.agent_id}</p>
        </div>
        <StatusBadge status={stale ? "stale" : provider.availability} />
      </div>

      {hasCounters ? (
        <dl className="mt-4 grid grid-cols-2 gap-4 border-t border-slate-100 pt-4">
          <Counter label="Total" value={provider.counters.total} primary />
          <Counter label="Input" value={provider.counters.input} />
          <Counter label="Output" value={provider.counters.output} />
          <Counter label="Cache read" value={provider.counters.cache_read_input} />
          <Counter label="Sessions" value={provider.sessions} />
          <Counter label="Reasoning" value={provider.counters.reasoning_output} />
        </dl>
      ) : (
        <p className="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm leading-5 text-slate-600">
          No supported local counter is available for this source.
        </p>
      )}

      <div className="mt-4 border-t border-slate-100 pt-3 text-xs leading-5 text-slate-600">
        <p><span className="font-semibold text-slate-700">Provenance:</span> {humanize(provider.provenance.id)} · {humanize(provider.provenance.completeness)}</p>
        <p className="mt-1">Last observed: {formatTimestamp(provider.last_observed_at)}</p>
        {provider.note ? <p className="mt-1 text-slate-500">{provider.note}</p> : null}
      </div>
    </li>
  );
}

function Counter({ label, value, primary = false }: { label: string; value: string | null; primary?: boolean }) {
  const formatted = formatDecimal(value);
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={`${primary ? "text-xl" : "text-sm"} mt-1 truncate font-semibold tabular-nums ${value === null ? "text-slate-500" : "text-slate-950"}`} title={formatted}>
        {formatted}
      </dd>
    </div>
  );
}

function formatDecimal(value: string | null): string {
  if (value === null) return "Unavailable";
  return value.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatTimestamp(value: string | null): string {
  if (value === null) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}
