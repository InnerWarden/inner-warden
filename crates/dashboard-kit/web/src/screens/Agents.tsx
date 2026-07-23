import type { AgentInventory, AgentSubject, IdentityConfidence } from "../api/v1";
import { StatusBadge } from "../components/StatusBadge";

export function agentIdentitySummary(agent: Pick<AgentSubject, "agent_id" | "product" | "provider" | "identity_confidence">): {
  heading: string;
  product: string;
  provider: string;
  confidence: IdentityConfidence;
} {
  return {
    heading: `Observed agent ${agent.agent_id}`,
    product: agent.product ?? "Not reported",
    provider: agent.provider ?? "Not reported",
    confidence: agent.identity_confidence,
  };
}

export function Agents({ inventory, stale = false }: { inventory: AgentInventory; stale?: boolean }) {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Agent subjects</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Evidence-based agent inventory</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Product and provider fields are descriptive metadata. Discovery, identity, integration, token visibility and protection remain independent.
          </p>
        </div>
        <StatusBadge status={stale ? "stale" : inventory.availability} />
      </div>

      {inventory.discovery_limited ? (
        <div role="status" className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-950">
          <span className="font-semibold">Discovery is limited.</span> Subjects outside the current evidence sources may be absent; absence is not proof that no agent is running.
        </div>
      ) : null}

      {inventory.subjects.length > 0 ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {inventory.subjects.map((agent) => <AgentCard key={agent.agent_id} agent={agent} stale={stale} />)}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white px-5 py-10 text-center">
          <h2 className="font-semibold text-slate-900">No agent subjects reported</h2>
          <p className="mx-auto mt-1 max-w-xl text-sm leading-6 text-slate-600">
            This response contains no subjects. No vendor, trust, connection, token support or protection state is inferred.
          </p>
        </div>
      )}
    </div>
  );
}

function AgentCard({ agent, stale }: { agent: AgentSubject; stale: boolean }) {
  const identity = agentIdentitySummary(agent);
  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{humanize(agent.agent_class)}</p>
          <h2 className="mt-1 [overflow-wrap:anywhere] text-lg font-semibold text-slate-950">{identity.heading}</h2>
        </div>
        <StatusBadge status={stale ? "stale" : identity.confidence} />
      </div>

      <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2">
        <Datum label="Reported product" value={identity.product} />
        <Datum label="Reported provider" value={identity.provider} />
        <Datum label="Principal" value={agent.principal ?? "Not attributed"} />
        <Datum label="Runtime" value={agent.runtime ?? "Not reported"} />
        <Datum label="Model" value={agent.model ?? "Not reported"} />
        <Datum label="Sessions attributed" value={agent.sessions.length.toString()} />
      </dl>

      <div className="mt-5 border-t border-slate-100 pt-5">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Independent capabilities</h3>
          <span className="text-xs text-slate-500">{agent.identity_evidence.length} identity evidence record{agent.identity_evidence.length === 1 ? "" : "s"}</span>
        </div>
        {agent.capabilities.length > 0 ? (
          <ul className="mt-3 grid gap-2 sm:grid-cols-2">
            {agent.capabilities.map((capability) => (
              <li key={capability.capability} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="[overflow-wrap:anywhere] text-sm font-semibold text-slate-800">{humanize(capability.capability)}</span>
                  <StatusBadge status={stale ? "stale" : capability.availability} />
                </div>
                <p className="mt-2 text-xs text-slate-600">
                  Support: {humanize(capability.support)} · Evidence: {capability.evidence.length} · Observed: {formatTime(capability.observed_at)}
                </p>
                {capability.limitations.length > 0 ? (
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-600">
                    {capability.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
                  </ul>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-slate-600">No capability state was reported. The subject name does not fill these values.</p>
        )}
      </div>

      {identity.confidence !== "host_verified" ? (
        <p className="mt-5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600">
          This identity is not host verified. Renaming, wrapping, self-registration or a familiar vendor label does not establish trust or protection.
        </p>
      ) : null}
    </article>
  );
}

function Datum({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 [overflow-wrap:anywhere] text-sm font-medium text-slate-900">{value}</dd>
    </div>
  );
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}

function formatTime(value: string | null): string {
  if (value === null) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
