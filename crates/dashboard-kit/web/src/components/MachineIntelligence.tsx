import { useEffect, useState, type ReactNode } from "react";
import {
  fetchAgents,
  fetchTokenIntelligence,
  type AgentsResponse,
  type LocalAgent,
  type TokenAgent,
  type TokenIntelligenceResponse,
} from "../api";

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

export function MachineIntelligence() {
  const agents = usePollingResource(fetchAgents, 30_000, agentsAreLoading);
  const tokens = usePollingResource(fetchTokenIntelligence, 60_000, tokensAreLoading);

  return (
    <div className="space-y-6">
      <AgentsPanel state={agents} />
      <TokenPanel state={tokens} />
    </div>
  );
}

function usePollingResource<T>(load: () => Promise<T>, intervalMs: number, retrySoon: (data: T) => boolean): PollState<T> {
  const [state, setState] = useState<PollState<T>>(INITIAL_POLL_STATE);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let timer: number | undefined;

    const refresh = () => {
      if (inFlight) return;
      inFlight = true;
      let nextDelay = intervalMs;
      setState((current) => ({
        ...current,
        loading: current.data == null,
        refreshing: current.data != null,
      }));
      load()
        .then((data) => {
          if (!active) return;
          nextDelay = retrySoon(data) ? 750 : intervalMs;
          setState({ data, error: false, loading: false, refreshing: false });
        })
        .catch(() => {
          if (!active) return;
          nextDelay = Math.min(intervalMs, 5_000);
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

function AgentsPanel({ state }: { state: PollState<AgentsResponse> }) {
  const { data, error, loading } = state;
  const scanning = loading || data?.availability === "loading";
  const autoConnectKnown = data?.auto_connect.status === "available"
    && data.auto_connect.enabled != null
    && data.auto_connect.mode != null;
  return (
    <section aria-labelledby="local-agents-title" aria-busy={scanning}>
      <SectionHeading
        eyebrow="Community visibility"
        title="Agents on this machine"
        description="Local detection and guardrail setup are shown as separate signals, so presence is never presented as proof of active protection."
        aside={data ? <GeneratedAt value={data.generated_at_ms} /> : undefined}
      />
      {error && data && <StaleNotice />}
      {scanning ? (
        <PanelSkeleton cards={3} label="Loading locally detected agents" />
      ) : data ? (
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-col gap-2 border-b border-slate-100 bg-slate-50/70 px-4 py-3 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between sm:px-5">
            <span>
              Automatic setup is <strong className="font-semibold text-slate-800">{!autoConnectKnown ? "unavailable" : data.auto_connect.enabled ? "enabled" : "disabled"}</strong>
              {autoConnectKnown && data.auto_connect.enabled ? ` in ${humanise(data.auto_connect.mode!)} mode` : ""}.
            </span>
            <span className="tabular-nums">
              {!autoConnectKnown
                ? "Check policy with the CLI"
                : data.auto_connect.enabled
                ? `Checks every ${formatInterval(data.auto_connect.refresh_interval_secs)}`
                : "Enable from setup or the CLI"}
            </span>
          </div>
          {data.discovery_limited && (
            <div className="border-b border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-5 text-amber-950 sm:px-5" role="status">
              Agent discovery reached its local safety limit. Reviewed integrations remain visible, but some generic MCP configurations may be omitted to keep the dashboard responsive.
            </div>
          )}
          {data.agents.length === 0 ? (
            <EmptyPanel title="No compatible agents detected" body="Install or launch an agent, or configure a standard MCP client, then keep the InnerWarden dashboard process running while it checks again." />
          ) : (
            <ul className="grid gap-px bg-slate-200 md:grid-cols-2">
              {data.agents.map((agent) => <AgentCard key={agent.id} agent={agent} />)}
            </ul>
          )}
        </div>
      ) : (
        <UnavailablePanel title="Agent detection is unavailable" body="The local endpoint did not respond. InnerWarden will keep trying; automatic setup continues to follow the policy shown when the endpoint is available." />
      )}
    </section>
  );
}

function AgentCard({ agent }: { agent: LocalAgent }) {
  const running = runningStatus(agent.running);
  const guardrail = statusTone(agent.guardrail.mode);
  return (
    <li className="min-w-0 bg-white p-4 sm:p-5">
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

      <dl className="mt-4 grid grid-cols-1 gap-3 text-xs min-[380px]:grid-cols-2">
        <Detail label="Configured mode">
          <span className={`font-semibold ${guardrail}`}>{humanise(agent.guardrail.mode)}</span>
        </Detail>
        <Detail label="Setup support">{humanise(agent.guardrail.setup_support)}</Detail>
        <Detail label="Mechanism">{agent.guardrail.mechanism ? humanise(agent.guardrail.mechanism) : "Not available"}</Detail>
        <Detail label="Automatic setup">
          {agent.guardrail.mode === "partial"
            ? "Manual review required"
            : agent.guardrail.mode !== "not_configured"
            ? "Already configured"
            : agent.auto_connect_eligible == null
              ? "Eligibility unavailable"
              : agent.auto_connect_eligible
              ? "Eligible when enabled"
              : agent.guardrail.setup_support === "manual"
                ? "Manual setup"
                : agent.guardrail.setup_support === "unsupported"
                  ? "Not available"
                  : "Not eligible automatically"}
        </Detail>
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
        description="Available local history helps explain agent activity and context pressure without turning usage into a security score."
        aside={data ? <AvailabilityBadge value={data.availability} /> : undefined}
      />

      <div className="mb-3 rounded-xl border border-cyan-200 bg-cyan-50/70 px-4 py-3 text-xs leading-5 text-cyan-950">
        <strong className="font-semibold">Privacy by design:</strong> this view receives numeric counters only, not prompts, responses or tool content. Counts come from available local history and are not billing data.
      </div>
      {error && data && <StaleNotice />}
      {loading && !data ? (
        <PanelSkeleton cards={3} label="Loading token intelligence" lgColumns={3} />
      ) : data ? (
        data.agents.length === 0 ? (
          <EmptyPanel title="No local token history available" body="A missing counter is shown as unavailable, never as zero. Supported local history will appear after a later check." />
        ) : (
          <ul className="grid gap-3 lg:grid-cols-3">
            {data.agents.map((agent) => <TokenCard key={agent.agent_id} agent={agent} />)}
          </ul>
        )
      ) : (
        <UnavailablePanel title="Token intelligence is unavailable" body="The local endpoint did not respond. No usage value is being inferred from the missing response." />
      )}
    </section>
  );
}

function TokenCard({ agent }: { agent: TokenAgent }) {
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
    <li className="min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
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

function statusTone(mode: string): string {
  const value = mode.toLowerCase();
  if (value === "enforce") return "text-blue-700";
  if (value === "monitor") return "text-blue-700";
  if (value.includes("partial") || value.includes("mixed")) return "text-amber-700";
  return "text-slate-700";
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
