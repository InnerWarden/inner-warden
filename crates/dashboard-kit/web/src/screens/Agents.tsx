import type { AgentInventory, AgentSubject, IdentityConfidence } from "../api/v1";
import { gridColumnsClass, gridSpanClass, joinClasses } from "../components/cardGrid";
import { StatusBadge } from "../components/StatusBadge";
import { TruncatedId } from "../components/TruncatedId";

// ─────────────────────────── guardrail liveness ──────────────────────────────
//
// Port of the producer's intent-vs-live rule (guardrail_liveness in the paid
// agent, and the shared-bundle downgrade that fixed the sixteen-days-of-zero
// "Already configured" card): a positive, present-tense mode may only be shown
// when a dated observation inside the budget backs it. A policy row is intent,
// not a running guardrail, and the absence of evidence is never promoted into
// the presence of one.

/** A dated observation older than this cannot be called "live". */
export const LIVE_OBSERVATION_MAX_AGE_SECS = 24 * 60 * 60;

export type GuardrailObservation = "observed" | "not_observed_recently" | "never_observed" | "unknown";

function parseTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

export function guardrailObservation(subject: AgentSubject, nowMs: number): GuardrailObservation {
  const observed = parseTime(subject.guardrail_last_observed_at);
  if (observed !== null) {
    const age = Math.floor((nowMs - observed) / 1000);
    // Closed at zero: a future-dated observation (clock skew, a writer we do
    // not control) is not evidence of anything.
    return age >= 0 && age <= LIVE_OBSERVATION_MAX_AGE_SECS ? "observed" : "not_observed_recently";
  }
  const activity = subject.guardrail_recorded_activity;
  if (activity === 0) return "never_observed";
  if (typeof activity === "number") return "not_observed_recently";
  return "unknown";
}

/** Coarse age in words; the point is the order of magnitude, not precision. */
export function humanAge(seconds: number): string {
  const secs = Math.max(0, seconds);
  if (secs < 90) return "less than a minute";
  if (secs < 5_400) return `${Math.floor(secs / 60)}m`;
  if (secs < 172_800) return `${Math.floor(secs / 3_600)}h`;
  return `${Math.floor(secs / 86_400)}d`;
}

function modeVerb(mode: string | null | undefined): string {
  switch ((mode ?? "").toLowerCase()) {
    case "block":
    case "enforce":
      return "Blocking risky actions";
    case "warn":
    case "monitor":
    case "observe":
      return "Screening actions";
    default:
      return "Guardrail active";
  }
}

function configuredClause(subject: AgentSubject, nowMs: number): string {
  const configured = parseTime(subject.guardrail_configured_at);
  if (configured === null) return "Configured";
  const age = Math.floor((nowMs - configured) / 1000);
  return age >= 0 ? `Configured ${humanAge(age)} ago` : "Configured";
}

/**
 * The ONE status line per card, and the only place a present-tense mode word
 * may appear. Positive wording requires observation "observed"; every other
 * state leads with "Configured", never with the mode's verb.
 */
export function guardrailStatusLine(subject: AgentSubject, nowMs: number): { text: string; observed: boolean } {
  if (!subject.guardrail_mode && subject.guardrail_configured_at == null && subject.guardrail_recorded_activity == null && subject.guardrail_last_observed_at == null) {
    return { text: "No guardrail recorded for this agent", observed: false };
  }
  const observation = guardrailObservation(subject, nowMs);
  const observedAt = parseTime(subject.guardrail_last_observed_at);
  switch (observation) {
    case "observed": {
      const age = humanAge(Math.floor((nowMs - (observedAt ?? nowMs)) / 1000));
      return { text: `${modeVerb(subject.guardrail_mode)}, last seen ${age} ago`, observed: true };
    }
    case "not_observed_recently": {
      if (observedAt !== null) {
        const age = Math.floor((nowMs - observedAt) / 1000);
        if (age >= 0) return { text: `${configuredClause(subject, nowMs)}, last seen ${humanAge(age)} ago`, observed: false };
      }
      return { text: `${configuredClause(subject, nowMs)}, activity recorded at an unknown time`, observed: false };
    }
    case "never_observed":
      return { text: `${configuredClause(subject, nowMs)}, never observed`, observed: false };
    default:
      return { text: `${configuredClause(subject, nowMs)}, no activity evidence`, observed: false };
  }
}

// ────────────────────────────── identity ─────────────────────────────────────

/** Card identity: the human product name leads; the registry id is the fallback. */
export function agentDisplay(agent: Pick<AgentSubject, "agent_id" | "product" | "provider" | "agent_class">): {
  heading: string;
  headingIsId: boolean;
  subtitle: string;
} {
  const product = agent.product?.trim();
  const provider = agent.provider?.trim();
  // An "unknown" class row would render a lone "Unknown" subtitle: a datum that
  // carries nothing. Rows render only when they carry data.
  const classLabel = agent.agent_class === "unknown" ? undefined : humanize(agent.agent_class);
  const parts = [provider, classLabel].filter((part): part is string => Boolean(part));
  return {
    heading: product && product.length > 0 ? product : agent.agent_id,
    headingIsId: !(product && product.length > 0),
    subtitle: parts.join(" · "),
  };
}

export const IDENTITY_TOOLTIP =
  "This identity is not host verified. Renaming, wrapping, self-registration or a familiar vendor label does not establish trust or protection.";

export function identityTooltip(confidence: IdentityConfidence): string | undefined {
  return confidence === "host_verified" ? undefined : IDENTITY_TOOLTIP;
}

// ─────────────────────────────── footnote ────────────────────────────────────

/**
 * The discovery-bounded truth, kept as a quiet footnote instead of a warning.
 * The old amber role="status" banner rendered on every load forever (the
 * producer always bounds discovery), which taught operators that amber means
 * nothing. The fact stays; the alarm does not.
 */
export function discoveryFootnote(limited: boolean): { kind: "footnote"; text: string } | null {
  if (!limited) return null;
  return {
    kind: "footnote",
    text: "Showing agents recorded by the local registry. An agent not listed here may still be running.",
  };
}

export const EMPTY_STATE = {
  title: "No agents connected yet.",
  action: "Run innerwarden agents connect to put a guardrail on an agent.",
  command: "innerwarden agents connect",
} as const;

// ──────────────────────────────── layout ─────────────────────────────────────
//
// An agent card carries a heading, a status line and up to three detail cells,
// so two across is the widest it reads well at. Everything else about the grid
// is the shared fill rule: the row the cards are given is the row they fill, at
// one agent as much as at five. Before this, one agent took half the page and
// the other half was an empty box.

export function agentsGridClass(count: number): string {
  return joinClasses("grid gap-4", gridColumnsClass("pair-lg", count));
}

export function agentsCardSpanClass(index: number, count: number): string {
  return gridSpanClass("pair-lg", index, count);
}

// ─────────────────────────────── screen ──────────────────────────────────────

export function Agents({ inventory, stale = false, nowMs }: { inventory: AgentInventory; stale?: boolean; nowMs?: number }) {
  const now = nowMs ?? Date.now();
  const footnote = discoveryFootnote(inventory.discovery_limited);
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Agents</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Connected agents</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Which agents are wired through the guardrail, and whether each guardrail has actually been seen running.
          </p>
        </div>
        <StatusBadge status={stale ? "stale" : inventory.availability} />
      </div>

      {inventory.subjects.length > 0 ? (
        <div className={agentsGridClass(inventory.subjects.length)}>
          {inventory.subjects.map((agent, index) => (
            <AgentCard
              key={agent.agent_id}
              agent={agent}
              stale={stale}
              nowMs={now}
              spanClass={agentsCardSpanClass(index, inventory.subjects.length)}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white px-5 py-10 text-center">
          <h2 className="font-semibold text-slate-900">{EMPTY_STATE.title}</h2>
          <p className="mx-auto mt-1 max-w-xl text-sm leading-6 text-slate-600">
            Run <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-800">{EMPTY_STATE.command}</code> to put a guardrail on an agent.
          </p>
        </div>
      )}

      {footnote ? <p className="text-xs leading-5 text-slate-500">{footnote.text}</p> : null}
    </div>
  );
}

function AgentCard({ agent, stale, nowMs, spanClass = "" }: { agent: AgentSubject; stale: boolean; nowMs: number; spanClass?: string }) {
  const display = agentDisplay(agent);
  const status = guardrailStatusLine(agent, nowMs);
  const tooltip = identityTooltip(agent.identity_confidence);
  const detailRows: Array<[string, string | null]> = [
    ["Principal", agent.principal],
    ["Runtime", agent.runtime],
    ["Model", agent.model],
  ];
  const presentRows = detailRows.filter((row): row is [string, string] => row[1] !== null && row[1] !== undefined);
  return (
    <article className={joinClasses("min-w-0 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", spanClass)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          {display.headingIsId ? (
            <h2 className="mt-0.5 text-lg font-semibold text-slate-950"><TruncatedId value={display.heading} labelClassName="text-slate-950 text-base" /></h2>
          ) : (
            <h2 className="[overflow-wrap:anywhere] text-lg font-semibold text-slate-950">{display.heading}</h2>
          )}
          {display.subtitle ? <p className="mt-0.5 text-xs font-medium text-slate-500">{display.subtitle}</p> : null}
        </div>
        <span title={tooltip} className="shrink-0">
          <StatusBadge status={stale ? "stale" : agent.identity_confidence} />
        </span>
      </div>

      <p className={`mt-4 border-t border-slate-100 pt-4 text-sm font-medium ${status.observed ? "text-emerald-800" : "text-slate-700"}`}>
        {status.text}
      </p>

      {presentRows.length > 0 ? (
        <dl className="mt-3 grid gap-3 sm:grid-cols-2">
          {presentRows.map(([label, value]) => (
            <div key={label}>
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
              <dd className="mt-1 [overflow-wrap:anywhere] text-sm font-medium text-slate-900">{value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </article>
  );
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
}
