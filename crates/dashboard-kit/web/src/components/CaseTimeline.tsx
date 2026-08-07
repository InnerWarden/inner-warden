import type { CaseEvent, CaseEventType, RelationshipConfidence } from "../api/cases";
import { StatusBadge } from "./StatusBadge";
import { friendlyId } from "./TruncatedId";

const eventLabels: Record<CaseEventType, string> = {
  agent_intent: "Agent intent",
  host_observation: "Host observation",
  signal: "Security signal",
  incident: "Incident",
  recommendation: "Recommendation",
  policy_decision: "Policy decision",
  enforcement_attempt: "Enforcement attempt",
  verification: "Runtime verification",
  operator_action: "Operator action",
  feedback: "Analyst feedback",
  evidence_gap: "Evidence gap",
};

const relationshipLabels: Record<RelationshipConfidence, string> = {
  causal: "Causal",
  strongly_supported: "Strongly supported",
  contextual: "Contextual",
  unknown: "Unknown relationship",
};

export function evidenceDomId(id: string): string {
  let encoded = "";
  for (const character of new TextEncoder().encode(id)) encoded += character.toString(16).padStart(2, "0");
  return `evidence-${encoded || "unknown"}`;
}

export function CaseTimeline({ events }: { events: CaseEvent[] }) {
  if (events.length === 0) {
    return (
      <section aria-labelledby="case-timeline-title" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 id="case-timeline-title" className="text-base font-semibold text-slate-950">Evidence timeline</h2>
        <div className="mt-4 rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-600">
          No timeline events were reported. Intent, decision, enforcement and outcome remain unknown.
        </div>
      </section>
    );
  }

  return (
    <section aria-labelledby="case-timeline-title" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Ordered evidence</p>
          <h2 id="case-timeline-title" className="mt-1 text-base font-semibold text-slate-950">Evidence timeline</h2>
        </div>
        <p className="max-w-md text-xs leading-5 text-slate-500">Events remain separately typed. Their order does not make a contextual relationship causal.</p>
      </div>
      <ol className="mt-5 space-y-0">
        {events.map((event, index) => (
          <li key={event.id} className="relative grid grid-cols-[2rem_minmax(0,1fr)] gap-3 pb-5 last:pb-0">
            {index < events.length - 1 && <span aria-hidden="true" className="absolute bottom-0 left-[0.94rem] top-8 w-px bg-slate-200" />}
            <span aria-hidden="true" className="relative z-10 flex h-8 w-8 items-center justify-center rounded-full border border-slate-300 bg-white text-xs font-semibold tabular-nums text-slate-700">{index + 1}</span>
            <article className="min-w-0 rounded-xl border border-slate-200 bg-slate-50/70 p-4" data-event-type={event.event_type}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="font-semibold text-slate-950">{eventLabels[event.event_type]}</h3>
                  <p className="mt-0.5 text-xs text-slate-500"><time dateTime={event.observed_at}>{formatTime(event.observed_at)}</time></p>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <StatusBadge
                    status={event.relationship === "causal" ? "available" : event.relationship === "strongly_supported" ? "degraded" : "unknown"}
                    label={relationshipLabels[event.relationship]}
                  />
                  {event.mode && <StatusBadge status={event.mode === "enforce" ? "degraded" : "unknown"} label={`${event.mode} mode`} />}
                </div>
              </div>
              <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-800 [overflow-wrap:anywhere]">{event.summary}</p>
              {event.relationship === "contextual" && <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">Context only: this record does not establish causation.</p>}
              {event.relationship === "unknown" && <p className="mt-3 rounded-lg bg-slate-100 px-3 py-2 text-xs leading-5 text-slate-700">The relationship to adjacent events is unknown.</p>}
              <dl className="mt-3 grid gap-2 border-t border-slate-200 pt-3 text-xs sm:grid-cols-2">
                <div><dt className="text-slate-500">Authority</dt><dd className="mt-0.5 break-words font-medium text-slate-800 [overflow-wrap:anywhere]">{event.authority ?? "Unknown"}</dd></div>
                <div><dt className="text-slate-500">Recorded</dt><dd className="mt-0.5 font-medium text-slate-800"><time dateTime={event.recorded_at}>{formatTime(event.recorded_at)}</time></dd></div>
              </dl>
              <EvidenceLinks evidence={event.source_refs} />
            </article>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function EvidenceLinks({ evidence }: { evidence: CaseEvent["source_refs"] }) {
  if (evidence.length === 0) return <p className="mt-3 text-xs font-medium text-slate-500">Evidence: unknown</p>;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2" aria-label="Event evidence links">
      <span className="text-xs text-slate-500">Evidence:</span>
      {evidence.map((entry) => {
        const id = friendlyId(entry.id);
        return (
          <a key={entry.id} href={`#${evidenceDomId(entry.id)}`} title={id.full} className="inline-flex max-w-full items-center gap-1 rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 font-mono text-xs font-semibold text-cyan-900 hover:bg-cyan-100 focus:outline-none focus:ring-2 focus:ring-cyan-700">
            <span className="truncate">{id.label}</span>
            {id.short && <span className="shrink-0 text-cyan-500">· {id.short}</span>}
          </a>
        );
      })}
    </div>
  );
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(new Date(value));
}
