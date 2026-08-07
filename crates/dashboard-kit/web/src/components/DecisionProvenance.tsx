import type { CaseEvent, FeedbackRecord } from "../api/cases";
import { EvidenceLinks } from "./CaseTimeline";
import { StatusBadge } from "./StatusBadge";

const decisionTypes = new Set(["recommendation", "policy_decision", "operator_action"]);

export function DecisionProvenance({ events, feedback }: { events: CaseEvent[]; feedback: FeedbackRecord[] }) {
  const decisions = events.filter((event) => decisionTypes.has(event.event_type));
  return (
    <section aria-labelledby="decision-provenance-title" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Decision record</p>
          <h2 id="decision-provenance-title" className="mt-1 text-base font-semibold text-slate-950">Who decided what</h2>
        </div>
      </div>

      {decisions.length === 0 ? (
        <div className="mt-4 rounded-xl border border-dashed border-slate-300 px-4 py-5 text-sm text-slate-600">Nobody and nothing is recorded as having decided anything about this case.</div>
      ) : (
        <div className="mt-4 space-y-3">
          {decisions.map((event) => {
            const fallback = event.source_refs.filter((entry) => entry.source.authority === "fallback");
            const uncertain = event.relationship === "unknown" || event.relationship === "contextual"
              || event.source_refs.length === 0
              || event.source_refs.some((entry) => entry.source.completeness !== "complete" || entry.freshness.state !== "fresh" || entry.integrity === "unknown" || entry.integrity === "unverified");
            return (
              <article key={event.id} className="rounded-xl border border-slate-200 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="break-words font-semibold text-slate-950 [overflow-wrap:anywhere]">{event.authority ?? "Authority unknown"}</p>
                    <p className="mt-0.5 text-xs text-slate-500">{event.event_type.replaceAll("_", " ")} · {event.mode ?? "mode unknown"}</p>
                  </div>
                  <StatusBadge status={uncertain ? "unknown" : "available"} label={uncertain ? "Uncertainty present" : "Current source record"} />
                </div>
                <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{event.summary}</p>
                {/* Four cells of source bookkeeping used to render under every
                    decision on every case: versions, fallback ids, the
                    relationship word the badge already carries, and a
                    semicolon-joined uncertainty string. The badge above says
                    whether there IS uncertainty, which is the part an operator
                    reads; the rest is one click away for whoever needs it. */}
                <details className="mt-3">
                  <summary className="cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-700">Where this came from</summary>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    <ProvenanceFact label="Versions" value={versions(event)} />
                    <ProvenanceFact label="Fallback" value={fallback.length > 0 ? fallback.map((entry) => entry.source.id).join(", ") : "Not reported"} />
                    <ProvenanceFact label="Relationship" value={event.relationship.replaceAll("_", " ")} />
                    <ProvenanceFact label="Uncertainty" value={uncertainty(event)} />
                  </div>
                  {event.source_refs.some((entry) => entry.source.limitations.length > 0) && (
                    <p className="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
                      <strong>Source limitations:</strong> {event.source_refs.flatMap((entry) => entry.source.limitations).join(" · ")}
                    </p>
                  )}
                </details>
                <EvidenceLinks evidence={event.source_refs} />
              </article>
            );
          })}
        </div>
      )}

      <div className="mt-5 border-t border-slate-200 pt-5">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h3 className="font-semibold text-slate-950">Analyst feedback</h3>
          <StatusBadge status="observed_only" label="Read only" />
        </div>
        {/* Was: "Feedback writes remain unavailable until the reviewed action
            API exists." Our roadmap is not the user's business; what it means
            for them is that reading this screen changes nothing. */}
        <p className="mt-1 text-xs leading-5 text-slate-500">Nothing on this screen changes a rule, an allowlist or a policy.</p>
        {feedback.length === 0 ? (
          <p className="mt-3 rounded-lg bg-slate-50 px-3 py-3 text-sm text-slate-600">No analyst has left a note on this case.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {feedback.map((record) => (
              <li key={record.id} className="rounded-lg border border-slate-200 px-3 py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-slate-900">{record.finding_type.replaceAll("_", " ")}</p>
                  <StatusBadge status={record.status === "resolved" ? "available" : "unknown"} label={record.status.replaceAll("_", " ")} />
                </div>
                <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{record.reason || "Reason was not supplied by the producer."}</p>
                <p className="mt-2 break-all text-xs text-slate-500">Actor: {record.actor_id}</p>
                <EvidenceLinks evidence={record.evidence} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function ProvenanceFact({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 rounded-lg bg-slate-50 px-3 py-2 text-xs"><p className="text-slate-500">{label}</p><p className="mt-0.5 break-words font-semibold text-slate-800 [overflow-wrap:anywhere]">{value}</p></div>;
}

function versions(event: CaseEvent): string {
  const found = [...new Set(event.source_refs.map((entry) => entry.source.version).filter((version): version is string => version !== null && version.length > 0))];
  return found.length > 0 ? found.join(", ") : "Not reported";
}

function uncertainty(event: CaseEvent): string {
  const descriptions = new Set<string>();
  if (event.relationship === "contextual") descriptions.add("context is not causal");
  if (event.relationship === "unknown") descriptions.add("relationship unknown");
  if (event.source_refs.length === 0) descriptions.add("supporting evidence missing");
  for (const evidence of event.source_refs) {
    if (evidence.source.completeness !== "complete") descriptions.add(`${evidence.source.id} is ${evidence.source.completeness}`);
    if (evidence.freshness.state !== "fresh") descriptions.add(`${evidence.id} is ${evidence.freshness.state}`);
    if (evidence.integrity !== "verified" && evidence.integrity !== "local_chain") descriptions.add(`${evidence.id} integrity ${evidence.integrity}`);
  }
  return descriptions.size > 0 ? [...descriptions].join("; ") : "No uncertainty reported by current sources";
}
