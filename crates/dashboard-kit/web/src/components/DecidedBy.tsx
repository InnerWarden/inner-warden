import { decidedByLabel } from "../presentation";

// Which layer of the pipeline decided an action: deterministic rules,
// the session graph (chain escalation), the on-device Warden model, an LLM second
// opinion, a human, or Active Defence. Tinted so it is obvious when something
// beyond the plain rules made the call.
export function DecidedBy({ by }: { by?: string }) {
  const b = by && by.length > 0 ? by : "unknown";
  const map: Record<string, string> = {
    rules: "border-slate-200 bg-slate-50 text-slate-600",
    graph: "border-cyan-200 bg-cyan-50 text-cyan-800",
    warden: "border-violet-200 bg-violet-50 text-violet-700",
    llm: "border-blue-200 bg-blue-50 text-blue-700",
    human: "border-amber-200 bg-amber-50 text-amber-800",
    // a user override / trust decision reads the same as a human call (it was
    // falling through to the plain-rules grey).
    user: "border-amber-200 bg-amber-50 text-amber-800",
    "host-edr": "border-orange-200 bg-orange-50 text-orange-800",
    unknown: "border-slate-200 bg-white text-slate-500",
  };
  const cls = map[b] ?? map.unknown;
  return (
    <span
      className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium ${cls}`}
      title={`Decision source: ${decidedByLabel(b)}`}
    >
      {decidedByLabel(b)}
    </span>
  );
}
