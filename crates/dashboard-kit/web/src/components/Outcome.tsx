export function Outcome({ value }: { value?: string }) {
  const map: Record<string, [string, string]> = {
    blocked: ["Blocked", "border-red-200 bg-red-50 text-red-700"],
    would_block: ["Would block", "border-blue-200 bg-blue-50 text-blue-700"],
    allowed: ["Allowed to run", "border-emerald-200 bg-emerald-50 text-emerald-700"],
    screened: ["Screened", "border-slate-200 bg-slate-50 text-slate-600"],
    unknown: ["Outcome unknown", "border-slate-200 bg-white text-slate-500"],
  };
  if (!value) return null;
  const [label, cls] = map[value] ?? map.unknown;
  return <span className={`inline-flex shrink-0 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${cls}`}>{label}</span>;
}
