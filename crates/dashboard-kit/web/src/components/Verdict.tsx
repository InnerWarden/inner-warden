import { verdictLabel } from "../presentation";

export function Verdict({ rec }: { rec?: string }) {
  const map: Record<string, [string, string]> = {
    deny: ["bg-red-500", "border-red-200 bg-red-50 text-red-700"],
    review: ["bg-amber-500", "border-amber-200 bg-amber-50 text-amber-800"],
    allow: ["bg-emerald-500", "border-emerald-200 bg-emerald-50 text-emerald-700"],
  };
  // An unknown / corrupt verdict must NOT read as a safe "allow" (green). Fall
  // back to a neutral, explicit "unknown" so nothing dangerous looks approved.
  const hit = rec ? map[rec] : undefined;
  const [dot, cls] = hit ?? ["bg-slate-400", "border-slate-200 bg-slate-50 text-slate-600"];
  return (
    <span className={`inline-flex shrink-0 self-start justify-self-start items-center gap-1.5 whitespace-nowrap rounded-lg border px-2.5 py-0.5 text-xs font-semibold leading-5 ${cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden="true" />
      {verdictLabel(hit ? rec : undefined)}
    </span>
  );
}
