import { verdictLabel } from "../presentation";
import { TONE_AMBER, TONE_EMERALD, TONE_SLATE } from "./classes";

/**
 * `reviewLabel` replaces the words on a `review` chip where the shared
 * "Needs review" would collide with something else on the same screen (see
 * `REVIEW_VERDICT_CHIP` in Home). The colours never change with it.
 */
export function Verdict({ rec, reviewLabel }: { rec?: string; reviewLabel?: string }) {
  const map: Record<string, [string, string]> = {
    deny: ["bg-red-500", "border-red-200 bg-red-50 text-red-700"],
    review: ["bg-amber-500", TONE_AMBER],
    allow: ["bg-emerald-500", TONE_EMERALD],
  };
  // An unknown / corrupt verdict must NOT read as a safe "allow" (green). Fall
  // back to a neutral, explicit "unknown" so nothing dangerous looks approved.
  const hit = rec ? map[rec] : undefined;
  const [dot, cls] = hit ?? ["bg-slate-400", TONE_SLATE];
  return (
    <span className={`inline-flex shrink-0 self-start justify-self-start items-center gap-1.5 whitespace-nowrap rounded-lg border px-2.5 py-0.5 text-xs font-semibold leading-5 ${cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden="true" />
      {hit && rec === "review" && reviewLabel ? reviewLabel : verdictLabel(hit ? rec : undefined)}
    </span>
  );
}
