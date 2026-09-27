/**
 * What happened to one screened command, as a chip, with what the word means
 * on hover.
 *
 * "Screened" was left unexplained, beside a verdict: "Deny · Screened" read
 * as if denying were the screening. The outcome means the command was judged
 * by a one-off check, and the guardrail did not run it or watch it run, so
 * whether it ran is not in this record. The chip says "Checked only", and
 * every chip says in its title what its word stands for.
 */
export const OUTCOME_CHIPS: Record<string, { label: string; meaning: string; className: string }> = {
  blocked: {
    label: "Blocked",
    meaning: "The guardrail refused it before it ran.",
    className: "border-red-200 bg-red-50 text-red-700",
  },
  would_block: {
    label: "Would block",
    meaning: "Watch mode: the guardrail would have refused it, and let it run.",
    className: "border-blue-200 bg-blue-50 text-blue-700",
  },
  allowed: {
    label: "Allowed to run",
    meaning: "The guardrail let it run.",
    className: "border-emerald-200 bg-emerald-50 text-emerald-700",
  },
  screened: {
    label: "Checked only",
    meaning: "Judged by a one-off check. The guardrail did not run it or watch it run, so whether it ran is not in this record.",
    className: "border-slate-200 bg-slate-50 text-slate-600",
  },
  unknown: {
    label: "Outcome unknown",
    meaning: "No outcome was recorded for this command.",
    className: "border-slate-200 bg-white text-slate-500",
  },
};

export function Outcome({ value }: { value?: string }) {
  if (!value) return null;
  const chip = OUTCOME_CHIPS[value] ?? OUTCOME_CHIPS.unknown;
  return (
    <span title={chip.meaning} className={`inline-flex shrink-0 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${chip.className}`}>
      {chip.label}
    </span>
  );
}
