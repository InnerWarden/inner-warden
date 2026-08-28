import type { CaseEvent, VerifiedOutcome as VerifiedOutcomeRecord } from "../api/cases";
import type { SecurityOutcome } from "../api/v1";
import { StatusBadge, type StatusTone } from "./StatusBadge";
import { EvidenceLinks } from "./CaseTimeline";

export type OutcomePresentation = {
  /// The header may report this outcome. `recorded` counts: an in-path guard
  /// refusal is a real event whether or not a second component watched it.
  trusted: boolean;
  /// Something INDEPENDENT observed it. Only this earns a verified badge.
  independentlyChecked: boolean;
  status: SecurityOutcome | "unknown";
  label: string;
  tone: StatusTone;
  explanation: string;
};

/**
 * Render the backend's verdict. Do not compute one here.
 *
 * This function used to run its own predicate over `enforcement_attempt_id`,
 * evidence integrity, freshness, scope and verification time. The header ran a
 * DIFFERENT predicate in Rust, and for every Community guard block the two
 * disagreed, so one case showed three answers to "was it blocked?" at once:
 *
 *     header: Reported outcome: Blocked Before Execution
 *     badge:  1 verified result
 *     body:   Outcome claim withheld ... Verification: Unknown
 *
 * The guard projection always writes `enforcement_attempt_id: null`, because an
 * in-path refusal has no separate attempt record: the refusal IS the record.
 * So the disagreement was not an edge case, it was every block, every time.
 *
 * The rule now lives in one place, `agent/src/dashboard/v1/outcome_trust.rs`,
 * and arrives on the record. Reintroducing a second opinion here reintroduces
 * the bug.
 */
export function verifiedOutcomePresentation(outcome: VerifiedOutcomeRecord, _timeline: CaseEvent[], _evaluatedAt: string): OutcomePresentation {
  const trusted = outcome.trust !== "unproven";
  const independentlyChecked = outcome.trust === "proven";
  if (!trusted) {
    return {
      trusted: false,
      independentlyChecked: false,
      status: "unknown",
      label: "No outcome reported",
      tone: "neutral",
      explanation: outcome.trust_explanation,
    };
  }
  return {
    trusted: true,
    independentlyChecked,
    status: outcome.outcome,
    label: label(outcome.outcome, independentlyChecked),
    tone: tone(outcome.outcome),
    explanation: outcome.trust_explanation,
  };
}

/**
 * What the reader sees at a glance.
 *
 * The independence split is carried in the WORDS, not only in a badge, because
 * a badge is the first thing that gets dropped from a compact layout and the
 * difference between "we watched this" and "the guard says so" is the whole
 * honesty claim.
 */
function label(outcome: SecurityOutcome, independentlyChecked: boolean): string {
  const checked: Record<SecurityOutcome, string> = {
    blocked_before_execution: "Blocked before it ran, checked",
    contained: "Contained, checked",
    allowed: "Allowed, checked",
    would_block: "Would have been blocked, checked",
    observed_only: "Seen, not acted on, checked",
    failed: "The attempt failed, checked",
    reverted: "Undone, checked",
    not_observed: "Never happened, checked",
    unknown: "Outcome unknown",
  };
  const reported: Record<SecurityOutcome, string> = {
    blocked_before_execution: "Blocked before it ran",
    contained: "Contained",
    allowed: "Allowed",
    would_block: "Would have been blocked",
    observed_only: "Seen, not acted on",
    failed: "The attempt failed",
    reverted: "Undone",
    not_observed: "Never happened",
    unknown: "Outcome unknown",
  };
  return independentlyChecked ? checked[outcome] : reported[outcome];
}

function tone(outcome: SecurityOutcome): StatusTone {
  const tones: Partial<Record<SecurityOutcome, StatusTone>> = {
    blocked_before_execution: "critical",
    contained: "positive",
    allowed: "positive",
    would_block: "attention",
    observed_only: "informational",
    failed: "critical",
    reverted: "informational",
  };
  return tones[outcome] ?? "neutral";
}

export function VerifiedOutcome({ outcome, timeline, evaluatedAt }: {
  outcome: VerifiedOutcomeRecord;
  timeline: CaseEvent[];
  evaluatedAt: string;
}) {
  const presentation = verifiedOutcomePresentation(outcome, timeline, evaluatedAt);
  return (
    <article className="rounded-xl border border-slate-200 bg-slate-50 p-4" data-outcome-trusted={presentation.trusted ? "true" : "false"} data-outcome-checked={presentation.independentlyChecked ? "true" : "false"}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <StatusBadge status={presentation.status} label={presentation.label} tone={presentation.tone} />
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{outcome.mode} mode</span>
      </div>
      <p className="mt-3 text-sm leading-6 text-slate-700">{presentation.explanation}</p>
      <dl className="mt-3 grid gap-2 border-t border-slate-200 pt-3 text-xs sm:grid-cols-3">
        <div><dt className="text-slate-500">Checked by someone else</dt><dd className="mt-0.5 font-semibold text-slate-800">{checkedWord(presentation)}</dd></div>
        <div><dt className="text-slate-500">Reported by</dt><dd className="mt-0.5 break-words font-semibold text-slate-800 [overflow-wrap:anywhere]">{outcome.verifier ?? "Not reported"}</dd></div>
        <div><dt className="text-slate-500">Recorded at</dt><dd className="mt-0.5 font-semibold text-slate-800">{outcome.verified_at ? formatTime(outcome.verified_at) : "Not reported"}</dd></div>
      </dl>
      <EvidenceLinks evidence={outcome.evidence} />
    </article>
  );
}

/**
 * Three words for three states.
 *
 * The old field said "Verification: Current" or "Unknown", and "Unknown" was
 * shown over records where the guard had refused a command and said so. Not
 * knowing and nobody-else-looked are different facts and the reader has to be
 * able to tell them apart.
 */
function checkedWord(presentation: OutcomePresentation): string {
  if (presentation.independentlyChecked) return "Yes";
  if (presentation.trusted) return "No, this is the guard's own record";
  return "Nothing to check";
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value));
}
