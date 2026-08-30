import type { CaseEvent, VerifiedOutcome as VerifiedOutcomeRecord } from "../api/cases";
import type { SecurityOutcome } from "../api/v1";
import { StatusBadge, type StatusTone } from "./StatusBadge";
import { EvidenceLinks } from "./CaseTimeline";
import { TechnicalOnly } from "./TechnicalDetail";

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
  /// The one-line "what this means" shown under the badge and on hover. Carried
  /// on the presentation rather than derived from `status` by the caller, so the
  /// pending case can explain itself instead of borrowing `not_observed`'s
  /// sentence, which says the opposite of what is true for it.
  meaning: string;
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
export function verifiedOutcomePresentation(outcome: VerifiedOutcomeRecord, timeline: CaseEvent[], _evaluatedAt: string): OutcomePresentation {
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
      meaning: "The record does not hold together well enough to report an outcome.",
    };
  }
  if (outcome.outcome === "not_observed" && awaitingAPerson(timeline)) {
    // `status` deliberately keeps the wire value. The machine-readable field
    // stays exactly what the host said; only the words a person reads change,
    // so nothing downstream that keys off the outcome starts seeing a value
    // the backend never sent.
    return {
      trusted: true,
      independentlyChecked,
      status: outcome.outcome,
      label: "Waiting for you",
      tone: "attention",
      explanation:
        "This was decided and is queued for a person. Nothing has been applied yet, which is why no effect on the attack has been observed.",
      meaning: "It is waiting for a person to apply it. It has not been missed and it has not failed.",
    };
  }
  return {
    trusted: true,
    independentlyChecked,
    status: outcome.outcome,
    label: label(outcome.outcome, independentlyChecked),
    tone: tone(outcome.outcome),
    explanation: outcome.trust_explanation,
    meaning: outcomeMeaning(outcome.outcome),
  };
}

/**
 * Is this action proposed and still queued for a person?
 *
 * The host writes `awaiting_human` for an action it decided on and did not
 * apply, and the outcome projector turns that into lifecycle `pending` with
 * outcome `not_observed`, because nothing was observed to happen to the attack.
 * Both halves are true, and read together on screen they were a lie: the panel
 * renders the OUTCOME, so 17488 items queued for the operator said "Never
 * happened" and "There is no record of this happening".
 *
 * The lifecycle was already on the wire (`action_lifecycle` on every timeline
 * event, cases.ts:326) and this component already received the timeline and
 * ignored it. So the fix reads what is there rather than adding a field: the
 * kit parser rejects unknown keys outright (`exact`, cases.ts:269), so a new
 * field would fail the whole page for every reader on an older bundle.
 */
function awaitingAPerson(timeline: CaseEvent[]): boolean {
  return timeline.some((event) => event.action_lifecycle === "pending");
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
  // `reverted` is one wire value covering three endings: the TTL ran out
  // ("expired", overwhelmingly the common one), an operator removed the block
  // ("manual"), or the rule was already gone ("already_absent"). "Undone" reads
  // as a retraction of a decision, so a page of timed blocks that ran their
  // full course looked like the product changing its mind. "Block ended" is
  // true for all three and claims nothing about which.
  const checked: Record<SecurityOutcome, string> = {
    blocked_before_execution: "Blocked before it ran, checked",
    contained: "Contained, checked",
    allowed: "Allowed, checked",
    would_block: "Would have been blocked, checked",
    observed_only: "Seen, not acted on, checked",
    failed: "The attempt failed, checked",
    reverted: "Block ended, checked",
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
    reverted: "Block ended",
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

/**
 * What each outcome MEANS, in one line, next to the words themselves.
 *
 * "Contained" and "Blocked before it ran" are different facts and the screen
 * never said how: the first means the activity was already under way and was
 * cut off, the second means it never executed at all. An operator was left to
 * guess, and guessing wrong about whether something ran is the worst guess this
 * product can invite.
 *
 * Shown as a `title` so it is available on hover for the dense layout, AND as
 * visible text under the badge, because a tooltip is unreachable on a phone and
 * unreadable by a screen reader that is not looking for it.
 */
export function outcomeMeaning(outcome: SecurityOutcome): string {
  const meanings: Record<SecurityOutcome, string> = {
    blocked_before_execution: "It never ran. The guardrail refused it in line, before execution.",
    contained: "It was already under way and was cut off, for example by a firewall block.",
    allowed: "It was examined and permitted to proceed.",
    would_block: "In enforcing mode this would have been stopped. Here it was only recorded.",
    observed_only: "It was seen and recorded. Nothing was done about it.",
    failed: "Something was supposed to stop it and the attempt did not succeed.",
    reverted: "The block is no longer in place. Usually its time ran out.",
    not_observed: "There is no record of this happening.",
    unknown: "The record does not say what happened.",
  };
  return meanings[outcome];
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
        <span title={presentation.meaning}>
          <StatusBadge status={presentation.status} label={presentation.label} tone={presentation.tone} />
        </span>
        <TechnicalOnly>
          <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{outcome.mode} mode</span>
        </TechnicalOnly>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-500">{presentation.meaning}</p>
      <p className="mt-3 text-sm leading-6 text-slate-700">{presentation.explanation}</p>
      {/* Provenance, not verdict.
        *
        * "Checked by someone else: no", "Reported by: Not reported" and
        * "Recorded at: Not reported" are three cells of doubt on a case where
        * the outcome above already said what happened. They answer an
        * auditor's question, and to a buyer they read as the product hedging
        * about its own work. They stay, exactly as they were, one click away.
        *
        * Hidden by not being MOUNTED, not by CSS: three fewer DOM nodes per
        * case on a list the operator scrolls through. */}
      <TechnicalOnly>
        <dl className="mt-3 grid gap-2 border-t border-slate-200 pt-3 text-xs sm:grid-cols-3">
          <div><dt className="text-slate-500">Checked by someone else</dt><dd className="mt-0.5 font-semibold text-slate-800">{checkedWord(presentation)}</dd></div>
          <div><dt className="text-slate-500">Reported by</dt><dd className="mt-0.5 break-words font-semibold text-slate-800 [overflow-wrap:anywhere]">{outcome.verifier ?? "Not reported"}</dd></div>
          <div><dt className="text-slate-500">Recorded at</dt><dd className="mt-0.5 font-semibold text-slate-800">{outcome.verified_at ? formatTime(outcome.verified_at) : "Not reported"}</dd></div>
        </dl>
      </TechnicalOnly>
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
