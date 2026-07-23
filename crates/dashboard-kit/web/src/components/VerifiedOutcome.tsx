import type { CaseEvent, VerifiedOutcome as VerifiedOutcomeRecord } from "../api/cases";
import type { SecurityOutcome } from "../api/v1";
import { StatusBadge, type StatusTone } from "./StatusBadge";
import { EvidenceLinks } from "./CaseTimeline";

export type OutcomePresentation = {
  trusted: boolean;
  status: SecurityOutcome | "unknown";
  label: string;
  tone: StatusTone;
  explanation: string;
};

export function verifiedOutcomePresentation(outcome: VerifiedOutcomeRecord, timeline: CaseEvent[], evaluatedAt: string): OutcomePresentation {
  const verificationTime = outcome.verified_at === null ? Number.NaN : Date.parse(outcome.verified_at);
  const evaluationTime = Date.parse(evaluatedAt);
  const currentTime = Number.isNaN(evaluationTime) ? Date.now() : evaluationTime;
  const attemptMatches = outcome.enforcement_attempt_id !== null
    && timeline.some((event) => event.id === outcome.enforcement_attempt_id && event.event_type === "enforcement_attempt");
  const currentVerifiedEvidence = outcome.evidence.some((entry) => {
    const observed = Date.parse(entry.observed_at);
    return entry.integrity === "verified"
      && entry.freshness.state === "fresh"
      && entry.freshness.age_seconds !== null
      && entry.freshness.age_seconds <= entry.freshness.budget_seconds
      && !Number.isNaN(observed)
      && observed <= currentTime;
  });
  const commonVerification = outcome.verification_status === "verified"
    && outcome.verifier !== null
    && outcome.verified_at !== null
    && !Number.isNaN(verificationTime)
    && verificationTime <= currentTime
    && outcome.effective_scope.length > 0
    && currentVerifiedEvidence;

  if (outcome.outcome === "blocked_before_execution" || outcome.outcome === "contained") {
    const trusted = commonVerification
      && outcome.mode === "enforce"
      && outcome.actual_denial_or_containment_occurred
      && attemptMatches;
    if (!trusted) {
      return {
        trusted: false,
        status: "unknown",
        label: "Outcome claim withheld",
        tone: "neutral",
        explanation: "A blocking or containment claim requires current integrity-verified runtime evidence, effective scope, a matching enforcement attempt and a non-future verification time.",
      };
    }
    return outcome.outcome === "contained"
      ? { trusted: true, status: "contained", label: "Verified containment", tone: "positive", explanation: "Fresh runtime evidence verifies containment in the displayed scope." }
      : { trusted: true, status: "blocked_before_execution", label: "Verified pre-execution block", tone: "critical", explanation: "Fresh runtime evidence verifies denial before execution in the displayed scope." };
  }

  if (outcome.outcome === "would_block") {
    const trusted = commonVerification
      && (outcome.mode === "observe" || outcome.mode === "rehearse")
      && !outcome.actual_denial_or_containment_occurred;
    return trusted
      ? { trusted: true, status: "would_block", label: "Would block · no denial", tone: "attention", explanation: "Verified Observe/Rehearse evidence records a recommendation only; no action was denied." }
      : withheld("Would-block evidence is incomplete or inconsistent with Observe/Rehearse semantics.");
  }

  if (outcome.outcome === "observed_only") {
    const trusted = commonVerification && outcome.mode === "observe" && !outcome.actual_denial_or_containment_occurred;
    return trusted
      ? { trusted: true, status: "observed_only", label: "Observed only · no denial", tone: "informational", explanation: "The runtime verified an observation without enforcement." }
      : withheld("Observation evidence is incomplete or reports an enforcement effect that Observe mode cannot support.");
  }

  if (!commonVerification) return withheld("The producer did not provide current integrity-verified evidence for this outcome.");

  const labels: Record<SecurityOutcome, string> = {
    observed_only: "Observed only",
    allowed: "Verified allowed outcome",
    blocked_before_execution: "Verified pre-execution block",
    would_block: "Would block",
    contained: "Verified containment",
    failed: "Verified failed attempt",
    reverted: "Verified reverted action",
    not_observed: "Verified not observed",
    unknown: "Outcome remains unknown",
  };
  const tones: Partial<Record<SecurityOutcome, StatusTone>> = { allowed: "positive", failed: "critical", reverted: "informational" };
  return {
    trusted: outcome.outcome !== "unknown",
    status: outcome.outcome,
    label: labels[outcome.outcome],
    tone: tones[outcome.outcome] ?? "neutral",
    explanation: outcome.outcome === "unknown" ? "The evidence does not establish a canonical security outcome." : "The outcome is backed by current integrity-verified evidence.",
  };
}

function withheld(reason: string): OutcomePresentation {
  return { trusted: false, status: "unknown", label: "Outcome claim withheld", tone: "neutral", explanation: reason };
}

export function VerifiedOutcome({ outcome, timeline, evaluatedAt }: {
  outcome: VerifiedOutcomeRecord;
  timeline: CaseEvent[];
  evaluatedAt: string;
}) {
  const presentation = verifiedOutcomePresentation(outcome, timeline, evaluatedAt);
  return (
    <article className="rounded-xl border border-slate-200 bg-slate-50 p-4" data-outcome-trusted={presentation.trusted ? "true" : "false"}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <StatusBadge status={presentation.status} label={presentation.label} tone={presentation.tone} />
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{outcome.mode} mode</span>
      </div>
      <p className="mt-3 text-sm leading-6 text-slate-700">{presentation.explanation}</p>
      <dl className="mt-3 grid gap-2 border-t border-slate-200 pt-3 text-xs sm:grid-cols-3">
        <div><dt className="text-slate-500">Verification</dt><dd className="mt-0.5 font-semibold text-slate-800">{presentation.trusted ? "Current" : "Unknown"}</dd></div>
        <div><dt className="text-slate-500">Verifier</dt><dd className="mt-0.5 break-words font-semibold text-slate-800 [overflow-wrap:anywhere]">{outcome.verifier ?? "Not reported"}</dd></div>
        <div><dt className="text-slate-500">Verified at</dt><dd className="mt-0.5 font-semibold text-slate-800">{outcome.verified_at ? formatTime(outcome.verified_at) : "Not reported"}</dd></div>
      </dl>
      <EvidenceLinks evidence={outcome.evidence} />
    </article>
  );
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value));
}
