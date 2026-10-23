import { DECIDER_WORDS, type DecisionOutcomeKey, type MessageOutcomeKey } from "./words";

/**
 * What InnerWarden did with one decision, in three steps: Seen, Decided,
 * and whether it was refused. The third step's label is what happened
 * ("Refused", "Not refused", "Nothing to refuse", "Not recorded"), never
 * "Refused" for a decision that was not: the bold labels alone read true.
 * Then, said once under them, that nothing was checked afterwards
 * (`NOT_CHECKED_AFTERWARDS`): Community records the guard's own answer and
 * never looks at what a command did after it ran.
 *
 * A pure function of structured fields only; nothing here reads a sentence.
 * Two marks never appear: `verified`, because nothing is read back after the
 * fact, and `waiting`, because nothing in Community waits on a person to
 * decide a decision.
 */
export type LadderMark = "done" | "no" | "not_applicable" | "unknown";

export type LadderStep = {
  key: "seen" | "decided" | "refused";
  label: string;
  mark: LadderMark;
  /** What the step says, in words: the mark is never the only signal. */
  words: string;
};

export type LadderInput = {
  outcomeKey: DecisionOutcomeKey;
  mode: string;
  /** What the rules said: `deny`, `review` or `allow`. */
  recommendation: string;
  decidedBy: string;
};

export const NOT_CHECKED_AFTERWARDS = "Not checked afterwards: Community does not look at what a command did after it ran.";

export const MONITOR_NOT_REFUSED = "Monitor records and does not refuse";
export const REVIEW_NOT_REFUSED = "A review is recorded and, by default, still runs";

const VERDICT_WORDS: Record<string, string> = { deny: "Deny", review: "Review", allow: "Allow" };

/** The third step's labels: what happened, in the label itself. */
export const REFUSED_LABEL = "Refused";
export const NOT_REFUSED_LABEL = "Not refused";
export const NOTHING_TO_REFUSE_LABEL = "Nothing to refuse";
export const NOT_RECORDED_LABEL = "Not recorded";

function refused(input: LadderInput): Pick<LadderStep, "label" | "mark" | "words"> {
  switch (input.outcomeKey) {
    case "refused_before_run":
      return { label: REFUSED_LABEL, mark: "done", words: "Before it ran" };
    case "unsafe_may_have_run":
      return { label: NOT_REFUSED_LABEL, mark: "no", words: "Judged unsafe, and it ran" };
    case "would_have_refused":
      return { label: NOT_REFUSED_LABEL, mark: "not_applicable", words: MONITOR_NOT_REFUSED };
    case "flagged_ran":
      return input.mode === "monitor"
        ? { label: NOT_REFUSED_LABEL, mark: "not_applicable", words: MONITOR_NOT_REFUSED }
        : { label: NOT_REFUSED_LABEL, mark: "not_applicable", words: REVIEW_NOT_REFUSED };
    case "checked_only":
      return { label: NOTHING_TO_REFUSE_LABEL, mark: "not_applicable", words: "A check by hand runs nothing" };
    case "allowed":
      return { label: NOTHING_TO_REFUSE_LABEL, mark: "not_applicable", words: "It was allowed" };
    case "unplaced":
      return { label: NOT_RECORDED_LABEL, mark: "unknown", words: "Not recorded whether it was refused" };
  }
}

/** The decided step's words: the verdict, and who decided when the page has words for them. */
export function decidedWords(recommendation: string, decidedBy: string): string {
  const verdict = VERDICT_WORDS[recommendation];
  const decider = DECIDER_WORDS[decidedBy];
  if (verdict === undefined) return decider === undefined ? "Decided" : `Decided by ${decider}`;
  return decider === undefined ? verdict : `${verdict}, by ${decider}`;
}

/** The three steps of a decision. */
export function decisionLadder(input: LadderInput): LadderStep[] {
  return [
    { key: "seen", label: "Seen", mark: "done", words: "On record" },
    // No time on Decided: the record keeps one time per decision, so a "+0 s"
    // here would be a constant dressed as a measurement.
    { key: "decided", label: "Decided", mark: "done", words: decidedWords(input.recommendation, input.decidedBy) },
    { key: "refused", ...refused(input) },
  ];
}

/**
 * Who decided a message. An outcome the record could not see says so, never
 * "not recorded": a chat that does not report the agent's reply is a limit
 * of the channel, not a fault in the record.
 */
function messageDecided(outcomeKey: MessageOutcomeKey): Pick<LadderStep, "mark" | "words"> {
  switch (outcomeKey) {
    case "declined_by_agent":
      return { mark: "done", words: "Your agent declined" };
    case "stopped_by_innerwarden":
      return { mark: "done", words: "The guard refused what your agent tried" };
    case "answered":
      return { mark: "done", words: "Your agent answered" };
    case "not_seen":
    case "unplaced":
      return { mark: "unknown", words: "Who decided could not be seen" };
  }
}

/**
 * The three steps of a message someone sent the agent: seen, decided (by the
 * agent itself, or by the guard), and refused only when the guard refused
 * what the agent then tried. Recording a conversation does not block it.
 */
export function messageLadder(outcomeKey: MessageOutcomeKey): LadderStep[] {
  return [
    { key: "seen", label: "Seen", mark: "done", words: "On record" },
    { key: "decided", label: "Decided", ...messageDecided(outcomeKey) },
    {
      key: "refused",
      ...(outcomeKey === "stopped_by_innerwarden"
        ? { label: REFUSED_LABEL, mark: "done" as const, words: "The guard refused it" }
        : { label: NOT_REFUSED_LABEL, mark: "not_applicable" as const, words: "Observe records and does not block" }),
    },
  ];
}
