/**
 * The one sentence a customer came for.
 *
 * Someone who bought this opens the dashboard to answer two questions: is it
 * working, and is there anything I have to do. Neither was answered anywhere.
 * The screen offered five counters ("15,571 recorded", "252 deny verdicts",
 * "136 needs review", "15,183 allowed", "0 unknown") and left the arithmetic,
 * and the conclusion, to the reader.
 *
 * Worse, the counters read as an accusation. "252 classified as unsafe" next to
 * "3 blocked before execution" says, to anyone who does not know what monitor
 * mode is, that the product found 252 dangerous things and stopped three.
 *
 * So this computes the conclusion instead of implying it, and it is a pure
 * function of numbers the host already sends. No new endpoint, no new field, no
 * extra request.
 */

export type HeadlineInput = {
  /** Actions the product decided it cannot settle alone. */
  needsReview: number;
  /** Verdicts of "unsafe". */
  denyVerdicts: number;
  /** Of those, how many were actually stopped before running. */
  blockedBeforeExecution: number;
  /** True when the guardrail is watching but not enforcing. */
  monitorOnly: boolean;
  /** Agents configured but never seen working. */
  unprovenAgents: number;
};

export type Headline = {
  /** The sentence. Never empty. */
  answer: string;
  /** What to do, or null when there is nothing to do. */
  next: string | null;
  tone: "good" | "attention";
};

/**
 * Rules, in priority order, and the reasoning behind each.
 *
 * 1. Work queued for a person wins over everything. It is the only state where
 *    the product is genuinely waiting on the reader, and burying it under a
 *    reassuring headline would be the worst thing this screen could do.
 * 2. Monitor mode is reported as a CHOICE, not a failure, and only once nothing
 *    is queued. "Watching, not blocking" is what the operator picked; saying it
 *    plainly is honest, and it explains the deny-versus-blocked gap that
 *    otherwise reads as the product failing to act.
 * 3. An agent that is configured but never observed working is worth a nudge,
 *    but it is not an emergency and does not deserve the top line to itself.
 * 4. Otherwise: protected, nothing to do. Reached only when nothing is queued,
 *    enforcement is on, and every agent has been seen working. It is a narrow
 *    door on purpose.
 */
export function headline(input: HeadlineInput): Headline {
  if (input.needsReview > 0) {
    const plural = input.needsReview === 1 ? "action needs" : "actions need";
    return {
      answer: `${input.needsReview.toLocaleString()} ${plural} your decision`,
      next: "Open Activity and filter by Needs review.",
      tone: "attention",
    };
  }
  if (input.monitorOnly) {
    // Deliberately not "you are unprotected". Monitor is a deployment stage
    // people choose on purpose, and calling it a fault would push them to
    // enforce before they are ready, which is how a gate bricks a host.
    return {
      answer: "Watching, not blocking",
      next:
        input.denyVerdicts > 0
          ? `${input.denyVerdicts.toLocaleString()} actions would have been blocked. Switch to enforcing when you are ready.`
          : "Switch to enforcing when you are ready.",
      tone: "attention",
    };
  }
  if (input.unprovenAgents > 0) {
    const plural = input.unprovenAgents === 1 ? "agent has" : "agents have";
    return {
      answer: "Protecting",
      next: `${input.unprovenAgents} ${plural} not run anything yet, so there is nothing to confirm from.`,
      tone: "good",
    };
  }
  return {
    answer: "Protected. Nothing needs you.",
    next: null,
    tone: "good",
  };
}
