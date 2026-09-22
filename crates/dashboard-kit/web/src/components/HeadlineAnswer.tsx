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
  /**
   * How many decisions the host recorded as stopped before running.
   *
   * `null` when the host reports no outcome figures at all. A missing figure is
   * NOT zero: reading it as zero would let this function accuse a host of
   * stopping nothing when the truth is that it never said.
   */
  blockedBeforeExecution: number | null;
  /**
   * Verdicts the guardrail would have blocked but did not, because it was not
   * enforcing. A verdict counted here is EXPLAINED: the operator chose to
   * watch, so it is not a gap they have to answer for.
   */
  wouldBlock: number | null;
  /** Verdicts from a one-off check, which never had an execution to stop. */
  screened: number | null;
  /** Verdicts whose recorded outcome this version cannot read. */
  outcomesUnknown: number | null;
  /**
   * Denies whose outcome was NOT a block, counted by the producer as a cross of
   * the two partitions.
   *
   * Never derive this here. `denyVerdicts` partitions by recommendation and the
   * outcome counters partition by outcome, and `screened` covers allows too: on
   * the measured host it was 16 against 11 denies, so subtracting it explained
   * away ten real denies and the page went back to saying all was well.
   */
  deniesWithoutBlock: number | null;
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
 * 3. A verdict is not an act. When the host judged actions unsafe and recorded
 *    fewer blocks than verdicts, that gap IS the headline. A reassuring
 *    sentence printed above it is the worst thing a security product can say,
 *    and it is what this screen used to say: `blockedBeforeExecution` arrived
 *    from the caller and was never read, so eleven unsafe verdicts against one
 *    recorded block still led with "Protected. Nothing needs you.".
 *    The wording stays at what the two counters support, which is verdicts
 *    with no block recorded against them. It is not a count of attacks that
 *    succeeded, and this function has no evidence that any of them ran.
 * 4. An agent that is configured but never observed working is worth a nudge,
 *    but it is not an emergency and does not deserve the top line to itself.
 * 5. Otherwise: protected, nothing to do. Reached only when nothing is queued,
 *    the host is not merely watching, every unsafe verdict it reported has a
 *    block recorded against it, and every agent has been seen working. It is a
 *    narrow door on purpose.
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
  // The gap between judging and acting, which nothing compared until now.
  //
  // It sits above the agent nudge and above the final return because an
  // unstopped unsafe action outranks both: an operator who reads "Protecting"
  // over this gap has been told the opposite of what the counters beside it
  // say. Monitor mode is handled above and keeps its own sentence, since there
  // the gap is the deployment the operator chose, not a surprise.
  if (input.denyVerdicts > 0) {
    if (input.blockedBeforeExecution === null) {
      // Outcomes were never reported, so the gap cannot be computed and is not
      // claimed. "Not recorded" beats a confident wrong number.
      return {
        answer: `${input.denyVerdicts.toLocaleString()} judged unsafe, outcome not recorded`,
        next: "This host reports no outcome for its verdicts. Open Posture to see what each control is doing.",
        tone: "attention",
      };
    }
      // Counted by the PRODUCER as a cross of the two partitions, never derived
      // here. `denyVerdicts` partitions by recommendation and the outcome
      // counters partition by outcome, and `screened` covers allows too: on the
      // measured host it was 16 against 11 denies, so subtracting it explained
      // away ten real denies and the page went back to saying all was well.
      const noBlockRecorded = input.deniesWithoutBlock ?? 0;
    if (noBlockRecorded > 0) {
      // A floor, not an estimate: a recorded block may belong to a verdict that
      // was not a deny, so the true number of unsafe verdicts with nothing
      // against them can only be this or higher. Understating is the only safe
      // direction for a number that accuses.
      const plural = noBlockRecorded === 1 ? "action" : "actions";
        // TONE, deliberately good. Most of these are a one-off `check-command`:
        // the guard was asked, it answered deny, and there was no execution to
        // stop. That is the product WORKING. Painting a healthy host red over
        // questions it answered correctly is its own kind of lie, and the fast
        // way to teach an operator to ignore the screen. This reports, it does
        // not accuse. The one thing nobody here can know is whether the caller
        // honoured the answer, and that is what the detail says.
      return {
          answer: `Protecting. ${noBlockRecorded.toLocaleString()} unsafe ${plural} judged, not stopped here`,
          next: `${input.denyVerdicts.toLocaleString()} judged unsafe, ${input.blockedBeforeExecution.toLocaleString()} stopped before execution here. The rest were one-off checks with no execution to stop, so whether the caller honoured the answer is not recorded on this host.`,
          tone: "good",
      };
    }
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
