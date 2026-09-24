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
  /**
   * Agent actions the agent guardrail answered `review` on: it could not
   * settle them alone. These are guardrail verdicts. A paid host's Cases screen
   * has a "Needs review" status of its own, and that is a case status, not a
   * guardrail verdict: a different count, under the same two words.
   *
   * It is NOT a count of actions being held. A `review` verdict stops the
   * action only where the hook runs in block-review mode, and a one-off
   * `innerwarden check` records a verdict with nothing pending at all. The
   * count cannot tell which, so the sentence says "flagged", never "waiting".
   */
  needsReview: number;
  /**
   * Where the actions counted in `needsReview` can be listed, which is where
   * the Decision record's "view everything" button goes (`decisionRecordCta`
   * in Home), so the sentence and the button can never disagree.
   *
   * It used to be one constant, "Open Activity and filter by Needs review.",
   * on both products. Enterprise has no Activity tab at all, so a paid reader
   * was sent to a screen that does not exist, and the only "Needs review"
   * they could find was the Cases status: a case status, not a guardrail
   * verdict.
   */
  reviewListedIn: "activity" | "cases" | "hidden";
  /**
   * Whether the Recent activity section on the same page lists decisions with
   * their verdicts: true only when the host sent `recent_decisions` and it is
   * not empty. Read only when `reviewListedIn` is `hidden`, where Recent
   * activity is the one place left to point at.
   *
   * False on an older host that sends only `recent_blocks`: that list holds
   * deny verdicts alone, so a `review` verdict never appears in it, and
   * pointing a reader at it for one is a promise the section cannot keep. An
   * empty list says "No recent decisions are available yet." directly under
   * the sentence that would have sent them there.
   */
  recentShowsDecisions: boolean;
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
 * Where to go to see the actions the agent guardrail flagged for review, named
 * by a control that exists on the product the reader is looking at.
 *
 * - `activity` (Community): the Activity tab, and its "Needs review" verdict
 *   filter, which lists exactly these.
 * - `cases` (Enterprise with a Cases screen): there is no Activity tab. The
 *   guardrail's verdicts sit inside the agent-session cases, which the
 *   Capability filter's "The agent guardrail" option narrows to. The Cases
 *   screen's own "Needs review" is a case status, not a guardrail verdict,
 *   and must not be named here: that is the collision this sentence exists to
 *   avoid.
 * - `hidden`: no screen lists them all, and the sentence says so rather than
 *   naming one. It points at Recent activity only when that section really
 *   lists decisions with their verdicts (`recentShowsDecisions`).
 */
export function reviewRemedy(
  where: HeadlineInput["reviewListedIn"],
  recentShowsDecisions: boolean,
): string {
  if (where === "activity") return "Open Activity and filter by Needs review.";
  if (where === "cases") {
    return "These are the agent guardrail's verdicts, not host cases. Use View all in Cases and set "
      + "Capability to \"The agent guardrail\" to find them in their agent sessions.";
  }
  if (recentShowsDecisions) {
    return "These are the agent guardrail's verdicts. Recent activity below shows the latest decisions "
      + "with their verdicts; no screen in this installation lists them all.";
  }
  return "These are the agent guardrail's verdicts. No screen in this installation lists them.";
}

/**
 * Rules, in priority order, and the reasoning behind each.
 *
 * 1. Actions the guardrail flagged for a person win over everything. Burying
 *    them under a reassuring headline would be the worst thing this screen
 *    could do. The sentence says they were FLAGGED, not that they are waiting:
 *    the count includes one-off checks where nothing is pending, and it cannot
 *    tell whether the hook held anything (see `needsReview`).
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
    // "agent actions", not "actions": on a paid host this sentence sits on the
    // same page as a count of host cases waiting, and the two are different
    // things counted by different parts of the product.
    //
    // "were flagged for review", not "need your decision": the tile under this
    // sentence says flagged, and this count cannot tell whether anything was
    // held. A one-off `innerwarden check` answered `review` is counted here
    // with nothing pending, and "need your decision" told its reader something
    // was waiting on them that never was.
    const plural = input.needsReview === 1 ? "agent action was" : "agent actions were";
    return {
      answer: `${input.needsReview.toLocaleString()} ${plural} flagged for review`,
      next: reviewRemedy(input.reviewListedIn, input.recentShowsDecisions),
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
