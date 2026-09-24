import { describe, expect, it } from "vitest";
import { headline } from "./HeadlineAnswer";

const healthy = {
  needsReview: 0,
  reviewListedIn: "activity" as const,
  recentShowsDecisions: true,
  denyVerdicts: 0,
  blockedBeforeExecution: 0,
  wouldBlock: 0,
  screened: 0,
  outcomesUnknown: 0,
  deniesWithoutBlock: 0,
  monitorOnly: false,
  unprovenAgents: 0,
};

/**
 * The operator's brief, in his words: the customer "só quer saber se está
 * funcionando, se tá tudo ativado, ou seja se ele precisa fazer mais alguma
 * coisa ou não". These pin that the answer is computed, not implied, and that
 * it can never be reassuring while work is queued.
 */
describe("headline answer", () => {
  it("says protected only when nothing is queued and enforcement is on", () => {
    const result = headline(healthy);
    expect(result.answer).toBe("Protected. Nothing needs you.");
    expect(result.next).toBeNull();
    expect(result.tone).toBe("good");
  });

  /**
   * THE LINE THAT MUST NOT BE CROSSED. A queued action outranks every other
   * state, including a host that is otherwise perfect. Reassurance printed over
   * 136 waiting decisions is the single worst thing this screen could say.
   */
  it("never reassures while work is waiting on a person", () => {
    for (const extra of [{}, { monitorOnly: true }, { unprovenAgents: 3 }]) {
      const result = headline({ ...healthy, needsReview: 136, ...extra });
      expect(result.answer).toContain("136");
      expect(result.answer).not.toContain("Protected. Nothing needs you");
      expect(result.tone).toBe("attention");
      expect(result.next, "a queued state must say where to go").toBeTruthy();
    }
  });

  it("counts one action in the singular, because 1 actions is a tell", () => {
    expect(headline({ ...healthy, needsReview: 1 }).answer).toBe("1 agent action was flagged for review");
    expect(headline({ ...healthy, needsReview: 2 }).answer).toBe("2 agent actions were flagged for review");
  });

  /**
   * The count is every decision the guardrail answered `review` on, and that
   * includes one-off `innerwarden check` screenings, where nothing is pending
   * and nobody has anything to decide. The headline read "2 agent actions need
   * your decision" over a record of five screened checks. It now says what the
   * count supports, in the same word the tile under it uses.
   */
  it("says the actions were flagged, never that they wait on the reader", () => {
    const allScreened = headline({ ...healthy, needsReview: 2, screened: 5 });
    expect(allScreened.answer).toBe("2 agent actions were flagged for review");
    expect(allScreened.answer).not.toContain("decision");
    expect(allScreened.answer).not.toContain("need");
    expect(allScreened.tone).toBe("attention");
  });

  /**
   * Monitor mode is a CHOICE and is reported as one. Calling it a failure would
   * push someone to enforce before they are ready, and arming a kernel gate
   * early is how a production box gets bricked.
   *
   * It also explains the gap that reads as an accusation today: 252 classified
   * unsafe against 3 actually blocked.
   */
  it("explains monitor mode instead of reading as a failure to act", () => {
    const result = headline({ ...healthy, monitorOnly: true, denyVerdicts: 252 });
    expect(result.answer).toBe("Watching, not blocking");
    expect(result.next).toContain("252");
    expect(result.next).toContain("would have been blocked");
    expect(result.answer).not.toMatch(/unprotected|fail|error/i);
  });

  /**
   * THE LIABILITY. Measured on the live enterprise dashboard: eleven deny
   * verdicts, one "Blocked before execution" printed directly underneath, and
   * the headline read "Protected. Nothing needs you.".
   *
   * `blockedBeforeExecution` was declared in the input type, computed by the
   * caller and never read once in the body, and the only branch that looked at
   * `denyVerdicts` was gated on monitor mode, which a paid host can never
   * report. So no arithmetic in this function could reach the sentence.
   */
  /**
   * THE ARITHMETIC THAT WAS WRONG.
   *
   * The first fix subtracted the outcome counters from the deny count. Those
   * are two different partitions: `screened` covers allows as well as denies,
   * and on the measured host it was 16 against 11 denies, so the subtraction
   * explained away ten real denies and the page went back to saying everything
   * was fine. The producer now counts the cross and this reads it.
   *
   * FAILS ON REVERT: derive the number here again and the measured host stops
   * reporting its ten.
   */
  it("reads the producer's cross instead of subtracting the marginals", () => {
    // The measured host, exactly: 11 deny, 1 blocked, 16 screened (six of which
    // are allows), and ten denies whose outcome was not a block.
    const measured = headline({
      ...healthy,
      denyVerdicts: 11,
      blockedBeforeExecution: 1,
      screened: 16,
      deniesWithoutBlock: 10,
    });
    expect(measured.answer).toContain("10");
    // The marginals must not be able to talk it out of the number.
    const noisy = headline({
      ...healthy,
      denyVerdicts: 11,
      blockedBeforeExecution: 1,
      screened: 999,
      wouldBlock: 999,
      outcomesUnknown: 999,
      deniesWithoutBlock: 10,
    });
    expect(noisy.answer).toContain("10");
  });

  /**
   * A HEALTHY HOST MUST NOT BE PAINTED RED.
   *
   * A screened deny is the guard being ASKED and answering: there was no
   * execution to stop. Alarming over it would fill a working host with lights
   * about questions it got right, which teaches the operator to ignore the
   * screen. It reports the number and keeps the good tone, and it says the one
   * thing nobody can know.
   */
  it("reports a screened deny without raising an alarm", () => {
    const result = headline({
      ...healthy,
      denyVerdicts: 11,
      blockedBeforeExecution: 1,
      screened: 16,
      deniesWithoutBlock: 10,
    });
    expect(result.tone).toBe("good");
    expect(result.answer).toContain("Protecting");
    expect(result.next).toContain("not recorded");
    for (const alarming of ["breach", "attack", "succeeded", "failed", "unprotected"]) {
      expect(result.answer).not.toContain(alarming);
    }
  });

  /**
   * And the clean host still gets the clean sentence: no number is invented to
   * look busy.
   */
  it("says nothing needs you when every deny was stopped", () => {
    const result = headline({
      ...healthy,
      denyVerdicts: 11,
      blockedBeforeExecution: 11,
      deniesWithoutBlock: 0,
    });
    expect(result.answer).toBe("Protected. Nothing needs you.");
    expect(result.tone).toBe("good");
  });

  /**
   * Posture never calls an unpinned claim "enforcing", so the headline must not
   * send the reader there expecting that word.
   */
  it("does not promise Posture will name what is enforcing", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1, deniesWithoutBlock: 10 });
    expect(result.next).not.toContain("enforcing");
  });

  it("never says nothing needs you while unsafe verdicts have no block against them", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1, deniesWithoutBlock: 10 });
    expect(result.answer).not.toContain("Protected. Nothing needs you");
    expect(result.answer).toContain("10");
    expect(result.tone).toBe("good");
    expect(result.next).toContain("11");
    expect(result.next).toContain("1 stopped before execution");
    expect(result.next).toContain("not recorded");
  });

  /**
   * The input must be READ, which is the defect this pins. Two calls differing
   * in nothing but the number of blocks must not produce the same sentence.
   */
  it("changes its answer when the number of blocks changes", () => {
    const unstopped = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1, deniesWithoutBlock: 10 });
    const allStopped = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 11, deniesWithoutBlock: 0 });
    expect(unstopped.answer).not.toBe(allStopped.answer);
    expect(allStopped.answer).toBe("Protected. Nothing needs you.");
    // More blocks than deny verdicts is normal: a block can belong to a review
    // verdict. It must not turn into a negative count.
    expect(headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 14 }).answer).toBe(
      "Protected. Nothing needs you.",
    );
  });

  it("counts one unstopped action in the singular", () => {
    expect(headline({ ...healthy, denyVerdicts: 4, blockedBeforeExecution: 3, deniesWithoutBlock: 1 }).answer).toBe(
      "Protecting. 1 unsafe action judged, not stopped here",
    );
      expect(headline({ ...healthy, denyVerdicts: 4, blockedBeforeExecution: 2, deniesWithoutBlock: 2 }).answer).toBe(
        "Protecting. 2 unsafe actions judged, not stopped here",
    );
  });

  /**
   * The sentence accuses, so it may only say what the two counters support.
   * "Judged unsafe with no block recorded" is a fact about the record; "ran",
   * "succeeded" and "attacks" are claims this function has no evidence for.
   */
  it("reports the record, not an outcome it cannot see", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1, deniesWithoutBlock: 10 });
    expect(result.answer).not.toMatch(/attack|succeed|breach|compromis|ran\b/i);
    expect(result.answer).toContain("not stopped here");
  });

  /**
   * A host that sends no outcome figures at all has not said it stopped
   * nothing. Claiming a gap of eleven there would be the same over-claim in the
   * other direction, so the gap is not computed and not printed.
   */
  it("says the outcome is unrecorded rather than inventing a gap", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: null });
    expect(result.answer).toBe("11 judged unsafe, outcome not recorded");
    expect(result.answer).not.toContain("Protected. Nothing needs you");
      // A host reporting NO outcome at all is not the screened-deny case: the
      // product cannot see what happened, which is a visibility gap and does
      // deserve the operator's attention. It is also unreachable on a real
      // host today, since `actual_blocks` is always sent.
      expect(result.tone).toBe("attention");
      expect(result.next).toContain("no outcome");
  });

  it("mentions an unproven agent without making it the headline", () => {
    const result = headline({ ...healthy, unprovenAgents: 2 });
    expect(result.answer).toBe("Protecting");
    expect(result.next).toContain("2 agents");
    expect(result.tone).toBe("good");
  });

  it("always returns a sentence, whatever the numbers", () => {
    for (const needsReview of [0, 1, 999]) {
      for (const monitorOnly of [true, false]) {
        for (const unprovenAgents of [0, 5]) {
          const result = headline({ ...healthy, needsReview, monitorOnly, unprovenAgents });
          expect(result.answer.length).toBeGreaterThan(3);
        }
      }
    }
  });
});
