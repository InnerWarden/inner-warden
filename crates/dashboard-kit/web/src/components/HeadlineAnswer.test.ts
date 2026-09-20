import { describe, expect, it } from "vitest";
import { headline } from "./HeadlineAnswer";

const healthy = {
  needsReview: 0,
  denyVerdicts: 0,
  blockedBeforeExecution: 0,
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
      expect(result.answer).not.toContain("Protected");
      expect(result.tone).toBe("attention");
      expect(result.next, "a queued state must say where to go").toBeTruthy();
    }
  });

  it("counts one action in the singular, because 1 actions is a tell", () => {
    expect(headline({ ...healthy, needsReview: 1 }).answer).toBe("1 action needs your decision");
    expect(headline({ ...healthy, needsReview: 2 }).answer).toBe("2 actions need your decision");
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
  it("never says protected while unsafe verdicts have no block against them", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1 });
    expect(result.answer).not.toContain("Protected");
    expect(result.answer).toContain("10");
    expect(result.tone).toBe("attention");
    expect(result.next).toContain("11");
    expect(result.next).toContain("1 stopped before execution");
    expect(result.next).toContain("Posture");
  });

  /**
   * The input must be READ, which is the defect this pins. Two calls differing
   * in nothing but the number of blocks must not produce the same sentence.
   */
  it("changes its answer when the number of blocks changes", () => {
    const unstopped = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1 });
    const allStopped = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 11 });
    expect(unstopped.answer).not.toBe(allStopped.answer);
    expect(allStopped.answer).toBe("Protected. Nothing needs you.");
    // More blocks than deny verdicts is normal: a block can belong to a review
    // verdict. It must not turn into a negative count.
    expect(headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 14 }).answer).toBe(
      "Protected. Nothing needs you.",
    );
  });

  it("counts one unstopped action in the singular", () => {
    expect(headline({ ...healthy, denyVerdicts: 4, blockedBeforeExecution: 3 }).answer).toBe(
      "1 unsafe action judged, no block recorded",
    );
    expect(headline({ ...healthy, denyVerdicts: 4, blockedBeforeExecution: 2 }).answer).toBe(
      "2 unsafe actions judged, no block recorded",
    );
  });

  /**
   * The sentence accuses, so it may only say what the two counters support.
   * "Judged unsafe with no block recorded" is a fact about the record; "ran",
   * "succeeded" and "attacks" are claims this function has no evidence for.
   */
  it("reports the record, not an outcome it cannot see", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: 1 });
    expect(result.answer).not.toMatch(/attack|succeed|breach|compromis|ran\b/i);
    expect(result.answer).toContain("no block recorded");
  });

  /**
   * A host that sends no outcome figures at all has not said it stopped
   * nothing. Claiming a gap of eleven there would be the same over-claim in the
   * other direction, so the gap is not computed and not printed.
   */
  it("says the outcome is unrecorded rather than inventing a gap", () => {
    const result = headline({ ...healthy, denyVerdicts: 11, blockedBeforeExecution: null });
    expect(result.answer).toBe("11 judged unsafe, outcome not recorded");
    expect(result.answer).not.toContain("Protected");
    expect(result.tone).toBe("attention");
    expect(result.next).toContain("Posture");
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
