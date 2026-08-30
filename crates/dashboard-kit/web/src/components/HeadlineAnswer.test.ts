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
