import { describe, expect, it } from "vitest";
import { caseLadder, messageLadder } from "./ladder";
import { DECISION_OUTCOMES, MESSAGE_OUTCOMES, type DecisionOutcomeKey } from "./words";

function marks(outcomeKey: DecisionOutcomeKey, mode = "monitor") {
  return Object.fromEntries(caseLadder({ outcomeKey, mode, decidedBy: "rules" }).map((step) => [step.key, step.mark]));
}

describe("a case's four steps", () => {
  it("draws each outcome the way the spec's table says", () => {
    expect(marks("refused_before_run", "enforce")).toEqual({ seen: "done", decided: "done", enforced: "done", verified: "unknown" });
    expect(marks("unsafe_may_have_run", "enforce")).toEqual({ seen: "done", decided: "done", enforced: "no", verified: "not_applicable" });
    expect(marks("would_have_refused")).toEqual({ seen: "done", decided: "done", enforced: "not_applicable", verified: "not_applicable" });
    expect(marks("flagged_ran", "enforce").enforced).toBe("not_applicable");
    expect(marks("checked_only", "check").enforced).toBe("not_applicable");
    expect(marks("unplaced", "unknown").enforced).toBe("unknown");
  });

  it("says why a step was not done, in the words a screen reader reads", () => {
    const monitor = caseLadder({ outcomeKey: "flagged_ran", mode: "monitor", decidedBy: "rules" });
    const enforce = caseLadder({ outcomeKey: "flagged_ran", mode: "enforce", decidedBy: "rules" });
    expect(monitor[2].words).toContain("monitor mode");
    expect(enforce[2].words).toContain("only a deny is refused");
    expect(monitor[1].words).toBe("decided by InnerWarden's rules");
    // A decider this bundle has no words for gets none, never the token.
    expect(caseLadder({ outcomeKey: "flagged_ran", mode: "monitor", decidedBy: "shadow-model" })[1].words).toBe("decided");
  });

  /**
   * Community reads nothing back after the fact, so nothing is VERIFIED
   * (emerald), and nothing in Community waits on a person to decide a case
   * (amber). FAILS ON REVERT: mark Verified done for a refused case.
   */
  it("never draws a confirmed read back or a step waiting on a person", () => {
    for (const outcomeKey of DECISION_OUTCOMES) {
      for (const mode of ["monitor", "enforce", "check", "unknown"]) {
        for (const step of caseLadder({ outcomeKey, mode, decidedBy: "rules" })) {
          expect(step.mark, `${outcomeKey} ${mode} ${step.key}`).not.toBe("verified");
          expect(step.mark, `${outcomeKey} ${mode} ${step.key}`).not.toBe("waiting");
        }
      }
    }
    for (const outcomeKey of MESSAGE_OUTCOMES) {
      for (const step of messageLadder(outcomeKey)) {
        expect(step.mark, `${outcomeKey} ${step.key}`).not.toBe("verified");
        expect(step.mark, `${outcomeKey} ${step.key}`).not.toBe("waiting");
      }
    }
  });

  it("never enforces a message: observe records and does not block", () => {
    const steps = messageLadder("declined_by_agent");
    expect(steps.map((step) => step.mark)).toEqual(["done", "done", "not_applicable", "not_applicable"]);
    expect(messageLadder("not_seen")[1].mark).toBe("unknown");
  });

  /**
   * An outcome the record could not see is said as not seen, never "not
   * recorded", which reads as a recording fault; and a refusal by the guard
   * names who decided. FAILS ON REVERT: the old ladder printed "who decided
   * was not recorded" for both.
   */
  it("says an unseen outcome was not seen and names the guard when it refused", () => {
    for (const outcomeKey of ["not_seen", "unplaced"] as const) {
      const decided = messageLadder(outcomeKey)[1];
      expect(decided.words).toBe("who decided could not be seen");
      expect(decided.words).not.toContain("recorded");
    }
    const stopped = messageLadder("stopped_by_innerwarden");
    expect(stopped[1]).toMatchObject({ mark: "done", words: "the guard refused what your agent tried" });
    expect(stopped[2]).toMatchObject({ mark: "done", words: "the guard refused it" });
  });
});
