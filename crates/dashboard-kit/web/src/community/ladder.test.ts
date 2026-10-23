import { describe, expect, it } from "vitest";
import { decidedWords, decisionLadder, messageLadder, MONITOR_NOT_REFUSED, NOT_CHECKED_AFTERWARDS, REVIEW_NOT_REFUSED } from "./ladder";
import { DECISION_OUTCOMES, MESSAGE_OUTCOMES, type DecisionOutcomeKey } from "./words";

function marks(outcomeKey: DecisionOutcomeKey, mode = "monitor", recommendation = "deny") {
  return Object.fromEntries(decisionLadder({ outcomeKey, mode, recommendation, decidedBy: "rules" }).map((step) => [step.key, step.mark]));
}

function refused(outcomeKey: DecisionOutcomeKey, mode: string) {
  return decisionLadder({ outcomeKey, mode, recommendation: "review", decidedBy: "rules" })[2];
}

describe("a decision's three steps", () => {
  it("is Seen, Decided, Refused, in that order, and nothing after", () => {
    const steps = decisionLadder({ outcomeKey: "refused_before_run", mode: "enforce", recommendation: "deny", decidedBy: "rules" });
    expect(steps.map((step) => step.label)).toEqual(["Seen", "Decided", "Refused"]);
    expect(NOT_CHECKED_AFTERWARDS).toBe("Not checked afterwards: Community does not look at what a command did after it ran.");
  });

  it("draws each outcome the way the spec's table says", () => {
    expect(marks("refused_before_run", "enforce")).toEqual({ seen: "done", decided: "done", refused: "done" });
    expect(marks("unsafe_may_have_run", "enforce")).toEqual({ seen: "done", decided: "done", refused: "no" });
    expect(marks("would_have_refused")).toEqual({ seen: "done", decided: "done", refused: "not_applicable" });
    expect(marks("flagged_ran", "enforce", "review").refused).toBe("not_applicable");
    expect(marks("checked_only", "check").refused).toBe("not_applicable");
    expect(marks("unplaced", "unknown").refused).toBe("unknown");
  });

  it("says why a step was not done, in the words a screen reader reads", () => {
    expect(refused("refused_before_run", "enforce").words).toBe("Refused before it ran");
    expect(refused("would_have_refused", "monitor").words).toBe(MONITOR_NOT_REFUSED);
    expect(refused("flagged_ran", "monitor").words).toBe(MONITOR_NOT_REFUSED);
    expect(refused("flagged_ran", "enforce").words).toBe(REVIEW_NOT_REFUSED);
    expect(REVIEW_NOT_REFUSED).toBe("Not refused: a review is recorded and, by default, still runs");
    expect(refused("unplaced", "unknown").words).toBe("Not recorded whether it was refused");
  });

  it("says the verdict and who decided, and never prints a token it has no words for", () => {
    expect(decidedWords("deny", "rules")).toBe("Deny, by InnerWarden's rules");
    expect(decidedWords("review", "llm")).toBe("Review, by your model's second opinion");
    expect(decidedWords("allow", "shadow-model")).toBe("Allow");
    expect(decidedWords("unknown", "shadow-model")).toBe("Decided");
    expect(decidedWords("unknown", "rules")).toBe("Decided by InnerWarden's rules");
  });

  /**
   * Community reads nothing back after the fact, so nothing is VERIFIED,
   * and nothing in Community waits on a person to decide a decision.
   * Monitor never reads as refused.
   */
  it("never draws a confirmed read back, a step waiting on a person, or monitor as refused", () => {
    for (const outcomeKey of DECISION_OUTCOMES) {
      for (const mode of ["monitor", "enforce", "check", "unknown"]) {
        const steps = decisionLadder({ outcomeKey, mode, recommendation: "deny", decidedBy: "rules" });
        for (const step of steps) {
          expect(["done", "no", "not_applicable", "unknown"], `${outcomeKey} ${mode} ${step.key}`).toContain(step.mark);
        }
        if (outcomeKey !== "refused_before_run") expect(steps[2].mark, `${outcomeKey} ${mode}`).not.toBe("done");
      }
    }
    for (const outcomeKey of MESSAGE_OUTCOMES) {
      for (const step of messageLadder(outcomeKey)) {
        expect(["done", "no", "not_applicable", "unknown"], `${outcomeKey} ${step.key}`).toContain(step.mark);
      }
    }
  });

  it("never refuses a message: observe records and does not block", () => {
    const steps = messageLadder("declined_by_agent");
    expect(steps.map((step) => step.mark)).toEqual(["done", "done", "not_applicable"]);
    expect(steps[2].words).toBe("Not refused: observe records and does not block");
    expect(messageLadder("not_seen")[1].mark).toBe("unknown");
  });

  /**
   * An outcome the record could not see is said as not seen, never "not
   * recorded", which reads as a recording fault; and a refusal by the guard
   * names who decided.
   */
  it("says an unseen outcome was not seen and names the guard when it refused", () => {
    for (const outcomeKey of ["not_seen", "unplaced"] as const) {
      const decided = messageLadder(outcomeKey)[1];
      expect(decided.words).toBe("Who decided could not be seen");
      expect(decided.words).not.toContain("recorded");
    }
    const stopped = messageLadder("stopped_by_innerwarden");
    expect(stopped[1]).toMatchObject({ mark: "done", words: "The guard refused what your agent tried" });
    expect(stopped[2]).toMatchObject({ mark: "done", words: "The guard refused it" });
  });
});
