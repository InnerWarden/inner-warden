import { describe, expect, it } from "vitest";
import { dominantOutcome, hatchFor, OUTCOME_STYLE, outcomeStyle, SEVERITY_ORDER, TONE_COLOUR } from "./outcomeStyle";
import { DECISION_OUTCOMES, MESSAGE_OUTCOMES, OUTCOME_WORDS } from "./words";

describe("how every outcome is drawn (spec 9.4)", () => {
  it("gives every outcome the CLI sends a shape, a colour and a fill, and words", () => {
    for (const key of [...DECISION_OUTCOMES, ...MESSAGE_OUTCOMES]) {
      const style = OUTCOME_STYLE[key];
      expect(style, key).toBeDefined();
      expect(TONE_COLOUR[style.tone], key).toMatch(/^var\(--iw-/);
      expect(OUTCOME_WORDS[key], key).toBeTruthy();
    }
    expect(Object.keys(OUTCOME_STYLE).sort()).toEqual(Object.keys(OUTCOME_WORDS).sort());
  });

  it("draws the table as written: shape for the rule, colour for what happened, hatching for monitor", () => {
    expect(OUTCOME_STYLE.refused_before_run).toEqual({ shape: "octagon", tone: "stopped", fill: "solid" });
    expect(OUTCOME_STYLE.would_have_refused).toEqual({ shape: "octagon", tone: "deny", fill: "hatched" });
    expect(OUTCOME_STYLE.unsafe_may_have_run).toEqual({ shape: "octagon", tone: "deny", fill: "solid" });
    expect(OUTCOME_STYLE.flagged_ran).toEqual({ shape: "diamond", tone: "review", fill: "solid" });
    expect(OUTCOME_STYLE.allowed).toEqual({ shape: "circle", tone: "allow", fill: "hollow" });
    expect(OUTCOME_STYLE.checked_only).toEqual({ shape: "square", tone: "ink", fill: "hollow" });
    expect(OUTCOME_STYLE.unplaced).toEqual({ shape: "circle", tone: "unknown", fill: "dashed" });
    expect(OUTCOME_STYLE.stopped_by_innerwarden).toEqual({ shape: "octagon", tone: "stopped", fill: "solid" });
    expect(OUTCOME_STYLE.declined_by_agent).toEqual({ shape: "circle", tone: "allow", fill: "solid" });
    expect(OUTCOME_STYLE.answered).toEqual({ shape: "diamond", tone: "review", fill: "solid" });
    expect(OUTCOME_STYLE.not_seen).toEqual({ shape: "circle", tone: "unknown", fill: "dashed" });
  });

  it("hatches only what would have happened, and only with words that say so", () => {
    for (const [key, style] of Object.entries(OUTCOME_STYLE)) {
      if (style.fill === "hatched") expect(OUTCOME_WORDS[key as keyof typeof OUTCOME_WORDS]).toMatch(/would have/i);
    }
    expect(hatchFor("deny")).toBe("iw-hatch-deny");
  });

  it("draws an outcome it does not know as not recorded, never as allowed", () => {
    expect(outcomeStyle("something_new")).toEqual(OUTCOME_STYLE.unplaced);
  });

  it("finds the outcome a set of counts is mostly made of, the most severe winning a tie", () => {
    expect(dominantOutcome({ flagged_ran: 15 })).toBe("flagged_ran");
    expect(dominantOutcome({ would_have_refused: 3, unsafe_may_have_run: 1 })).toBe("would_have_refused");
    expect(dominantOutcome({ would_have_refused: 2, unsafe_may_have_run: 2 })).toBe("unsafe_may_have_run");
    expect(dominantOutcome({})).toBeUndefined();
    expect(new Set(SEVERITY_ORDER).size).toBe(Object.keys(OUTCOME_STYLE).length);
  });
});
