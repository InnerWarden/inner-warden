import { describe, expect, it } from "vitest";
import { countWords } from "./readCount";
import { compactCount } from "./presentation";

describe("a count that says what it promises", () => {
  it("is just the number when the read was complete, whatever it promised", () => {
    for (const promise of ["floor", "sample"] as const) {
      expect(countWords(202, true, promise, "sentence")).toBe("202");
      expect(countWords(2_420, true, promise, "inline")).toBe("2,420");
    }
    expect(countWords(2_420, true, "sample", "badge")).toBe("2,420");
  });

  it("is AT LEAST for a floor: every case counted exists, and more can only add", () => {
    expect(countWords(202, false, "floor", "sentence")).toBe("At least 202");
    expect(countWords(1, false, "floor", "inline")).toBe("at least 1");
  });

  it("is ABOUT for a sample, which can fall as the store grows", () => {
    expect(countWords(2_420, false, "sample", "sentence")).toBe("About 2,420");
    expect(countWords(2_420, false, "sample", "inline")).toBe("about 2,420");
    expect(countWords(2_420, false, "sample", "badge")).toBe("~2,420");
  });

  it("has no badge for a floor: a floor asked for as a badge is a programming error", () => {
    expect(() => countWords(4, false, "floor", "badge")).toThrow();
  });
});

describe("a large count in words", () => {
  it("rounds only what a reader cannot hold whole", () => {
    expect(compactCount(14_225)).toBe("14,225");
    expect(compactCount(99_999)).toBe("99,999");
    expect(compactCount(412_000)).toBe("412 thousand");
    expect(compactCount(38_308_385)).toBe("38 million");
    expect(compactCount(2_316_740_339n)).toBe("2.3 billion");
    expect(compactCount(1_000_000_000n)).toBe("1.0 billion");
    expect(compactCount(0)).toBe("0");
  });

  it("keeps one decimal below ten of a million or more, so neighbours read alike", () => {
    expect(compactCount(1_312_354_350n)).toBe("1.3 billion");
    expect(compactCount(1_004_385_989n)).toBe("1.0 billion");
    expect(compactCount(2_000_000)).toBe("2.0 million");
    expect(compactCount(10_400_000)).toBe("10 million");
  });

  /** FAILS ON REVERT: the old rounding said "1,000 thousand" and "1,000 million". */
  it("moves up a scale when the rounding reaches a thousand", () => {
    expect(compactCount(999_960)).toBe("1.0 million");
    expect(compactCount(999_960_000)).toBe("1.0 billion");
    expect(compactCount(999_499)).toBe("999 thousand");
    expect(compactCount(9_960_000)).toBe("10 million");
  });
});
