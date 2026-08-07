import { describe, expect, it } from "vitest";
import { providerCardSpanClass, providerGridClass } from "./TokenIntelligence";

/**
 * The same half empty box the agent grid had, one screen over. A flat
 * `lg:grid-cols-3` left two thirds of the row grey when a host reported one
 * provider, and one third grey at two, four, five. The cards now fill whatever
 * row they are in.
 */
describe("the provider grid fills the row it is given", () => {
  it("gives a single provider the whole width", () => {
    expect(providerGridClass(1)).toBe("grid gap-4");
    expect(providerCardSpanClass(0, 1)).toBe("");
  });

  it("splits the row between two providers instead of leaving a third empty", () => {
    expect(providerGridClass(2)).toBe("grid gap-4 md:grid-cols-2");
    expect(providerCardSpanClass(0, 2)).toBe("");
    expect(providerCardSpanClass(1, 2)).toBe("");
  });

  it("puts three across and closes the odd row at md", () => {
    expect(providerGridClass(3)).toBe("grid gap-4 md:grid-cols-2 lg:grid-cols-6");
    expect(providerCardSpanClass(0, 3)).toBe("lg:col-span-2");
    expect(providerCardSpanClass(1, 3)).toBe("lg:col-span-2");
    expect(providerCardSpanClass(2, 3)).toBe("md:col-span-2 lg:col-span-2");
  });

  it("widens a lone trailing card to the full row", () => {
    expect(providerCardSpanClass(3, 4)).toBe("lg:col-span-6");
  });

  it("splits a trailing pair in half rather than leaving a third empty", () => {
    expect(providerCardSpanClass(3, 5)).toBe("lg:col-span-3");
    expect(providerCardSpanClass(4, 5)).toBe("md:col-span-2 lg:col-span-3");
  });

  it("leaves a full row of six alone", () => {
    for (let index = 0; index < 6; index += 1) expect(providerCardSpanClass(index, 6)).toBe("lg:col-span-2");
  });

  it("is one column below the md breakpoint at every count from 1 to 6", () => {
    for (const count of [1, 2, 3, 4, 5, 6]) {
      for (const token of providerGridClass(count).split(" ")) {
        expect(token === "grid" || token === "gap-4" || token.startsWith("md:") || token.startsWith("lg:")).toBe(true);
      }
      for (let index = 0; index < count; index += 1) {
        for (const token of providerCardSpanClass(index, count).split(" ").filter(Boolean)) {
          expect(token.startsWith("md:") || token.startsWith("lg:")).toBe(true);
        }
      }
    }
  });
});
