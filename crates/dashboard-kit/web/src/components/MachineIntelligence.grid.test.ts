import { describe, expect, it } from "vitest";
import { agentCardSpanClass, agentGridClass } from "./MachineIntelligence";

/**
 * The cards live in a `gap-px` grid over a `bg-slate-200` parent, so every cell
 * the cards do NOT fill shows that grey parent through. The tests below are
 * about those cells: at one agent the whole second column was grey, which read
 * as a card that had failed to load.
 */
describe("agent card grid", () => {
  it("gives a single agent the whole row", () => {
    const grid = agentGridClass(1);
    expect(grid).not.toContain("grid-cols-2");
    expect(agentCardSpanClass(0, 1)).toBe("");
  });

  it("puts two agents side by side", () => {
    expect(agentGridClass(2)).toContain("md:grid-cols-2");
    expect(agentCardSpanClass(0, 2)).toBe("");
    expect(agentCardSpanClass(1, 2)).toBe("");
  });

  it("widens the odd trailing card at three agents so no cell is left empty", () => {
    expect(agentGridClass(3)).toContain("md:grid-cols-2");
    expect(agentCardSpanClass(0, 3)).toBe("");
    expect(agentCardSpanClass(1, 3)).toBe("");
    expect(agentCardSpanClass(2, 3)).toBe("md:col-span-2");
  });

  it("closes the gap at every odd count, not only the one that was tested", () => {
    for (const count of [5, 7, 9, 11]) {
      expect(agentCardSpanClass(count - 1, count)).toBe("md:col-span-2");
      for (let index = 0; index < count - 1; index += 1) expect(agentCardSpanClass(index, count)).toBe("");
    }
  });

  it("leaves even counts alone, because they already fill both columns", () => {
    for (const count of [2, 4, 6, 12]) {
      for (let index = 0; index < count; index += 1) expect(agentCardSpanClass(index, count)).toBe("");
    }
  });

  it("never asks for more than two columns", () => {
    for (const count of [1, 2, 3, 8, 40]) {
      expect(agentGridClass(count)).not.toMatch(/grid-cols-([3-9]|\d\d)/);
    }
  });

  /**
   * Narrow viewports. Every column class carries the `md:` prefix, so below that
   * breakpoint the grid is one column at every count and the cards are never
   * squeezed into a half-width strip on a phone.
   */
  it("is a single column below the md breakpoint at every count", () => {
    for (const count of [1, 2, 3, 9]) {
      const columnClasses = agentGridClass(count).split(" ").filter((token) => token.includes("grid-cols-"));
      for (const token of columnClasses) expect(token.startsWith("md:")).toBe(true);
    }
    expect(agentCardSpanClass(2, 3)).toBe("md:col-span-2");
  });

  /**
   * The class strings must be literal in the source. Tailwind finds utilities by
   * scanning text, so a name built at runtime compiles to a class that is in the
   * markup and in no stylesheet -- the card would silently lose its column.
   */
  it("returns whole literal class names", () => {
    expect(agentGridClass(2)).toBe("grid gap-px bg-slate-200 md:grid-cols-2");
    expect(agentGridClass(1)).toBe("grid gap-px bg-slate-200");
  });
});
