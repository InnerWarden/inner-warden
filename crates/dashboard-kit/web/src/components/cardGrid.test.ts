import { describe, expect, it } from "vitest";
import { gridColumnsClass, gridSpanClass, joinClasses, type CardGridShape } from "./cardGrid";

const SHAPES: CardGridShape[] = ["pair-md", "pair-lg", "trio"];

/**
 * How many grid units each card occupies at a given breakpoint, worked out from
 * the classes alone. The point of the whole module is that these add up to a
 * whole number of full rows, so the test computes the rows the browser would lay
 * out rather than asserting one class string per count.
 */
function valueOf(classes: string, prefix: "md" | "lg", utility: "col-span" | "grid-cols"): number | undefined {
  const match = new RegExp(` ${prefix}:${utility}-(\\d+) `).exec(` ${classes} `);
  return match ? Number(match[1]) : undefined;
}

/** A `lg:` class wins at `lg`; an `md:` class still applies there when it does not. */
function effective(classes: string, breakpoint: "md" | "lg", utility: "col-span" | "grid-cols"): number | undefined {
  if (breakpoint === "lg") return valueOf(classes, "lg", utility) ?? valueOf(classes, "md", utility);
  return valueOf(classes, "md", utility);
}

function unitsAt(shape: CardGridShape, index: number, count: number, breakpoint: "md" | "lg"): number {
  return effective(gridSpanClass(shape, index, count), breakpoint, "col-span") ?? 1;
}

function columnsAt(shape: CardGridShape, count: number, breakpoint: "md" | "lg"): number {
  return effective(gridColumnsClass(shape, count), breakpoint, "grid-cols") ?? 1;
}

/** The grid units every row would hold, in order. */
function rows(shape: CardGridShape, count: number, breakpoint: "md" | "lg"): number[] {
  const columns = columnsAt(shape, count, breakpoint);
  const laidOut: number[] = [];
  let current = 0;
  for (let index = 0; index < count; index += 1) {
    const units = unitsAt(shape, index, count, breakpoint);
    if (current + units > columns) {
      laidOut.push(current);
      current = 0;
    }
    current += units;
  }
  if (current > 0) laidOut.push(current);
  return laidOut;
}

describe("card grid", () => {
  it.each(SHAPES)("leaves no empty cell at any count from 1 to 6 (%s)", (shape) => {
    for (const count of [1, 2, 3, 4, 5, 6]) {
      for (const breakpoint of ["md", "lg"] as const) {
        const columns = columnsAt(shape, count, breakpoint);
        expect(`${shape}/${count}/${breakpoint}: ${rows(shape, count, breakpoint).join(",")}`)
          .toBe(`${shape}/${count}/${breakpoint}: ${rows(shape, count, breakpoint).map(() => columns).join(",")}`);
      }
    }
  });

  it.each(SHAPES)("keeps filling every row well past six cards (%s)", (shape) => {
    for (let count = 7; count <= 24; count += 1) {
      for (const breakpoint of ["md", "lg"] as const) {
        const columns = columnsAt(shape, count, breakpoint);
        for (const row of rows(shape, count, breakpoint)) {
          expect(`${shape}/${count}/${breakpoint}: row of ${row}`).toBe(`${shape}/${count}/${breakpoint}: row of ${columns}`);
        }
      }
    }
  });

  /**
   * The narrow-viewport promise. Every column and span class is behind a
   * breakpoint, so below `md` the grid is one column at every count and a card
   * can never be squeezed into a half-width strip on a phone.
   */
  it.each(SHAPES)("is a single column below the md breakpoint at every count (%s)", (shape) => {
    for (let count = 1; count <= 12; count += 1) {
      for (const token of gridColumnsClass(shape, count).split(" ").filter(Boolean)) {
        expect(token.startsWith("md:") || token.startsWith("lg:")).toBe(true);
      }
      for (let index = 0; index < count; index += 1) {
        for (const token of gridSpanClass(shape, index, count).split(" ").filter(Boolean)) {
          expect(token.startsWith("md:") || token.startsWith("lg:")).toBe(true);
        }
      }
    }
  });

  it("gives a single card the whole width in every shape", () => {
    for (const shape of SHAPES) {
      expect(gridColumnsClass(shape, 1)).toBe("");
      expect(gridSpanClass(shape, 0, 1)).toBe("");
    }
  });

  /**
   * Tailwind scans source text for utilities, so a name built at runtime exists
   * in the markup and in no stylesheet. These are the exact strings that must
   * appear literally in `cardGrid.ts`.
   */
  it("returns whole literal class names", () => {
    expect(gridColumnsClass("pair-md", 2)).toBe("md:grid-cols-2");
    expect(gridColumnsClass("pair-lg", 2)).toBe("lg:grid-cols-2");
    expect(gridColumnsClass("trio", 2)).toBe("md:grid-cols-2");
    expect(gridColumnsClass("trio", 3)).toBe("md:grid-cols-2 lg:grid-cols-6");
    expect(gridSpanClass("pair-md", 2, 3)).toBe("md:col-span-2");
    expect(gridSpanClass("pair-lg", 2, 3)).toBe("lg:col-span-2");
    expect(gridSpanClass("trio", 2, 3)).toBe("md:col-span-2 lg:col-span-2");
    expect(gridSpanClass("trio", 3, 4)).toBe("lg:col-span-6");
    expect(gridSpanClass("trio", 4, 5)).toBe("md:col-span-2 lg:col-span-3");
  });

  it("ignores an index that is not on the grid", () => {
    expect(gridSpanClass("trio", -1, 5)).toBe("");
    expect(gridSpanClass("trio", 5, 5)).toBe("");
    expect(gridSpanClass("pair-lg", Number.NaN, 5)).toBe("");
    expect(gridColumnsClass("pair-lg", Number.NaN)).toBe("");
  });

  it("joins only the fragments that carry a class", () => {
    expect(joinClasses("grid gap-4", "", undefined, null, false, "lg:grid-cols-2")).toBe("grid gap-4 lg:grid-cols-2");
    expect(joinClasses("", undefined)).toBe("");
  });
});
