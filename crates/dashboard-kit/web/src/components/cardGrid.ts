/**
 * Card grids that fill the row they are given.
 *
 * A fixed `grid-cols-N` is only correct when the number of cards happens to be
 * a multiple of N. Every other count leaves the tail of the last row empty, and
 * an empty cell beside a real card does not read as "this host has one agent",
 * it reads as a card that failed to load. The Overview panel already carried a
 * local fix for its own two-column case; this module is that idea, once, for
 * every card grid in the kit.
 *
 * Two rules:
 *
 * 1. The container asks for no more columns than there are cards, so a single
 *    card is never squeezed into half a page.
 * 2. A card in an incomplete final row widens to share that row equally, so
 *    the last row is as full as the ones above it.
 *
 * Both rules are expressed as WHOLE literal class names. Tailwind finds
 * utilities by scanning source text, so a name assembled at runtime compiles to
 * a class that exists in the markup and in no stylesheet: the card silently
 * loses its column and the bug only shows up in a built bundle.
 *
 * Every column and span class carries a breakpoint prefix. Below the smallest
 * prefix the grid is a single column at every count, so none of this can squeeze
 * a card into a strip on a phone.
 */

/**
 * How wide a grid is allowed to get, and from which breakpoint.
 *
 * `trio` counts in SIXTHS rather than thirds. A three-column row cannot split a
 * leftover row of two evenly, but a six-column grid can: two sixths is exactly
 * one third, three sixths is exactly one half, and six sixths is the full width,
 * with identical gap arithmetic in each case. So one grid expresses thirds,
 * halves and full rows without a second container class.
 */
export type CardGridShape = "pair-md" | "pair-lg" | "trio";

/** Join class fragments, dropping the empty ones so no stray spaces ship. */
export function joinClasses(...parts: (string | undefined | false | null)[]): string {
  return parts.filter((part): part is string => typeof part === "string" && part.length > 0).join(" ");
}

/**
 * The column class for a container holding `count` cards.
 *
 * Returns an empty string when the grid should stay one column, which is both
 * the single-card case and every viewport below the shape's breakpoint.
 */
export function gridColumnsClass(shape: CardGridShape, count: number): string {
  if (!Number.isFinite(count) || count <= 1) return "";
  switch (shape) {
    case "pair-md":
      return "md:grid-cols-2";
    case "pair-lg":
      return "lg:grid-cols-2";
    case "trio":
      // Two cards never need the six-column grid: at two columns they already
      // fill the row, and asking for sixths would only give them a third each.
      return count === 2 ? "md:grid-cols-2" : "md:grid-cols-2 lg:grid-cols-6";
  }
}

/**
 * The span class for the card at `index`, so the final row is never ragged.
 *
 * A card can carry a span for two breakpoints at once, because the row it ends
 * up in differs between them: five cards are three rows of two at `md` and two
 * rows (three then two) at `lg`. When both apply, the wider breakpoint wins,
 * which is Tailwind's own ordering and the reason the pair class is emitted
 * before the trio class rather than instead of it.
 */
export function gridSpanClass(shape: CardGridShape, index: number, count: number): string {
  if (!Number.isFinite(count) || !Number.isFinite(index)) return "";
  if (count <= 1 || index < 0 || index >= count) return "";
  const last = index === count - 1;
  const fillsPairRow = last && count % 2 === 1;
  switch (shape) {
    case "pair-md":
      return fillsPairRow ? "md:col-span-2" : "";
    case "pair-lg":
      return fillsPairRow ? "lg:col-span-2" : "";
    case "trio": {
      if (count === 2) return "";
      const leftover = count % 3;
      const trio = leftover === 1 && last
        ? "lg:col-span-6"
        : leftover === 2 && index >= count - 2
          ? "lg:col-span-3"
          : "lg:col-span-2";
      return joinClasses(fillsPairRow ? "md:col-span-2" : "", trio);
    }
  }
}
