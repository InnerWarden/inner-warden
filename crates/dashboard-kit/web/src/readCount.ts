import { formatCount } from "./presentation";

/**
 * What a count promises when its producer could not read everything.
 *
 * Two different promises, and the words must keep them apart:
 *
 *  - `floor`: every item counted exists, and what the read did not reach can
 *    only add more. The paid host's waiting count is one: a capped read that
 *    found 202 waiting cases proves at least 202 are waiting. "At least" is
 *    true of it.
 *  - `sample`: a count over a truncated projection of the store. It can FALL
 *    while the store grows (a window read 4,924 cases and then 4,922), so it
 *    is never "at least"; it is "about".
 *
 * A complete count, of either kind, is just the number.
 */
export type CountPromise = "floor" | "sample";

export type CountStyle = "sentence" | "inline" | "badge";

/**
 * A count in words, by what it promises and where it is printed:
 *
 * - complete: "202"
 * - floor, incomplete: sentence "At least 202", inline "at least 202"
 * - sample, incomplete: sentence "About 2,420", inline "about 2,420", badge "~2,420"
 *
 * A floor has no badge form: a badge is too short to say "at least", and a
 * "~" would turn a floor into a sample. Asking for one is a programming
 * error, and it throws outside production builds.
 */
export function countWords(count: number, complete: boolean, promise: CountPromise, style: CountStyle): string {
  const figure = formatCount(count);
  if (complete) return figure;
  if (promise === "floor") {
    if (style === "badge") {
      if (import.meta.env?.DEV !== false) throw new Error("a floor count has no badge form");
      return figure;
    }
    return style === "sentence" ? `At least ${figure}` : `at least ${figure}`;
  }
  if (style === "badge") return `~${figure}`;
  return style === "sentence" ? `About ${figure}` : `about ${figure}`;
}
