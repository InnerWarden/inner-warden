import type { CaseListPage } from "../api/cases";
import { LANE_WINDOW_PHRASE } from "../lanes";
import { formatCount } from "../presentation";
import { countWords } from "../readCount";

/**
 * The count line above a page of cases: "20 rows on this page of 312 · 4,394
 * cases in this window".
 *
 * Two different numbers, and the line names both units because they are not
 * the same thing. The pages walk ROWS: a finding seen three times is folded
 * into one row. The window holds CASES, counted before that fold, which is
 * what lets the totals under each filter value add up to the unfiltered one.
 * The old line, "20 on this page of 4,394 in window", took its "of" from
 * `total_in_window`, which now counts cases: it would put a case total under
 * a row count. On the challenge box two folded groups of 134 and 140 cases
 * are 2 rows, so walking every page would end 272 short of that number.
 *
 * So the "of M" after the rows is `rows_in_window` and nothing else, and the
 * case total is its own clause. Each piece appears only when the server sent
 * it: absent is not reported, never zero, and no number stands in for another.
 *
 * `window_complete === false` means the server read a bounded tail of its
 * sources, so the numbers describe that read, not the whole window. They can
 * fall while the store grows, so the line never says "at least"; it says the
 * read was partial.
 */
export function casePageCountLabel(
  visible: number,
  page: Pick<CaseListPage, "rows_in_window" | "total_in_window" | "window_complete" | "window">,
): string {
  let label = `${counted(visible, "row", "rows")} on this page`;
  if (page.rows_in_window !== undefined) label += ` of ${number(page.rows_in_window)}`;
  // The span by name when the server echoed it ("in the last 7 days"): "in
  // this window" left the reader to find which window that was.
  const span = page.window === undefined ? "in this window" : LANE_WINDOW_PHRASE[page.window];
  const qualified = page.rows_in_window !== undefined || page.total_in_window !== undefined;
  const partial = qualified && page.window_complete === false;
  // A partial read says "about" before the figure it cannot vouch for and
  // where it counted from, in words: "from a partial read" after two counts
  // in two units could not be parsed in a glance.
  // A SAMPLE of a truncated read, never a floor: `readCount.ts`.
  if (page.total_in_window !== undefined) {
    const total = page.total_in_window;
    label += ` · ${countWords(total, !partial, "sample", "inline")} ${total === 1 ? "case" : "cases"} ${span}`;
  }
  if (partial) label += " (counted from the newest records)";
  return label;
}

function counted(value: number, one: string, many: string): string {
  return `${number(value)} ${value === 1 ? one : many}`;
}

// One fixed locale, so the same count reads the same on every viewer's screen
// and in every test (`formatCount`).
function number(value: number): string {
  return formatCount(value);
}

/**
 * The badge the count line wears: the list's state, never a promise the line
 * does not make. A green check sat on "from a partial read", which reads as
 * all clear over numbers that describe only part of the window. A partial
 * read is neutral, and a list being refreshed says so.
 */
export function casePageCountBadge(
  visible: number,
  page: Pick<CaseListPage, "rows_in_window" | "total_in_window" | "window_complete" | "window">,
  stale: boolean,
): { status: "stale" | "partial" | "available"; label: string } {
  const label = casePageCountLabel(visible, page);
  if (stale) return { status: "stale", label };
  const qualified = page.rows_in_window !== undefined || page.total_in_window !== undefined;
  return { status: qualified && page.window_complete === false ? "partial" : "available", label };
}
