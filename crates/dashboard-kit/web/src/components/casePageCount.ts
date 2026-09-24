import type { CaseListPage } from "../api/cases";

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
  page: Pick<CaseListPage, "rows_in_window" | "total_in_window" | "window_complete">,
): string {
  let label = `${counted(visible, "row", "rows")} on this page`;
  if (page.rows_in_window !== undefined) label += ` of ${number(page.rows_in_window)}`;
  if (page.total_in_window !== undefined) label += ` · ${counted(page.total_in_window, "case", "cases")} in this window`;
  const qualified = page.rows_in_window !== undefined || page.total_in_window !== undefined;
  if (qualified && page.window_complete === false) label += ", from a partial read";
  return label;
}

function counted(value: number, one: string, many: string): string {
  return `${number(value)} ${value === 1 ? one : many}`;
}

// One fixed locale, so the same count reads the same on every viewer's screen
// and in every test. `+ 0` turns -0 into 0, which would otherwise print "-0".
function number(value: number): string {
  return (value + 0).toLocaleString("en-US");
}
