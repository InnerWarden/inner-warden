import { describe, expect, it } from "vitest";

import { parseCaseListPage } from "../api/cases";
import { casePageCountLabel } from "./casePageCount";

/**
 * The pages walk ROWS (a finding seen three times is one row) and the window
 * holds CASES (counted before that fold, so per-filter totals add up). The
 * count line names each number by its own unit, and the "of" after the rows
 * is only ever the row total.
 */
describe("the case page count line", () => {
  it("pages against the row total and names the case total separately", () => {
    const label = casePageCountLabel(20, { rows_in_window: 312, total_in_window: 4_394, window_complete: true });
    expect(label).toBe("20 rows on this page of 312 · 4,394 cases in this window");
  });

  /**
   * THE DEFECT. With `total_in_window` counting cases, an "of" taken from it
   * puts 4,394 under a count of rows the pages can never reach. A server that
   * did not send the row total leaves the rows with no "of" at all, rather
   * than borrowing the case total for it.
   */
  it("never uses the case total as the denominator of the rows", () => {
    const withRows = casePageCountLabel(20, { rows_in_window: 312, total_in_window: 4_394, window_complete: true });
    expect(withRows).not.toContain("of 4,394");
    const withoutRows = casePageCountLabel(20, { total_in_window: 4_394, window_complete: true });
    expect(withoutRows).toBe("20 rows on this page · 4,394 cases in this window");
    expect(withoutRows).not.toContain(" of ");
  });

  it("reads the numbers straight from a parsed server page", () => {
    const page = parseCaseListPage({
      schema_version: "innerwarden.dashboard.v1",
      generated_at: "2026-09-24T08:00:00Z",
      items: [],
      next_cursor: null,
      window: "7d",
      total_in_window: 4_394,
      window_complete: true,
      rows_in_window: 312,
    });
    expect(casePageCountLabel(20, page)).toBe("20 rows on this page of 312 · 4,394 cases in this window");
  });

  it("says only what the page shows when the server sent neither total", () => {
    expect(casePageCountLabel(0, {})).toBe("0 rows on this page");
    expect(casePageCountLabel(2, {})).toBe("2 rows on this page");
  });

  it("gives the row total without a window, and invents no case total", () => {
    const label = casePageCountLabel(20, { rows_in_window: 312 });
    expect(label).toBe("20 rows on this page of 312");
    expect(label).not.toContain("cases");
  });

  it("uses the singular for one of each", () => {
    expect(casePageCountLabel(1, { rows_in_window: 1, total_in_window: 1, window_complete: true }))
      .toBe("1 row on this page of 1 · 1 case in this window");
  });

  /**
   * A partial read is a bounded tail of the sources, and its numbers can FALL
   * while the store grows (one host read 4,924 and then 4,922). So it is never
   * "at least N"; the line says the read was partial.
   */
  it("says a partial read was partial, and never calls it a floor", () => {
    const label = casePageCountLabel(20, { rows_in_window: 312, total_in_window: 4_394, window_complete: false });
    expect(label).toBe("20 rows on this page of 312 · 4,394 cases in this window, from a partial read");
    expect(label).not.toContain("at least");
  });

  /**
   * -0 is an integer and not below zero, so it reaches the label from any
   * caller that did not go through the parser, and used to print "of -0".
   */
  it("prints a negative zero as 0", () => {
    expect(casePageCountLabel(0, { rows_in_window: -0, total_in_window: -0, window_complete: true }))
      .toBe("0 rows on this page of 0 · 0 cases in this window");
  });

  it("does not qualify a line that carries no total", () => {
    expect(casePageCountLabel(3, { window_complete: false })).toBe("3 rows on this page");
  });
});
