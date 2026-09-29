/**
 * Runs of alike rows on one page of cases.
 *
 * An agent that trips the same rule forty times in a row fills the list with
 * forty identical-looking rows and pushes everything else off the page. Three
 * or more CONSECUTIVE rows, in the order the server sent them, with the same
 * reason key AND the same session, fold under their first row. Grouped by
 * structured keys only (the CLI's reason key and the session label), never by
 * reading a title; never across a different session, which is a different
 * run of work; never across pages, which the page does not hold.
 */

export const RUN_MINIMUM = 3;

export type Run<T> = { first: T; folded: T[] };

export function rowRuns<T extends { reason: { key: string }; session: string }>(items: readonly T[]): Run<T>[] {
  const runs: Run<T>[] = [];
  let at = 0;
  while (at < items.length) {
    const first = items[at];
    let end = at + 1;
    while (
      end < items.length
      && items[end].reason.key === first.reason.key
      && items[end].session === first.session
      && first.reason.key !== "none"
    ) {
      end += 1;
    }
    if (end - at >= RUN_MINIMUM) {
      runs.push({ first, folded: items.slice(at + 1, end) });
    } else {
      for (let index = at; index < end; index += 1) runs.push({ first: items[index], folded: [] });
    }
    at = end;
  }
  return runs;
}

/** Whether a run holds the open case among its folded rows: it then stays open. */
export function runHolds<T extends { id: string }>(run: Run<T>, openId: string | undefined): boolean {
  return openId !== undefined && run.folded.some((item) => item.id === openId);
}
