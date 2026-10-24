import { describe, expect, it } from "vitest";
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import { readDecisionsPage } from "./api";
import { rowRuns, RUN_MINIMUM, runHolds } from "./rows";

const row = (id: string, key: string, session = "s1") => ({ id, reason: { key }, session });

describe("runs of alike rows", () => {
  it("folds three or more consecutive rows with the same reason and session", () => {
    const runs = rowRuns([row("a", "r1"), row("b", "r1"), row("c", "r1"), row("d", "r2")]);
    expect(runs.map((run) => [run.first.id, run.folded.map((item) => item.id)])).toEqual([
      ["a", ["b", "c"]],
      ["d", []],
    ]);
  });

  it("never folds two, a gap, or across a different session", () => {
    expect(rowRuns([row("a", "r1"), row("b", "r1")]).every((run) => run.folded.length === 0)).toBe(true);
    expect(rowRuns([row("a", "r1"), row("b", "r2"), row("c", "r1"), row("d", "r1")]).every((run) => run.folded.length === 0)).toBe(true);
    const sessions = rowRuns([row("a", "r1", "s1"), row("b", "r1", "s1"), row("c", "r1", "s2"), row("d", "r1", "s2")]);
    expect(sessions.every((run) => run.folded.length === 0)).toBe(true);
  });

  it("never folds rows that have no reason key", () => {
    expect(rowRuns([row("a", "none"), row("b", "none"), row("c", "none")]).length).toBe(3);
  });

  it("keeps every row: the count on the page is the rows it was sent", () => {
    const items = Array.from({ length: 25 }, (_, index) => row(String(index), index < 12 ? "r1" : `r${index}`));
    const runs = rowRuns(items);
    expect(runs.reduce((total, run) => total + 1 + run.folded.length, 0)).toBe(25);
  });

  it("knows when a folded run holds the open case, so it stays open", () => {
    const [run] = rowRuns([row("a", "r1"), row("b", "r1"), row("c", "r1")]);
    expect(runHolds(run, "c")).toBe(true);
    expect(runHolds(run, "a")).toBe(false);
    expect(runHolds(run, undefined)).toBe(false);
  });

  it("keeps the newest-first order of the page: a run sits where its first row is", () => {
    const items = [row("a", "r1"), row("b", "r2"), row("c", "r2"), row("d", "r2"), row("e", "r3")];
    expect(rowRuns(items).map((run) => run.first.id)).toEqual(["a", "b", "e"]);
  });

  it("folds by the reason and the session only, whatever happened to each command in the run", () => {
    const items = [
      { id: "a", reason: { key: "r1" }, session: "s1", outcomeKey: "would_have_refused" },
      { id: "b", reason: { key: "r1" }, session: "s1", outcomeKey: "flagged_ran" },
      { id: "c", reason: { key: "r1" }, session: "s1", outcomeKey: "refused_before_run" },
    ];
    const [run] = rowRuns(items);
    expect(run.folded.map((item) => item.outcomeKey)).toEqual(["flagged_ran", "refused_before_run"]);
    expect(RUN_MINIMUM).toBe(3);
  });

  /** The fixture's agent ran six build-cache scripts in a row: one row and "5 more in a row" after the first of them. */
  it("folds the fixture's run of build-cache scripts and nothing else on its first page", () => {
    const runs = rowRuns(readDecisionsPage(page1).items);
    const folded = runs.filter((run) => run.folded.length > 0);
    expect(folded.length).toBeGreaterThan(0);
    for (const run of folded) {
      expect(run.folded.every((item) => item.reason.key === run.first.reason.key && item.session === run.first.session)).toBe(true);
    }
    expect(runs.reduce((total, run) => total + 1 + run.folded.length, 0)).toBe(page1.items.length);
  });
});
