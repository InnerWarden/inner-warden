import { describe, expect, it } from "vitest";
import { rowRuns, runHolds } from "./rows";

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
});
