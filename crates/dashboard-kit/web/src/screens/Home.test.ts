import { describe, expect, it } from "vitest";
import { missingOverviewFields } from "./Home";
import type { Overview } from "../api";

function overview(extra: Record<string, unknown>): Overview {
  return {
    commands: 0,
    sessions: 0,
    blocked: 0,
    review: 0,
    allowed: 0,
    top_categories: [],
    recent_blocks: [],
    ...extra,
  } as unknown as Overview;
}

describe("missingOverviewFields", () => {
  it("accepts a payload that honours the contract", () => {
    expect(missingOverviewFields(overview({}))).toEqual([]);
  });

  // The production failure: a server answered without these, the screen sliced
  // undefined during render, and the whole dashboard went white with no message.
  it("names a missing top_categories instead of letting the render throw", () => {
    expect(missingOverviewFields(overview({ top_categories: undefined }))).toEqual([
      "top_categories",
    ]);
  });

  it("accepts either recent field, and reports only when BOTH are absent", () => {
    expect(missingOverviewFields(overview({ recent_blocks: undefined, recent_decisions: [] }))).toEqual([]);
    expect(
      missingOverviewFields(overview({ recent_blocks: undefined, recent_decisions: undefined })),
    ).toEqual(["recent_decisions/recent_blocks"]);
  });

  /// An empty array is a host with nothing to report. An absent field is a
  /// producer that did not answer. Collapsing them would tell an operator their
  /// host is quiet when in truth nobody asked.
  it("does not confuse an empty list with an absent one", () => {
    expect(missingOverviewFields(overview({ top_categories: [] }))).toEqual([]);
  });
});
