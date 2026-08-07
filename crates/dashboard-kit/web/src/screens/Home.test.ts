import { describe, expect, it } from "vitest";
import { decisionEntryLink, decisionRecordCta, missingOverviewFields } from "./Home";
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

/**
 * Where a recent-activity entry leads. The production failure this pins: on an
 * Enterprise host every Home entry navigated to `?view=activity`, a route the
 * paid shell does not offer, so the shell bounced straight back to Overview
 * and every click went NOWHERE.
 */
describe("decisionEntryLink", () => {
  it("deep-links to the case the server named, when Cases can open", () => {
    expect(decisionEntryLink("case:incident:abc", "enterprise", true)).toEqual({
      kind: "case",
      caseId: "case:incident:abc",
    });
  });

  // Community's Activity screen IS its case surface: same decisions, same
  // graph, one place. A second case list over the same records would recreate
  // the two-places problem this change exists to end.
  it("sends a Community entry to Activity, its case surface", () => {
    expect(decisionEntryLink(undefined, "community", false)).toEqual({ kind: "activity" });
  });

  it("keeps a case link working on Community if a server ever names one there", () => {
    expect(decisionEntryLink("case:x:1", "community", true)).toEqual({ kind: "case", caseId: "case:x:1" });
  });

  it("makes an Enterprise entry without a case inert instead of a dead link", () => {
    expect(decisionEntryLink(undefined, "enterprise", true)).toEqual({ kind: "none" });
    expect(decisionEntryLink("case:x:1", "enterprise", false)).toEqual({ kind: "none" });
  });

  it("stays inert while the edition is unresolved", () => {
    expect(decisionEntryLink(undefined, undefined, false)).toEqual({ kind: "none" });
  });
});

describe("decisionRecordCta", () => {
  it("offers Community its activity record", () => {
    expect(decisionRecordCta("community", false)).toEqual({ kind: "activity", label: "View all activity" });
  });

  it("offers Enterprise the Cases screen when the shell mounts one", () => {
    expect(decisionRecordCta("enterprise", true)).toEqual({ kind: "cases", label: "View all in Cases" });
  });

  // The pre-change behaviour: the button said "View all activity" on a shell
  // with no Activity tab, and clicking it landed back on Overview.
  it("hides the button rather than rendering a link to nowhere", () => {
    expect(decisionRecordCta("enterprise", false).kind).toBe("hidden");
    expect(decisionRecordCta(undefined, false).kind).toBe("hidden");
  });
});
