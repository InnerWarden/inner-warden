import { describe, expect, it } from "vitest";
import { caseViewUrl, EMPTY_CASE_VIEW, readCaseViewState } from "./CaseFilters";

/**
 * The status filter travels in the address bar like every other Cases
 * filter, and is validated on the way back in. These pin the two halves of
 * that round trip for the value the Overview's queue link writes, and for the
 * values the host never produces.
 */
describe("the status filter in the address bar", () => {
  it("reads the queue and each reachable status", () => {
    for (const status of ["waiting", "needs_review", "open", "contained"]) {
      expect(readCaseViewState(`?view=cases&status=${status}`).status).toBe(status);
    }
  });

  /**
   * `dismissed`, `closed` and `observing` exist on the host's enum and no
   * projector assigns them. A URL naming one falls back to no filter rather
   * than to a dropdown value the operator cannot see.
   */
  it("drops a status the host never produces, and junk", () => {
    for (const status of ["dismissed", "closed", "observing", "unknown", "WAITING", "", "*"]) {
      expect(readCaseViewState(`?view=cases&status=${encodeURIComponent(status)}`).status).toBe("");
    }
    expect(readCaseViewState("?view=cases").status).toBe("");
  });

  it("writes the status when set and omits it when clear", () => {
    const base = "https://dashboard.test/?view=overview";
    const withQueue = caseViewUrl({ ...EMPTY_CASE_VIEW, status: "waiting" }, base);
    expect(withQueue.searchParams.get("status")).toBe("waiting");
    expect(withQueue.searchParams.get("view")).toBe("cases");
    const clear = caseViewUrl({ ...EMPTY_CASE_VIEW, status: "" }, `${base}&status=waiting`);
    expect(clear.searchParams.get("status")).toBeNull();
  });

  it("survives a round trip through the address bar", () => {
    const state = { ...EMPTY_CASE_VIEW, status: "contained" as const, severity: "high" as const, window: "7d" as const };
    const url = caseViewUrl(state, "https://dashboard.test/");
    const back = readCaseViewState(url.search);
    expect(back.status).toBe("contained");
    expect(back.severity).toBe("high");
    expect(back.window).toBe("7d");
  });
});
