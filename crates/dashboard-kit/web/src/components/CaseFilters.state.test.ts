import { describe, expect, it } from "vitest";
import { caseViewUrl, DEFAULT_CASE_WINDOW, EMPTY_CASE_VIEW, readCaseViewState } from "./CaseFilters";

/**
 * The status filter travels in the address bar like every other Cases
 * filter, and is validated on the way back in. These pin the two halves of
 * that round trip for the value the Overview's queue link writes, and for the
 * values the host never produces.
 */
describe("the status filter in the address bar", () => {
  it("reads the queue and each reachable status", () => {
    for (const status of ["waiting", "needs_review", "open", "observing", "contained"]) {
      expect(readCaseViewState(`?view=cases&status=${status}`).status).toBe(status);
    }
  });

  /**
   * `dismissed` and `closed` exist on the host's enum and no projector
   * assigns them. A URL naming one falls back to no filter rather
   * than to a dropdown value the operator cannot see.
   */
  it("drops a status the host never produces, and junk", () => {
    for (const status of ["dismissed", "closed", "unknown", "WAITING", "", "*"]) {
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

/**
 * Cases opens on the span the Overview's cards count. It opened on the last
 * 24 hours while the cards counted 7 days, so a reader who read "4 messages
 * in the last 7 days" and pressed the Cases tab found 2, over a span nothing
 * on screen named.
 *
 * FAILS ON REVERT: put the default back to 24h and both halves read it.
 */
describe("the span Cases opens on", () => {
  it("is the last 7 days when the address names none, and is left out of the address", () => {
    expect(DEFAULT_CASE_WINDOW).toBe("7d");
    expect(readCaseViewState("?view=cases").window).toBe("7d");
    expect(caseViewUrl(EMPTY_CASE_VIEW, "https://dashboard.test/?view=cases").searchParams.has("window")).toBe(false);
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, window: "24h" }, "https://dashboard.test/?view=cases").searchParams.get("window")).toBe("24h");
  });
});
