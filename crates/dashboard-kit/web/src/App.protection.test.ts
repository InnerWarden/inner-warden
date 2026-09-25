import { describe, expect, it } from "vitest";
import type { CapabilityStatus, DashboardBootstrap } from "./api/v1";
import { deriveShellNavigation, PROTECTION_LABEL } from "./App";
import { headline, outcomeNotRecordedNext } from "./components/HeadlineAnswer";
import { PAID_SCREEN_TOUR_STEPS } from "./components/ProductTour";

/**
 * The paid tab for the `posture` route is called "Protection": it answers
 * what is switched on to protect this host, and "posture" was our word for
 * it. The route keeps its name, so links and bookmarks keep working, and
 * every sentence that sends a paid reader to the tab uses the tab's name.
 */

function bootstrap(edition: DashboardBootstrap["edition"]): DashboardBootstrap {
  return {
    edition,
    capabilities: [{ id: "enterprise.posture", tier: "enterprise_core", availability: "available" } as CapabilityStatus],
  } as DashboardBootstrap;
}

describe("the Protection tab", () => {
  /**
   * FAILS ON REVERT: label the route "Posture" again and the paid nav says it.
   */
  it("is what the paid nav calls the posture route", () => {
    const items = deriveShellNavigation(bootstrap("enterprise"), "enterprise");
    expect(PROTECTION_LABEL).toBe("Protection");
    expect(items.find((item) => item.route === "posture")?.label).toBe("Protection");
    expect(items.some((item) => item.label === "Posture")).toBe(false);
  });

  it("leaves Community's navigation exactly as it was", () => {
    expect(deriveShellNavigation(bootstrap("community"), "community")).toEqual([
      { route: "overview", label: "Overview" },
      { route: "activity", label: "Activity" },
    ]);
  });

  it("is the name a paid headline and the tour send the reader to", () => {
    for (const where of ["cases", "lane", "hidden"] as const) {
      expect(outcomeNotRecordedNext(where)).toContain("Open Protection");
      expect(outcomeNotRecordedNext(where)).not.toContain("Posture");
    }
    const paid = headline({
      needsReview: 0,
      reviewListedIn: "cases",
      recentShowsDecisions: true,
      denyVerdicts: 2,
      blockedBeforeExecution: null,
      wouldBlock: null,
      screened: null,
      outcomesUnknown: null,
      deniesWithoutBlock: null,
      monitorOnly: false,
      unprovenAgents: 0,
    });
    expect(paid.next).toContain("Open Protection");
    expect(PAID_SCREEN_TOUR_STEPS.find((step) => step.route === "posture")?.title).toBe("Protection");
  });

  /** Community's own sentence is not changed by a paid rename. */
  it("keeps Community's sentence as it was", () => {
    expect(outcomeNotRecordedNext("activity")).toBe("This host reports no outcome for its verdicts. Open Posture to see what each control is doing.");
  });
});
