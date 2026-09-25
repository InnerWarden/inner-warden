import { describe, expect, it } from "vitest";

import {
  COMMUNITY_TOUR_STEPS,
  OPTIONAL_ANCHOR_ATTEMPTS,
  PAID_SCREEN_TOUR_STEPS,
  skipsMissingAnchor,
} from "./ProductTour";

/**
 * The tour table is fixed before the Overview knows which layout the host's
 * answer picks: the three lane cards, or the sensor and agent panels up
 * front. A step whose panel this host does not show is passed over, instead
 * of a card floating over the middle of the screen describing nothing.
 */

describe("a step for a panel only some hosts show", () => {
  it("is passed over once its anchor has not appeared after the quick retries", () => {
    expect(skipsMissingAnchor({ optional: true }, OPTIONAL_ANCHOR_ATTEMPTS)).toBe(true);
    expect(skipsMissingAnchor({ optional: true }, OPTIONAL_ANCHOR_ATTEMPTS - 1)).toBe(false);
  });

  /**
   * FAILS ON REVERT: skip every step whose anchor is slow, and the tour walks
   * straight past a screen that was still loading.
   */
  it("is the only kind passed over", () => {
    expect(skipsMissingAnchor({}, OPTIONAL_ANCHOR_ATTEMPTS * 10)).toBe(false);
    expect(skipsMissingAnchor({ optional: false }, OPTIONAL_ANCHOR_ATTEMPTS * 10)).toBe(false);
  });

  it("marks the lane cards and the panels they replace up front as optional", () => {
    const paid = new Map(PAID_SCREEN_TOUR_STEPS.map((step) => [step.key, step]));
    expect(paid.get("overview-lanes")?.optional).toBe(true);
    expect(paid.get("overview-lanes")?.selectors).toContain('[data-tour="overview-lanes"]');
    expect(paid.get("overview-sensor")?.optional).toBe(true);
    expect(COMMUNITY_TOUR_STEPS.find((step) => step.key === "overview-agents")?.optional).toBe(true);
    // The lanes step leads the paid screens: it is what the Overview leads with.
    expect(PAID_SCREEN_TOUR_STEPS[0].key).toBe("overview-lanes");
  });

  it("names the lanes in words a reader uses", () => {
    const lanes = PAID_SCREEN_TOUR_STEPS[0];
    expect(`${lanes.title} ${lanes.body}`).not.toMatch(/_|\blane\b/);
  });
});
