import { deriveShellNavigation } from "../App";
import { describe, expect, it } from "vitest";
import {
  COMMUNITY_TOUR_STEPS,
  PAID_SCREEN_TOUR_STEPS,
  COMMUNITY_TOUR_STORAGE_KEY,
  COMMUNITY_UPGRADE_STEP_KEY,
  TOUR_FINISH_STEP_KEY,
  clampStep,
  markTourSeen,
  shouldAutoOpen,
  type TourStorage,
} from "./ProductTour";

// The tour is the first thing a new operator meets, so its step table and its
// open-once gate are pinned here rather than trusted to a manual click-through.

function fakeStorage(initial: Record<string, string> = {}): TourStorage {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
  };
}

const upgradeStep = COMMUNITY_TOUR_STEPS.find((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY);

describe("the step table", () => {
  it("is non-empty and every step carries a title and a body", () => {
    expect(COMMUNITY_TOUR_STEPS.length).toBeGreaterThan(0);
    for (const step of COMMUNITY_TOUR_STEPS) {
      expect(step.key.length, `step ${step.key} needs a key`).toBeGreaterThan(0);
      expect(step.title.length, `step ${step.key} needs a title`).toBeGreaterThan(0);
      expect(step.body.length, `step ${step.key} needs a body`).toBeGreaterThan(0);
    }
  });

  it("never reuses a step key", () => {
    const keys = COMMUNITY_TOUR_STEPS.map((step) => step.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("only navigates to screens the COMMUNITY shell actually renders", () => {
    // Derived, not listed. `deriveShellNavigation` is the shell's own answer to
    // "which tabs does this edition get", and for community it is exactly
    // Overview and Activity; every other route is bounced back to overview by
    // `shouldResetToOverview`. A hardcoded allow-list here passed while three
    // steps pointed at Enterprise-only tabs, so the assertion now reads the
    // same function the shell does.
    const offered = new Set(deriveShellNavigation(undefined, "community").map((item) => item.route));
    for (const step of COMMUNITY_TOUR_STEPS) {
      if (step.route !== undefined) {
        expect(offered, `step ${step.key} routes to ${step.route}, which the community shell never renders`).toContain(step.route);
      }
    }
  });

  it("keeps the paid-screen steps out of the community table", () => {
    // They exist for the paid bundle to compose in, and every one of them is a
    // screen a free host does not have.
    const communityKeys = new Set(COMMUNITY_TOUR_STEPS.map((step) => step.key));
    for (const step of PAID_SCREEN_TOUR_STEPS) {
      expect(communityKeys, `paid-screen step ${step.key} leaked into the community tour`).not.toContain(step.key);
    }
  });

  it("opens and closes on a centered card, so no anchor has to exist for them", () => {
    expect(COMMUNITY_TOUR_STEPS[0].selectors).toBeUndefined();
    expect(COMMUNITY_TOUR_STEPS[COMMUNITY_TOUR_STEPS.length - 1].selectors).toBeUndefined();
  });

  it("opens on welcome and closes on finish", () => {
    expect(COMMUNITY_TOUR_STEPS[0].key).toBe("welcome");
    expect(COMMUNITY_TOUR_STEPS[COMMUNITY_TOUR_STEPS.length - 1].key).toBe(TOUR_FINISH_STEP_KEY);
  });

  it("an anchored step always has at least one selector", () => {
    for (const step of COMMUNITY_TOUR_STEPS) {
      if (step.selectors !== undefined) {
        expect(step.selectors.length, `step ${step.key} declares selectors but lists none`).toBeGreaterThan(0);
      }
    }
  });
});

describe("the upgrade step is an honest offer", () => {
  // The free tour ends by pointing at the Active Defence card the Overview
  // ALREADY renders for Community (`ActiveDefenceCard` in screens/Home.tsx),
  // rather than restating the offer here. One pitch, one voice, one place to
  // change it: a second copy in tour prose would drift from the card.
  it("exists, and sits just before the closing step", () => {
    expect(upgradeStep, "the Community tour must offer Active Defence").toBeDefined();
    const index = COMMUNITY_TOUR_STEPS.findIndex((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY);
    expect(index).toBe(COMMUNITY_TOUR_STEPS.length - 2);
  });

  it("names the product and what it adds", () => {
    const text = `${upgradeStep?.title ?? ""} ${upgradeStep?.body ?? ""}`;
    expect(text).toContain("Active Defence");
    for (const claim of ["host protection", "response", "kernel enforcement"]) {
      expect(text, `the offer should name ${claim}`).toContain(claim);
    }
  });

  it("points at the offer the product already renders, instead of a second copy of it", () => {
    // The card carries the real call to action; the step only spotlights it.
    expect(upgradeStep?.route).toBe("overview");
    expect(upgradeStep?.selectors ?? []).toContain('aside[aria-labelledby="active-defence-title"]');
    expect(upgradeStep?.body ?? "", "the CTA belongs to the card, not to tour prose").not.toContain("http");
  });

  it("is phrased as an addition, never as something already installed", () => {
    const body = upgradeStep?.body ?? "";
    expect(body).toContain("Active Defence is the paid tier that adds");
    for (const wrong of ["you have", "your Active Defence", "already protecting", "is enforcing on this host"]) {
      expect(body.toLowerCase(), `the offer must not claim ${wrong}`).not.toContain(wrong.toLowerCase());
    }
  });
});

describe("no Community step claims a paid feature is already running", () => {
  // Every step except the offer describes what this installation shows. A paid
  // capability named anywhere else would read as "you have this", which is the
  // one thing an upsell in a free product must never do.
  const paidOnlyTerms = [
    "Active Defence",
    "execution gate",
    "DNS guard",
    "host EDR",
    "kernel enforcement",
    "response actions",
    "Cases",
    "Evaluation",
  ];

  it.each(paidOnlyTerms)("does not mention %s outside the offer", (term) => {
    const offenders = COMMUNITY_TOUR_STEPS.filter(
      (step) =>
        step.key !== COMMUNITY_UPGRADE_STEP_KEY &&
        `${step.title} ${step.body}`.toLowerCase().includes(term.toLowerCase()),
    ).map((step) => step.key);
    expect(offenders).toEqual([]);
  });
});

describe("Back and Next clamp at the ends", () => {
  const total = COMMUNITY_TOUR_STEPS.length;

  it("Back on the first step stays on the first step", () => {
    expect(clampStep(0, -1, total)).toBe(0);
  });

  it("Next on the last step stays on the last step", () => {
    expect(clampStep(total - 1, 1, total)).toBe(total - 1);
  });

  it("moves one step at a time in between", () => {
    expect(clampStep(1, 1, total)).toBe(2);
    expect(clampStep(2, -1, total)).toBe(1);
  });
});

describe("the open-once gate", () => {
  it("opens on a first visit, when the flag is absent", () => {
    expect(shouldAutoOpen(fakeStorage(), COMMUNITY_TOUR_STORAGE_KEY)).toBe(true);
  });

  it("stays closed once the tour has been seen", () => {
    const storage = fakeStorage();
    markTourSeen(storage, COMMUNITY_TOUR_STORAGE_KEY);
    expect(storage.getItem(COMMUNITY_TOUR_STORAGE_KEY)).not.toBeNull();
    expect(shouldAutoOpen(storage, COMMUNITY_TOUR_STORAGE_KEY)).toBe(false);
  });

  it("Skip persists exactly like finishing does", () => {
    // Skip and Done share markTourSeen; either one must silence the auto-open.
    const storage = fakeStorage();
    markTourSeen(storage, COMMUNITY_TOUR_STORAGE_KEY);
    expect(shouldAutoOpen(storage, COMMUNITY_TOUR_STORAGE_KEY)).toBe(false);
  });

  it("keeps the two editions apart, so dismissing one never silences the other", () => {
    const storage = fakeStorage();
    markTourSeen(storage, COMMUNITY_TOUR_STORAGE_KEY);
    expect(shouldAutoOpen(storage, "iw-enterprise-tour-v1")).toBe(true);
  });

  it("treats unusable storage as seen, so it can never nag on every load", () => {
    const broken: TourStorage = {
      getItem: () => {
        throw new Error("storage disabled");
      },
      setItem: () => {
        throw new Error("storage disabled");
      },
    };
    expect(shouldAutoOpen(broken, COMMUNITY_TOUR_STORAGE_KEY)).toBe(false);
    expect(() => markTourSeen(broken, COMMUNITY_TOUR_STORAGE_KEY)).not.toThrow();
  });
});
