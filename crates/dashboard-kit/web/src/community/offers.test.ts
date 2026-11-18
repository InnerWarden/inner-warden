import { describe, expect, it } from "vitest";
import * as offers from "./offers";
import { EDITIONS_URL, GENERIC_LINE, INSTALLED_LINE, PRICING_URL, protectionOffer, TOUR_UPGRADE_LINE } from "./offers";
import { COMMUNITY_UPGRADE_STEP_KEY } from "../components/ProductTour";
import { COMMUNITY_SHELL_TOUR_STEPS, communityShellTourSteps } from "./tour";

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

/**
 * Community says what the paid edition is for in one generic line, at the
 * foot of Protection, and once in the tour. It names no capability and
 * says nothing about how anything works, and nothing about this machine.
 */
describe("the one offer", () => {
  it("is the generic line, one link to the editions page, and Not now's own slot", () => {
    expect(protectionOffer()).toEqual({
      slot: "protection",
      key: "protection",
      body: GENERIC_LINE,
      action: "Compare the editions",
      href: EDITIONS_URL,
    });
  });

  it("links to innerwarden.com only, with no query string", () => {
    for (const href of [EDITIONS_URL, PRICING_URL]) {
      expect(href.startsWith("https://innerwarden.com/")).toBe(true);
      expect(href).not.toMatch(/[?#]/);
    }
  });

  it("never says what the edition would have done here", () => {
    for (const line of [GENERIC_LINE, TOUR_UPGRADE_LINE]) {
      expect(line).not.toMatch(/would have|this machine|here\b|stopped|blocked|protected\b/i);
    }
  });

  it("is all this module offers: no per-decision, per-agent or per-capability offer", () => {
    expect(Object.keys(offers).sort()).toEqual(
      ["EDITIONS_URL", "GENERIC_LINE", "INSTALLED_LINE", "PRICING_URL", "TOUR_UPGRADE_LINE", "protectionOffer"].sort(),
    );
  });

  it("claims installation, never enforcement, where the paid edition is installed", () => {
    const words = `${INSTALLED_LINE.lead} ${INSTALLED_LINE.body}`;
    for (const forbidden of ["armed", "enforcing", "enforced", "protected"]) expect(words.toLowerCase()).not.toContain(forbidden);
    expect(INSTALLED_LINE.command).toBe("innerwarden get status");
  });

  it("keeps every sentence short, and carries no em or en dash", () => {
    for (const line of [GENERIC_LINE, TOUR_UPGRADE_LINE, INSTALLED_LINE.lead, INSTALLED_LINE.body]) {
      expect(line).not.toMatch(DASHES);
      for (const sentence of line.split(/(?<=\.)\s+/)) expect(sentence.split(/\s+/).length, sentence).toBeLessThanOrEqual(20);
    }
  });
});

describe("the tour's upgrade step", () => {
  it("says the tour line, and points at the Protection footer", () => {
    const step = COMMUNITY_SHELL_TOUR_STEPS.find((candidate) => candidate.key === COMMUNITY_UPGRADE_STEP_KEY);
    expect(step?.body).toBe(TOUR_UPGRADE_LINE);
    expect(step?.title).not.toContain("InnerWarden Pro");
    expect(step?.route).toBe("posture");
    expect(step?.selectors).toEqual(['[data-tour="upgrade"]']);
  });

  it("is dropped where the paid edition is installed, and only then", () => {
    expect(communityShellTourSteps(false).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(true);
    expect(communityShellTourSteps(true).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(false);
    expect(communityShellTourSteps(true)).toHaveLength(COMMUNITY_SHELL_TOUR_STEPS.length - 1);
  });
});
