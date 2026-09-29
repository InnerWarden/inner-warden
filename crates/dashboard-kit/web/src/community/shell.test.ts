import { describe, expect, it } from "vitest";
import { deriveShellNavigation, resolveRoute } from "../App";
import { COMMUNITY_TOUR_STEPS, COMMUNITY_UPGRADE_STEP_KEY } from "../components/ProductTour";
import { COMMUNITY_SHELL, communityAlias } from "./shell";
import { COMMUNITY_SHELL_TOUR_STEPS, communityShellTourSteps } from "./tour";

describe("the Community shell", () => {
  it("offers five tabs, in the order a reader needs them, on the base routes", () => {
    const nav = deriveShellNavigation(undefined, "community", [], COMMUNITY_SHELL.screens);
    expect(nav.map((item) => `${item.route}:${item.label}`)).toEqual([
      "overview:Overview",
      "posture:Protection",
      "activity:Cases",
      "agents:Agents",
      "tokens:Tokens",
    ]);
  });

  it("opens each tab from its address, so a deep link lands on the page it names", () => {
    for (const route of ["posture", "activity", "agents", "tokens"]) {
      expect(resolveRoute(`?view=${route}`)).toBe(route);
    }
  });

  it("opens a link written for the paid Cases on the same decision here", () => {
    expect(communityAlias("?view=cases&case=cmd%3As1%3A4&lane=everything&window=7d&status=waiting")).toBe("?view=activity&decision=cmd%3As1%3A4");
    expect(communityAlias("?view=cases&lane=agent_messages")).toBe("?view=activity&lane=agent_messages");
    expect(communityAlias("?view=activity&decision=x")).toBeUndefined();
    expect(communityAlias("")).toBeUndefined();
  });
});

describe("the Community tour", () => {
  it("walks only to screens the Community shell draws", () => {
    const routes = new Set(COMMUNITY_SHELL.screens.map((screen) => screen.route));
    for (const step of COMMUNITY_SHELL_TOUR_STEPS) {
      if (step.route !== undefined) expect(routes, step.key).toContain(step.route);
    }
  });

  it("drops the pitch where Active Defence is installed", () => {
    expect(communityShellTourSteps(false).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(true);
    expect(communityShellTourSteps(true).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(false);
  });

  it("leaves the table the paid bundle composes exactly as it was", () => {
    expect(COMMUNITY_TOUR_STEPS.map((step) => step.key)).toEqual(["welcome", "nav", "overview-agents", "activity", "upgrade", "finish"]);
  });
});
