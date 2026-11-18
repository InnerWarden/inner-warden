import { describe, expect, it } from "vitest";
import { deriveShellNavigation, resolveRoute } from "../App";
import { COMMUNITY_TOUR_STEPS, COMMUNITY_UPGRADE_STEP_KEY } from "../components/ProductTour";
import type { DashboardMeta } from "../api";
import { HEADER_ROWS, HeaderPill, headerRow } from "./HeaderStatus";
import { COMMUNITY_SHELL, communityAlias, movedBetweenPages } from "./shell";
import { ENFORCE_MEANS, MONITOR_MEANS } from "./words";
import { COMMUNITY_SHELL_TOUR_STEPS, communityShellTourSteps } from "./tour";

describe("the Community shell", () => {
  it("offers five tabs, in the order a reader needs them, on the base routes", () => {
    const nav = deriveShellNavigation(undefined, "community", [], COMMUNITY_SHELL.screens);
    expect(nav.map((item) => `${item.route}:${item.label}`)).toEqual([
      "overview:Overview",
      "posture:Protection",
      "activity:Decisions",
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

  it("drops the pitch where InnerWarden Pro is installed", () => {
    expect(communityShellTourSteps(false).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(true);
    expect(communityShellTourSteps(true).some((step) => step.key === COMMUNITY_UPGRADE_STEP_KEY)).toBe(false);
  });

  it("leaves the table the paid bundle composes exactly as it was", () => {
    expect(COMMUNITY_TOUR_STEPS.map((step) => step.key)).toEqual(["welcome", "nav", "overview-agents", "activity", "upgrade", "finish"]);
  });
});

describe("moving between Community pages", () => {
  it("moves focus to the new page's heading only on a move, never on the first load or a re-render", () => {
    expect(movedBetweenPages(undefined, "overview")).toBe(false);
    expect(movedBetweenPages("overview", "overview")).toBe(false);
    expect(movedBetweenPages("overview", "activity")).toBe(true);
  });
});

describe("the header's one status (spec 5.1)", () => {
  const meta = (mode: string, extra: Partial<DashboardMeta> = {}): DashboardMeta => ({ edition: "community", exposed: false, guardrail: { mode }, ...extra });

  it("is the first row of the table that is true, in order", () => {
    expect(headerRow(undefined, "loading", undefined)).toBe(0);
    expect(headerRow(meta("enforce", { exposed: true }), "ready", { recording: false })).toBe(1);
    expect(headerRow(meta("enforce"), "ready", { recording: false })).toBe(2);
    expect(headerRow(meta("partial"), "ready", { recording: true })).toBe(3);
    expect(headerRow(meta("not_configured"), "ready", undefined)).toBe(3);
    expect(headerRow(meta("sideways"), "ready", undefined)).toBe(4);
    expect(headerRow(meta("mixed"), "ready", undefined)).toBe(5);
    expect(headerRow(meta("monitor"), "ready", undefined)).toBe(6);
    expect(headerRow(meta("dry-run"), "ready", undefined)).toBe(6);
    expect(headerRow(meta("enforce"), "ready", undefined)).toBe(7);
  });

  it("never keeps a mode from an answer that has since failed: that is unknown", () => {
    expect(headerRow(meta("enforce"), "error", undefined)).toBe(4);
    expect(headerRow(undefined, "error", undefined)).toBe(4);
    // Open to the network is still said: it is the risk, not a claim of protection.
    expect(headerRow(meta("enforce", { exposed: true }), "error", undefined)).toBe(1);
  });

  it("names each row in words a screen reader reads whole, with what monitor and enforce mean", () => {
    expect(HEADER_ROWS[0].label).toBe("Status: checking");
    expect(HEADER_ROWS[1].label).toBe("Open to the network: anyone who can reach this machine can read these pages");
    expect(HEADER_ROWS[6].label).toBe(MONITOR_MEANS);
    expect(HEADER_ROWS[6].label).toMatch(/^Monitor /);
    expect(HEADER_ROWS[7].label).toBe(ENFORCE_MEANS);
    expect(HEADER_ROWS[7].label).toMatch(/^Enforce: /);
    expect(HEADER_ROWS[4].words).toBe("Unknown");
    expect(HEADER_ROWS[4].state).toBe("unknown");
    for (const row of Object.values(HEADER_ROWS)) expect(row.label).not.toMatch(/protected|\bsafe\b|secure/i);
  });

  it("re-renders only when the row changes, so a poll on the same row announces nothing", () => {
    expect((HeaderPill as unknown as { $$typeof: symbol }).$$typeof).toBe(Symbol.for("react.memo"));
  });
});
