import { describe, expect, it } from "vitest";
import type { CapabilityStatus, DashboardBootstrap } from "./api/v1";
import { activityUrl, caseLaneUrl, caseQueueUrl, caseUrl, machinePanelsFor } from "./App";
import { reviewRemedy } from "./components/HeadlineAnswer";
import { decisionRecordCta } from "./screens/Home";

/**
 * How the shell carries a lane: the Overview card's link into Cases, the case
 * opened from inside a lane, and the lane being dropped when the reader goes
 * anywhere else.
 */

const base = "https://dashboard.test/?view=overview";

describe("the link from a lane card", () => {
  it("opens Cases on the lane, in the window the card counted", () => {
    const url = caseLaneUrl("agent", { window: "24h" }, base);
    expect(url.searchParams.get("view")).toBe("cases");
    expect(url.searchParams.get("lane")).toBe("agent");
    expect(url.searchParams.get("window")).toBe("24h");
    expect(url.searchParams.has("status")).toBe(false);
    expect(url.searchParams.has("case")).toBe(false);
  });

  it("opens what is waiting in the lane, from any day", () => {
    const url = caseLaneUrl("host", { window: "all", status: "waiting" }, base);
    expect(url.searchParams.get("lane")).toBe("host");
    expect(url.searchParams.get("status")).toBe("waiting");
    expect(url.searchParams.get("window")).toBe("all");
  });

  /** A filter left over from another screen must not narrow the lane. */
  it("drops every filter the reader left elsewhere", () => {
    const url = caseLaneUrl("prompt", { window: "7d" }, "https://dashboard.test/?view=cases&severity=high&q=ssh&cursor=abc&case=case:x&lane=host");
    expect(url.searchParams.get("lane")).toBe("prompt");
    for (const name of ["severity", "q", "cursor", "case"]) expect(url.searchParams.has(name)).toBe(false);
  });
});

describe("a case opened from a lane", () => {
  it("opens inside that lane, so the list beside it is the one the card was about", () => {
    const url = caseUrl("case:community-session:1", base, "agent");
    expect(url.searchParams.get("case")).toBe("case:community-session:1");
    expect(url.searchParams.get("lane")).toBe("agent");
    expect(url.searchParams.get("window")).toBe("all");
  });

  it("carries no lane when none was given, or one this bundle does not know", () => {
    expect(caseUrl("case:x:1", base).searchParams.has("lane")).toBe(false);
    expect(caseUrl("case:x:1", base, "network" as never).searchParams.has("lane")).toBe(false);
    // "View all" names no case and no lane.
    expect(caseUrl(undefined, base, "agent").searchParams.has("lane")).toBe(false);
  });

  /**
   * THE RULE THIS PINS: `lane` is a screen parameter like every Cases filter,
   * so leaving the lane for any other destination drops it.
   *
   * FAILS ON REVERT: take `lane` out of `SCREEN_PARAMS` and the queue link,
   * opened from inside the agent's lane, silently stays in that lane.
   */
  it("is dropped when the reader goes anywhere else", () => {
    const inLane = "https://dashboard.test/?view=cases&lane=agent&window=24h";
    expect(caseQueueUrl(inLane).searchParams.has("lane")).toBe(false);
    expect(caseUrl("case:x:1", inLane).searchParams.has("lane")).toBe(false);
    expect(activityUrl({ id: "d1" }, inLane).searchParams.has("lane")).toBe(false);
  });
});

describe("the decision record's way to everything", () => {
  it("opens the agent's lane on a host that serves lanes, and Cases as before on one that does not", () => {
    expect(decisionRecordCta("enterprise", true, true)).toEqual({ kind: "lane", label: "View all in Cases" });
    expect(decisionRecordCta("enterprise", true, false)).toEqual({ kind: "cases", label: "View all in Cases" });
    expect(decisionRecordCta("enterprise", true)).toEqual({ kind: "cases", label: "View all in Cases" });
    expect(decisionRecordCta("enterprise", false, true)).toEqual({ kind: "hidden", label: "" });
    expect(decisionRecordCta("community", false, true).kind).toBe("activity");
  });

  it("says where the lane button goes, and never asks for a filter by hand", () => {
    const remedy = reviewRemedy("lane", true);
    expect(remedy).toContain("View all in Cases opens them under What your AI agent did.");
    expect(remedy).not.toContain("Capability");
    expect(remedy).not.toContain("Activity");
  });
});

function capability(id: string, availability: CapabilityStatus["availability"]): CapabilityStatus {
  return { id, availability } as CapabilityStatus;
}

function bootstrap(capabilities: CapabilityStatus[]): DashboardBootstrap {
  return { edition: "enterprise", capabilities } as DashboardBootstrap;
}

describe("the agent and token panels a paid Overview offers", () => {
  it("leaves out a source the host reports as not configured, the same rule the nav follows", () => {
    expect(machinePanelsFor(bootstrap([
      capability("community.agent_discovery", "not_configured"),
      capability("community.token_intelligence", "not_configured"),
    ]))).toEqual({ agents: false, tokens: false });
    expect(machinePanelsFor(bootstrap([
      capability("community.agent_discovery", "available"),
      capability("community.token_intelligence", "degraded"),
    ]))).toEqual({ agents: true, tokens: true });
  });

  it("keeps a panel whose source the bootstrap does not mention, as before", () => {
    expect(machinePanelsFor(bootstrap([]))).toEqual({ agents: true, tokens: true });
    expect(machinePanelsFor(undefined)).toBeUndefined();
  });
});
