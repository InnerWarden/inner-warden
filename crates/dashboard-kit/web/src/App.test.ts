import { describe, expect, it } from "vitest";
import type { CapabilityStatus, DashboardBootstrap } from "./api/v1";
import { deriveShellNavigation, resolveRoute, shouldResetToOverview, type ScreenModule } from "./App";

const stage = { state: "unknown" as const, evidence: [], reason_code: "fixture" };

function capability(
  id: string,
  tier: CapabilityStatus["tier"],
  entitlement: CapabilityStatus["entitlement"],
  availability: CapabilityStatus["availability"] = "unsupported",
): CapabilityStatus {
  return {
    id,
    tier,
    availability,
    entitlement,
    support: "unsupported",
    desired_mode: "unknown",
    effective_mode: "unknown",
    convergence: { configured: stage, loaded: stage, running: stage, enforcing: stage, verified_effective: stage },
    rollout_state: "ineligible",
    health: "unknown",
    scope: [],
    covered_action_classes: [],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: { observed_at: null, budget_seconds: 30, state: "missing", age_seconds: null },
    last_evidence: null,
    sources: [],
    claims: [],
    reason_code: "fixture",
    summary: "fixture capability",
  };
}

function bootstrap(edition: DashboardBootstrap["edition"], capabilities: CapabilityStatus[]): DashboardBootstrap {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-07-18T12:00:00Z",
    edition,
    product_version: "fixture",
    community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"a".repeat(64)}` },
    assurance_matrix: null,
    authorization_matrix: null,
    platform: { os: "linux", architecture: "x86_64", enterprise_candidate: true, reason_code: null },
    session: { authenticated: edition === "enterprise", actor_id: edition === "enterprise" ? "operator" : null, role: edition === "enterprise" ? "reader" : null, scopes: [] },
    capabilities,
    highest_priority_gap: null,
    privacy: { storage: [], redactions: [], egress: [] },
  };
}

describe("deriveShellNavigation", () => {
  it("preserves the complete Community shell when Enterprise is absent", () => {
    expect(deriveShellNavigation(bootstrap("community", []), "community")).toEqual([
      { route: "overview", label: "Overview" },
      { route: "activity", label: "Activity" },
    ]);
  });

  it("uses declared capabilities, not licence entitlement, for Enterprise routes", () => {
    const host = capability("kernel_execution_control", "enterprise_core", "invalid");
    const agents = capability("community.agent_discovery", "community", "not_required", "available");
    const tokens = capability("community.token_intelligence", "community", "not_required", "available");
    expect(deriveShellNavigation(bootstrap("enterprise", [host, agents, tokens]), "enterprise")).toEqual([
      { route: "overview", label: "Overview" },
      { route: "posture", label: "Posture" },
      { route: "agents", label: "Agents" },
      { route: "tokens", label: "Tokens" },
    ]);
  });

  it("does not offer a tab for a capability that is published but unavailable", () => {
    // The capability contract requires the Enterprise superset to PUBLISH every
    // Community id, so presence is guaranteed by design and was never a signal.
    // A published-but-unavailable record belongs in the inventory, not in the
    // navigation, or the operator clicks a screen that can only say "no data".
    const host = capability("kernel_execution_control", "enterprise_core", "invalid");
    const tokens = capability("community.token_intelligence", "community", "not_required", "unavailable");
    const agents = capability("community.agent_discovery", "community", "not_required", "unavailable");
    expect(deriveShellNavigation(bootstrap("enterprise", [host, tokens, agents]), "enterprise")).toEqual([
      { route: "overview", label: "Overview" },
      { route: "posture", label: "Posture" },
    ]);
  });

  it("does not mount undeclared Enterprise routes from edition text alone", () => {
    expect(deriveShellNavigation(bootstrap("enterprise", []), "enterprise")).toEqual([
      { route: "overview", label: "Overview" },
    ]);
  });

  it("mounts Posture only from a declared enterprise_core capability", () => {
    const host = capability("kernel_execution_control", "enterprise_core", "valid");
    expect(deriveShellNavigation(bootstrap("enterprise", [host]), "enterprise")).toEqual([
      { route: "overview", label: "Overview" },
      { route: "posture", label: "Posture" },
    ]);
  });
});

const enterpriseWithScreens = bootstrap("enterprise", [
  capability("enterprise.posture", "enterprise_core", "valid"),
]);

function contributedScreen(route: string, offered: boolean, ownState = false): ScreenModule {
  return {
    route,
    label: route.toUpperCase(),
    offersTab: () => offered,
    rendersOwnUnavailableState: ownState,
    render: () => null,
  };
}

describe("contributed screens", () => {
  it("appends a contributed tab after the shell's own tabs", () => {
    const navigation = deriveShellNavigation(enterpriseWithScreens, "enterprise", [
      contributedScreen("cases", true),
    ]);
    expect(navigation).toEqual([
      { route: "overview", label: "Overview" },
      { route: "posture", label: "Posture" },
      { route: "cases", label: "CASES" },
    ]);
  });

  it("holds a contributed screen to the same availability rule as a base screen", () => {
    const navigation = deriveShellNavigation(enterpriseWithScreens, "enterprise", [
      contributedScreen("cases", false),
    ]);
    expect(navigation.map((item) => item.route)).not.toContain("cases");
  });

  // A contributed module is loaded by a different build than the one that owns
  // these routes, so a stale or hostile module must not be able to capture the
  // shell's own screens by claiming their names.
  it("refuses to let a contributed screen shadow a route the shell owns", () => {
    const navigation = deriveShellNavigation(enterpriseWithScreens, "enterprise", [
      contributedScreen("posture", true),
    ]);
    expect(navigation.filter((item) => item.route === "posture")).toEqual([
      { route: "posture", label: "Posture" },
    ]);
  });

  it("never offers a contributed tab to the Community shell", () => {
    const navigation = deriveShellNavigation(bootstrap("community", []), "community", [
      contributedScreen("cases", true),
    ]);
    expect(navigation.map((item) => item.route)).toEqual(["overview", "activity"]);
  });
});

describe("resolveRoute", () => {
  it("resolves a base route from the query string", () => {
    expect(resolveRoute("?view=posture")).toBe("posture");
  });

  it("falls back to overview for a route no build contributed", () => {
    expect(resolveRoute("?view=cases")).toBe("overview");
  });

  it("resolves a contributed route once its build supplies the module", () => {
    expect(resolveRoute("?view=cases", [contributedScreen("cases", true)])).toBe("cases");
  });

  it("refuses a contributed module that claims a shell-owned route name", () => {
    expect(resolveRoute("?view=posture", [contributedScreen("posture", true)])).toBe("posture");
  });
});

describe("shouldResetToOverview", () => {
  const navigation = [
    { route: "overview" as const, label: "Overview" },
    { route: "posture" as const, label: "Posture" },
  ];

  it("resets a route the navigation does not offer", () => {
    expect(shouldResetToOverview("agents", navigation)).toBe(true);
  });

  it("keeps a route the navigation offers", () => {
    expect(shouldResetToOverview("posture", navigation)).toBe(false);
  });

  // The tab is hidden because the capability is unavailable, but an operator who
  // typed the URL asked a specific question. The screen answers it with a stated
  // reason; a bounce to Overview would answer with nothing.
  it("keeps an explicit deep link to a screen that states its own unavailability", () => {
    expect(shouldResetToOverview("proof", navigation, [contributedScreen("proof", false, true)])).toBe(false);
  });

  it("still resets a contributed screen that does not state its own unavailability", () => {
    expect(shouldResetToOverview("cases", navigation, [contributedScreen("cases", false, false)])).toBe(true);
  });

  it("does not reset while the navigation is still empty", () => {
    expect(shouldResetToOverview("agents", [])).toBe(false);
  });
});
