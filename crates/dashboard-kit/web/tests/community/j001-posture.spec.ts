import { expect, test } from "@playwright/test";
import { casesPage, EMPTY_OVERVIEW, fulfillJson, installMachineDefaults } from "./support";

test.describe("CJC-090-J001 Community shell and posture", () => {
  test("shows loading, fresh configured posture, navigation, and logo-home without reload", async ({ page }) => {
    let releaseOverview!: () => void;
    const overviewReady = new Promise<void>((resolve) => { releaseOverview = resolve; });
    let documentRequests = 0;
    page.on("request", (request) => {
      if (request.resourceType() === "document") documentRequests += 1;
    });

    await page.route("**/api/guard/meta", (route) => fulfillJson(route, {
      version: "0.16.4-fixture",
      exposed: false,
      edition: "community",
      guardrail: { mode: "monitor", guarded_agents: 2 },
    }));
    await page.route("**/api/guard/overview", async (route) => {
      await overviewReady;
      await fulfillJson(route, EMPTY_OVERVIEW);
    });
    await page.route("**/api/cases**", (route) => fulfillJson(route, casesPage({ sessions: [], total_sessions: 0, total_commands: 0 })));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.getByText("Community", { exact: true })).toBeVisible();
    await expect(page.getByRole("status", { name: "Loading overview" })).toBeVisible();
    releaseOverview();

    await expect(page.getByText("Monitor configured", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("2 agent integrations configured", { exact: true })).toBeVisible();
    await expect(page.getByText("Local · read-only API", { exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Dashboard views" })).toContainText("Overview");
    await expect(page.getByRole("navigation", { name: "Dashboard views" })).toContainText("Activity");

    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Activity", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Go to overview" }).click();
    await expect(page.getByRole("heading", { name: "Build confidence before you turn on blocking." })).toBeVisible();
    expect(documentRequests).toBe(1);
  });

  test("withdraws stale posture claims and restores them only after a fresh response", async ({ page }) => {
    let metaRequests = 0;
    await page.clock.install();
    await page.route("**/api/guard/meta", async (route) => {
      metaRequests += 1;
      if (metaRequests === 2) {
        await fulfillJson(route, { error: "fixture_refresh_failed" }, 503);
        return;
      }
      await fulfillJson(route, {
        version: "0.16.4-fixture",
        exposed: false,
        edition: "community",
        guardrail: { mode: "enforce", guarded_agents: 1 },
      });
    });
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.getByText("Enforce configured", { exact: true }).first()).toBeVisible();
    await page.clock.fastForward(5_000);
    await expect(page.getByText("Last known local", { exact: true })).toBeVisible();
    await expect(page.getByText("Status unknown", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Agent action security, with evidence." })).toBeVisible();
    await expect(page.getByText("Enforce configured", { exact: true })).toHaveCount(0);

    await page.clock.fastForward(5_000);
    await expect(page.getByText("Enforce configured", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Local · read-only API", { exact: true })).toBeVisible();
  });

  test("does not infer a safe local endpoint when exposure evidence is absent", async ({ page }) => {
    await page.route("**/api/guard/meta", (route) => fulfillJson(route, {
      version: "0.16.4-fixture",
      edition: "community",
      guardrail: { mode: "unknown" },
    }));
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);
    await page.goto("/");

    await expect(page.getByText("Exposure unknown", { exact: true })).toBeVisible();
    await expect(page.getByText("Local · read-only API", { exact: true })).toHaveCount(0);
  });
});
