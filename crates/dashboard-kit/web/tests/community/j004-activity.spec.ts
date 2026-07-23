import { expect, test } from "@playwright/test";
import { action, EMPTY_OVERVIEW, fulfillJson, installMachineDefaults } from "./support";

test.describe("CJC-090-J004 local decision overview", () => {
  test.beforeEach(async ({ page }) => {
    await installMachineDefaults(page);
  });

  test("renders a source-confirmed zero as onboarding rather than an incident", async ({ page }) => {
    await page.route("**/api/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "No decisions recorded yet" })).toBeVisible();
    await expect(page.getByText("The local dashboard is unavailable", { exact: true })).toHaveCount(0);
  });

  test("retains the last good overview and labels it stale after refresh failure", async ({ page }) => {
    let calls = 0;
    await page.clock.install();
    await page.route("**/api/overview", async (route) => {
      calls += 1;
      if (calls > 1) {
        await fulfillJson(route, { error: "graph_unreadable" }, 503);
        return;
      }
      await fulfillJson(route, {
        ...EMPTY_OVERVIEW,
        sessions: 1,
        commands: 1,
        allowed: 1,
        allow_verdicts: 1,
        screened: 1,
        recent_blocks: [action()],
        recent_decisions: [action()],
      });
    });
    await page.goto("/");
    await expect(page.getByText("1", { exact: true }).first()).toBeVisible();
    await page.clock.fastForward(4_000);
    await expect(page.getByText("Reconnecting to the local dashboard. The figures below may be slightly out of date.")).toBeVisible();
    await expect(page.getByText("Last good response retained", { exact: true })).toBeVisible();
    await expect(page.getByText("printf safe", { exact: true })).toBeVisible();
  });

  test("does not replace an initially corrupt source with healthy zero metrics", async ({ page }) => {
    await page.route("**/api/overview", (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");
    await expect(page.getByRole("alert")).toContainText("The local dashboard is unavailable");
    await expect(page.getByRole("heading", { name: "No decisions recorded yet" })).toHaveCount(0);
    await expect(page.getByText("Recorded decisions", { exact: true })).toHaveCount(0);
  });

  test("keeps absent execution outcomes null instead of deriving them from verdicts", async ({ page }) => {
    const legacy = action({
      id: "legacy-null-outcome",
      command: "legacy decision",
      recommendation: "deny",
      outcome: undefined,
      mode_at_decision: undefined,
    });
    await page.route("**/api/overview", (route) => fulfillJson(route, {
      sessions: 1,
      commands: 1,
      blocked: 1,
      review: 0,
      allowed: 0,
      deny_verdicts: 1,
      review_verdicts: 0,
      allow_verdicts: 0,
      unknown_verdicts: 0,
      top_categories: [],
      recent_blocks: [legacy],
      recent_decisions: [legacy],
    }));
    await page.goto("/");

    const row = page.getByRole("button", { name: "Open deny decision for legacy decision" });
    await expect(row).toContainText("Deny");
    await expect(row).toContainText("Outcome unknown");
    await expect(row).not.toContainText("Blocked");
    await expect(page.getByRole("heading", { name: "Execution evidence" })).toHaveCount(0);
  });
});
