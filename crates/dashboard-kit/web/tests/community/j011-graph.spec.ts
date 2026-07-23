import { expect, test } from "@playwright/test";
import { fulfillJson, installMachineDefaults } from "./support";

test.describe("CJC-090-J011 corrupt local graph behavior", () => {
  test("returns an explicit corrupt-source HTTP error instead of a fabricated empty graph", async ({ page }) => {
    await page.route("**/api/graph", (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");
    const result = await page.evaluate(async () => {
      const response = await fetch("api/graph", { cache: "no-store" });
      return { status: response.status, payload: await response.json() as { error?: string } };
    });
    expect(result).toEqual({ status: 503, payload: { error: "graph_corrupt" } });
  });

  test("projects corrupt overview and activity sources as unavailable, never healthy zero data", async ({ page }) => {
    await installMachineDefaults(page);
    await page.route("**/api/overview", (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.route("**/api/cases**", (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");

    await expect(page.getByRole("alert")).toContainText("The local dashboard is unavailable");
    await expect(page.getByRole("heading", { name: "No decisions recorded yet" })).toHaveCount(0);
    await expect(page.getByText("Recorded decisions", { exact: true })).toHaveCount(0);

    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Could not load activity from the local dashboard.");
    await expect(page.getByRole("heading", { name: "No activity recorded yet" })).toHaveCount(0);
  });
});
