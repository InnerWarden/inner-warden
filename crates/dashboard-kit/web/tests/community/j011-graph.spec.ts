import { expect, test } from "@playwright/test";
import { fulfillJson, guardRoute } from "./support";

/**
 * CJC-090-J011. A corrupt local graph is an error in its own place, never an
 * empty record: the API answers 503, the Overview says the record could not
 * be read and still draws what other sources answered, and Cases says the
 * same instead of "nothing flagged".
 */
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

  test("the Overview and Cases say the record could not be read, and claim no zero", async ({ page }) => {
    await page.route(guardRoute("overview"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.route(guardRoute("decisions"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");

    await expect(page.getByRole("alert").filter({ hasText: "The decision record could not be read" })).toBeVisible();
    await expect(page.getByText("The local dashboard is unavailable")).toHaveCount(0);
    await expect(page.getByText(/Nothing flagged/)).toHaveCount(0);
    // Partial render: the header, the tabs and the machine strip stay.
    await expect(page.getByRole("navigation", { name: "Dashboard views" })).toBeVisible();
    await expect(page.locator('section[aria-labelledby="on-machine-title"]')).toContainText("connected");

    await page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: "Cases", exact: true }).click();
    const alert = page.getByRole("alert").filter({ hasText: "The decision record could not be read" });
    await expect(alert).toBeVisible();
    await expect(alert.getByRole("button", { name: "Try again" })).toBeVisible();
    await expect(page.getByText("Nothing recorded yet.", { exact: false })).toHaveCount(0);
    await expect(page.getByText(/Nothing flagged/)).toHaveCount(0);
    await expect(page.locator("[data-case-row]")).toHaveCount(0);
  });
});
