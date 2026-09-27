import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const bootstrap = JSON.parse(readFileSync(new URL("../fixtures/community/bootstrap.json", import.meta.url), "utf8"));

/**
 * A phone, 320 px wide. The page scrolled sideways (scrollWidth 337) and the
 * header took 175 of 640 px before anything the reader came for. Every
 * Community screen now fits the width, and the header is one row over the
 * nav, with the technical switch and the tour behind one button.
 */

test.use({ viewport: { width: 320, height: 640 } });

for (const [name, path, drawn] of [
  ["Overview", "/", "#posture-title"],
  ["Activity", "/?view=activity", '[data-tour="activity"]'],
] as const) {
  test(`${name} fits a 320 px screen without scrolling sideways`, async ({ page }) => {
    // A version as long as a real build's, which is what pushed the live
    // header past the edge.
    await page.route("**/api/dashboard/v1/bootstrap", (route) =>
      route.fulfill({ json: { ...bootstrap, product_version: "0.16.66+g7e14d083" } }));
    await page.goto(path);
    // Wait for the screen itself, not the shell, before measuring it.
    await expect(page.locator(drawn)).toBeVisible();
    const width = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
    }));
    expect(width.scroll).toBe(width.client);
  });
}

test("the header is one row over the nav, with the switch and the tour behind the menu", async ({ page }) => {
  await page.goto("/");
  const header = page.locator("header");
  await expect(page.getByRole("navigation", { name: "Dashboard views" })).toBeVisible();
  const height = await header.evaluate((element) => element.getBoundingClientRect().height);
  expect(height).toBeLessThan(120);

  const toggle = page.getByRole("checkbox", { name: "Show technical detail" });
  await expect(toggle).toBeHidden();
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(toggle).toBeVisible();
  await expect(page.getByRole("button", { name: "Open the product tour" })).toBeVisible();
});

test.describe("on a wide screen", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("keeps the switch and the tour in the header, with no menu", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("checkbox", { name: "Show technical detail" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open the product tour" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Menu" })).toBeHidden();
  });
});
