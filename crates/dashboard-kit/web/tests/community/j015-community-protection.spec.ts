import { expect, test } from "@playwright/test";
import { expectHonestUpsell, fulfillJson, guardRoute, META } from "./support";

/**
 * Community's Protection: the ring counts exactly the rows under it, "what
 * Community did for you" is the guard's own event log, and "Not in Community"
 * names the paid features by their public names with ONE link out, or, where
 * Active Defence is installed, the installed line and no link.
 */

test("the ring counts exactly the controls listed under it", async ({ page }) => {
  await page.goto("/?view=posture");
  await expect(page.getByRole("heading", { name: "What Community covers on this Mac" })).toBeVisible();
  const rows = page.locator("li[data-control]");
  await expect(rows.first()).toBeVisible();
  const states = await rows.evaluateAll((items) => items.map((item) => item.getAttribute("data-control-state")));
  const counted = states.filter((state) => state !== "none");
  const on = counted.filter((state) => state === "refusing" || state === "on").length;
  const needs = counted.filter((state) => state === "needs").length;
  const off = counted.filter((state) => state === "off").length;
  const needsWords = needs === 0 ? "" : `, ${needs} ${needs === 1 ? "needs" : "need"} you`;
  await expect(page.locator("#coverage-title")).toHaveText(`${counted.length} Community controls: ${on} on${needsWords}, ${off} off.`);
  await expect(page.getByRole("img", { name: `${on} of ${counted.length} Community controls on` })).toBeVisible();
});

test("what Community did for you comes from the guard's event log", async ({ page }) => {
  await page.goto("/?view=posture");
  const did = page.locator('section[aria-labelledby="did-title"]');
  await expect(did).toContainText("since 30 Jul 2026, from the guard's event log");
  await expect(did).toContainText("123 refused before they ran");
  await expect(did).toContainText("30 would have been refused (monitor mode)");
  await expect(did).toContainText("3 changes to your allow and mute list.");
});

test("Not in Community names the paid features, says nothing of how one works, and links out once", async ({ page }) => {
  await page.goto("/?view=posture");
  const section = page.locator('section[aria-labelledby="not-in-community-title"]');
  await expect(section.locator("li[data-paid]")).toHaveCount(7);
  await expect(section.locator('li[data-paid="secret_read_guard"]')).toHaveText(/Secret Read Guard\s*Part of Active Defence\./);
  const link = section.getByRole("link", { name: /Compare the editions/ });
  await expect(link).toHaveAttribute("href", "https://innerwarden.com/docs/editions-and-guarantees");
  await expectHonestUpsell(page);

  // Not now leaves the plain sentence behind, and no link at all.
  await section.getByRole("button", { name: /Not now/ }).click();
  await expect(section).toContainText("These are Active Defence, for Linux servers.");
  await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
});

test("where Active Defence is installed, the section says so and links nowhere", async ({ page }) => {
  await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
  await page.goto("/?view=posture");
  await expect(page.getByRole("heading", { name: "Active Defence is installed on this host" })).toBeVisible();
  await expect(page.locator('[data-ad-state="installed"]')).toBeVisible();
  await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
  await expect(page.locator("li[data-paid]")).toHaveCount(0);
});

test("an unreadable protection answer is said, and the controls from other sources stay", async ({ page }) => {
  await page.route(guardRoute("protection"), (route) => fulfillJson(route, { error: "fixture_down" }, 503));
  await page.goto("/?view=posture");
  await expect(page.getByRole("alert").filter({ hasText: "What Community covers could not be read" })).toBeVisible();
  await expect(page.locator("li[data-control]").first()).toBeVisible();
});
