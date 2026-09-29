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
  const guard = section.locator('li[data-paid="secret_read_guard"]');
  await expect(guard).toContainText("Secret Read Guard");
  await expect(guard).toContainText("Part of Active Defence.");
  // Tied to this machine: a count of what happened here, and no word on how it works.
  await expect(guard.locator("[data-paid-fact]")).toHaveText("4 cases here reached for a credential file since 25 Sept 2026.");
  await expect(section.locator('li[data-paid="execution_gate"] [data-paid-fact]')).toHaveText("21 flagged commands ran on this machine since 25 Sept 2026.");
  await expect(section.locator('li[data-paid="host_sensor"] [data-paid-fact]')).toHaveCount(0);
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

/**
 * FAILS ON REVERT: the hero said "0 Refusing" and the Tool-call screening
 * ladder "watching only: nothing is refused" while Cursor and Gemini CLI
 * refused, because Codex being partly connected made the control "needs you".
 */
test("never says nothing refuses beside agents that refuse", async ({ page }) => {
  await page.goto("/?view=posture");
  await expect(page.locator('[data-legend="refusing"]')).toHaveText(/Some refuse/);
  const tools = page.locator('li[data-control="tool_call_screening"]');
  await expect(tools).toContainText("Cursor and Gemini CLI refuse a deny. Codex is not fully behind the guard.");
  await expect(tools).not.toContainText("nothing is refused");
  await expect(tools).toContainText("Cursor and Gemini CLI refuse a deny; Codex does not");
});

test("what Community did comes before the controls, and draws only whole weeks", async ({ page }) => {
  await page.goto("/?view=posture");
  const did = page.locator('section[aria-labelledby="did-title"]');
  const first = page.locator('li[data-control="command_screening"]');
  await expect(first).toBeVisible();
  const didTop = await did.evaluate((element) => element.getBoundingClientRect().top);
  const controlsTop = await first.evaluate((element) => element.getBoundingClientRect().top);
  expect(didTop).toBeLessThan(controlsTop);
  await expect(did).toContainText("per full week");
});

test("an unreadable protection answer is said, and the controls from other sources stay", async ({ page }) => {
  await page.route(guardRoute("protection"), (route) => fulfillJson(route, { error: "fixture_down" }, 503));
  await page.goto("/?view=posture");
  await expect(page.getByRole("alert").filter({ hasText: "What Community covers could not be read" })).toBeVisible();
  await expect(page.locator("li[data-control]").first()).toBeVisible();
});
