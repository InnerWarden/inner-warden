import { expect } from "@playwright/test";
import { test } from "./clock";
import { expectHonestUpsell, fulfillJson, guardRoute, META } from "./support";

/**
 * Community's Protection (spec 6.2): one summary sentence that counts exactly
 * the rows under it (no ring), the mode box with both definitions, the
 * decision record and the guard's log by week, the optional defences, the
 * exceptions, and at the foot one generic line about the paid edition with
 * ONE link out, or, where Active Defence is installed, the installed line and
 * no link.
 *
 * The test titles are the ones the page had before v2: a composing bundle
 * matches these tests by their exact titles, so only the assertions change.
 */

test("the ring counts exactly the controls listed under it", async ({ page }) => {
  await page.goto("/?view=posture");
  await expect(page.getByRole("heading", { level: 1, name: "Protection on this Mac" })).toBeVisible();
  // No ring: the summary sentence counts the screening rows, state by state.
  await expect(page.getByRole("img", { name: /Community controls on/ })).toHaveCount(0);
  const rows = page.locator("li[data-screening]");
  await expect(rows.first()).toBeVisible();
  const states = await rows.evaluateAll((items) => items.map((item) => item.getAttribute("data-control-state")));
  const parts: string[] = [];
  const words: [string, (n: number) => string][] = [
    ["refusing", () => "refusing a deny"],
    ["monitor", () => "in monitor"],
    ["needs_you", (n) => (n === 1 ? "needs you" : "need you")],
    ["unknown", () => "not yet seen working"],
  ];
  for (const [state, say] of words) {
    const n = states.filter((value) => value === state).length;
    if (n > 0) parts.push(parts.length === 0 ? `${n} ${n === 1 ? "agent" : "agents"} ${say(n)}` : `${n} ${say(n)}`);
  }
  await expect(page.locator("[data-protection-summary]")).toContainText(`Screening: ${parts.join(", ")}.`);
  await expect(page.locator("[data-protection-summary]")).toContainText("Optional: AI Jail ready, alerts off, second opinion off, messages recording.");
});

test("what Community did for you comes from the guard's event log", async ({ page }) => {
  await page.goto("/?view=posture");
  const record = page.locator("#record");
  await expect(record).toContainText("The guard's log keeps refusals and list changes since 30 Jul (10 weeks).");
  await expect(record.getByRole("img", { name: "Last 10 weeks: 123 refused, 30 would have been refused" })).toBeVisible();
  await expect(page.locator("#exceptions [data-exception-changes]")).toHaveText(/^3 changes since 30 Jul, the last on 10 Sept at \d\d:\d\d\.$/);
});

test("Not in Community names the paid features, says nothing of how one works, and links out once", async ({ page }) => {
  await page.goto("/?view=posture");
  // v2: no paid rows and no paid names; one generic line at the foot.
  await expect(page.locator("li[data-paid]")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Not in Community" })).toHaveCount(0);
  const footer = page.locator('[data-tour="upgrade"]');
  const link = footer.getByRole("link", { name: /Compare the editions/ });
  await expect(link).toHaveAttribute("href", "https://innerwarden.com/docs/editions-and-guarantees");
  await expectHonestUpsell(page);

  // Not now hides it, and no link at all is left.
  await footer.getByRole("button", { name: /Not now/ }).click();
  await expect(footer.locator('[data-ad-state="offer"]')).toHaveCount(0);
  await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
});

test("where Active Defence is installed, the section says so and links nowhere", async ({ page }) => {
  await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
  await page.goto("/?view=posture");
  const installed = page.locator('[data-tour="upgrade"] [data-ad-state="installed"]');
  await expect(installed).toBeVisible();
  await expect(installed).toContainText("Active Defence is installed on this host.");
  await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
  await expect(page.locator("li[data-paid]")).toHaveCount(0);
});

/**
 * FAILS ON REVERT: the hero once said "0 Refusing" and a ladder "watching
 * only: nothing is refused" while Cursor and Gemini CLI refused, because
 * Codex being partly connected made the control "needs you".
 */
test("never says nothing refuses beside agents that refuse", async ({ page }) => {
  await page.goto("/?view=posture");
  const mode = page.locator("#mode");
  await expect(mode.locator("#mode-title")).toHaveText("Mixed: Cursor and Gemini CLI are set to refuse a deny, Claude Code is in monitor.");
  await expect(mode).toContainText("Codex is only partly connected. Its step is under Screening.");
  await expect(page.locator("main")).not.toContainText("nothing is refused");
  // Refusing a deny is said only for an agent seen working since its settings changed.
  await expect(page.locator('li[data-screening="cursor"]')).toHaveAttribute("data-control-state", "refusing");
  await expect(page.locator('li[data-screening="gemini"]')).toHaveAttribute("data-control-state", "unknown");
  // Screened before its settings changed and not since: never drawn as "Screened".
  await expect(page.locator('li[data-screening="gemini"]')).toContainText("Nothing since its settings changed on 27 Sept at 14:05");
  await expect(page.locator('li[data-screening="gemini"] [data-seen="screened"]')).toHaveCount(0);
});

test("what Community did comes before the controls, and draws only whole weeks", async ({ page }) => {
  await page.goto("/?view=posture");
  const record = page.locator("#record");
  const optional = page.locator("#optional");
  await expect(optional).toBeVisible();
  const recordTop = await record.evaluate((element) => element.getBoundingClientRect().top);
  const optionalTop = await optional.evaluate((element) => element.getBoundingClientRect().top);
  expect(recordTop).toBeLessThan(optionalTop);
  // v2 draws the week under way too, at half strength and said as so far:
  // never dropped, never a fall, and never dashed (dashed means not read).
  await expect(record.getByText("This week so far", { exact: true })).toBeVisible();
  await expect(record.locator("[data-partial]")).toHaveAttribute("opacity", "0.5");
  await expect(record.locator("svg [stroke-dasharray]")).toHaveCount(0);
});

test("an unreadable protection answer is said, and the controls from other sources stay", async ({ page }) => {
  await page.route(guardRoute("protection"), (route) => fulfillJson(route, { error: "fixture_down" }, 503));
  await page.goto("/?view=posture");
  await expect(page.locator("[data-protection-summary]")).toContainText("Optional: not read.");
  await expect(page.locator('#optional li[data-control="alerts"]')).toContainText("Not read");
  await expect(page.locator('#optional li[data-control="alerts"]')).not.toContainText("Off");
  await expect(page.locator("li[data-screening]").first()).toBeVisible();
});
