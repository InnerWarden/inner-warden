import { expect, test, type Page } from "@playwright/test";

/**
 * The shell's licence notice, wired into the real shell (`App.tsx`): the
 * bootstrap the fixture server answers by the `iw-plan` cookie, read again on
 * the shell's own timer, drawn as the first thing in `main`, and named in
 * the header and the tab title. The pure parts are tested in `plan.test.ts`
 * and `PlanNotice.test.tsx`; these are the wires between them, which a
 * revert of any one of them breaks here.
 *
 * `page.clock` drives the shell's timers, so a minute passes in no time.
 */

const BASE = "http://127.0.0.1:4174";
const FIXTURE_NOW = new Date("2026-07-18T12:00:00Z");

async function withPlan(page: Page, plan: string | undefined) {
  if (plan !== undefined) await page.context().addCookies([{ name: "iw-plan", value: plan, url: BASE }]);
}

/** Every bootstrap read the page makes, counted. */
function countBootstrapReads(page: Page): () => number {
  let reads = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/dashboard/v1/bootstrap") reads += 1;
  });
  return () => reads;
}

const notice = (page: Page) => page.locator("main > [data-shell-notice] [data-plan-notice]");

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: FIXTURE_NOW });
});

test("free mode: the host's line and step, Enterprise, free mode in the header and the title, and no Hide", async ({ page }) => {
  await withPlan(page, "free-mode");
  await page.goto("/");
  // The notice is the first thing in main, inside the shell's live region.
  const region = page.locator("main > [data-shell-notice]");
  await expect(region).toHaveAttribute("role", "status");
  await expect(region).toHaveAttribute("aria-live", "polite");
  expect(await page.locator("main > *").first().getAttribute("data-shell-notice")).not.toBeNull();
  await expect(notice(page)).toHaveAttribute("data-plan-state", "free_mode");
  await expect(notice(page)).toContainText("Free mode since 17 Jul 2026");
  await expect(notice(page)).toContainText("Fixture host sentence: the licence is not in effect, so this host runs in free mode.");
  await expect(notice(page).locator("code")).toHaveText("fixture-licence renew");
  await expect(notice(page).getByRole("button", { name: "Copy command: fixture-licence renew" })).toBeVisible();
  await expect(notice(page).getByRole("button", { name: "Hide" })).toHaveCount(0);
  await expect(page.getByText("Enterprise, free mode", { exact: true })).toBeVisible();
  await expect(page).toHaveTitle("InnerWarden Enterprise, free mode: Agent Security");
});

test("free mode is kept, notice and label, when a later bootstrap read fails, and is read again within a minute", async ({ page }) => {
  await withPlan(page, "free-mode");
  const reads = countBootstrapReads(page);
  let fail = false;
  await page.route("**/api/dashboard/v1/bootstrap", (route) => (fail ? route.fulfill({ status: 503, json: { error: "unavailable" } }) : route.continue()));
  await page.goto("/");
  await expect(notice(page)).toHaveAttribute("data-plan-state", "free_mode");
  const first = reads();
  fail = true;
  await page.clock.fastForward(61_000);
  await expect.poll(reads).toBeGreaterThan(first);
  await expect(notice(page)).toHaveAttribute("data-plan-state", "free_mode");
  await expect(page.getByText("Enterprise, free mode", { exact: true })).toBeVisible();
});

test("a renewal is confirmed after the next read, says nothing is back on, and leaves after ten minutes even with no read", async ({ page }) => {
  await withPlan(page, `renewed-run${Date.now().toString(36)}`);
  await page.goto("/");
  await expect(notice(page)).toHaveAttribute("data-plan-state", "free_mode");
  await page.clock.fastForward(61_000);
  await expect(notice(page)).toHaveAttribute("data-plan-state", "renewed");
  await expect(notice(page)).toContainText("Licence valid again, read at");
  await expect(notice(page)).toContainText("Each control shows its own state on Protection.");
  await expect(notice(page)).not.toContainText(/back on|restored|re-?enabled|protected/i);
  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  // No read lands from here on: the confirmation still ends on time.
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ status: 503, json: { error: "unavailable" } }));
  await page.clock.fastForward(10 * 60_000 + 1_000);
  await expect(notice(page)).toHaveCount(0);
  await expect(page.locator("main > [data-shell-notice]")).toHaveCount(1);
});

test("ending soon draws the notice with Hide, and Hide removes it; the cadence is not every minute far from the end", async ({ page }) => {
  await withPlan(page, "ending-soon");
  const reads = countBootstrapReads(page);
  await page.goto("/");
  await expect(notice(page)).toHaveAttribute("data-plan-state", "ending_soon");
  await expect(notice(page)).toContainText("The licence ends on 23 Jul 2026");
  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  const first = reads();
  await page.clock.fastForward(61_000);
  expect(reads()).toBe(first);
  await notice(page).getByRole("button", { name: "Hide" }).click();
  await expect(notice(page)).toHaveCount(0);
});

test("a licence state the host could not read is said, never as free mode and never as silence", async ({ page }) => {
  await withPlan(page, "not-read");
  await page.goto("/");
  await expect(notice(page)).toHaveAttribute("data-plan-state", "unknown");
  await expect(notice(page)).toContainText("Licence state not read");
  await expect(notice(page)).toContainText("Fixture host sentence: the licence state could not be read on this host.");
  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  await expect(page.getByText("Enterprise, free mode", { exact: true })).toHaveCount(0);
});

test("no plan: the live region is there and empty, and the header says Enterprise", async ({ page }) => {
  await withPlan(page, undefined);
  await page.goto("/");
  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  await expect(page.locator("main > [data-shell-notice]")).toHaveCount(1);
  await expect(page.locator("[data-plan-notice]")).toHaveCount(0);
  await expect(page).toHaveTitle("InnerWarden Enterprise: Agent Security");
});
