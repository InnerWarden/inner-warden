import { expect, test, type Page } from "@playwright/test";
import { CASE, expectHonestUpsell, fulfillJson, guardRoute, META } from "./support";

/**
 * Community's Cases at a desk, 1440 x 900: the list and the open case side by
 * side, the three answers of a case (what happened, what InnerWarden did,
 * what you can do) on the first screen, runs of the same reason folded,
 * Newer and Older, the one offer a case can carry, and commands copied whole.
 */

test.use({ viewport: { width: 1440, height: 900 } });

async function openCase(page: Page, id: string) {
  await page.goto(`/?view=activity&decision=${encodeURIComponent(id)}`);
  const card = page.locator(`section[data-case="${id}"]`);
  await expect(card).toBeVisible();
  return card;
}

test("the list and the open case sit side by side", async ({ page }) => {
  await openCase(page, CASE.wouldRefuse);
  const list = await page.locator(`[data-case-row="${CASE.wouldRefuse}"]`).boundingBox();
  const detail = await page.locator(`section[data-case="${CASE.wouldRefuse}"]`).boundingBox();
  expect(list).not.toBeNull();
  expect(detail).not.toBeNull();
  expect(list!.x + list!.width).toBeLessThanOrEqual(detail!.x);
  await expect(page.locator(`[data-case-row="${CASE.wouldRefuse}"] button`)).toHaveAttribute("aria-current", "true");
  await expectHonestUpsell(page);
});

for (const [name, id] of [
  ["a would-refuse", CASE.wouldRefuse],
  ["a refused", CASE.refused],
  ["a fetch by name", CASE.domainFetch],
  ["a flagged run", CASE.flaggedRan],
  ["an unsafe MCP call", CASE.unsafeRan],
  ["a check by hand", CASE.checked],
] as const) {
  test(`what you can do is on the first screen for ${name} case`, async ({ page }) => {
    const card = await openCase(page, id);
    const answer = card.locator("dt").filter({ hasText: "What you can do" });
    await expect(answer).toBeVisible();
    const box = await answer.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.y).toBeLessThanOrEqual(600);
  });
}

test("a run of the same reason folds into one line, and opens", async ({ page }) => {
  await page.goto("/?view=activity");
  const fold = page.getByText("5 more in a row, flagged for the same reason").first();
  await expect(fold).toBeVisible();
  const toggle = fold.locator("xpath=ancestor::li[1]").getByRole("button", { name: "Show" });
  await expect(page.getByText("bash /tmp/build-cache/step-3.sh")).toHaveCount(0);
  await toggle.click();
  await expect(page.getByText("bash /tmp/build-cache/step-3.sh")).toBeVisible();
});

test("Newer and Older move through the list, and keep it in the address", async ({ page }) => {
  await openCase(page, CASE.flaggedRan);
  const card = page.locator("section[data-case]");
  await card.getByRole("button", { name: "Newer", exact: true }).click();
  await expect(page.locator(`section[data-case="${CASE.wouldRefuse}"]`)).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`decision=${encodeURIComponent(CASE.wouldRefuse)}`));
  await expect(card.getByRole("button", { name: "Newer", exact: true })).toBeDisabled();
  await card.getByRole("button", { name: "Older", exact: true }).click();
  await expect(page.locator(`section[data-case="${CASE.flaggedRan}"]`)).toBeVisible();
});

test("the arrow keys move the open case from a focused row, and nowhere else", async ({ page }) => {
  await openCase(page, CASE.wouldRefuse);
  await page.locator(`[data-case-row="${CASE.wouldRefuse}"] button`).focus();
  await page.keyboard.press("ArrowDown");
  await expect(page.locator(`section[data-case="${CASE.flaggedRan}"]`)).toBeVisible();
  await page.getByRole("searchbox", { name: "Search flagged commands" }).focus();
  await page.keyboard.press("ArrowDown");
  await expect(page.locator(`section[data-case="${CASE.flaggedRan}"]`)).toBeVisible();
});

test("a case carries at most one offer; Not now hides it and it stays hidden after a reload", async ({ page }) => {
  const card = await openCase(page, CASE.wouldRefuse);
  const offer = card.locator('[data-ad-state="offer"]');
  await expect(offer).toHaveCount(1);
  await expect(offer).toHaveAttribute("data-offer", "credential_read");
  await expect(offer).toContainText("Secret Read Guard");
  await expectHonestUpsell(page);
  await offer.getByRole("button", { name: /Not now/ }).click();
  await expect(card.locator('[data-ad-state="offer"]')).toHaveCount(0);
  await page.reload();
  await expect(page.locator(`section[data-case="${CASE.wouldRefuse}"]`)).toBeVisible();
  await expect(page.locator('section[data-case] [data-ad-state="offer"]')).toHaveCount(0);
});

test("a refused case and a check by hand carry no offer", async ({ page }) => {
  for (const id of [CASE.refused, CASE.checked]) {
    const card = await openCase(page, id);
    await expect(card.locator('[data-ad-state="offer"]')).toHaveCount(0);
  }
});

test("a host with Active Defence installed gets the installed line, never an offer", async ({ page }) => {
  await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
  const card = await openCase(page, CASE.wouldRefuse);
  await expect(card.locator('[data-ad-state="installed"]')).toBeVisible();
  await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
});

test("Copy copies the exact command the CLI sent", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const card = await openCase(page, CASE.flaggedRan);
  const allow = "innerwarden allow 'bash /tmp/build-cache/run.sh --clean'";
  await card.getByRole("button", { name: `Copy the command ${allow}` }).click();
  await expect(card.getByRole("button", { name: `Copy the command ${allow}` })).toHaveText("Copied");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(allow);
});

test("the plain view shows no session id, no step number and no score", async ({ page }) => {
  await openCase(page, CASE.wouldRefuse);
  // What a reader SEES: the investigators' details are closed, and a closed
  // disclosure is not read out.
  const main = page.locator("main");
  const seen = { useInnerText: true };
  await expect(main).not.toContainText("4b1d9c2e-demo-4000-8000-000000000001", seen);
  await expect(main).not.toContainText("cmd:", seen);
  await expect(main).not.toContainText("#63", seen);
  await expect(main).not.toContainText("Risk", seen);
  await page.getByText("Details for investigators").click();
  await expect(main).toContainText(`${CASE.wouldRefuse}`, seen);
  await expect(main).toContainText("60, as the rules scored it", seen);
});
