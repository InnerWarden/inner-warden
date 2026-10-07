import { expect, test, type Page } from "@playwright/test";
import { CASE, expectHonestUpsell, FIXTURE_NOW_MS, fulfillJson, guardRoute, META } from "./support";

/**
 * Community's Cases at a desk, 1440 x 900: the list and the open case side by
 * side, the three answers of a case (what happened, what InnerWarden did,
 * what you can do) on the first screen, runs of the same reason folded,
 * Newer and Older, the one offer a case can carry, and commands copied whole.
 */

test.use({ viewport: { width: 1440, height: 900 } });

// The fixture's cases are dated 2026-09-29. A row's time is relative for a
// few days and an absolute date after that, and the absolute date is longer
// and wraps the row, so a run weeks later measured a different page.
test.beforeEach(async ({ page }) => {
  await page.clock.setFixedTime(FIXTURE_NOW_MS);
});

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
    const answer = card.locator("dl > div").filter({ has: page.locator("dt", { hasText: "What you can do" }) }).locator("dd");
    await expect(answer).toBeVisible();
    // Its first line sits on the first screen with room below it for the
    // command. Measured against the screen, not a pixel row: the same page
    // lays out about 60 px taller with Linux fonts than with macOS ones.
    const box = await answer.locator("p").first().boundingBox();
    expect(box).not.toBeNull();
    expect(box!.y + box!.height).toBeLessThanOrEqual(900 - 100);
  });
}

test("a run of the same reason folds into one line, and opens", async ({ page }) => {
  await page.goto("/?view=activity");
  const fold = page.getByText("6 more in a row, flagged for the same reason").first();
  await expect(fold).toBeVisible();
  const toggle = fold.locator("xpath=ancestor::li[1]").getByRole("button", { name: "Show" });
  await expect(page.getByText("bash /tmp/build-cache/step-3.sh")).toHaveCount(0);
  await toggle.click();
  await expect(page.getByText("bash /tmp/build-cache/step-3.sh")).toBeVisible();
});

test("Newer and Older move through the list, and keep it in the address", async ({ page }) => {
  await openCase(page, CASE.scratch);
  const card = page.locator("section[data-case]");
  await card.getByRole("button", { name: "Newer", exact: true }).click();
  await expect(page.locator(`section[data-case="${CASE.wouldRefuse}"]`)).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`decision=${encodeURIComponent(CASE.wouldRefuse)}`));
  await expect(card.getByRole("button", { name: "Newer", exact: true })).toBeDisabled();
  await card.getByRole("button", { name: "Older", exact: true }).click();
  await expect(page.locator(`section[data-case="${CASE.scratch}"]`)).toBeVisible();
});

test("the arrow keys move the open case from a focused row, and nowhere else", async ({ page }) => {
  await openCase(page, CASE.wouldRefuse);
  await page.locator(`[data-case-row="${CASE.wouldRefuse}"] button`).focus();
  await page.keyboard.press("ArrowDown");
  await expect(page.locator(`section[data-case="${CASE.scratch}"]`)).toBeVisible();
  await page.getByRole("searchbox", { name: "Search flagged commands" }).focus();
  await page.keyboard.press("ArrowDown");
  await expect(page.locator(`section[data-case="${CASE.scratch}"]`)).toBeVisible();
});

/**
 * The offer is ONE line under the case, never a box inside it: the reader's
 * own step stays the heaviest thing on the card.
 */
test("a case carries at most one offer, under it; Not now hides it and it stays hidden after a reload", async ({ page }) => {
  const card = await openCase(page, CASE.wouldRefuse);
  await expect(card.locator('[data-ad-state="offer"]')).toHaveCount(0);
  const offer = page.locator('[data-ad-state="offer"]');
  await expect(offer).toHaveCount(1);
  await expect(offer).toHaveAttribute("data-offer", "credential_read");
  await expect(offer).toContainText("Secret Read Guard");
  const cardBox = await card.boundingBox();
  const offerBox = await offer.boundingBox();
  expect(offerBox!.y).toBeGreaterThanOrEqual(cardBox!.y + cardBox!.height);
  // A text link, lighter than the reader's own Copy button.
  expect(await offer.locator("a").evaluate((link) => getComputedStyle(link).borderTopWidth)).toBe("0px");
  await expectHonestUpsell(page);
  await offer.getByRole("button", { name: /Not now/ }).click();
  await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
  await page.reload();
  await expect(page.locator(`section[data-case="${CASE.wouldRefuse}"]`)).toBeVisible();
  await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
});

test("a refused case and a check by hand carry no offer", async ({ page }) => {
  for (const id of [CASE.refused, CASE.checked]) {
    await openCase(page, id);
    await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
  }
});

test("a host with Active Defence installed gets the installed line, never an offer", async ({ page }) => {
  await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
  await openCase(page, CASE.wouldRefuse);
  await expect(page.locator('[data-ad-state="installed"]')).toBeVisible();
  await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
});

test("the agent's own scratch scripts are hidden from the list in one press, and shown again", async ({ page }) => {
  const card = await openCase(page, CASE.scratch);
  // Nothing to allow: the folder is new every session.
  await expect(card.locator("[data-command]").filter({ hasText: "innerwarden allow" })).toHaveCount(0);
  await card.getByRole("button", { name: /Hide .world-writable folder. in the list/ }).click();
  await expect(page).toHaveURL(/hide=rule%3Atmp_execution/);
  const summary = page.locator("[data-hidden-summary]");
  await expect(summary).toHaveText(/flagged without world-writable folder/);
  await expect(page.locator(`[data-case-row="${CASE.flaggedRan}"]`)).toHaveCount(0);
  await page.getByRole("button", { name: "Show them again" }).click();
  await expect(page).not.toHaveURL(/hide=/);
  await expect(page.locator("[data-hidden-summary]")).toHaveCount(0);
});

test("a command with hidden characters is listed with a chip, shown written out, and never copied", async ({ page }) => {
  const card = await openCase(page, CASE.hidden);
  await expect(page.locator(`[data-case-row="${CASE.hidden}"] [data-hidden-characters]`)).toBeVisible();
  await expect(card.locator("[data-command]").first()).toContainText("\\u{202E}");
  await expect(card).toContainText("Shown with its hidden characters written out, so there is nothing whole to copy.");
  await expect(card.getByRole("button", { name: /^Copy the command printf/ })).toHaveCount(0);
  // Its step is a template: the placeholder is drawn apart, and nothing is copied.
  const template = card.locator("[data-command][data-template]");
  await expect(template.locator("var[data-placeholder]")).toHaveText("<pattern>");
  await expect(card.getByRole("button", { name: /Copy the command innerwarden allow/ })).toHaveCount(0);
});

/** The outcome words are a row's main signal: never cut, in either view. */
test("a row's outcome words are never cut, and its command gets two lines", async ({ page }) => {
  for (const technical of [false, true]) {
    await page.goto("/?view=activity");
    if (technical) await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const words = page.locator("[data-case-row] [data-outcome-words] > span:last-child");
    await expect(words.first()).toBeVisible();
    const cut = await words.evaluateAll((spans) => spans.filter((span) => span.scrollWidth > span.clientWidth + 1).length);
    expect(cut, technical ? "technical view" : "plain view").toBe(0);
    // A relative time in both views; the exact UTC time is the technical line's.
    await expect(page.locator("[data-case-row] time").first()).toHaveText(/ago|yesterday|\d{1,2} \w+/);
    if (!technical) {
      // Two lines of command when it needs them, and the row stays under
      // 100 px. A row that also carries the hidden-characters chip may take
      // one line more: it is the row that most needs reading.
      const heights = await page.locator("[data-case-row] > button").evaluateAll((rows) =>
        rows.filter((row) => row.querySelector("[data-hidden-characters]") === null).map((row) => row.getBoundingClientRect().height));
      expect(heights.length).toBeGreaterThan(5);
      expect(Math.max(...heights)).toBeLessThanOrEqual(100);
    }
  }
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
  await expect(main).not.toContainText("#66", seen);
  await expect(main).not.toContainText("Risk", seen);
  await page.getByText("Details for investigators").click();
  await expect(main).toContainText(`${CASE.wouldRefuse}`, seen);
  await expect(main).toContainText("60, as the rules scored it", seen);
});
