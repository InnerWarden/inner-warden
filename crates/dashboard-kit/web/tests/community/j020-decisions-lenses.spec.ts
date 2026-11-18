import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, S_APP } from "./support";

/**
 * Decisions, read three ways. Newest first (the default), by reason, and by
 * session, as tabs the arrow keys move between; the list flows with the page
 * and the open decision stays in view beside it at a desk; on a phone a
 * decision opens in place and "Back to decisions" returns to the row it came
 * from, where the list was. An InnerWarden that does not list sessions gets
 * no By session tab.
 */

const lensTabs = (page: Page) => page.getByRole("tablist", { name: "Read the decisions" }).getByRole("tab");

test.describe("at a desk", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("offers three lenses, newest first by default, and the arrow keys move between them", async ({ page }) => {
    await page.goto("/?view=activity");
    await expect(lensTabs(page)).toHaveText(["Newest first", "By reason", "By session"]);
    const newest = page.getByRole("tab", { name: "Newest first" });
    await expect(newest).toHaveAttribute("aria-selected", "true");
    await expect(page.locator("[data-decision-row]").first()).toBeVisible();

    await newest.focus();
    await page.keyboard.press("ArrowRight");
    const reason = page.getByRole("tab", { name: "By reason" });
    await expect(reason).toHaveAttribute("aria-selected", "true");
    await expect(reason).toBeFocused();
    await expect(page).toHaveURL(/lens=reason/);
    await expect(page.locator("[data-reason-group]").first()).toBeVisible();

    await page.keyboard.press("End");
    const session = page.getByRole("tab", { name: "By session" });
    await expect(session).toBeFocused();
    await expect(page.locator("[data-session-row]").first()).toBeVisible();
    await expect(page.getByText("Sessions with decisions still in the record.")).toBeVisible();

    await page.keyboard.press("ArrowRight");
    await expect(newest).toBeFocused();
    await expect(page).not.toHaveURL(/lens=/);
  });

  test("a reason opens its newest five, and Show all lists every one in the newest list", async ({ page }) => {
    await page.goto("/?view=activity&lens=reason");
    const group = page.locator('[data-reason-group="rule:tmp_execution"]');
    const opener = group.locator("button[aria-expanded]");
    await expect(opener).toHaveAttribute("aria-expanded", "false");
    await opener.click();
    await expect(opener).toHaveAttribute("aria-expanded", "true");
    await expect(group.locator("[data-decision-row]")).toHaveCount(5);
    await group.getByRole("link", { name: /^Show all 15/ }).click();
    await expect(page).toHaveURL(/reason=rule%3Atmp_execution/);
    await expect(page.getByRole("tab", { name: "Newest first" })).toHaveAttribute("aria-selected", "true");
    await expect(page.locator('[data-filter-chip="reason"]')).toContainText("world-writable folder");
    await page.getByRole("button", { name: "Remove the reason filter" }).click();
    await expect(page).not.toHaveURL(/reason=/);
  });

  test("a session opens the newest list of that session, as a filter a press removes", async ({ page }) => {
    await page.goto("/?view=activity&lens=session");
    await page.locator(`[data-session-row="${S_APP}"] a`).click();
    await expect(page).toHaveURL(new RegExp(`session=${S_APP}`));
    await expect(page).not.toHaveURL(/lens=/);
    const chip = page.locator('[data-filter-chip="session"]');
    await expect(chip).toHaveText(/Session 4b1d9c2e/);
    await chip.getByRole("button", { name: "Remove the session filter" }).click();
    await expect(page).not.toHaveURL(/session=/);
  });

  /**
   * The arrow keys browse the list: each press opens the next decision and
   * focus stays on the rows. FAILS ON REVERT: the detail took focus on every
   * open and the arrows stopped after one or two presses.
   */
  test("three ArrowDown presses open three successive decisions, and focus stays on the rows", async ({ page }) => {
    await page.goto("/?view=activity");
    const rows = page.locator("[data-decision-row] a");
    await expect(rows.first()).toBeVisible();
    await rows.first().focus();
    const opened: string[] = [];
    for (let press = 0; press < 3; press += 1) {
      await page.keyboard.press("ArrowDown");
      await expect.poll(() => new URL(page.url()).searchParams.get("decision")).not.toBe(opened.at(-1) ?? null);
      const id = new URL(page.url()).searchParams.get("decision")!;
      opened.push(id);
      await expect(page.locator(`section[data-decision="${id}"]`)).toBeVisible();
      await expect.poll(() => page.evaluate(() => document.activeElement?.getAttribute("data-row-id"))).toBe(id);
    }
    expect(new Set(opened).size).toBe(3);
    expect(await page.evaluate(() => document.activeElement?.id)).not.toBe("decision-title");
  });

  /** With no decision open the list takes the width at a desk, and a command shows three lines of itself. */
  test("with nothing open, the list takes the width and the guide is a short aside", async ({ page }) => {
    await page.goto("/?view=activity");
    const panel = page.locator("#decisions-panel");
    await expect(panel.locator("[data-decision-row]").first()).toBeVisible();
    const width = (await panel.boundingBox())!.width;
    expect(width).toBeGreaterThan(700);
    await expect(page.locator('[data-detail-column="guide"]')).toBeVisible();
    await expect(page.locator("[data-legend]")).toHaveCount(0);
    await expect(page.locator('[data-outcome-bar][data-tour="legend"]')).toHaveCount(1);
    const clamp = await panel.locator("[data-command-text]").first().evaluate((code) => getComputedStyle(code).webkitLineClamp);
    expect(clamp).toBe("3");
    // A decision opened: the list goes back to its column beside it.
    await panel.locator("[data-decision-row] a").first().click();
    await expect(page.locator('[data-detail-column="open"]')).toBeVisible();
    expect((await panel.boundingBox())!.width).toBeLessThan(width);
    await expect(page.locator("#decision-title")).toBeFocused();
  });

  test("the list flows with the page, and the open decision stays in view beside it", async ({ page }) => {
    await page.goto(`/?view=activity&decision=${encodeURIComponent(CASE.wouldRefuse)}`);
    const detail = page.locator(`section[data-decision="${CASE.wouldRefuse}"]`);
    await expect(detail).toBeVisible();
    // No inner scroller: every box from a row up to the page is as tall as what it holds.
    const scrollers = await page.locator("[data-decision-row]").first().evaluate((row) => {
      const found: string[] = [];
      for (let element: HTMLElement | null = row.parentElement; element !== null && element !== document.body; element = element.parentElement) {
        const overflow = getComputedStyle(element).overflowY;
        if ((overflow === "auto" || overflow === "scroll") && element.scrollHeight > element.clientHeight) found.push(element.className);
      }
      return found;
    });
    expect(scrollers).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollHeight > window.innerHeight)).toBe(true);

    const before = await detail.boundingBox();
    const firstRow = await page.locator("[data-decision-row]").first().boundingBox();
    await page.mouse.move(300, 600);
    await page.mouse.wheel(0, 700);
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(300);
    const rowAfter = await page.locator("[data-decision-row]").first().boundingBox();
    const after = await detail.boundingBox();
    // The list moved with the page; the decision stuck near the top of the screen.
    expect(rowAfter!.y).toBeLessThan(firstRow!.y - 300);
    expect(after!.y).toBeGreaterThanOrEqual(0);
    expect(after!.y).toBeLessThan(before!.y);
    expect(after!.y).toBeLessThanOrEqual(40);
  });
});

test.describe("on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("a decision opens in place, and Back returns to its row where the list was", async ({ page }) => {
    await page.goto("/?view=activity");
    const row = page.locator(`[data-decision-row="${CASE.refused}"]`);
    await row.scrollIntoViewIfNeeded();
    await page.evaluate(() => window.scrollBy(0, 120));
    const listY = await page.evaluate(() => window.scrollY);
    expect(listY).toBeGreaterThan(200);
    await row.locator("a").click();

    const detail = page.locator(`section[data-decision="${CASE.refused}"]`);
    await expect(detail).toBeVisible();
    await expect(detail.getByRole("heading", { level: 2 })).toBeFocused();
    // The list is not drawn beside it on a phone.
    await expect(page.locator(`[data-decision-row="${CASE.wouldRefuse}"]`)).toBeHidden();
    const back = page.getByRole("button", { name: "Back to decisions" });
    await expect(back).toBeInViewport();

    await back.click();
    await expect(page).not.toHaveURL(/decision=/);
    await expect(row).toBeVisible();
    await expect(row.locator("a")).toBeFocused();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(listY - 40);
    expect(await page.evaluate(() => window.scrollY)).toBeLessThan(listY + 40);
  });

  test("Escape closes the decision, and a link that opened it directly goes back to the list", async ({ page }) => {
    await page.goto(`/?view=activity&decision=${encodeURIComponent(CASE.refused)}`);
    const detail = page.locator(`section[data-decision="${CASE.refused}"]`);
    // Opened from a link: no focus move on a first load, and Escape still goes back.
    await expect(detail.getByRole("heading", { level: 2 })).toBeVisible();
    await expect(detail.getByRole("heading", { level: 2 })).not.toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\?view=activity$/);
    await expect(page.locator("[data-decision-row]").first()).toBeVisible();

    await page.goto(`/?view=activity&decision=${encodeURIComponent(CASE.refused)}`);
    await page.getByRole("button", { name: "Back to decisions" }).click();
    // Opened from a link, not from the list: back removes the decision, it does not leave the page.
    await expect(page).toHaveURL(/\?view=activity$/);
    await expect(page.getByRole("heading", { name: "Decisions", level: 1 })).toBeVisible();
  });
});

test("an InnerWarden that does not list sessions gets no By session tab", async ({ page }) => {
  await page.context().addCookies([{ name: "iw-fixture", value: "older-cli", url: "http://127.0.0.1:4173" }]);
  await page.goto("/?view=activity&lens=session");
  await expect(lensTabs(page)).toHaveText(["Newest first", "By reason"]);
  // The address asked for it; the newest list is what can be shown.
  await expect(page.getByRole("tab", { name: "Newest first" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("[data-decision-row]").first()).toBeVisible();
});

test("the old Cases address still opens the decision", async ({ page }) => {
  await page.goto(`/?view=cases&case=${encodeURIComponent(CASE.domainFetch)}`);
  await expect(page).toHaveURL(`/?view=activity&decision=${encodeURIComponent(CASE.domainFetch)}`);
  await expect(page.locator(`section[data-decision="${CASE.domainFetch}"]`)).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: "Decisions", exact: true }))
    .toHaveAttribute("aria-current", "page");
});

test("a lens stays on Decisions: moving to another page and back starts from the newest", async ({ page }) => {
  await page.goto("/?view=activity&lens=reason");
  await expect(page.getByRole("tab", { name: "By reason" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: "Agents", exact: true }).click();
  await expect(page).not.toHaveURL(/lens=/);
  await page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: "Decisions", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Newest first" })).toHaveAttribute("aria-selected", "true");
});
