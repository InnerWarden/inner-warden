import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page, type Route } from "@playwright/test";

const communityUrl = "http://127.0.0.1:4173";
const enterpriseUrl = "http://127.0.0.1:4174";
const fixture = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/enterprise/${name}.json`, import.meta.url), "utf8"));
const casesBootstrap = fixture("cases-bootstrap");
const casesPage = fixture("cases-page-1");
const longCase = fixture("case-context-only-002");

async function installCases(page: Page, listHandler?: (route: Route) => void | Promise<void>) {
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/dashboard/v1/cases?*", (route) => listHandler ? listHandler(route) : route.fulfill({ json: casesPage }));
  await page.route(/\/api\/dashboard\/v1\/cases\/[^/?]+$/, (route) => route.fulfill({ json: longCase }));
}

async function tabTo(page: Page, target: Locator, reverse = false) {
  for (let index = 0; index < 32; index += 1) {
    await page.keyboard.press(reverse ? "Shift+Tab" : "Tab");
    if (await target.evaluate((element) => element === document.activeElement)) return;
  }
  throw new Error(`keyboard focus did not reach ${await target.getAttribute("aria-label") ?? await target.textContent() ?? "target"}`);
}

async function expectVisibleFocus(target: Locator) {
  const focus = await target.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
      outlineColor: style.outlineColor,
      boxShadow: style.boxShadow,
    };
  });
  expect(
    (focus.outlineStyle !== "none" && focus.outlineWidth >= 2 && focus.outlineColor !== "transparent")
      || focus.boxShadow !== "none",
  ).toBe(true);
}

function luminance(value: [number, number, number]): number {
  const linear = value.map((channel) => {
    const component = channel / 255;
    return component <= 0.04045 ? component / 12.92 : ((component + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(foreground: [number, number, number], background: [number, number, number]): number {
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
  return (lighter + 0.05) / (darker + 0.05);
}

test("primary navigation is keyboard-completable and exposes a visible focus indicator", async ({ page }) => {
  await page.goto(communityUrl);
  await expect(page.getByRole("heading", { name: "Connect an agent to start screening its actions." })).toBeVisible();

  const skipLink = page.getByRole("link", { name: "Skip to content" });
  await page.keyboard.press("Tab");
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toBeVisible();
  await expectVisibleFocus(skipLink);

  const activity = page.getByRole("button", { name: "Activity" });
  await tabTo(page, activity);
  await expectVisibleFocus(activity);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/view=activity/);
  await expect(page.getByRole("heading", { name: "Activity", exact: true })).toBeVisible();

  const overview = page.getByRole("button", { name: "Overview", exact: true });
  await tabTo(page, overview, true);
  await expectVisibleFocus(overview);
  await page.keyboard.press("Enter");
  await expect(page).not.toHaveURL(/view=/);
  await expect(page.getByRole("heading", { name: "Connect an agent to start screening its actions." })).toBeVisible();
});

test("keyboard case selection preserves visible focus when detail context changes", async ({ page }) => {
  await installCases(page);
  await page.goto(`${enterpriseUrl}/?view=cases`);

  const caseButton = page.getByRole("button", { name: /A very long source-neutral investigation title/ });
  await tabTo(page, caseButton);
  await expectVisibleFocus(caseButton);
  await page.keyboard.press("Enter");

  const detail = page.getByLabel("Case detail case-context-only-002");
  const title = detail.getByRole("heading", { name: /A very long source-neutral investigation title/ });
  await expect(title).toBeFocused();
  await expectVisibleFocus(title);
});

test("status is announced and readable without colour alone at WCAG AA contrast", async ({ page }) => {
  await installCases(page, (route) => route.fulfill({
    status: 503,
    json: { code: "cases_unavailable", message: "Fixture unavailable", retryable: true },
  }));
  await page.goto(`${enterpriseUrl}/?view=cases`);

  const statusRegion = page.getByRole("status").filter({ hasText: "Cases is unavailable" });
  await expect(statusRegion).toHaveAttribute("aria-live", "polite");
  await expect(statusRegion.getByRole("heading", { name: "Cases is unavailable" })).toBeVisible();

  const badge = statusRegion.locator('[data-status="unavailable"]');
  await expect(badge).toContainText("Unavailable");
  await expect(badge.locator('[aria-hidden="true"]')).toHaveText("—");
  const colours = await badge.evaluate((element) => {
    const style = getComputedStyle(element);
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("2d canvas unavailable");
    const sample = (colour: string): [number, number, number] => {
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = colour;
      context.fillRect(0, 0, 1, 1);
      const [red, green, blue] = context.getImageData(0, 0, 1, 1).data;
      return [red, green, blue];
    };
    return { foreground: sample(style.color), background: sample(style.backgroundColor) };
  });
  expect(contrast(colours.foreground, colours.background)).toBeGreaterThanOrEqual(4.5);
});

test("long labels wrap without horizontal overflow at narrow and wide viewports", async ({ page }) => {
  await installCases(page);

  for (const viewport of [{ width: 320, height: 800 }, { width: 768, height: 900 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport);
    await page.goto(`${enterpriseUrl}/?view=cases&case=case-context-only-002`);
    const detail = page.getByLabel("Case detail case-context-only-002");
    const title = detail.getByRole("heading", { name: /A very long source-neutral investigation title/ });
    await expect(title).toBeVisible();
    await expect(page.getByText(/agent-renamed-wrapper-aaaaaaaaaaaaaaaa/).first()).toBeVisible();

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);

    const titleBounds = await title.boundingBox();
    expect(titleBounds).not.toBeNull();
    expect(titleBounds!.x).toBeGreaterThanOrEqual(0);
    expect(titleBounds!.x + titleBounds!.width).toBeLessThanOrEqual(viewport.width + 1);

    const clippedBadges = await page.locator("[data-status]").evaluateAll((badges) => badges
      .filter((badge) => {
        const bounds = badge.getBoundingClientRect();
        return bounds.width > 0 && (bounds.left < -1 || bounds.right > document.documentElement.clientWidth + 1 || badge.scrollWidth > badge.clientWidth + 1);
      })
      .map((badge) => badge.textContent));
    expect(clippedBadges).toEqual([]);
  }
});
