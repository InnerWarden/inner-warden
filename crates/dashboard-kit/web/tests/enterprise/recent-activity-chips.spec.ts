import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page } from "@playwright/test";

const fixture = (name: string) => JSON.parse(readFileSync(
  new URL(`../fixtures/enterprise/${name}.json`, import.meta.url),
  "utf8",
));

// A paid host with Cases, and the five recent decisions the Overview lists,
// carrying the three outcome chips this list draws: "Flagged for review",
// "Stopped by the kernel" and "Allowed". Rows that name a case are buttons and
// the others are plain, which are two separate grids, so both are present.
const casesBootstrap = fixture("cases-bootstrap");
const chipsOverview = fixture("overview-recent-activity-chips");

const CHIPS = ["Flagged for review", "Stopped by the kernel", "Allowed"] as const;

type Box = { x: number; y: number; width: number; height: number };

async function box(locator: Locator): Promise<Box> {
  const found = await locator.boundingBox();
  if (found === null) throw new Error("the element is not drawn");
  return found;
}

/**
 * The outcome chip in the first column of Recent activity, and the command
 * beside it, as drawn.
 *
 * The first column was a fixed 7rem. "Flagged for review" does not fit in it on
 * one line and is not allowed to wrap, so it ran over the command beside it;
 * "Stopped by the kernel" wrapped onto two lines. The chip is found by its
 * words, never by its place in the markup, so a test that cannot find one
 * fails instead of passing over nothing.
 */
async function rows(page: Page) {
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/guard/overview", (route) => route.fulfill({ json: chipsOverview }));
  await page.goto("/");
  const recent = page.getByRole("region", { name: "Recent activity" });
  const items = recent.getByRole("listitem");
  await expect(items).toHaveCount(chipsOverview.recent_decisions.length);
  const measured: { chip: string; box: Box; lineHeight: number; command: Box; row: Box }[] = [];
  for (const item of await items.all()) {
    const matches = await Promise.all(CHIPS.map(async (label) => ({ label, found: item.getByText(label, { exact: true }) })));
    const present = [];
    for (const match of matches) if (await match.found.count() === 1) present.push(match);
    // One chip per row, and it is one of the three.
    expect(present.map((match) => match.label)).toHaveLength(1);
    const chip = present[0].found;
    await expect(chip).toBeVisible();
    measured.push({
      chip: present[0].label,
      box: await box(chip),
      lineHeight: await chip.evaluate((element) => Number.parseFloat(getComputedStyle(element).lineHeight)),
      command: await box(item.locator("code")),
      row: await box(item),
    });
  }
  // Every chip is drawn at least once, or the loop above proved nothing.
  for (const label of CHIPS) expect(measured.some((entry) => entry.chip === label)).toBe(true);
  return measured;
}

test.describe("Recent activity keeps each outcome chip inside its column", () => {
  test("at desktop width every chip is on one line, clear of the command, and the commands line up", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    const measured = await rows(page);

    for (const { chip, box: chipBox, lineHeight, command } of measured) {
      // The chip ends before the command begins: no overlap.
      expect.soft(chipBox.x + chipBox.width, `"${chip}" runs over its command`).toBeLessThanOrEqual(command.x);
      // One line: the line, the chip's padding (4px) and its border (2px).
      expect.soft(chipBox.height, `"${chip}" wraps`).toBeLessThanOrEqual(lineHeight + 6 + 1);
    }

    // The list stays aligned: the command starts at one x in every row.
    const starts = measured.map((entry) => entry.command.x);
    for (const start of starts) expect.soft(start).toBeCloseTo(starts[0], 0);
    // And the chips start at one x too.
    const chipStarts = measured.map((entry) => entry.box.x);
    for (const start of chipStarts) expect.soft(start).toBeCloseTo(chipStarts[0], 0);
  });

  test("on a phone a chip may wrap but never leaves its column", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    const measured = await rows(page);

    for (const { chip, box: chipBox, command, row } of measured) {
      expect.soft(chipBox.x + chipBox.width, `"${chip}" runs over its command`).toBeLessThanOrEqual(command.x);
      // Inside the row it sits in, on the left.
      expect.soft(chipBox.x, `"${chip}" leaves the row`).toBeGreaterThanOrEqual(row.x);
      expect.soft(command.x + command.width, "the command leaves the row").toBeLessThanOrEqual(row.x + row.width + 0.5);
    }
    // The page itself does not scroll sideways for it.
    const width = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
    expect(width.scroll).toBe(width.client);
  });
});
