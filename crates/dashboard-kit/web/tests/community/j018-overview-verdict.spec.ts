import { expect, type Locator, type Page } from "@playwright/test";
import { test } from "./clock";

/**
 * The Overview's five-second promise. Without scrolling, at a desk (1440 x
 * 900) and on a phone (390 x 844), a reader can answer: are my agents
 * connected and in which mode (the band's headline and the header's pill),
 * and what is the one next step (the band's step, or its restart words when
 * there is no command to give). Each scenario is the same fixture server in
 * a state a reader meets, picked by the `iw-fixture` cookie.
 */

type Expected = {
  row: number;
  headline: string;
  pill: { state: string; words: RegExp };
  /** The band's one command, or, with no command to give, the agent whose restart comes first. */
  step: { command: string } | { restart: string };
};

const MONITOR_PARTIAL: Expected = {
  row: 5,
  headline: "Codex is only partly connected",
  pill: { state: "needs", words: /Needs you/ },
  step: { command: "innerwarden agents connect codex --monitor" },
};

const SCENARIOS: [string | undefined, Expected][] = [
  [undefined, MONITOR_PARTIAL],
  ["enforce", {
    row: 9,
    headline: "Your 3 AI agents are connected and set to refuse a deny.",
    pill: { state: "enforce", words: /Enforce/ },
    step: { command: "innerwarden notify" },
  }],
  ["mixed", {
    row: 7,
    headline: "1 of 2 agents is set to refuse a deny. Claude Code only records.",
    pill: { state: "mixed", words: /Mixed/ },
    step: { command: "innerwarden agents connect claude-code" },
  }],
  ["partial", MONITOR_PARTIAL],
  ["no-agents", {
    row: 4,
    headline: "No AI agent is connected yet",
    pill: { state: "needs", words: /Needs you/ },
    step: { command: "innerwarden agents connect cursor --monitor" },
  }],
  // The default state: every connected agent in monitor, seen working.
  ["monitor", {
    row: 8,
    headline: "Your 3 AI agents are connected. Monitor: nothing is refused.",
    pill: { state: "monitor", words: /Monitor/ },
    step: { command: "innerwarden enforce" },
  }],
  ["never-screened", {
    row: 6,
    headline: "Connected, but nothing screened since the settings changed",
    pill: { state: "monitor", words: /Monitor/ },
    step: { restart: "Claude Code" },
  }],
  ["unknown", {
    row: 3,
    headline: "Could not read whether your agents are connected",
    pill: { state: "unknown", words: /Unknown/ },
    step: { command: "innerwarden status" },
  }],
  ["not-recording", {
    row: 2,
    headline: "Decisions are not being recorded",
    pill: { state: "needs", words: /Not recording/ },
    step: { command: "innerwarden status" },
  }],
  ["exposed", {
    row: 1,
    headline: "This dashboard is open to the network",
    pill: { state: "exposed", words: /Open to network/ },
    step: { command: "innerwarden dashboard" },
  }],
  ["empty-record", MONITOR_PARTIAL],
  ["log-unreadable", MONITOR_PARTIAL],
  ["older-cli", MONITOR_PARTIAL],
  ["ad-installed", MONITOR_PARTIAL],
];

const VIEWPORTS = [
  { width: 1440, height: 900 },
  { width: 390, height: 844 },
];

async function choose(page: Page, scenario: string | undefined) {
  if (scenario === undefined) return;
  await page.context().addCookies([{ name: "iw-fixture", value: scenario, url: "http://127.0.0.1:4173" }]);
}

/** The element is drawn, and all of it sits inside the first screen. */
async function aboveTheFold(locator: Locator, height: number) {
  await expect(locator).toBeVisible();
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height).toBeLessThanOrEqual(height);
}

for (const viewport of VIEWPORTS) {
  for (const [scenario, expected] of SCENARIOS) {
    test(`the headline, the pill and the one step sit above the fold: ${scenario ?? "plain"}, ${viewport.width} px`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await choose(page, scenario);
      await page.goto("/");

      const band = page.locator("[data-verdict-row]");
      await expect(band).toHaveAttribute("data-verdict-row", String(expected.row));
      const headline = band.getByRole("heading", { level: 1 });
      await expect(headline).toHaveText(new RegExp(`${expected.headline.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
      await aboveTheFold(headline, viewport.height);

      const pill = page.locator("header [data-meta-status] [data-pill]");
      await expect(pill).toHaveAttribute("data-pill", expected.pill.state);
      await expect(pill).toHaveText(expected.pill.words);
      await aboveTheFold(pill, viewport.height);

      // The two numbers are part of the five-second answer too (spec 6.1).
      if ((await page.locator("#refused [data-count]").count()) > 0) {
        await aboveTheFold(page.locator("#refused [data-count]").nth(1), viewport.height);
      }

      if ("command" in expected.step) {
        // ONE step: the first command in the band is the one named, and it is on the first screen.
        const step = band.locator("[data-step]").first();
        await expect(step.locator("[data-command]")).toHaveText(expected.step.command);
        await aboveTheFold(step.locator("[data-command]"), viewport.height);
        await expect(band.locator("[data-step]")).toHaveCount(1);
      } else {
        await expect(band.locator("[data-step]")).toHaveCount(0);
        await aboveTheFold(band.locator(`[data-restart="${expected.step.restart}"]`), viewport.height);
      }
    });
  }
}

test("an unknown is drawn dashed and never as a zero or off", async ({ page }) => {
  await choose(page, "unknown");
  await page.goto("/");
  const band = page.locator('[data-verdict-row="3"]');
  await expect(band).toHaveAttribute("data-tone", "unknown");
  await expect(band).toContainText("Nothing on this page is counted as zero.");
  const agents = page.locator("#overview-agents");
  await expect(agents.locator("[data-not-read]")).toContainText("Not read: the dashboard did not answer for the agents.");
  await expect(agents).not.toContainText("Not connected");
  await expect(agents).not.toContainText(/\b0\b/);
});

test("the Overview asks for exactly seven pages of data, and never for token history", async ({ page }) => {
  const asked: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/guard/") && url.pathname !== "/api/guard/meta") asked.push(`${url.pathname}${url.search}`);
  });
  await page.goto("/");
  await expect(page.locator("#needs-a-look [data-reason-row]").first()).toBeVisible();
  await expect(page.locator("#refused [data-count]")).toHaveCount(2);
  await page.waitForLoadState("networkidle");
  expect(asked.slice().sort()).toEqual([
    "/api/guard/agents",
    "/api/guard/decisions?flagged=1&limit=1",
    "/api/guard/decisions?flagged=1&verdict=deny&limit=3",
    "/api/guard/history",
    "/api/guard/overview",
    "/api/guard/protection",
    "/api/guard/record-health",
  ]);
});

test("the tour's first Overview step points at the band and the counts", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator('[data-tour="overview-verdict"]')).toHaveCount(1);
  await expect(page.locator('[data-tour="overview-lanes"]')).toHaveCount(1);
  await expect(page.locator('[data-tour="overview-lanes"]')).toContainText("Refused, or would have been");
});
