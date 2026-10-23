import { expect } from "@playwright/test";
import { test } from "./clock";
import { EMPTY_AGENTS, fixture, FIXTURE_NOW_MS, fulfillJson, guardRoute, installZero } from "./support";

/**
 * CJC-090-J004. The Overview: a fresh install is onboarding, not an incident;
 * a failed refresh keeps the last answer and says so; an unreadable record is
 * said in its own place while the agents and the guard's log still render;
 * and every count says the source and the span it covers.
 */

/** An agent connected in monitor that nothing has come through yet. */
const CONNECTED_UNSEEN = {
  ...EMPTY_AGENTS,
  unnamed_by_channel: {},
  agents: [
    {
      id: "claude-code",
      display_name: "Claude Code",
      installed: true,
      running: null,
      detected_by: ["executable_on_path"],
      guardrail: { mode: "monitor", mechanism: "pretooluse_hook", setup_support: "automatic", config_changed_at: "2026-09-29T13:00:00Z" },
      auto_connect_eligible: false,
    },
  ],
};
test.describe("CJC-090-J004 local decision overview", () => {
  test("a fresh install is one onboarding panel, never an incident", async ({ page }) => {
    await installZero(page);
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Getting started" })).toHaveCount(1);
    // The band says what is true: nothing is connected, and nothing was found to connect.
    const band = page.locator("[data-verdict-row]");
    await expect(band).toHaveAttribute("data-verdict-row", "4");
    await expect(band).toContainText("No AI agent is connected yet");
    await expect(band).toContainText("No supported agent was found on this machine.");
    // Getting started says what to do; an empty "Needs a look" would only repeat that nothing happened.
    await expect(page.getByRole("heading", { name: "Needs a look" })).toHaveCount(0);
    await expect(page.locator("#overview-agents")).toContainText("No supported agent was found on this machine.");
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByText("The local dashboard is unavailable")).toHaveCount(0);
  });

  /**
   * FAILS ON REVERT: Getting started sat under three cards and four tiles,
   * at about y=828 at 1440x900 (below the fold), after a paid offer. Now the
   * band leads with what is true, and the steps follow on the first screen.
   */
  test("a first run's steps are the first thing on screen, with no offer and no link out", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await installZero(page);
    await page.goto("/");
    const steps = page.locator("[data-get-started]");
    await expect(steps).toBeVisible();
    const band = await page.locator("[data-verdict-row]").boundingBox();
    expect(band!.y).toBeLessThanOrEqual(200);
    const top = await steps.evaluate((element) => element.getBoundingClientRect().top + window.scrollY);
    expect(top).toBeLessThanOrEqual(700);
    await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
    await expect(page.locator("[data-offer], [data-ad-state]")).toHaveCount(0);
    // No agent here: the first step asks for one, and offers no connect that would connect nothing.
    await expect(steps).toContainText("Install a supported agent (Claude Code, Codex, Cursor, Gemini CLI), then connect it");
    await expect(steps.locator("[data-command]").filter({ hasText: "agents connect" })).toHaveCount(0);
    // The page being read is not a step, and observe is not offered without OpenClaw.
    await expect(page.locator("[data-command]").filter({ hasText: "innerwarden dashboard" })).toHaveCount(0);
    await expect(page.locator("[data-command]").filter({ hasText: "observe install" })).toHaveCount(0);
  });

  test("an agent connected with nothing recorded yet is not onboarding again", async ({ page }) => {
    await installZero(page);
    await page.unroute(guardRoute("agents"));
    await page.route(guardRoute("agents"), (route) => fulfillJson(route, CONNECTED_UNSEEN));
    await page.goto("/");
    const band = page.locator("[data-verdict-row]");
    await expect(band).toHaveAttribute("data-verdict-row", "6");
    await expect(band).toContainText("Connected, but nothing screened since the settings changed");
    await expect(page.locator("#needs-a-look")).toContainText("Nothing recorded yet.");
    await expect(page.getByRole("heading", { name: "Getting started" })).toHaveCount(0);
  });

  test("keeps the last good answer and says so when a refresh fails", async ({ page }) => {
    let calls = 0;
    const firstPage = fixture("decisions-page-1.json");
    await page.clock.install({ time: FIXTURE_NOW_MS });
    await page.route(guardRoute("decisions"), async (route) => {
      if (new URL(route.request().url()).searchParams.has("verdict")) return route.fallback();
      calls += 1;
      if (calls > 1) {
        await fulfillJson(route, { error: "graph_unreadable" }, 503);
        return;
      }
      await fulfillJson(route, firstPage);
    });
    await page.goto("/");
    const reasons = page.locator("#needs-a-look [data-reason-row]");
    await expect(reasons).toHaveCount(4);
    await page.clock.runFor(30_000);
    await expect(page.getByText("Could not refresh. Showing the last answer.")).toBeVisible();
    await expect(reasons).toHaveCount(4);
    // Nothing is said as unread while the last answer is still shown.
    await expect(page.locator("#needs-a-look [data-not-read]")).toHaveCount(0);
  });

  test("an unreadable record is said in its place, and agents and tokens still render", async ({ page }) => {
    await page.route(guardRoute("overview"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.route(guardRoute("decisions"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");

    await expect(page.getByRole("alert").filter({ hasText: "The decision record could not be read" })).toBeVisible();
    // No zero stands in for what could not be read.
    await expect(page.getByText("Nothing flagged", { exact: false })).toHaveCount(0);
    await expect(page.getByText("Nothing recorded yet", { exact: false })).toHaveCount(0);
    await expect(page.locator("#needs-a-look [data-reason-row], #needs-a-look [data-decision-row]")).toHaveCount(0);
    // The sources that did answer still say what they know.
    await expect(page.locator("#overview-agents")).toContainText("Claude Code");
    await expect(page.locator("#refused [data-count]")).toHaveCount(2);
    await expect(page.locator("[data-overview-footer]")).toContainText("Tokens");
  });

  test("says the span its counts cover: since the day the record starts", async ({ page }) => {
    await page.goto("/");
    const record = page.locator("#needs-a-look [data-source]").first();
    await expect(record).toHaveText("From the decision record: newest 96 decisions, about 4 days.");
    // The exact span, from the day the record starts, is one hover away.
    await expect(record.locator("span[title]")).toHaveAttribute("title", /^25 Sept 2026, 17:34 UTC to 29 Sept 2026, 14:03 UTC$/);
    await expect(page.locator("#refused [data-source]")).toHaveText("From the guard's log, last 7 days (UTC). It keeps refusals since 30 Jul.");
    await expect(page.getByText("No time window", { exact: false })).toHaveCount(0);
  });

  /**
   * FAILS ON REVERT: a check by hand was in the list's flagged set and not in
   * the Overview's count, so "See all 28" led to "28 flagged" beside a card of 27.
   */
  test("See all N leads to a list whose summary says the same N, and the card's flagged parts add up to it", async ({ page }) => {
    await page.goto("/");
    const link = page.locator("[data-see-all]");
    const linkCount = Number((await link.textContent())?.match(/See all ([\d,]+)/)?.[1].replace(/,/g, ""));
    expect(linkCount).toBeGreaterThan(0);
    await link.click();
    await expect(page.getByRole("heading", { name: "Decisions", level: 1 })).toBeVisible();
    await expect(page.getByRole("tab", { name: /What your AI agent did/ })).toContainText(linkCount.toLocaleString("en-GB"));
    // The list's own split by outcome adds up to the same N, and a check by hand is not in it.
    const bar = page.locator("[data-outcome-bar]");
    await expect(bar).not.toContainText("Checked by hand");
    const parts = await bar.locator("[data-outcome-filter]").evaluateAll((items) =>
      items.map((item) => Number(item.querySelector("span.font-semibold")?.textContent?.replace(/,/g, "") ?? "0")));
    expect(parts.reduce((sum, part) => sum + part, 0)).toBe(linkCount);
  });

  test("the technical view counts verdicts and outcomes apart", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const records = page.locator('section[aria-labelledby="overview-records-title"]');
    await expect(records).toContainText("By verdict");
    await expect(records).toContainText("By outcome");
    await expect(records).toContainText("outcome not recorded");
    await expect(records).toContainText("Decisions kept: 96");
  });
});
