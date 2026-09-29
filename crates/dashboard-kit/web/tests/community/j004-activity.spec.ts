import { expect, test } from "@playwright/test";
import { fixture, fulfillJson, guardRoute, installZero, ZERO_OVERVIEW } from "./support";

/**
 * CJC-090-J004. The Overview: a fresh install is onboarding, not an incident;
 * a failed refresh keeps the last answer and says so; an unreadable record is
 * said in its own place while agents and tokens still render; and every
 * count says the span it covers ("since 25 Sept 2026" when the record is
 * younger than the window).
 */
test.describe("CJC-090-J004 local decision overview", () => {
  test("a fresh install is one onboarding panel, never an incident", async ({ page }) => {
    await installZero(page);
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Getting started" })).toHaveCount(1);
    const actions = page.locator('[data-lane="agent_actions"]');
    await expect(actions).toHaveAttribute("data-lane-state", "no_source");
    await expect(actions).toContainText("No agent is connected to the guard yet.");
    await expect(actions.locator("[data-command]")).toHaveText("innerwarden agents connect --all --monitor");
    // Getting started says what to do; an empty "Recently flagged" would only repeat that nothing happened.
    await expect(page.getByRole("heading", { name: "Recently flagged" })).toHaveCount(0);
    await expect(page.getByText("No AI agent found on this machine.")).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByText("The local dashboard is unavailable")).toHaveCount(0);
  });

  test("an agent connected with nothing recorded yet is not onboarding again", async ({ page }) => {
    await installZero(page);
    await page.unroute(guardRoute("overview"));
    await page.route(guardRoute("overview"), (route) => fulfillJson(route, {
      ...ZERO_OVERVIEW,
      lanes: {
        ...ZERO_OVERVIEW.lanes,
        agent_actions: { lane: "agent_actions", availability: "available", count_of: "commands", window: "7d", count: 0, sentence: "Connected. Nothing screened yet." },
      },
    }));
    await page.goto("/");
    await expect(page.locator('[data-lane="agent_actions"]')).toContainText("Connected. Nothing screened yet.");
    await expect(page.getByRole("heading", { name: "Getting started" })).toHaveCount(0);
  });

  test("keeps the last good answer and says so when a refresh fails", async ({ page }) => {
    let calls = 0;
    const overview = fixture("overview.json");
    await page.clock.install();
    await page.route(guardRoute("overview"), async (route) => {
      calls += 1;
      if (calls > 1) {
        await fulfillJson(route, { error: "graph_unreadable" }, 503);
        return;
      }
      await fulfillJson(route, overview);
    });
    await page.goto("/");
    const count = page.locator('[data-lane="agent_actions"] [data-lane-count]');
    await expect(count).toHaveText("92");
    await page.clock.runFor(10_000);
    await expect(page.getByText("Could not refresh. Showing the last answer.")).toBeVisible();
    await expect(count).toHaveText("92");
    // Slate, not amber: nobody has to decide anything.
    await expect(page.locator("[data-needs-you]").filter({ hasText: "Could not refresh" })).toHaveCount(0);
  });

  test("an unreadable record is said in its place, and agents and tokens still render", async ({ page }) => {
    await page.route(guardRoute("overview"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.route(guardRoute("decisions"), (route) => fulfillJson(route, { error: "graph_corrupt" }, 503));
    await page.goto("/");

    await expect(page.getByRole("alert").filter({ hasText: "The decision record could not be read" })).toBeVisible();
    await expect(page.getByRole("alert").filter({ hasText: "The flagged commands could not be read" })).toBeVisible();
    // No zero stands in for what could not be read.
    await expect(page.getByText("Nothing flagged yet.")).toHaveCount(0);
    await expect(page.getByText(/Nothing flagged since/)).toHaveCount(0);
    await expect(page.locator("[data-lane-count]")).toHaveCount(0);
    // The sources that did answer still say what they know.
    const strip = page.locator('section[aria-labelledby="on-machine-title"]');
    await expect(strip).toContainText("connected");
    await expect(strip).toContainText("tokens");
  });

  test("says the span its counts cover: since the day the record starts", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator('[data-lane="agent_actions"]')).toContainText("commands since 25 Sept 2026");
    await expect(page.locator('section[aria-labelledby="on-machine-title"]')).toContainText("93 decisions since 25 Sept 2026");
    await expect(page.getByText("No time window", { exact: false })).toHaveCount(0);
  });

  test("the technical view counts verdicts and outcomes apart", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const records = page.locator('section[aria-labelledby="overview-records-title"]');
    await expect(records).toContainText("By verdict");
    await expect(records).toContainText("By outcome");
    await expect(records).toContainText("outcome not recorded");
    await expect(records).toContainText("Decisions kept: 93");
  });
});
