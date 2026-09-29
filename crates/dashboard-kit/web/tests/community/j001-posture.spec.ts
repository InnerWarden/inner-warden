import { expect, test } from "@playwright/test";
import { COMMUNITY_TABS, fulfillJson, guardRoute, META } from "./support";

/**
 * CJC-090-J001. The Community shell: five tabs (the `activity` route is the
 * one labelled Cases), the mode the guard runs in as ONE chip in words, and
 * nothing that calls the dashboard local or safe unless the host said so.
 */
test.describe("CJC-090-J001 Community shell and posture", () => {
  test("names the edition, shows the mode in words once guard/meta answers, and the logo goes home without a reload", async ({ page }) => {
    let releaseMeta!: () => void;
    const metaReady = new Promise<void>((resolve) => { releaseMeta = resolve; });
    let documentRequests = 0;
    page.on("request", (request) => {
      if (request.resourceType() === "document") documentRequests += 1;
    });
    await page.route(guardRoute("meta"), async (route) => {
      await metaReady;
      await fulfillJson(route, { ...META, guardrail: { mode: "monitor", guarded_agents: 2 } });
    });

    await page.goto("/");
    await expect(page.getByText("Community", { exact: true })).toBeVisible();
    const status = page.locator("header [data-meta-status]");
    // Before the host answers, the header claims nothing.
    await expect(status).toHaveAttribute("data-meta-status", "loading");
    await expect(status).toHaveText(/Checking/);
    releaseMeta();
    await expect(status).toHaveAttribute("data-meta-status", "ready");
    await expect(status).toHaveText(/Watching only/);

    const nav = page.getByRole("navigation", { name: "Dashboard views" });
    await expect(nav.getByRole("button")).toHaveText(COMMUNITY_TABS.map(([label]) => label));
    // The plain view never recites the API's own description of itself.
    await expect(page.getByText("Local · read-only API", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Local only", { exact: true })).toHaveCount(0);

    await nav.getByRole("button", { name: "Cases", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Cases", exact: true, level: 1 })).toBeVisible();
    await expect(page).toHaveURL(/\?view=activity$/);
    await page.getByRole("button", { name: "Go to overview" }).click();
    await expect(page.getByRole("heading", { name: "What is happening here" })).toBeVisible();
    expect(new URL(page.url()).search).toBe("");
    expect(documentRequests).toBe(1);
  });

  test("withdraws the mode when a refresh fails, and restores it only on a fresh answer", async ({ page }) => {
    let metaRequests = 0;
    await page.clock.install();
    await page.route(guardRoute("meta"), async (route) => {
      metaRequests += 1;
      if (metaRequests === 2) {
        await fulfillJson(route, { error: "fixture_refresh_failed" }, 503);
        return;
      }
      await fulfillJson(route, { ...META, guardrail: { mode: "enforce", guarded_agents: 1 } });
    });

    await page.goto("/");
    const status = page.locator("header [data-meta-status]");
    await expect(status).toHaveAttribute("data-meta-status", "ready");
    await expect(status).toHaveText(/Refusing/);

    await page.clock.runFor(5_000);
    await expect(status).toHaveAttribute("data-meta-status", "error");
    await expect(status).toHaveText(/Status unknown/);
    await expect(status).not.toHaveText(/Refusing/);
    // The page itself stays: a failed refresh withdraws a claim, not the screen.
    await expect(page.getByRole("heading", { name: "What is happening here" })).toBeVisible();

    await page.clock.runFor(5_000);
    await expect(status).toHaveAttribute("data-meta-status", "ready");
    await expect(status).toHaveText(/Refusing/);
  });

  test("never calls the dashboard local when the host did not say where it listens", async ({ page }) => {
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, {
      version: "1.5.0-fixture",
      edition: "community",
      guardrail: { mode: "unknown" },
    }));
    await page.goto("/");
    const status = page.locator("header [data-meta-status]");
    await expect(status).toHaveAttribute("data-meta-status", "ready");
    await expect(status).toHaveText(/Status unknown/);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(status).not.toHaveText(/Local only/);
    await expect(status).not.toHaveText(/Open to the network/);
  });

  test("says Local only once, at the foot of the page, in the technical view, never as a second header chip", async ({ page }) => {
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, META));
    await page.goto("/");
    const status = page.locator("header [data-meta-status]");
    await expect(status).toHaveAttribute("data-meta-status", "ready");
    await expect(page.locator("[data-local-only]")).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(status).not.toHaveText(/Local only/);
    await expect(status.locator("[data-chip]")).toHaveCount(1);
    await expect(page.locator("[data-local-only]")).toHaveText(/Local only/);
  });

  test("opens each tab from its own address instead of falling back to Overview", async ({ page }) => {
    for (const [label, path] of COMMUNITY_TABS.slice(1)) {
      await page.goto(path);
      await expect(page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: label, exact: true }))
        .toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    }
  });
});
