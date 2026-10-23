import { expect } from "@playwright/test";
import { test } from "./clock";
import { COMMUNITY_TABS, expectHonestUpsell, fulfillJson, guardRoute, META, PAGE_READY } from "./support";

/**
 * The notices at the top of every Community page, in both views: a dashboard
 * open to the network (rose), decisions not being recorded (amber: a person
 * has to fix it), a newer InnerWarden installed (slate: nothing is wrong).
 */

for (const [label, path, titled] of COMMUNITY_TABS) {
  test(`${titled}: an exposed dashboard says so at the top, in rose`, async ({ page }) => {
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, exposed: true }));
    await page.goto(path);
    await expect(page.locator(PAGE_READY[label])).toBeVisible();
    if (path === "/") {
      // The Overview's band says it, with the step that closes it: not a second banner.
      const band = page.locator('[data-verdict-row="1"]');
      await expect(band).toHaveAttribute("data-tone", "exposed");
      await expect(band).toContainText("This dashboard is open to the network");
      await expect(band).toContainText("Anyone who can reach this machine can read your agents' commands here.");
      await expect(page.locator("main [data-exposed]")).toHaveCount(0);
    } else {
      const notice = page.locator("main [data-exposed][role=alert]");
      await expect(notice).toContainText("This dashboard is open to the network with no sign-in.");
    }
    await expect(page.locator('header [data-pill="exposed"]')).toHaveText(/Open to network/);
    await expectHonestUpsell(page);
  });

  test(`${titled}: a recording outage is amber, with what was lost`, async ({ page }) => {
    await page.route(guardRoute("record-health"), (route) => fulfillJson(route, {
      recording: false,
      since_unix: 1_790_686_920,
      lost_actions: 37,
      summary: "the decision store could not be written",
    }));
    await page.goto(path);
    await expect(page.locator(PAGE_READY[label])).toBeVisible();
    if (path === "/") {
      // The Overview's band says it, with what was lost and the step that says why.
      const band = page.locator('[data-verdict-row="2"]');
      await expect(band).toHaveAttribute("data-tone", "needs");
      await expect(band).toContainText("Decisions are not being recorded");
      await expect(band).toContainText("37 actions were not recorded.");
      await expect(band).toContainText("the decision store could not be written");
      await expect(band.locator("[data-command]")).toHaveText("innerwarden status");
      await expect(page.locator('main [data-notice="recording"]')).toHaveCount(0);
      await expectHonestUpsell(page);
      return;
    }
    const notice = page.locator('main [data-notice="recording"]');
    await expect(notice).toHaveAttribute("data-needs-you", "");
    await expect(notice).toContainText("InnerWarden is not recording decisions since");
    await expect(notice).toContainText("37 actions were not recorded.");
    await expect(notice).not.toContainText("the decision store could not be written");
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(notice).toContainText("the decision store could not be written");
    // The technical view says more evidence, never another word about the paid edition.
    await expectHonestUpsell(page);
  });
}

test("an installed update is a slate line, with the CLI's own words", async ({ page }) => {
  const note = "A newer InnerWarden is installed. Restart the dashboard to use it.";
  await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, update_pending: true, update_note: note }));
  await page.goto("/");
  const notice = page.locator('main [data-notice="update"]');
  await expect(notice).toContainText(note);
  await expect(notice).toHaveAttribute("role", "status");
  await expect(notice).not.toHaveAttribute("data-needs-you", /.*/);
});

test("with nothing to say, there are no notices", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator(PAGE_READY.Overview)).toBeVisible();
  await expect(page.locator("main [data-exposed], main [data-notice]")).toHaveCount(0);
  await expectHonestUpsell(page);
});
