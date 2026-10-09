import { expect } from "@playwright/test";
import { test } from "./clock";
import { COMMUNITY_TABS, expectHonestUpsell, fulfillJson, guardRoute, META, PAGE_READY } from "./support";

/**
 * The notices at the top of every Community page, in both views: a dashboard
 * open to the network (rose), decisions not being recorded (amber: a person
 * has to fix it), a newer InnerWarden installed (slate: nothing is wrong).
 */

for (const [label, path] of COMMUNITY_TABS) {
  test(`${label}: an exposed dashboard says so at the top, in rose`, async ({ page }) => {
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, exposed: true }));
    await page.goto(path);
    await expect(page.locator(PAGE_READY[label])).toBeVisible();
    const notice = page.locator("main [data-exposed][role=alert]");
    await expect(notice).toContainText("This dashboard is open to the network with no sign-in.");
    await expect(page.locator("header [data-exposed]")).toHaveText(/Open to the network/);
    await expectHonestUpsell(page);
  });

  test(`${label}: a recording outage is amber, with what was lost`, async ({ page }) => {
    await page.route(guardRoute("record-health"), (route) => fulfillJson(route, {
      recording: false,
      since_unix: 1_790_686_920,
      lost_actions: 37,
      summary: "the decision store could not be written",
    }));
    await page.goto(path);
    await expect(page.locator(PAGE_READY[label])).toBeVisible();
    const notice = page.locator('main [data-notice="recording"]');
    await expect(notice).toHaveAttribute("data-needs-you", "");
    await expect(notice).toContainText("InnerWarden is not recording decisions since");
    await expect(notice).toContainText("37 actions were not recorded.");
    await expect(notice).not.toContainText("the decision store could not be written");
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(notice).toContainText("the decision store could not be written");
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
});
