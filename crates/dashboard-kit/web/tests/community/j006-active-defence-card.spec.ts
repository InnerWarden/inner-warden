import { expect, test } from "@playwright/test";
import { EMPTY_OVERVIEW, fulfillJson, installMachineDefaults } from "./support";

/**
 * The Active Defence slot at the foot of the Overview.
 *
 * THE DEFECT. The card rendered unconditionally for the Community edition. On
 * `iw-challenge` -- sensor, watchdog and DNS guard running, Execution Gate
 * `Armed` over 1387 entries, Secret Read Guard in `ENFORCE` with a canary
 * proving the denial -- the dashboard on that host invited the operator to go
 * and acquire what was already running underneath the page, beneath a header
 * reading "Setup needed". The honest reading of the screen was "you are not
 * protected", on a host that was.
 */

const META = {
  version: "0.16.4-fixture",
  exposed: false,
  edition: "community",
  guardrail: { mode: "monitor", guarded_agents: 1 },
};

test.describe("CJC-J006 the Active Defence card reads the host", () => {
  test("stops offering the product on a host that already runs it", async ({ page }) => {
    await page.route("**/api/guard/meta", (route) =>
      fulfillJson(route, { ...META, active_defence_installed: true }),
    );
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.locator('[data-ad-state="installed"]')).toBeVisible();
    await expect(page.getByText("Extend protection from agent intent to the host.")).toHaveCount(0);
    await expect(page.getByText("Explore Active Defence")).toHaveCount(0);
    // It says where the answer it cannot give actually lives.
    await expect(page.getByText("innerwarden get status", { exact: true })).toBeVisible();
  });

  test("still offers it on a host that does not", async ({ page }) => {
    // The other half. Deleting the card outright would pass the test above, and
    // would take the product's only mention of host protection with it.
    await page.route("**/api/guard/meta", (route) => fulfillJson(route, META));
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.locator('[data-ad-state="offer"]')).toBeVisible();
    await expect(page.getByText("Extend protection from agent intent to the host.")).toBeVisible();
  });

  test("never claims the host is protected, only that the stack is installed", async ({ page }) => {
    // This dashboard runs unprivileged and cannot read LSM_POLICY. Whether a
    // kernel guard is ARMED is not a thing it can see, and a security product
    // that overstates its own coverage is worse than one that says too little.
    await page.route("**/api/guard/meta", (route) =>
      fulfillJson(route, { ...META, active_defence_installed: true }),
    );
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    const card = page.locator('[data-ad-state="installed"]');
    await expect(card).toBeVisible();
    const text = ((await card.textContent()) ?? "").toLowerCase();
    for (const claim of ["armed", "enforcing", "enforced", "you are protected"]) {
      expect(text, `the card must not claim "${claim}"`).not.toContain(claim);
    }
    // Anti-vacuous: an empty card satisfies every absence above.
    expect(text.length).toBeGreaterThan(120);
  });

  test("an older server that sends no verdict still gets the offer", async ({ page }) => {
    // The server omits the field when false, so absent and "not installed" are
    // the same bytes. Reading absence as installed would silence the card on
    // every host running an older binary.
    await page.route("**/api/guard/meta", (route) => fulfillJson(route, META));
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.locator('[data-ad-state="offer"]')).toBeVisible();
  });

  /**
   * THE REGRESSION THIS EXISTS FOR, and the more interesting half.
   *
   * The first cut of this feature had the tour fetch `guard/meta` for itself.
   * `guard/meta` is POLLED, and the posture journey proves a stale claim gets
   * withdrawn by failing the SECOND reading. A second reader took that 503 into
   * itself, the shell's poll got a healthy answer, and the stale claim stood --
   * a real defect in the product, not merely in the fixture: two readers of one
   * polled endpoint disagreeing about which answer was theirs.
   *
   * The tour now takes the reading the shell already made.
   */
  test("the shell reads guard/meta once per poll, not once per reader", async ({ page }) => {
    let metaRequests = 0;
    await page.clock.install();
    await page.route("**/api/guard/meta", (route) => {
      metaRequests += 1;
      return fulfillJson(route, META);
    });
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);

    await page.goto("/");
    await expect(page.locator('[data-ad-state="offer"]')).toBeVisible();
    expect(metaRequests, "the first paint must read guard/meta exactly once").toBe(1);

    // And one per interval after that, not two.
    await page.clock.fastForward(5_000);
    await expect.poll(() => metaRequests).toBe(2);
    await page.clock.fastForward(5_000);
    await expect.poll(() => metaRequests).toBe(3);
  });
});
