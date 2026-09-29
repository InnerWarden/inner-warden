import { expect, test } from "@playwright/test";
import { expectHonestUpsell, fulfillJson, guardRoute, META } from "./support";

/**
 * Where Community says what Active Defence adds: the card for attacks on this
 * machine, which Community does not watch. One offer per page, one link out,
 * and on a host that already runs Active Defence, a line saying it is
 * installed and nothing about what it does there.
 *
 * THE DEFECT this began with. The card rendered unconditionally for the
 * Community edition. On a host with the whole paid stack running, the
 * dashboard invited the operator to go and acquire what was already running
 * underneath the page. The honest reading of the screen was "you are not
 * protected", on a host that was.
 */

test.describe("CJC-J006 the Active Defence card reads the host", () => {
  test("stops offering the product on a host that already runs it", async ({ page }) => {
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
    await page.goto("/");
    const installed = page.locator('[data-lane="server_attacks"] [data-ad-state="installed"]');
    await expect(installed).toBeVisible();
    await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(0);
    await expect(page.locator('a[href^="https://innerwarden.com"]')).toHaveCount(0);
    // It says where the answer it cannot give actually lives.
    await expect(installed.locator("[data-command]")).toHaveText("innerwarden get status");
  });

  test("still offers it on a host that does not, once, in the card Community does not cover", async ({ page }) => {
    // The other half. Deleting the card outright would pass the test above, and
    // would take the product's only mention of host protection with it.
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, META));
    await page.goto("/");
    const offer = page.locator('[data-lane="server_attacks"] [data-ad-state="offer"]');
    await expect(offer).toBeVisible();
    await expect(offer).toContainText("the host sensor, an SSH decoy, and automatic response");
    // This fixture host is not Linux: the offer does not pretend it can run here.
    await expect(offer).toContainText("Active Defence runs on Linux servers, where it adds");
    await expect(page.locator('[data-ad-state="offer"]')).toHaveCount(1);
    await expectHonestUpsell(page);
  });

  test("never claims the host is protected, only that the stack is installed", async ({ page }) => {
    // This dashboard runs unprivileged and cannot read the host stack. Whether
    // a kernel guard is ARMED is not a thing it can see, and a security product
    // that overstates its own coverage is worse than one that says too little.
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, { ...META, active_defence_installed: true }));
    await page.goto("/");
    const card = page.locator('[data-ad-state="installed"]');
    await expect(card).toBeVisible();
    const text = ((await card.textContent()) ?? "").toLowerCase();
    for (const claim of ["armed", "enforcing", "enforced", "you are protected"]) {
      expect(text, `the line must not claim "${claim}"`).not.toContain(claim);
    }
    // Anti-vacuous: an empty line satisfies every absence above.
    expect(text.length).toBeGreaterThan(120);
  });

  test("an older server that sends no verdict still gets the offer", async ({ page }) => {
    // The server omits the field when false, so absent and "not installed" are
    // the same bytes. Reading absence as installed would silence the card on
    // every host running an older binary.
    await page.route(guardRoute("meta"), (route) => fulfillJson(route, META));
    await page.goto("/");
    await expect(page.locator('[data-ad-state="offer"]')).toBeVisible();
  });

  /**
   * The shell reads `guard/meta` ONCE per interval, and the tour takes that
   * reading rather than fetching its own (two readers of one polled endpoint
   * once disagreed about which answer was theirs, and a stale claim stood).
   *
   * The poll is a chain: the next request is asked for exactly 5 s after the
   * previous answer SETTLES, so there is one request per interval by
   * construction and never two in flight. The test waits for the shell's own
   * reading (`data-meta-status="ready"`), never for a default the page draws
   * before the answer lands.
   */
  test("the shell reads guard/meta once per poll, not once per reader", async ({ page }) => {
    let metaRequests = 0;
    await page.clock.install();
    await page.route(guardRoute("meta"), (route) => {
      metaRequests += 1;
      return fulfillJson(route, META);
    });

    await page.goto("/");
    await expect(page.locator('[data-meta-status="ready"]')).toBeVisible();
    expect(metaRequests, "the first paint must read guard/meta exactly once").toBe(1);

    await page.clock.fastForward(5_000);
    await expect.poll(() => metaRequests).toBe(2);
    await page.clock.fastForward(5_000);
    await expect.poll(() => metaRequests).toBe(3);
  });

  /**
   * FAILS ON REVERT. With a fixed `setInterval` the ticks fall at 5, 10, 15 s
   * whatever the answers do: a first answer that lands at 4 s is followed by a
   * second request at 5 s, one second later. The chain waits the whole
   * interval after the answer, so at 6 s there is still one request.
   */
  test("a slow first answer does not bring the next poll forward, and does not drop it", async ({ page }) => {
    // Each request is timed where it is made, by the page's own clock (the
    // one the poll runs on), not when this test's route sees it.
    await page.addInitScript(() => {
      const asked: number[] = [];
      (window as unknown as { metaAskedAt: number[] }).metaAskedAt = asked;
      const original = window.fetch.bind(window);
      window.fetch = (input, init) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (url.includes("api/guard/meta")) asked.push(Date.now());
        return original(input, init);
      };
    });
    const askedAt = () => page.evaluate(() => (window as unknown as { metaAskedAt: number[] }).metaAskedAt.slice());
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let answered = 0;
    await page.clock.install();
    await page.route(guardRoute("meta"), async (route) => {
      if (answered === 0) await held;
      answered += 1;
      await fulfillJson(route, META);
    });

    await page.goto("/");
    await expect.poll(async () => (await askedAt()).length).toBe(1);
    await page.clock.runFor(4_000);
    release();
    await expect(page.locator('[data-meta-status="ready"]')).toBeVisible();
    const answeredAt = await page.evaluate(() => Date.now());

    await page.clock.runFor(6_000);
    await expect.poll(async () => (await askedAt()).length, { message: "the next poll was dropped" }).toBe(2);
    const [, second] = await askedAt();
    expect(second - answeredAt, "the next request waits a whole interval after the answer").toBeGreaterThan(4_000);
  });
});
