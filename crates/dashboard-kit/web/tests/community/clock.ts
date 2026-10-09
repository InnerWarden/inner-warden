import { test as base } from "@playwright/test";
import { FIXTURE_NOW_MS } from "./support";

/**
 * Every Community journey runs at the fixture record's clock, never the wall
 * clock.
 *
 * The page renders times relative to `Date.now()` ("since", "ago", "today")
 * against fixtures written at FIXTURE_NOW_MS. j014 failed once the calendar
 * moved past what its fixture assumed, and was fixed alone with
 * `page.clock.setFixedTime`; the other journeys were never audited. Pinning
 * the browser clock here, before every test, makes the suite give the same
 * answer on any day it runs. A journey that needs a different moment still
 * sets its own (`page.clock.install({ time })` or `setFixedTime`); one that
 * drives time forward installs at FIXTURE_NOW_MS too, never a bare
 * `install()`, which would start from the wall clock again.
 *
 * Audited 2026-10-08 by running the whole Community suite with the browser
 * clock started 1, 30 and 400 days after the wall clock: 106 of 106 passed
 * each time, so no journey depends on the date it runs today; this keeps it so.
 */
export const test = base.extend<{ fixtureClock: void }>({
  fixtureClock: [
    async ({ page }, use) => {
      await page.clock.install({ time: FIXTURE_NOW_MS });
      await use();
    },
    { auto: true },
  ],
});
