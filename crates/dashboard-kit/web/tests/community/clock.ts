import { test as base } from "@playwright/test";
import { FIXTURE_NOW_MS } from "./support";

/** The most opening a tab, or installing its clock, may take. */
const BROWSER_START_MS = 60_000;

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
  // Opening the tab, and installing the clock below, are the browser's
  // start, not the journey: on a loaded runner one tab took 10 s to open
  // (2026-11-21), and charged to the test's 15 s it timed j001 out before its
  // first step. Each gets a budget of its own, so the test's timeout bounds
  // what the journey itself waits for. The page is the built-in one,
  // opened in the test's own context.
  page: [
    async ({ context }, use) => {
      await use(await context.newPage());
    },
    { timeout: BROWSER_START_MS },
  ],
  fixtureClock: [
    async ({ page }, use) => {
      await page.clock.install({ time: FIXTURE_NOW_MS });
      await use();
    },
    { auto: true, timeout: BROWSER_START_MS },
  ],
});
