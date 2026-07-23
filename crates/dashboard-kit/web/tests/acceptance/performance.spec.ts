// Spec 090 T155 — deterministic acceptance/performance coverage.
//
// Fixture + local-build only. No external service, no invented runtime result.
// Every budget is an explicit constant with an actionable diagnostic so a future
// regression names the exact number that moved. Community behaviour + claim
// language are asserted unchanged (a missing counter reads unavailable, never
// zero; a large counter renders EXACTLY, never a float-rounded approximation).

import { expect, test, type Page, type Route } from "@playwright/test";
import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = join(here, "..", "..");
const distAssets = join(webRoot, "dist", "assets");

// ── explicit budgets (raw on-disk bytes; measured baseline JS ~424KB, CSS ~43KB;
//    headroom catches a real regression without flapping on a small legit change) ──
const FIRST_MEANINGFUL_CONTENT_BUDGET_MS = 4_000;
const POLL_MIN_GAP_MS = 4_000; // the shell polls on a 5s interval; allow scheduling slack
const POLL_MAX_REQUESTS_IN_WINDOW = 3; // over a ~7.5s observation window
const MAX_CASES_PER_PAGE = 50; // a page must stay bounded regardless of the backend
const MAX_TOTAL_JS_BYTES = 520_000;
const MAX_TOTAL_CSS_BYTES = 60_000;
const MAX_SINGLE_ASSET_BYTES = 520_000;
const MAX_TOTAL_ASSET_BYTES = 600_000;

const COMMUNITY_META = {
  version: "0.16.4-fixture",
  exposed: false,
  edition: "community",
  guardrail: { mode: "monitor", guarded_agents: 2 },
};

function fulfill(route: Route, json: unknown, status = 200): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(json) });
}

async function readFixture(edition: "community" | "enterprise", name: string): Promise<unknown> {
  return JSON.parse(await readFile(join(here, "..", "fixtures", edition, `${name}.json`), "utf8"));
}

test.describe("CJC-090 / spec 090 T155 — dashboard performance acceptance", () => {
  test("first meaningful Community content renders within the budget", async ({ page }) => {
    const started = Date.now();
    await page.goto("/", { waitUntil: "commit" });
    // The Community shell's first meaningful, claim-honest content — not a spinner.
    await expect(page.getByText("Community", { exact: true })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Connect an agent to start screening its actions." }),
    ).toBeVisible();
    const elapsed = Date.now() - started;
    expect(
      elapsed,
      `first meaningful content took ${elapsed}ms, budget ${FIRST_MEANINGFUL_CONTENT_BUDGET_MS}ms`,
    ).toBeLessThanOrEqual(FIRST_MEANINGFUL_CONTENT_BUDGET_MS);
  });

  test("polling is bounded, never overlaps, and stops on navigation away (FR-101)", async ({ page }) => {
    test.setTimeout(30_000);
    const communityBootstrap = await readFixture("community", "bootstrap");
    const requestTimes: number[] = [];
    let inFlight = 0;
    let maxConcurrent = 0;

    await page.route("**/api/dashboard/v1/bootstrap", async (route) => {
      requestTimes.push(Date.now());
      inFlight += 1;
      maxConcurrent = Math.max(maxConcurrent, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 200));
      inFlight -= 1;
      await fulfill(route, communityBootstrap);
    });

    await page.goto("/");
    await expect(page.getByText("Community", { exact: true })).toBeVisible();
    // Observe ~1.5 poll intervals.
    await page.waitForTimeout(7_500);

    expect(maxConcurrent, "the shell must never have two bootstrap polls in flight at once").toBe(1);
    expect(
      requestTimes.length,
      `bootstrap polled ${requestTimes.length} times in 7.5s; a bounded 5s poll must stay <= ${POLL_MAX_REQUESTS_IN_WINDOW}`,
    ).toBeLessThanOrEqual(POLL_MAX_REQUESTS_IN_WINDOW);
    for (let i = 1; i < requestTimes.length; i += 1) {
      const gap = requestTimes[i] - requestTimes[i - 1];
      expect(gap, `poll gap ${gap}ms must be >= ${POLL_MIN_GAP_MS}ms (bounded, not a tight loop)`)
        .toBeGreaterThanOrEqual(POLL_MIN_GAP_MS);
    }

    // Navigating away tears the shell down: no further poll may start (abort/cleanup).
    const seenBeforeUnmount = requestTimes.length;
    await page.goto("about:blank");
    await page.waitForTimeout(7_000);
    expect(
      requestTimes.length,
      `polling must stop after navigation away; ${requestTimes.length - seenBeforeUnmount} extra poll(s) fired`,
    ).toBe(seenBeforeUnmount);
  });

  test("a large token counter renders as an exact decimal, never a float approximation", async ({ page }) => {
    const generatedAt = Date.UTC(2026, 6, 18, 12, 0, 0);
    // 30 digits — far beyond IEEE-754 exact-integer range; Number() would corrupt it.
    const HUGE = "123456789012345678901234567890";
    const EXACT = "123,456,789,012,345,678,901,234,567,890";
    const LOSSY = Number(HUGE).toLocaleString("en-US");
    // Sanity: the float-rounded rendering genuinely differs from the exact one.
    expect(LOSSY).not.toBe(EXACT);

    await page.route("**/api/token-intelligence", (route) =>
      fulfill(route, {
        schema_version: 1,
        generated_at_ms: generatedAt,
        scope: "available_local_history",
        availability: "available",
        agents: [
          {
            agent_id: "codex",
            display_name: "Codex",
            availability: "available",
            total_tokens: HUGE,
            input_tokens: HUGE,
            output_tokens: "890",
            cache_read_input_tokens: null,
            cached_input_tokens: "0",
            cache_creation_input_tokens: null,
            reasoning_output_tokens: null,
            sessions: 2,
            last_observed_at_ms: generatedAt,
            provenance: {
              source: "local_session_log",
              quality: "partial",
              note: "Retained local history; not billing data.",
            },
          },
        ],
      }),
    );

    await page.goto("/");
    const card = page
      .locator("li")
      .filter({ has: page.getByRole("heading", { name: "Codex", exact: true }) });
    await expect(card).toContainText(EXACT);
    // Community claim language + no float corruption.
    await expect(card).not.toContainText(LOSSY);
    await expect(card).toContainText("Retained local history; not billing data.");
    await expect(card).not.toContainText("billing total");
  });

  test("Enterprise case pagination stays bounded and cursor-driven", async ({ page }) => {
    const casesBootstrap = await readFixture("enterprise", "cases-bootstrap");
    const meta = await readFixture("enterprise", "meta");
    const pageOne = (await readFixture("enterprise", "cases-page-1")) as {
      items: unknown[];
      next_cursor: string | null;
    };
    const pageTwo = await readFixture("enterprise", "cases-page-2");

    const caseRequestCursors: (string | null)[] = [];
    await page.route("**/api/dashboard/v1/bootstrap", (route) => fulfill(route, casesBootstrap));
    await page.route("**/api/meta", (route) => fulfill(route, meta));
    await page.route("**/api/dashboard/v1/cases?*", async (route) => {
      const cursor = new URL(route.request().url()).searchParams.get("cursor");
      caseRequestCursors.push(cursor);
      await fulfill(route, cursor === "opaque-page-2" ? pageTwo : pageOne);
    });

    await page.goto("/?view=cases");

    // The first page is bounded and labelled as such.
    await expect(page.getByRole("heading", { name: "Case results" })).toBeVisible();
    await expect(
      page.getByText(`${pageOne.items.length} on this page`, { exact: false }),
    ).toBeVisible();
    expect(
      pageOne.items.length,
      `a page returned ${pageOne.items.length} items; a bounded page must stay <= ${MAX_CASES_PER_PAGE}`,
    ).toBeLessThanOrEqual(MAX_CASES_PER_PAGE);

    // Advancing uses the opaque cursor — one more bounded request, not a re-fetch of all pages.
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByText("Cursor page", { exact: true })).toBeVisible();

    // First request carries no cursor; the second carries exactly the server cursor.
    expect(caseRequestCursors[0], "the initial case request must not carry a cursor").toBeNull();
    expect(
      caseRequestCursors,
      "pagination must be exactly [initial, next_cursor] — never an unbounded fan-out",
    ).toEqual([null, "opaque-page-2"]);
  });

  test("the production bundle stays within the size budgets", async ({}, testInfo) => {
    const entries = await readdir(distAssets, { withFileTypes: true });
    let totalJs = 0;
    let totalCss = 0;
    let totalAll = 0;
    const oversize: string[] = [];
    const report: string[] = [];
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const bytes = (await stat(join(distAssets, entry.name))).size;
      totalAll += bytes;
      if (entry.name.endsWith(".js")) totalJs += bytes;
      if (entry.name.endsWith(".css")) totalCss += bytes;
      report.push(`${entry.name}: ${bytes}B (single-asset budget ${MAX_SINGLE_ASSET_BYTES}B)`);
      if (bytes > MAX_SINGLE_ASSET_BYTES) oversize.push(`${entry.name} ${bytes}B > ${MAX_SINGLE_ASSET_BYTES}B`);
    }
    // Attach the full size table so a regression is immediately actionable.
    await testInfo.attach("bundle-sizes", {
      body: [
        `total JS ${totalJs}B / budget ${MAX_TOTAL_JS_BYTES}B`,
        `total CSS ${totalCss}B / budget ${MAX_TOTAL_CSS_BYTES}B`,
        `total assets ${totalAll}B / budget ${MAX_TOTAL_ASSET_BYTES}B`,
        ...report,
      ].join("\n"),
      contentType: "text/plain",
    });

    expect(oversize, `oversized asset(s): ${oversize.join("; ")}`).toEqual([]);
    expect(totalJs, `total JS ${totalJs}B exceeds budget ${MAX_TOTAL_JS_BYTES}B`).toBeLessThanOrEqual(
      MAX_TOTAL_JS_BYTES,
    );
    expect(totalCss, `total CSS ${totalCss}B exceeds budget ${MAX_TOTAL_CSS_BYTES}B`).toBeLessThanOrEqual(
      MAX_TOTAL_CSS_BYTES,
    );
    expect(
      totalAll,
      `total assets ${totalAll}B exceeds budget ${MAX_TOTAL_ASSET_BYTES}B`,
    ).toBeLessThanOrEqual(MAX_TOTAL_ASSET_BYTES);
  });
});
