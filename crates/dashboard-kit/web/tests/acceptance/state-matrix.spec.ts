import { readFileSync } from "node:fs";
import { expect, test, type Page, type Route } from "@playwright/test";

const fixture = (name: string) => JSON.parse(readFileSync(
  new URL(`../fixtures/enterprise/${name}.json`, import.meta.url),
  "utf8",
));

const casesBootstrap = fixture("cases-bootstrap");
const pageOne = fixture("cases-page-1");
const pageTwo = fixture("cases-page-2");
const contextOnlyCase = fixture("case-context-only-002");
const staleVerificationCase = fixture("case-future-verification-003");

type ListHandler = (route: Route) => void | Promise<void>;

async function installCases(
  page: Page,
  listHandler: ListHandler,
  detailHandler: ListHandler = (route) => route.fulfill({ json: contextOnlyCase }),
) {
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/dashboard/v1/cases?*", listHandler);
  await page.route(/\/api\/dashboard\/v1\/cases\/[^/?]+$/, detailHandler);
}

function emptyPage() {
  return {
    ...structuredClone(pageOne),
    items: [],
    next_cursor: null,
  };
}

test("loading waits for a validated v1 response before mounting case data", async ({ page }) => {
  let releaseResponse!: () => void;
  const responseGate = new Promise<void>((resolve) => {
    releaseResponse = resolve;
  });

  await installCases(page, async (route) => {
    await responseGate;
    await route.fulfill({ json: pageOne });
  });
  await page.goto("/?view=cases");

  const loading = page.getByRole("status").filter({ hasText: "Loading cases" });
  await expect(loading.getByRole("heading", { name: "Loading cases" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Agent attempted to read/ })).toHaveCount(0);

  releaseResponse();
  await expect(page.getByRole("button", { name: /Agent attempted to read/ })).toBeVisible();
  await expect(loading).toHaveCount(0);
});

test("no-data is a valid empty projection and never an adapter error", async ({ page }) => {
  await installCases(page, (route) => route.fulfill({ json: emptyPage() }));
  await page.goto("/?view=cases&q=no-match");

  await expect(page.getByRole("heading", { name: "No matching cases" })).toBeVisible();
  await expect(page.getByText("0 on this page", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Cases response could not be validated" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Cases is unavailable" })).toHaveCount(0);
});

test("partial evidence stays explicit and cannot create a verified outcome", async ({ page }) => {
  await installCases(
    page,
    (route) => route.fulfill({ json: pageOne }),
    (route) => route.fulfill({ json: contextOnlyCase }),
  );
  await page.goto("/?view=cases&case=case-context-only-002");

  const detail = page.getByLabel("Case detail case-context-only-002");
  await expect(detail.getByText("Partial evidence", { exact: true })).toBeVisible();
  await expect(detail.getByText("No verified outcome", { exact: true })).toBeVisible();
  await expect(detail.locator('[data-outcome-trusted="true"]')).toHaveCount(0);
  await expect(detail.getByText("Verified pre-execution block", { exact: true })).toHaveCount(0);
  await expect(detail.getByText("Verified containment", { exact: true })).toHaveCount(0);
});

test("failed refresh retains only the last validated page and labels it stale", async ({ page }) => {
  let listRequests = 0;
  await installCases(page, (route) => {
    listRequests += 1;
    return listRequests === 1
      ? route.fulfill({ json: pageOne })
      : route.fulfill({
        status: 503,
        json: { code: "cases_unavailable", message: "Injected refresh failure", retryable: true },
      });
  });
  await page.goto("/?view=cases");
  const retainedCase = page.getByRole("button", { name: /Agent attempted to read/ });
  await expect(retainedCase).toBeVisible();

  await page.getByRole("button", { name: "Refresh cases" }).click();

  await expect(page.getByText("Showing the last validated cases snapshot", { exact: true })).toBeVisible();
  await expect(page.getByText("Current runtime state is unknown", { exact: false })).toBeVisible();
  await expect(retainedCase).toBeVisible();
  await expect(page.getByRole("heading", { name: "No matching cases" })).toHaveCount(0);
});

test("a corrupt 200 response fails closed instead of becoming no-data", async ({ page }) => {
  await installCases(page, (route) => route.fulfill({
    json: { items: [], next_cursor: null },
  }));
  await page.goto("/?view=cases");

  const corrupt = page.getByRole("alert").filter({ hasText: "Cases response could not be validated" });
  await expect(corrupt.getByRole("heading", { name: "Cases response could not be validated" })).toBeVisible();
  await expect(corrupt).toContainText("No legacy payload is used as a fallback");
  await expect(page.getByRole("heading", { name: "No matching cases" })).toHaveCount(0);
});

test("an unsupported adapter remains distinct from empty and unavailable", async ({ page }) => {
  await installCases(page, (route) => route.fulfill({
    status: 501,
    json: { code: "cases_unsupported", message: "Cases are unsupported on this host", retryable: false },
  }));
  await page.goto("/?view=cases");

  const unsupported = page.getByRole("status").filter({ hasText: "Cases is unsupported" });
  await expect(unsupported.getByRole("heading", { name: "Cases is unsupported" })).toBeVisible();
  await expect(unsupported).toContainText("No equivalent protection is implied");
  await expect(page.getByRole("heading", { name: "No matching cases" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Cases is unavailable" })).toHaveCount(0);
});

test("error state recovers through an explicit refresh without inventing empty data", async ({ page }) => {
  let listRequests = 0;
  await installCases(page, (route) => {
    listRequests += 1;
    return listRequests === 1
      ? route.fulfill({
        status: 500,
        json: { code: "storage_exception", message: "Injected storage exception", retryable: true },
      })
      : route.fulfill({ json: pageOne });
  });
  await page.goto("/?view=cases");

  await expect(page.getByRole("heading", { name: "Cases response could not be validated" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No matching cases" })).toHaveCount(0);

  await page.getByRole("button", { name: "Refresh cases" }).click();

  await expect(page.getByRole("button", { name: /Agent attempted to read/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Cases response could not be validated" })).toHaveCount(0);
  expect(listRequests).toBe(2);
});

test("opaque pagination and selected-case deep links survive a reload", async ({ page }) => {
  const requestedCursors: Array<string | null> = [];
  await installCases(
    page,
    (route) => {
      const cursor = new URL(route.request().url()).searchParams.get("cursor");
      requestedCursors.push(cursor);
      return route.fulfill({ json: cursor === "opaque-page-2" ? pageTwo : pageOne });
    },
    (route) => {
      const caseId = decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1) ?? "");
      return caseId === staleVerificationCase.id
        ? route.fulfill({ json: staleVerificationCase })
        : route.fulfill({ status: 404, json: { code: "case_not_found", message: "Case not found", retryable: false } });
    },
  );
  await page.goto("/?view=cases");

  await page.getByRole("button", { name: /^Next/ }).click();
  await expect(page).toHaveURL(/(?:\?|&)cursor=opaque-page-2(?:&|$)/);
  await expect(page.getByRole("button", { name: /future and stale containment/ })).toBeVisible();

  await page.getByRole("button", { name: /future and stale containment/ }).click();
  await expect(page).toHaveURL(/(?:\?|&)case=case-future-verification-003(?:&|$)/);
  const deepLink = page.url();

  await page.goto(deepLink);

  const detail = page.getByLabel("Case detail case-future-verification-003");
  await expect(detail.getByRole("heading", { name: "Producer supplied future and stale containment verification" })).toBeVisible();
  await expect(page.getByRole("button", { name: /future and stale containment/ })).toHaveAttribute("aria-current", "true");
  expect(requestedCursors).toContain("opaque-page-2");
});
