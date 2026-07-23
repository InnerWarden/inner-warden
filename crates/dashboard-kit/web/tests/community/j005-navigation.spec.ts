import { expect, test } from "@playwright/test";
import { action, casesPage, EMPTY_OVERVIEW, fulfillJson, installMachineDefaults, session } from "./support";

test.describe("CJC-090-J005 activity filters, pagination, and drilldown", () => {
  test.beforeEach(async ({ page }) => {
    await installMachineDefaults(page);
  });

  test("uses bounded server filters and pagination and exposes an explicit empty result", async ({ page }) => {
    const seen: URL[] = [];
    await page.route("**/api/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await page.route("**/api/cases**", async (route) => {
      const url = new URL(route.request().url());
      seen.push(url);
      const query = url.searchParams.get("q");
      const verdict = url.searchParams.get("verdict");
      const offset = Number(url.searchParams.get("offset") ?? 0);
      if (query === "does-not-exist") {
        await fulfillJson(route, casesPage({ sessions: [], total_sessions: 0, total_commands: 0, offset }));
      } else if (offset === 12) {
        await fulfillJson(route, casesPage({
          sessions: [session({ id: "page-two", label: "page-two", items: [action({ command: "page two action" })] })],
          total_sessions: 13,
          total_commands: 13,
          offset: 12,
        }));
      } else if (verdict === "deny") {
        await fulfillJson(route, casesPage({
          sessions: [session({ id: "deny-only", label: "deny-only", blocked: 1, allowed: 0, deny_verdicts: 1, allow_verdicts: 0, items: [action({ recommendation: "deny", command: "deny only" })] })],
          total_sessions: 1,
          total_commands: 1,
        }));
      } else {
        await fulfillJson(route, casesPage({
          sessions: [session({ id: "page-one", label: "page-one", items: [action({ command: "page one action" })] })],
          total_sessions: 13,
          total_commands: 13,
        }));
      }
    });

    await page.goto("/");
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await expect(page.getByText("Page 1 of 2", { exact: true })).toBeVisible();
    expect(seen.at(-1)?.searchParams.get("limit")).toBe("12");

    await page.getByRole("button", { name: "Next activity page" }).click();
    await expect(page.getByText("Page 2 of 2", { exact: true })).toBeVisible();
    await expect(page.getByText("page-two", { exact: true })).toBeVisible();
    expect(seen.at(-1)?.searchParams.get("offset")).toBe("12");

    await page.getByRole("button", { name: "Deny verdicts", exact: true }).click();
    await expect(page.getByText("deny-only", { exact: true })).toBeVisible();
    expect(seen.at(-1)?.searchParams.get("verdict")).toBe("deny");
    expect(seen.at(-1)?.searchParams.get("offset")).toBeNull();

    await page.getByRole("searchbox", { name: "Search recorded actions" }).fill("does-not-exist");
    await expect(page.getByRole("heading", { name: "No matching activity" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Clear filters", exact: true }).first()).toBeVisible();
  });

  test("keeps a recent-decision target reachable and opens its null-safe detail", async ({ page }) => {
    const deepLinkRequests: URL[] = [];
    const deepAction = action({
      id: "deep-decision",
      session: "deep-session",
      command: "deep target action",
      recommendation: "review",
      outcome: undefined,
      mode_at_decision: undefined,
      recorded_at_ms: undefined,
      explanation: "exact deep-link evidence",
    });
    const sameCommandWrongId = action({
      id: "different-decision",
      session: "deep-session",
      command: "deep target action",
      recommendation: "deny",
      explanation: "wrong decision evidence",
    });
    await page.route("**/api/overview", (route) => fulfillJson(route, {
      ...EMPTY_OVERVIEW,
      sessions: 1,
      commands: 1,
      review: 1,
      review_verdicts: 1,
      outcomes_unknown: 1,
      recent_blocks: [deepAction],
      recent_decisions: [deepAction],
    }));
    await page.route("**/api/cases**", (route) => {
      const url = new URL(route.request().url());
      deepLinkRequests.push(url);
      const scoped = url.searchParams.get("q") === "deep target action"
        && url.searchParams.get("session") === "deep-session";
      return fulfillJson(route, casesPage({
        sessions: scoped ? [session({
          id: "deep-session",
          label: "deep-session",
          review: 1,
          allowed: 0,
          review_verdicts: 1,
          allow_verdicts: 0,
          outcomes_unknown: 1,
          items: [sameCommandWrongId, deepAction],
          truncated: true,
        })] : [],
        total_sessions: scoped ? 1 : 0,
        total_commands: scoped ? 2 : 0,
      }));
    });

    await page.goto("/");
    await page.getByRole("button", { name: "Open review decision for deep target action" }).click();
    await expect(page.getByRole("heading", { name: "Activity", exact: true })).toBeVisible();
    await expect(page.getByText("Focused session:")).toContainText("deep-session");
    await expect.poll(() => deepLinkRequests.at(-1)?.searchParams.get("q")).toBe("deep target action");
    expect(deepLinkRequests.at(-1)?.searchParams.get("session")).toBe("deep-session");
    const dialog = page.getByRole("dialog", { name: "Decision details" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Needs review");
    await expect(dialog).toContainText("Outcome unknown");
    await expect(dialog).toContainText("exact deep-link evidence");
    await expect(dialog).not.toContainText("wrong decision evidence");
    await expect(dialog).not.toContainText("Decision mode");
    await expect(dialog.locator("dt").filter({ hasText: /^Recorded$/ })).toHaveCount(0);
  });

  test("retains the last activity page when a refresh fails", async ({ page }) => {
    let calls = 0;
    await page.route("**/api/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await page.route("**/api/cases**", async (route) => {
      calls += 1;
      if (calls > 1) {
        await fulfillJson(route, { error: "graph_refresh_failed" }, 503);
        return;
      }
      await fulfillJson(route, casesPage({ sessions: [session({ label: "last-good-session" })] }));
    });

    await page.goto("/");
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await expect(page.getByText("last-good-session", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Deny verdicts", exact: true }).click();
    await expect(page.getByText("Could not refresh. Showing the last available result.")).toBeVisible();
    await expect(page.getByText("last-good-session", { exact: true })).toBeVisible();
  });
});
