import { expect, test, type Page } from "@playwright/test";
import { EMPTY_OVERVIEW, fulfillJson, installMachineDefaults, NO_TOKEN_HISTORY } from "./support";

const generatedAt = Date.UTC(2026, 6, 18, 12, 0, 0);

async function installBase(page: Page) {
  await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
  await installMachineDefaults(page);
  await page.unroute("**/api/guard/token-intelligence");
}

test.describe("CJC-090-J010 provenance-aware token intelligence", () => {
  test("shows a deterministic loading state before data arrives", async ({ page }) => {
    await installBase(page);
    let release!: () => void;
    const ready = new Promise<void>((resolve) => { release = resolve; });
    await page.route("**/api/guard/token-intelligence", async (route) => {
      await ready;
      await fulfillJson(route, NO_TOKEN_HISTORY);
    });
    await page.goto("/");
    await expect(page.getByRole("status", { name: "Loading token intelligence" })).toBeVisible();
    release();
    await expect(page.getByRole("heading", { name: "No local token history yet" })).toBeVisible();
  });

  test("preserves arbitrary-precision decimal strings and independent null dimensions", async ({ page }) => {
    await installBase(page);
    await page.route("**/api/guard/token-intelligence", (route) => fulfillJson(route, {
      schema_version: 1,
      generated_at_ms: generatedAt,
      scope: "available_local_history",
      availability: "available",
      agents: [{
        agent_id: "codex",
        display_name: "Codex",
        availability: "available",
        total_tokens: "123456789012345678901234567890",
        input_tokens: "123456789012345678901234567000",
        output_tokens: "890",
        cache_read_input_tokens: null,
        cached_input_tokens: "0",
        cache_creation_input_tokens: null,
        reasoning_output_tokens: null,
        sessions: 2,
        last_observed_at_ms: generatedAt,
        provenance: { source: "local_session_log", quality: "partial", note: "Retained local history; not billing data." },
      }],
    }));
    await page.goto("/");

    const card = page.locator("li").filter({ has: page.getByRole("heading", { name: "Codex", exact: true }) });
    await expect(card).toContainText("123,456,789,012,345,678,901,234,567,890");
    await expect(card).toContainText("Unavailable");
    await expect(card).toContainText("Retained local history; not billing data.");
    await expect(card).toContainText("Partial");
    await expect(card).not.toContainText("billing total");
  });

  test("shows no-data without turning missing history into zero", async ({ page }) => {
    await installBase(page);
    await page.route("**/api/guard/token-intelligence", (route) => fulfillJson(route, NO_TOKEN_HISTORY));
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "No local token history yet" })).toBeVisible();
    // The empty state now names the next thing that has to happen instead of
    // reciting our own rule. The rule it recited is still enforced, and it is
    // still stated once, under the panel.
    await expect(page.getByText("Counts appear here once one does.")).toBeVisible();
    await expect(page.getByText("Prompts, responses and tool content never reach this dashboard")).toBeVisible();
  });

  test("shows endpoint errors as unavailable without inferring usage", async ({ page }) => {
    await installBase(page);
    await page.route("**/api/guard/token-intelligence", (route) => fulfillJson(route, { error: "token_source_failed" }, 503));
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Token intelligence is unavailable" })).toBeVisible();
    await expect(page.getByText("No usage value is being inferred from the missing response.")).toBeVisible();
  });

  test("keeps unsupported providers explicit and entirely nullable", async ({ page }) => {
    await installBase(page);
    await page.route("**/api/guard/token-intelligence", (route) => fulfillJson(route, {
      schema_version: 1,
      generated_at_ms: generatedAt,
      scope: "available_local_history",
      availability: "partial",
      agents: [{
        agent_id: "cursor",
        display_name: "Cursor",
        availability: "unsupported",
        total_tokens: null,
        input_tokens: null,
        output_tokens: null,
        cache_read_input_tokens: null,
        cached_input_tokens: null,
        cache_creation_input_tokens: null,
        reasoning_output_tokens: null,
        sessions: null,
        last_observed_at_ms: null,
        provenance: { source: "not_available", quality: "unsupported", note: "No reviewed local token source is available." },
      }],
    }));
    await page.goto("/");

    const card = page.locator("li").filter({ has: page.getByRole("heading", { name: "Cursor", exact: true }) });
    await expect(card).toContainText("Unsupported");
    await expect(card).toContainText("Token usage is unavailable for this agent");
    await expect(card).toContainText("No reviewed local token source is available.");
    await expect(card).not.toContainText("Tokens observed");
  });
});
