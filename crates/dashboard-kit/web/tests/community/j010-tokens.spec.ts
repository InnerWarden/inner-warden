import { expect } from "@playwright/test";
import { test } from "./clock";
import { FIXTURE_NOW_MS, fulfillJson, guardRoute, NO_TOKEN_HISTORY } from "./support";

/**
 * CJC-090-J010. Tokens: how much each agent used, from its own history on
 * this machine. Counts are exact integers (a counter past 2^53 is never a
 * float), a missing dimension is "not reported" and never zero, and an agent
 * with no history this can read says so rather than showing 0.
 */

const HUGE = {
  schema_version: 1,
  generated_at_ms: FIXTURE_NOW_MS,
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
    last_observed_at_ms: FIXTURE_NOW_MS,
    provenance: { source: "local_session_log", quality: "partial", note: "Retained local history; not billing data." },
  }],
};

test.describe("CJC-090-J010 provenance-aware token intelligence", () => {
  test("draws each agent's own split, and says which agent keeps no history", async ({ page }) => {
    await page.goto("/?view=tokens");
    const claude = page.locator('li[data-token-agent="claude"]');
    await expect(claude).toContainText("Claude Code");
    // The headline leaves cache reads out; they are said apart.
    await expect(claude.locator("[data-token-headline]")).toContainText("41 million");
    await expect(claude.locator("[data-token-headline]")).toContainText("tokens, not counting cache reads");
    await expect(claude.locator("[data-token-cache]")).toHaveText("plus 1.3 billion re-read from cache");
    await expect(claude.locator("[data-part]")).toHaveCount(4);
    // Codex's cached input is inside its input: never a bar segment of its own,
    // and nothing is stacked at all.
    const codex = page.locator('li[data-token-agent="codex"]');
    await expect(codex.locator("[data-part]")).toHaveCount(0);
    await expect(codex.locator("[data-token-lines]")).toContainText("of which 959 million cached");
    await expect(codex.locator("[data-token-lines]")).toContainText("of which 844,960 reasoning");
    const cursor = page.locator('li[data-token-agent="cursor"]');
    await expect(cursor).toContainText("No local source for Cursor's tokens.");
    await expect(cursor).not.toContainText("0 tokens");
    await expect(cursor.locator("[data-provenance]")).toHaveText("No local source");
    await expect(page.getByText("prompts and responses never reach this dashboard", { exact: false })).toBeVisible();
  });

  test("keeps an arbitrary-precision count exact in both views, and a missing dimension unreported", async ({ page }) => {
    await page.route(guardRoute("token-intelligence"), (route) => fulfillJson(route, HUGE));
    await page.goto("/?view=tokens");
    const row = page.locator('li[data-token-agent="codex"]');
    // The exact counts are one press away, every digit kept.
    await row.getByText("Show the exact counts").click();
    await expect(row).toContainText("123,456,789,012,345,678,901,234,567,000");
    await expect(row).toContainText("890");
    await expect(row).not.toContainText("e+");

    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const card = row.locator("[data-token-technical]");
    await expect(card).toContainText("123,456,789,012,345,678,901,234,567,890");
    await expect(card).toContainText("not reported");
    await expect(row).toContainText("Retained local history; not billing data.");
    await expect(row.locator("[data-provenance]")).toHaveText("Partial");
    await expect(card).toContainText("Quality: partial");
    await expect(row).not.toContainText("billing total");
    await expect(page.getByText("Per-day totals are not recorded.")).toBeVisible();
  });

  test("no history at all is said, never drawn as zero", async ({ page }) => {
    await page.route(guardRoute("token-intelligence"), (route) => fulfillJson(route, NO_TOKEN_HISTORY));
    await page.goto("/?view=tokens");
    await expect(page.getByText("No agent on this machine keeps a token history this can read.")).toBeVisible();
    await expect(page.getByText("0 tokens")).toHaveCount(0);
    // The Overview does not read token history at all: it links to Tokens.
    const asked: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("/api/guard/token-intelligence")) asked.push(request.url());
    });
    await page.goto("/");
    await expect(page.locator("#verdict-title")).toBeVisible();
    await expect(page.locator('[data-footer-item="tokens"]')).toHaveText("Tokens");
    await expect(page.getByText("0 tokens")).toHaveCount(0);
    expect(asked).toEqual([]);
  });

  test("an unreadable answer is unreadable, not no usage", async ({ page }) => {
    await page.route(guardRoute("token-intelligence"), (route) => fulfillJson(route, { error: "token_source_failed" }, 503));
    await page.goto("/?view=tokens");
    await expect(page.getByRole("alert")).toContainText("Token history did not answer. Nothing here is counted as zero.");
    await expect(page.getByText("No agent on this machine keeps a token history")).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    // Nothing was read, so the technical view claims no read either.
    await expect(page.locator('[data-read-at="/api/guard/token-intelligence"]')).toHaveCount(0);
    await expect(page.locator("li[data-token-agent]")).toHaveCount(0);
  });

  test("an unsupported provider stays explicit and entirely nullable", async ({ page }) => {
    await page.route(guardRoute("token-intelligence"), (route) => fulfillJson(route, {
      schema_version: 1,
      generated_at_ms: FIXTURE_NOW_MS,
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
    await page.goto("/?view=tokens");
    const row = page.locator('li[data-token-agent="cursor"]');
    await expect(row).toContainText("No local source for Cursor's tokens.");
    await expect(row).not.toContainText(/\d+ tokens/);
    await expect(row).toContainText("No reviewed local token source is available.");

    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const card = row.locator("[data-token-technical]");
    await expect(card).toContainText("Availability: unsupported");
    await expect(card).toContainText("Quality: unsupported");
    await expect(card).not.toContainText(/\b0\b/);
  });
});
