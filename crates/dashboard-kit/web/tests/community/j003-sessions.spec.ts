import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { FIXTURE_NOW_MS, fulfillJson, guardRoute } from "./support";

/**
 * CJC-090-J003. Hook and MCP protection status, on the Agents page: one row
 * per agent with its state in words and the CLI's own command to change it;
 * the technical view keeps every field apart (mode, mechanism, setup support,
 * runtime evidence) and never upgrades one into another.
 */

const AGENTS = {
  schema_version: 2,
  generated_at_ms: FIXTURE_NOW_MS,
  availability: "available",
  discovery_limited: false,
  auto_connect: { status: "available", enabled: false, mode: "disabled", refresh_interval_secs: 30 },
  agents: [
    {
      id: "claude-code",
      display_name: "Claude Code",
      installed: true,
      running: true,
      detected_by: ["executable_on_path", "process"],
      guardrail: { mode: "enforce", mechanism: "pretooluse_hook", setup_support: "automatic", last_observed_at: "2026-09-29T14:03:00Z" },
      auto_connect_eligible: false,
    },
    {
      id: "openclaw-config",
      display_name: "OpenClaw",
      installed: false,
      running: null,
      detected_by: ["configuration_file"],
      guardrail: { mode: "not_configured", mechanism: null, setup_support: "manual" },
      auto_connect_eligible: false,
    },
    {
      id: "partial-wrapper",
      display_name: "Partial MCP wrapper",
      installed: true,
      running: false,
      detected_by: ["compatible_mcp_configuration"],
      guardrail: { mode: "partial", mechanism: "mcp_proxy", setup_support: "manual" },
      auto_connect_eligible: false,
      next_step: {
        label: "To finish connecting it:",
        command: "innerwarden agents connect partial-wrapper",
        line: "Wires the MCP servers that are still open.",
      },
    },
  ],
};

function row(page: Page, id: string) {
  return page.locator(`li[data-agent="${id}"]`);
}

function card(page: Page, name: string) {
  return page.locator('section[aria-labelledby="local-agents-title"] li').filter({ has: page.getByRole("heading", { name, exact: true }) });
}

test.describe("CJC-090-J003 reviewed and unreviewed integration sessions", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(guardRoute("agents"), (route) => fulfillJson(route, AGENTS));
  });

  test("says each agent's state in words, with the one command that changes it", async ({ page }) => {
    await page.goto("/?view=agents");

    const reviewed = row(page, "claude-code");
    await expect(reviewed).toHaveAttribute("data-agent-state", "refusing");
    await expect(reviewed).toContainText("Refusing");
    await expect(reviewed).toContainText("Shell hook");
    await expect(reviewed).toContainText("Last screened a command");
    await expect(reviewed).not.toContainText("Automatic");

    // A configuration file alone is not an agent someone uses: not amber.
    const unreviewed = row(page, "openclaw-config");
    await expect(unreviewed).toHaveAttribute("data-agent-state", "not_connected");
    await expect(unreviewed).toContainText("Found a configuration for it; the agent itself was not found on this machine.");
    await expect(unreviewed.locator("[data-needs-you]")).toHaveCount(0);

    // Partly connected needs a person, and says what to run.
    const partial = row(page, "partial-wrapper");
    await expect(partial).toHaveAttribute("data-agent-state", "partial");
    await expect(partial.locator("[data-needs-you]")).toHaveText(/Partly connected/);
    await expect(partial.locator("[data-command]")).toHaveText("innerwarden agents connect partial-wrapper");
    await expect(partial).toContainText("MCP proxy");

    // Automatic setup is off: the page says so and gives the command.
    await expect(page.getByText("Automatic setup is off. This turns it on, in monitor mode:")).toBeVisible();
    await expect(page.locator("[data-command]").filter({ hasText: "innerwarden agents auto-connect --monitor" })).toHaveCount(1);
  });

  test("keeps every field apart in the technical view, and never upgrades missing evidence", async ({ page }) => {
    await page.goto("/?view=agents");
    await expect(row(page, "claude-code")).toBeVisible();
    await expect(page.locator('section[aria-labelledby="local-agents-title"]')).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();

    const reviewed = card(page, "Claude Code");
    await expect(reviewed).toContainText("Running");
    await expect(reviewed).toContainText("Enforce");
    await expect(reviewed).toContainText("Automatic");
    await expect(reviewed).toContainText("PreToolUse hook");
    await expect(reviewed).toContainText("Already configured");

    const unreviewed = card(page, "OpenClaw");
    // Not checked is said once for the page, below, never as a badge per card.
    await expect(unreviewed).not.toContainText("Runtime not confirmed");
    await expect(unreviewed).toContainText("Manual");
    await expect(unreviewed).toContainText("Not available");
    await expect(unreviewed).not.toContainText("Eligible when enabled");
    await expect(unreviewed).not.toContainText("Running process detected");

    const partial = card(page, "Partial MCP wrapper");
    await expect(partial).toContainText("Not running");
    await expect(partial).toContainText("Partial");
    await expect(partial).toContainText("Manual review required");
    await expect(partial).not.toContainText("Already configured");

    // Where the platform does not check whether an agent runs, it says so.
    await expect(page.getByText("Whether an agent is running is not checked on this platform.")).toBeVisible();
  });

  test("the Overview's Agents tile counts what the rows count and names who needs you", async ({ page }) => {
    await page.goto("/");
    const tile = page.locator("#on-machine-title").locator("..");
    await expect(tile).toContainText("1 of 2");
    await expect(tile.locator("[data-needs-you]")).toHaveText(/1 partly connected: Partial MCP wrapper/);
  });
});
