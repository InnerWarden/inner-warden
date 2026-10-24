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

test.describe("CJC-090-J003 reviewed and unreviewed integration sessions", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(guardRoute("agents"), (route) => fulfillJson(route, AGENTS));
  });

  test("says each agent's state in words, with the one command that changes it", async ({ page }) => {
    await page.goto("/?view=agents");

    // The mode is the config: Enforce, and when it was last screened, apart.
    const reviewed = row(page, "claude-code");
    await expect(reviewed).toHaveAttribute("data-agent-state", "refusing");
    await expect(reviewed.locator('[data-pill="enforce"]')).toHaveText(/Enforce/);
    await expect(reviewed).toContainText("Shell hook");
    await expect(reviewed).toContainText("Last screened");
    await expect(reviewed).not.toContainText("Automatic");

    // A configuration file alone is not an agent someone uses: neutral, never amber.
    const unreviewed = row(page, "openclaw-config");
    await expect(unreviewed).toHaveAttribute("data-agent-state", "not_connected");
    await expect(unreviewed).toContainText("Found a configuration for it; the agent itself was not found on this machine.");
    await expect(unreviewed.locator('[data-pill="needs"]')).toHaveCount(0);

    // Partly connected needs a person, says what to run, and how to restart it.
    const partial = row(page, "partial-wrapper");
    await expect(partial).toHaveAttribute("data-agent-state", "partial");
    await expect(partial.locator('[data-pill="needs"]')).toHaveText(/Partly connected/);
    await expect(partial.locator("[data-command]")).toHaveText("innerwarden agents connect partial-wrapper");
    await expect(partial.locator("[data-restart]")).toContainText("Quit Partial MCP wrapper and start it again.");
    await expect(partial).toContainText("MCP proxy");

    // Automatic setup is off: the page says so and gives the command.
    await expect(page.getByText("Automatic setup is off.")).toBeVisible();
    await expect(page.locator("[data-command]").filter({ hasText: "innerwarden agents auto-connect --monitor" })).toHaveCount(1);
  });

  test("keeps every field apart in the technical view, and never upgrades missing evidence", async ({ page }) => {
    await page.goto("/?view=agents");
    await expect(row(page, "claude-code")).toBeVisible();
    await expect(page.locator("[data-agent-evidence]")).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();

    const reviewed = row(page, "claude-code").locator("[data-agent-evidence]");
    await expect(reviewed).toContainText("Running: yes");
    await expect(reviewed).toContainText("Mode as sent: enforce");
    await expect(reviewed).toContainText("Setup: automatic");
    await expect(reviewed).toContainText("Connection: pretooluse_hook");
    await expect(reviewed).toContainText("Found by: executable_on_path, process");

    const unreviewed = row(page, "openclaw-config").locator("[data-agent-evidence]");
    // Not read is said as not read, never as not running.
    await expect(unreviewed).toContainText("Running: not read on");
    await expect(unreviewed).toContainText("Setup: manual");
    await expect(unreviewed).toContainText("Program on PATH: not found (its configuration file was found)");
    await expect(unreviewed).not.toContainText("Running: yes");

    const partial = row(page, "partial-wrapper").locator("[data-agent-evidence]");
    await expect(partial).toContainText("Running: no");
    await expect(partial).toContainText("Mode as sent: partial");
    await expect(partial).toContainText("Setup: manual");
    await expect(partial).not.toContainText("Setup: automatic");
  });

  test("the Overview's Agents tile counts what the rows count and names who needs you", async ({ page }) => {
    await page.goto("/");
    // The band names who needs you, with the CLI's own step for it.
    const band = page.locator("[data-verdict-row]");
    await expect(band).toHaveAttribute("data-verdict-row", "5");
    await expect(band.getByRole("heading", { level: 1 })).toHaveText(/Partial MCP wrapper is only partly connected/);
    await expect(band.locator("[data-command]")).toHaveText("innerwarden agents connect partial-wrapper");
    // The strip lists the two the rows list as connected, and not the leftover configuration.
    const strip = page.locator("#overview-agents");
    await expect(strip.locator("[data-agent-row]")).toHaveCount(2);
    await expect(strip.locator('[data-agent-row="partial-wrapper"] [data-pill="needs"]')).toHaveText(/Partly connected/);
    await expect(strip.locator('[data-agent-row="claude-code"] [data-pill="enforce"]')).toHaveText(/Enforce/);
    await expect(strip).not.toContainText("OpenClaw");
  });
});
