import { expect, test, type Page } from "@playwright/test";
import { EMPTY_OVERVIEW, fulfillJson, installMachineDefaults } from "./support";

function agentCard(page: Page, name: string) {
  return page.locator("li").filter({ has: page.getByRole("heading", { name, exact: true }) });
}

test.describe("CJC-090-J003 reviewed and unreviewed integration sessions", () => {
  test("renders reviewed, unreviewed, partial, and runtime-null states without upgrading evidence", async ({ page }) => {
    await page.route("**/api/guard/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);
    await page.unroute("**/api/guard/agents");
    await page.route("**/api/guard/agents", (route) => fulfillJson(route, {
      schema_version: 2,
      generated_at_ms: Date.UTC(2026, 6, 18, 12, 0, 0),
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
          guardrail: { mode: "enforce", mechanism: "pretooluse_hook", setup_support: "automatic" },
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
        },
      ],
    }));

    await page.goto("/");

    const reviewed = agentCard(page, "Claude Code");
    await expect(reviewed).toContainText("Running");
    await expect(reviewed).toContainText("Enforce");
    await expect(reviewed).toContainText("Automatic");
    await expect(reviewed).toContainText("PreToolUse hook");
    await expect(reviewed).toContainText("Already configured");

    const unreviewed = agentCard(page, "OpenClaw");
    await expect(unreviewed).toContainText("Runtime not confirmed");
    await expect(unreviewed).toContainText("Manual");
    await expect(unreviewed).toContainText("Not available");
    await expect(unreviewed).not.toContainText("Eligible when enabled");
    await expect(unreviewed).not.toContainText("Running process detected");

    const partial = agentCard(page, "Partial MCP wrapper");
    await expect(partial).toContainText("Not running");
    await expect(partial).toContainText("Partial");
    await expect(partial).toContainText("Manual review required");
    await expect(partial).not.toContainText("Already configured");
  });
});
