import { expect, test, type Page } from "@playwright/test";
import { EMPTY_OVERVIEW, fulfillJson, installMachineDefaults } from "./support";

function agentCard(page: Page, name: string) {
  return page.locator("li").filter({ has: page.getByRole("heading", { name, exact: true }) });
}

test.describe("CJC-090-J008 conservative general agent discovery", () => {
  test("keeps unknown, generic, limited, OpenClaw, Hermes, and runtime-null candidates non-authorizing", async ({ page }) => {
    await page.route("**/api/overview", (route) => fulfillJson(route, EMPTY_OVERVIEW));
    await installMachineDefaults(page);
    await page.unroute("**/api/agents");
    await page.route("**/api/agents", (route) => fulfillJson(route, {
      schema_version: 2,
      generated_at_ms: Date.UTC(2026, 6, 18, 12, 0, 0),
      availability: "available",
      discovery_limited: true,
      auto_connect: { status: "available", enabled: false, mode: "disabled", refresh_interval_secs: 30 },
      agents: [
        {
          id: "generic-mcp-client",
          display_name: "Unknown MCP client",
          installed: false,
          running: null,
          detected_by: ["compatible_mcp_configuration"],
          guardrail: { mode: "not_configured", mechanism: null, setup_support: "unsupported" },
          auto_connect_eligible: false,
        },
        {
          id: "openclaw-candidate",
          display_name: "OpenClaw",
          installed: false,
          running: null,
          detected_by: ["configuration_file"],
          guardrail: { mode: "not_configured", mechanism: null, setup_support: "manual" },
          auto_connect_eligible: false,
        },
        {
          id: "hermes-candidate",
          display_name: "Hermes",
          installed: true,
          running: null,
          detected_by: ["executable_on_path"],
          guardrail: { mode: "not_configured", mechanism: null, setup_support: "unsupported" },
          auto_connect_eligible: null,
        },
      ],
    }));

    await page.goto("/");
    // The discovery safety limit is producer bookkeeping: it renders as a
    // collapsed quiet disclosure under the list, never as an amber banner.
    const disclosure = page.getByText("Some integrations may not be listed");
    await expect(disclosure).toBeVisible();
    await expect(page.getByText("Agent discovery reached its local safety limit.")).toBeHidden();
    await disclosure.click();
    await expect(page.getByText("Agent discovery reached its local safety limit.")).toBeVisible();
    await expect(page.getByText("Automatic setup is")).toContainText("disabled");

    const generic = agentCard(page, "Unknown MCP client");
    await expect(generic).toContainText("Compatible MCP configuration found");
    await expect(generic).toContainText("Runtime not confirmed");
    await expect(generic).toContainText("Unsupported");
    await expect(generic).toContainText("Not available");
    await expect(generic).not.toContainText("Eligible when enabled");

    const openClaw = agentCard(page, "OpenClaw");
    await expect(openClaw).toContainText("Configuration found; CLI not confirmed");
    await expect(openClaw).toContainText("Runtime not confirmed");
    await expect(openClaw).toContainText("Manual setup");
    await expect(openClaw).not.toContainText("Already configured");

    const hermes = agentCard(page, "Hermes");
    await expect(hermes).toContainText("CLI available on this PATH");
    await expect(hermes).toContainText("Runtime not confirmed");
    await expect(hermes).toContainText("Eligibility unavailable");
    await expect(hermes).not.toContainText("Running process detected");
  });
});
