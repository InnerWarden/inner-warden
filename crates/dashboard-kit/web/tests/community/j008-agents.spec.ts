import { expect, test, type Page } from "@playwright/test";
import { FIXTURE_NOW_MS, fulfillJson, guardRoute } from "./support";

/**
 * CJC-090-J008. Conservative discovery: an unknown MCP client, a config file
 * with no agent behind it, and an agent the guard cannot wire yet are all
 * listed, none is called connected, none turns the page amber on its own,
 * and the technical view keeps the exact evidence and its limits.
 */

const AGENTS = {
  schema_version: 2,
  generated_at_ms: FIXTURE_NOW_MS,
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
};

function row(page: Page, id: string) {
  return page.locator(`li[data-agent="${id}"]`);
}

function card(page: Page, name: string) {
  return page.locator('section[aria-labelledby="local-agents-title"] li').filter({ has: page.getByRole("heading", { name, exact: true }) });
}

test.describe("CJC-090-J008 conservative general agent discovery", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(guardRoute("agents"), (route) => fulfillJson(route, AGENTS));
  });

  test("lists every candidate, calls none of them connected, and asks nothing of the reader for leftovers", async ({ page }) => {
    await page.goto("/?view=agents");

    const generic = row(page, "generic-mcp-client");
    await expect(generic).toHaveAttribute("data-agent-state", "unsupported");
    await expect(generic).toContainText("Cannot be connected yet");
    await expect(generic).toContainText("This agent has no hook or MCP configuration the guard can use yet.");

    const openClaw = row(page, "openclaw-candidate");
    await expect(openClaw).toHaveAttribute("data-agent-state", "not_connected");
    await expect(openClaw.locator("[data-needs-you]")).toHaveCount(0);

    const hermes = row(page, "hermes-candidate");
    await expect(hermes).toHaveAttribute("data-agent-state", "unsupported");
    await expect(hermes).toContainText("Cannot be connected yet");

    for (const candidate of [generic, openClaw, hermes]) {
      await expect(candidate).not.toContainText("Refusing");
      await expect(candidate).not.toContainText("Watching only");
      await expect(candidate).not.toContainText("Running now");
    }
  });

  test("the technical view keeps the evidence, its limits, and the two registers apart", async ({ page }) => {
    await page.goto("/?view=agents");
    await expect(row(page, "hermes-candidate")).toBeVisible();
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    const panel = page.locator('section[aria-labelledby="local-agents-title"]');

    // The discovery safety limit is producer bookkeeping: a collapsed quiet
    // disclosure under the list, never an amber banner.
    const disclosure = panel.getByText("Some integrations may not be listed");
    await expect(disclosure).toBeVisible();
    await expect(panel.getByText("Agent discovery reached its local safety limit.")).toBeHidden();
    await disclosure.click();
    await expect(panel.getByText("Agent discovery reached its local safety limit.")).toBeVisible();
    await expect(panel.getByText("Automatic setup is", { exact: false })).toContainText("disabled");

    const generic = card(page, "Unknown MCP client");
    await expect(generic).toContainText("Compatible MCP configuration found");
    await expect(generic).toContainText("Runtime not confirmed");
    await expect(generic).toContainText("Unsupported");
    await expect(generic).toContainText("Not available");
    await expect(generic).not.toContainText("Eligible when enabled");

    const openClaw = card(page, "OpenClaw");
    await expect(openClaw).toContainText("Configuration found; CLI not confirmed");
    await expect(openClaw).toContainText("Runtime not confirmed");
    await expect(openClaw).toContainText("Manual setup");
    await expect(openClaw).not.toContainText("Already configured");

    const hermes = card(page, "Hermes");
    await expect(hermes).toContainText("CLI available on this PATH");
    await expect(hermes).toContainText("Runtime not confirmed");
    await expect(hermes).not.toContainText("Running process detected");
    await expect(hermes).toContainText("Eligibility unavailable");
    await expect(hermes).not.toContainText("Eligible when enabled");
  });

  test("the Overview counts neither a leftover nor an agent the guard cannot wire as one to connect", async ({ page }) => {
    await page.goto("/");
    const strip = page.locator('section[aria-labelledby="on-machine-title"]');
    await expect(strip).toContainText("Unknown MCP client and Hermes cannot be connected yet.");
    await expect(strip).not.toContainText("Every agent found is connected");
    await expect(strip.locator("[data-needs-you]")).toHaveCount(0);
  });
});
