import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
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

test.describe("CJC-090-J008 conservative general agent discovery", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(guardRoute("agents"), (route) => fulfillJson(route, AGENTS));
  });

  test("lists every candidate, calls none of them connected, and asks nothing of the reader for leftovers", async ({ page }) => {
    await page.goto("/?view=agents");

    // An agent the guard cannot wire is listed where only the jail's walls are on offer.
    const jailOnly = page.locator("#agents-jail-only");
    const generic = row(page, "generic-mcp-client");
    await expect(jailOnly.locator('li[data-agent="generic-mcp-client"]')).toHaveCount(1);
    await expect(generic).toHaveAttribute("data-agent-state", "unsupported");
    await expect(generic).toContainText("Cannot be connected yet");
    await expect(generic).toContainText("It has no hook or MCP configuration the guard can use yet.");
    // The jail's step is a template the reader fills in: never copied as it is.
    await expect(generic.locator("[data-command][data-template]")).toHaveText("innerwarden contain -- <command>");
    await expect(generic.getByRole("button", { name: /Copy command/ })).toHaveCount(0);

    // A configuration with no agent behind it: found, not connected, neutral.
    const openClaw = row(page, "openclaw-candidate");
    await expect(page.locator('#agents-found li[data-agent="openclaw-candidate"]')).toHaveCount(1);
    await expect(openClaw).toHaveAttribute("data-agent-state", "not_connected");
    await expect(openClaw.locator('[data-pill="needs"]')).toHaveCount(0);
    await expect(openClaw.locator('[data-pill="off"]')).toHaveText(/Not connected/);

    const hermes = row(page, "hermes-candidate");
    await expect(hermes).toHaveAttribute("data-agent-state", "unsupported");
    await expect(hermes).toContainText("Cannot be connected yet");

    for (const candidate of [generic, openClaw, hermes]) {
      await expect(candidate.locator('[data-pill="enforce"], [data-pill="monitor"]')).toHaveCount(0);
      await expect(candidate).not.toContainText("Last screened");
      await expect(candidate).not.toContainText("Running");
    }
    // No agent is connected, so no mode is shown and none is explained.
    await expect(page.locator("[data-monitor-means]")).toHaveCount(0);
  });

  test("the technical view keeps the evidence, its limits, and the two registers apart", async ({ page }) => {
    await page.goto("/?view=agents");
    await expect(row(page, "hermes-candidate")).toBeVisible();
    const limit = page.getByText("Discovery stopped at its local safety limit: an agent may be missing from this list.");
    // The discovery safety limit is producer bookkeeping: the technical view's, never an amber banner.
    await expect(limit).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(limit).toBeVisible();
    await expect(page.getByText("Automatic setup is off.")).toBeVisible();

    const generic = row(page, "generic-mcp-client").locator("[data-agent-evidence]");
    await expect(generic).toContainText("Found by: compatible_mcp_configuration");
    await expect(generic).toContainText("Setup: unsupported");
    await expect(generic).toContainText("Program on PATH: not found");

    const openClaw = row(page, "openclaw-candidate").locator("[data-agent-evidence]");
    await expect(openClaw).toContainText("Program on PATH: not found (its configuration file was found)");
    await expect(openClaw).toContainText("Setup: manual");

    const hermes = row(page, "hermes-candidate").locator("[data-agent-evidence]");
    await expect(hermes).toContainText("Program on PATH: found");
    await expect(hermes).toContainText("Found by: executable_on_path");
    // Not checked on this platform is not read, never "not running".
    await expect(hermes).toContainText("Running: not read on");
    await expect(hermes).not.toContainText(/Running: no\b/);
    // The plain register is unchanged by the technical one: still not connected.
    await expect(row(page, "hermes-candidate")).toContainText("Cannot be connected yet");
  });

  test("the Overview counts neither a leftover nor an agent the guard cannot wire as one to connect", async ({ page }) => {
    await page.goto("/");
    const strip = page.locator("#overview-agents");
    await expect(strip).toContainText("Unknown MCP client and Hermes cannot be connected yet.");
    await expect(strip.locator("[data-agent-row]")).toHaveCount(0);
    await expect(strip.locator("[data-pill]")).toHaveCount(0);
    // Nothing found here can be connected, so the band offers no connect.
    const band = page.locator("[data-verdict-row]");
    await expect(band).toContainText("No supported agent was found on this machine.");
    await expect(band.locator("[data-command]")).toHaveCount(0);
  });
});
