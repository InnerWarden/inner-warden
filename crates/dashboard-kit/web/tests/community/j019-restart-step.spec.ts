import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, fixture, fulfillJson, guardRoute } from "./support";

/**
 * Restarting an agent is the person's step (spec T5). An agent reads its
 * hook or MCP config only when it starts, so every step that changes that
 * config is followed, in the same block, by how to restart that agent and
 * why. Nothing on any page says an agent restarted, reloaded or picked a
 * change up: the page cannot know that.
 *
 * Every page that offers such a step is opened in the states that draw one
 * (the fixture's own, a few scenarios, and an OpenClaw gateway that can be
 * set up), and every config-changing command on it is checked.
 */

/** The commands that change an agent's hook or MCP config (or the gateway's hooks). */
const CONFIG_CHANGING = ["innerwarden enforce", "innerwarden dry-run", "innerwarden install", "innerwarden agents connect", "innerwarden observe install"];

const WHY = "An agent reads its hook or MCP config only when it starts.";

async function useScenario(page: Page, baseURL: string | undefined, scenario: string) {
  await page.context().addCookies([{ name: "iw-fixture", value: scenario, url: baseURL ?? "http://127.0.0.1:4173" }]);
}

/**
 * Every config-changing command on the page, with the restart words of the
 * block it sits in. The block is the step itself, or the band's action when
 * the command is its way back.
 */
async function configSteps(page: Page) {
  return page.locator("[data-command]").evaluateAll((commands, prefixes) =>
    commands.flatMap((command) => {
      const text = (command.textContent ?? "").trim();
      if (!prefixes.some((prefix) => text === prefix || text.startsWith(`${prefix} `))) return [];
      const scope = command.closest("[data-step], [data-verdict-action]");
      const restarts = scope === null ? [] : Array.from(scope.querySelectorAll("[data-restart]")).map((note) => note.textContent ?? "");
      return [{ command: text, restarts }];
    }), CONFIG_CHANGING);
}

async function expectEveryStepRestarts(page: Page, least: number) {
  const steps = await configSteps(page);
  // Anti-vacuous: a page that drew no step would pass every check below.
  expect(steps.length, "config-changing steps on the page").toBeGreaterThanOrEqual(least);
  for (const step of steps) {
    expect(step.restarts.length, `${step.command} has no restart words beside it`).toBeGreaterThan(0);
    for (const note of step.restarts) {
      expect(note, step.command).toMatch(/^If .+ is running, restart it after this step\. /);
      expect(note, step.command).toMatch(/In Claude Code, type \/exit, then run claude\.|Quit .+ and start it again\./);
      expect(note, step.command).toContain(WHY);
    }
  }
}

async function expectNoRestartClaim(page: Page) {
  const text = (await page.locator("main").innerText()).toLowerCase();
  for (const claim of ["restarted", "reloaded", "picked up", "now protected"]) expect(text, claim).not.toContain(claim);
}

test("every config-changing step on the Overview says how to restart each agent, and why", async ({ page, baseURL }) => {
  await page.goto("/");
  await expect(page.locator("#verdict-title")).toBeVisible();
  await expectEveryStepRestarts(page, 1);
  await expectNoRestartClaim(page);
  for (const scenario of ["mixed", "no-agents", "enforce"]) {
    await useScenario(page, baseURL, scenario);
    await page.goto("/");
    await expect(page.locator("#verdict-title")).toBeVisible();
    await expectEveryStepRestarts(page, scenario === "enforce" ? 0 : 1);
    await expectNoRestartClaim(page);
  }
});

test("every config-changing step on Protection says how to restart each agent, and why", async ({ page, baseURL }) => {
  await page.goto("/?view=posture");
  await expect(page.locator("li[data-screening]").first()).toBeVisible();
  // The mode box's two steps and each agent's own switch.
  await expectEveryStepRestarts(page, 5);
  const claude = page.locator("#mode [data-restart]").filter({ hasText: "If Claude Code is running" }).first();
  await expect(claude).toContainText("In Claude Code, type /exit, then run claude.");
  await expect(page.locator("#mode [data-restart]").filter({ hasText: "If Codex is running" }).first()).toContainText("Quit Codex and start it again.");
  await expectNoRestartClaim(page);

  // An OpenClaw gateway that can be set up: its hooks load only when it starts.
  const protection = fixture("protection.json");
  await page.route(guardRoute("protection"), (route) => fulfillJson(route, { ...protection, observe: { installed: false, available: true } }));
  await page.reload();
  const messages = page.locator('#optional li[data-control="messages"]');
  await expect(messages.locator("[data-command]")).toHaveText("innerwarden observe install");
  await expect(messages.locator("[data-restart]")).toContainText("If the OpenClaw gateway is running, restart it after this step.");
  await expectEveryStepRestarts(page, 6);

  for (const scenario of ["enforce", "mixed", "partial"]) {
    await useScenario(page, baseURL, scenario);
    await page.goto("/?view=posture");
    await expect(page.locator("#mode-title")).toBeVisible();
    await expectEveryStepRestarts(page, 1);
    await expectNoRestartClaim(page);
  }
});

test("every config-changing step on Agents says how to restart each agent, and why", async ({ page, baseURL }) => {
  await page.goto("/?view=agents");
  await expect(page.locator('li[data-agent="claude-code"]')).toBeVisible();
  await expectEveryStepRestarts(page, 4);
  // An agent whose settings changed with nothing through since is asked for, by name.
  const gemini = page.locator('li[data-agent="gemini"] [data-restart-prompt]');
  await expect(gemini).toContainText("nothing has come through since");
  await expect(gemini.locator("[data-restart]")).toContainText("Quit Gemini CLI and start it again.");
  await expectNoRestartClaim(page);
  for (const scenario of ["no-agents", "never-screened"]) {
    await useScenario(page, baseURL, scenario);
    await page.goto("/?view=agents");
    await expect(page.locator("#agents-title")).toBeVisible();
    await expect(page.locator("li[data-agent]").first()).toBeVisible();
    await expectEveryStepRestarts(page, 1);
    await expectNoRestartClaim(page);
  }
});

test("every config-changing step on a decision says how to restart its agent, and why", async ({ page }) => {
  await page.goto(`/?view=activity&decision=${encodeURIComponent(CASE.wouldRefuse)}`);
  const detail = page.locator(`[data-decision="${CASE.wouldRefuse}"]`);
  await expect(detail.locator("[data-command]").filter({ hasText: "innerwarden enforce" })).toBeVisible();
  await expectEveryStepRestarts(page, 1);
  await expectNoRestartClaim(page);
  // `innerwarden enforce` switches every connected agent: each one's how and
  // why, not only the agent this decision is about. FAILS ON REVERT to one note.
  const step = detail.locator("[data-step]").filter({ has: page.locator("[data-command]", { hasText: /^innerwarden enforce$/ }) });
  const connected = (fixture("agents.json") as { agents: { display_name: string; guardrail: { mode: string } }[] }).agents
    .filter((agent) => ["monitor", "enforce", "partial", "mixed"].includes(agent.guardrail.mode))
    .map((agent) => agent.display_name);
  expect(connected.length).toBeGreaterThan(1);
  await expect(step.locator("[data-restart]")).toHaveCount(connected.length);
  for (const name of connected) await expect(step.locator(`[data-restart="${name}"]`)).toContainText(WHY);
});

/** A band or a prompt with no command before the restart says "now", never "after this step". */
test("a restart with no step before it says now", async ({ page, baseURL }) => {
  await useScenario(page, baseURL, "never-screened");
  await page.goto("/");
  const band = page.locator('[data-verdict-row="6"]');
  await expect(band.locator("[data-command]")).toHaveCount(0);
  const notes = band.locator("[data-restart]");
  expect(await notes.count()).toBeGreaterThan(0);
  for (const note of await notes.all()) {
    await expect(note).toHaveText(/^If .+ is running, restart it now\. /);
    await expect(note).not.toContainText("after this step");
  }
});
