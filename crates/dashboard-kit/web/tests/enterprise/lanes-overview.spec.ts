import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const fixture = (name: string) => JSON.parse(readFileSync(
  new URL(`../fixtures/enterprise/${name}.json`, import.meta.url),
  "utf8",
));

// A paid host that answers the Overview's three questions, and the same host
// on a server that answers only two, one of them with no source to read.
const casesBootstrap = fixture("cases-bootstrap");
const lanesOverview = fixture("overview-lanes");
const partialLanesOverview = fixture("overview-lanes-partial");
// A paid server from before lanes.
const olderOverview = fixture("overview-host-waiting");

async function open(page: Page, overview: unknown) {
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/guard/overview", (route) => route.fulfill({ json: overview }));
  await page.goto("/");
}

/**
 * The Overview, read by someone who has never seen the product.
 *
 * It used to lead with the agent's screened commands, give the server one
 * amber line, and say nothing at all about the messages people sent the
 * agent: about forty figures and no answer. On a host that answers the three
 * questions it now leads with them, one card each: a number, the span it
 * covers, the host's own sentence and the newest case. The figures it used to
 * lead with are all still there, behind "Show technical detail".
 */
test("a paid Overview leads with the three questions, one card each", async ({ page }) => {
  await open(page, lanesOverview);

  await expect(page.getByRole("heading", { level: 1, name: "What is happening here" })).toBeVisible();
  const prompt = page.getByRole("region", { name: "Messages to your AI agent" });
  const agent = page.getByRole("region", { name: "What your AI agent did" });
  const host = page.getByRole("region", { name: "Attacks on this server" });
  for (const card of [prompt, agent, host]) await expect(card).toBeVisible();

  await expect(agent).toContainText("8");
  await expect(agent).toContainText("in the last 24 hours");
  await expect(agent).toContainText("Your agent tried 8 commands. InnerWarden refused 5 before they ran");
  await expect(agent).toContainText("Latest:");
  await expect(agent).toContainText("AI agent session wren-visitor-28eb7f9c");
  await expect(prompt).toContainText("its AI provider's filter caught 1");
  await expect(host).toContainText("823");
  // What is waiting on a person is never behind the switch.
  await expect(host).toContainText("32 waiting on you");
  await expect(page.getByRole("region", { name: "1 address is waiting on you" })).toBeVisible();
  // What the kernel stopped reads as stopped, not as allowed.
  await expect(page.getByRole("region", { name: "Recent activity" })).toContainText("The kernel stopped sudo");

  // The figures the page used to lead with are behind the switch, whole.
  await expect(page.getByRole("heading", { name: "8 agent actions screened on this host." })).toHaveCount(0);
  await expect(page.getByText("Recorded decisions", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "What the guardrail actually did" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Risk signals" })).toHaveCount(0);

  await page.getByLabel("Show technical detail").check();
  await expect(page.getByRole("heading", { name: "The records behind these cards" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "8 agent actions screened on this host." })).toBeVisible();
  await expect(page.getByText("Recorded decisions", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What the guardrail actually did" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Risk signals" })).toBeVisible();
  // Still one page heading, and the cards still first.
  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
  await page.getByLabel("Show technical detail").uncheck();
});

/**
 * A lane with nothing on this host to read has no number, never a zero, and
 * the host's sentence says how to turn the source on. A lane the host did not
 * send is not drawn at all.
 */
test("a lane with no source says so without a number, and a lane not sent is not drawn", async ({ page }) => {
  await open(page, partialLanesOverview);

  const prompt = page.getByRole("region", { name: "Messages to your AI agent" });
  await expect(prompt).toContainText("InnerWarden is not reading this agent's conversations yet");
  await expect(prompt.locator("[data-lane-count]")).toHaveCount(0);
  await expect(prompt.getByRole("button")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "What your AI agent did" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Attacks on this server" })).toHaveCount(0);
});

/**
 * A paid server from before lanes sends none of the new fields, and its
 * Overview is the page it always was: the posture hero as the page heading,
 * the decision record with its tiles, and no card.
 */
test("a server that sends no lanes renders the Overview as before", async ({ page }) => {
  await open(page, olderOverview);

  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
  await expect(page.getByRole("heading", { name: "What is happening here" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "What your AI agent did" })).toHaveCount(0);
  await expect(page.getByText("Agent actions flagged for review", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recent activity" })).toBeVisible();
});

/** The cards wrap on a phone and never push the page sideways. */
for (const width of [320, 768, 1440]) {
  test(`the lane cards fit a ${width} px screen`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, lanesOverview);
    await expect(page.getByRole("region", { name: "Attacks on this server" })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
}
