import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { expectHonestUpsell } from "./support";

/**
 * CJC-104-J017. The Community identity screens, served by the fixture server
 * from what the CLI answers with a profiles file and a launcher's records
 * (`agents-identity.json`, `history-identity.json`,
 * `decisions-identity-by-id.json`, written by the CLI's own test):
 *
 * - P1/P2: each agent says how far its own word is backed, why, and the one
 *   command that would back it further; its instances are listed, live first.
 * - P3/P4: an instance's session opens its case, which names the instance and
 *   the layer that decided, and says once, below it, why the relaxation was
 *   not applied: the sentence chosen when the page renders, for where it runs
 *   (the fixture's platform is no Linux and no macOS, and Active Defence is
 *   not installed, so the Linux sentence without Active Defence).
 * - P6: what people decided about agents is listed under Changes.
 *
 * Nothing on these screens says Protected or Protecting.
 */

const OBSERVED = "9d2f41b800004000800000000000ab52";
const CONFINED = "5c1e0a7700004000800000000000c0f1";
const ENDED = "17a3c9e000004000800000000000e4d0";

test.beforeEach(async ({ context, baseURL }) => {
  await context.addCookies([{ name: "iw-fixture", value: "identity", url: baseURL ?? "http://127.0.0.1:4173" }]);
});

function row(page: Page, id: string) {
  return page.locator(`li[data-agent="${id}"]`);
}

async function noProtectedWords(page: Page) {
  const text = (await page.locator("main").innerText()).toLowerCase();
  expect(text).not.toContain("protected");
  expect(text).not.toContain("protecting");
}

test("each agent says how far its word is backed, why, and what would back it further", async ({ page }) => {
  await page.goto("/?view=agents");
  const claude = row(page, "claude-code");
  await expect(claude.locator("[data-agent-identity]")).toBeVisible();

  // The row is its worst live instance: one whose launcher could be replaced
  // (both live ones are observed, and the newer one gives the reason).
  await expect(claude.locator("[data-trust]").first()).toHaveAttribute("data-trust", "observed");
  await expect(claude.locator("[data-trust-reason]")).toHaveText(
    "The launcher is installed in your home folder, so any program you run could replace it: install it system-wide.",
  );
  await expect(claude.locator("[data-confine-step]")).toContainText("Install InnerWarden system-wide");
  await expect(claude.locator("[data-confine-step]")).toContainText("sudo npm install -g innerwarden");
  await expect(claude.locator("[data-profile]")).toHaveText("Profile: claude-code");
  await expect(claude.locator("[data-owner]")).toContainText("Owner: maria");
  await expect(claude.locator("[data-approved]")).toContainText("Approved by dev");

  // Its instances, live first, then the one that ended.
  const instances = claude.locator("[data-instance]");
  await expect(instances).toHaveCount(3);
  await expect(instances.nth(0)).toHaveAttribute("data-instance", OBSERVED);
  await expect(instances.nth(0)).toHaveAttribute("data-instance-trust", "observed");
  await expect(instances.nth(1)).toHaveAttribute("data-instance", CONFINED);
  // A reading from inside the jail tops at observed, even where everything
  // it can check held: the page never calls a Community instance confined.
  await expect(instances.nth(1)).toHaveAttribute("data-instance-trust", "observed");
  await expect(instances.nth(1)).toContainText("Observed");
  await expect(instances.nth(1)).not.toContainText("Confined");
  // The ended instance's graph label says confined; it is shown at observed.
  await expect(instances.nth(2)).toHaveAttribute("data-instance-trust", "observed");
  await expect(instances.nth(2)).toHaveAttribute("data-instance", ENDED);
  await expect(instances.nth(2)).toHaveAttribute("data-live", "false");
  await expect(instances.nth(2)).toContainText("Ended");

  // A jail whose hook has not reported yet is not called confined.
  const codex = row(page, "codex");
  await expect(codex.locator("[data-instance]")).toHaveAttribute("data-instance-trust", "declared");
  await expect(codex.locator("[data-instance]")).toContainText("Not checked yet: nothing was screened since it started.");
  await expect(codex.locator("[data-lifecycle]")).toHaveAttribute("data-lifecycle", "discovered");

  // An agent never started in a jail: its own word only, and no command
  // is guessed for a type whose launch command is not known.
  const cursor = row(page, "cursor");
  await expect(cursor.locator("[data-no-instance]")).toHaveText("No instance started in a jail yet.");
  await expect(cursor.locator("[data-confine-step]")).toHaveCount(0);

  // The one Active Defence line of the page, and what people decided.
  await expect(page.locator('[data-offer="agent_kernel"]')).toHaveCount(1);
  const changes = page.locator("[data-agent-changes]");
  await expect(changes).toBeVisible();
  await expect(changes.locator("li")).toHaveCount(2);
  await expectHonestUpsell(page);
  await noProtectedWords(page);
});

test("an instance's session opens its case, which says which layer decided and why", async ({ page }) => {
  await page.goto("/?view=agents");
  const observed = row(page, "claude-code").locator(`[data-instance="${OBSERVED}"]`);
  await observed.getByRole("button", { name: "9d2f41b8 (open case)" }).click();
  const card = page.locator('section[data-case="cmd:contain:2"]');
  await expect(card).toBeVisible();
  const identity = card.locator("[data-case-identity]");
  await expect(identity).toContainText("instance 9d2f41b8");
  await expect(identity.locator("[data-trust]")).toHaveAttribute("data-trust", "observed");
  const decided = card.locator("[data-decided-by-layer]");
  await expect(decided).toHaveAttribute("data-decided-by-layer", "general");
  await expect(decided).toHaveText("Sent for review by your general rules.");
  const withheld = card.locator("[data-relaxation-withheld]");
  await expect(withheld).toHaveCount(1);
  await expect(withheld).toHaveText(
    "Per-agent relaxations apply on Linux with Active Defence, for an agent started with innerwarden contain --identity.",
  );
  await noProtectedWords(page);
});
