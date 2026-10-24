import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, fixture, fulfillJson, guardRoute, S_APP } from "./support";

/**
 * CJC-090-J002. A decision keeps three facts apart: what the rules said (the
 * verdict), what finally happened (the outcome), and how far InnerWarden got
 * (Seen, Decided, Refused, and nothing checked afterwards). None is derived
 * from another, and a record that did not keep the outcome says so rather
 * than "Allowed".
 */

function stage(page: Page, key: string) {
  return page.locator(`section[data-decision] li[data-stage="${key}"]`);
}

async function openCase(page: Page, id: string) {
  await page.goto(`/?view=activity&decision=${encodeURIComponent(id)}`);
  await expect(page.locator(`section[data-decision="${id}"]`)).toBeVisible();
}

test.describe("CJC-090-J002 deterministic action screening", () => {
  test("a deny in monitor mode: would have been refused, not refused, and Enforced says why", async ({ page }) => {
    await openCase(page, CASE.wouldRefuse);
    const card = page.locator(`section[data-decision="${CASE.wouldRefuse}"]`);
    // The heading is what the guard did, in the CLI's words; the mode it decided in is beside it.
    await expect(card.getByRole("heading", { level: 2 })).toHaveText("The rules said deny. Monitor mode records and does not refuse, so it ran.");
    await expect(card.locator('[data-pill="monitor"]')).toHaveText("Decided in monitor");
    await expect(card).not.toContainText("Refused before it ran");
    await expect(stage(page, "refused")).toHaveAttribute("data-mark", "not_applicable");
    // The bold label says what happened: never "Refused" for a decision that ran.
    await expect(stage(page, "refused").locator("p").first()).toHaveText(/^Not refused/);
    await expect(stage(page, "refused")).toContainText("Monitor records and does not refuse");
    // Community reads nothing back, so nothing is ever marked verified.
    await expect(page.locator('section[data-decision] [data-mark="verified"]')).toHaveCount(0);
    await expect(card.locator("[data-not-checked-afterwards]")).toHaveText("Not checked afterwards: Community does not look at what a command did after it ran.");

    // The row in the list says the same outcome, in the same words.
    const row = page.locator(`[data-decision-row="${CASE.wouldRefuse}"]`);
    await expect(row.locator("[data-outcome-words]")).toHaveText("Would have been refused");

    // Verdict, mode and outcome, each as recorded, side by side for whoever asks.
    await page.getByText("Details for investigators").click();
    await expect(page.getByText("deny, monitor, outcome would_block", { exact: true })).toBeVisible();
  });

  test("a deny in enforce mode: refused before it ran, Enforced done, Verified not checked", async ({ page }) => {
    await openCase(page, CASE.refused);
    const card = page.locator(`section[data-decision="${CASE.refused}"]`);
    await expect(card.locator('[data-pill="enforce"]')).toHaveText("Decided in enforce");
    await expect(stage(page, "refused")).toHaveAttribute("data-mark", "done");
    await expect(stage(page, "refused").locator("p").first()).toHaveText(/^Refused/);
    await expect(stage(page, "refused")).toContainText("Before it ran");
    // There is no fourth step: what is not checked is said once, in words, never as a mark.
    await expect(stage(page, "verified")).toHaveCount(0);
    await expect(card.locator("[data-not-checked-afterwards]")).toContainText("Not checked afterwards");
  });

  test("an unsafe call that went through is drawn as a No, never as refused", async ({ page }) => {
    await openCase(page, CASE.unsafeRan);
    await expect(stage(page, "refused")).toHaveAttribute("data-mark", "no");
    await expect(page.locator(`[data-decision-row="${CASE.unsafeRan}"] [data-outcome-words]`)).toHaveText("Judged unsafe, and it ran");
  });

  test("a record that kept no outcome says so, and never becomes Allowed", async ({ page }) => {
    const byId = fixture("decisions-by-id.json");
    const base = byId[CASE.wouldRefuse];
    const id = `cmd:${S_APP}:900`;
    const legacy = {
      ...base.item,
      id,
      seq: 900,
      command: "legacy --no-evidence",
      command_whole: true,
      outcome: "unknown",
      outcome_key: "unplaced",
      mode_at_decision: "unknown",
      recommendation: "deny",
      concern: "other",
      next: [],
      story: {
        happened: [{ kind: "text", text: "Claude Code asked to run this. The guard flagged it." }],
        did: "The rules said deny. This record did not keep whether it ran.",
      },
    };
    const page1 = fixture("decisions-page-1.json");
    await page.route(guardRoute("decisions"), (route) => fulfillJson(route, { ...page1, items: [legacy, ...page1.items.slice(0, 3)] }));
    await page.route(guardRoute("decision"), (route) => fulfillJson(route, { ...base, item: legacy, around: { before: [], after: [] } }));

    await openCase(page, id);
    const row = page.locator(`[data-decision-row="${id}"]`);
    await expect(row.locator("[data-outcome-words]")).toHaveText("Outcome not recorded");
    await expect(row).not.toContainText("Allowed");
    await expect(stage(page, "refused")).toHaveAttribute("data-mark", "unknown");
    await expect(stage(page, "refused")).toContainText("Not recorded whether it was refused");
    await expect(page.locator(`section[data-decision="${id}"]`)).not.toContainText("Allowed");
  });
});
