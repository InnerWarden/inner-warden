import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, fixture, fulfillJson, guardRoute, S_APP } from "./support";

/**
 * CJC-090-J002. A case keeps three facts apart: what the rules said (the
 * verdict), what finally happened (the outcome), and how far InnerWarden got
 * (Seen, Decided, Enforced, Verified). None is derived from another, and a
 * record that did not keep the outcome says so rather than "Allowed".
 */

function stage(page: Page, key: string) {
  return page.locator(`section[data-case] li[data-stage="${key}"]`);
}

async function openCase(page: Page, id: string) {
  await page.goto(`/?view=activity&decision=${encodeURIComponent(id)}`);
  await expect(page.locator(`section[data-case="${id}"]`)).toBeVisible();
}

test.describe("CJC-090-J002 deterministic action screening", () => {
  test("a deny in monitor mode: would have been refused, not refused, and Enforced says why", async ({ page }) => {
    await openCase(page, CASE.wouldRefuse);
    const card = page.locator(`section[data-case="${CASE.wouldRefuse}"]`);
    await expect(card.getByRole("heading", { level: 2 })).toHaveText("Claude Code ran a command the guard flagged");
    await expect(card).toContainText("The rules said deny. Monitor mode records and does not refuse, so it ran.");
    await expect(card).not.toContainText("refused before it ran");
    await expect(stage(page, "enforced")).toHaveAttribute("data-mark", "not_applicable");
    await expect(stage(page, "enforced")).toContainText("monitor");
    // Community reads nothing back, so nothing is ever marked verified.
    await expect(page.locator('section[data-case] [data-mark="verified"]')).toHaveCount(0);

    // The row in the list says the same outcome, in the same words.
    const row = page.locator(`[data-case-row="${CASE.wouldRefuse}"]`);
    await expect(row.locator("[data-outcome-words]")).toHaveText("Would have been refused");

    // Verdict, mode and outcome, each as recorded, side by side for whoever asks.
    await page.getByText("Details for investigators").click();
    await expect(page.getByText("deny, monitor, outcome would_block", { exact: true })).toBeVisible();
  });

  test("a deny in enforce mode: refused before it ran, Enforced done, Verified not checked", async ({ page }) => {
    await openCase(page, CASE.refused);
    const card = page.locator(`section[data-case="${CASE.refused}"]`);
    await expect(card.getByRole("heading", { level: 2 })).toHaveText("Claude Code tried a command the guard refused");
    await expect(stage(page, "enforced")).toHaveAttribute("data-mark", "done");
    await expect(stage(page, "enforced")).toContainText("refused");
    await expect(stage(page, "verified")).toHaveAttribute("data-mark", "unknown");
    await expect(stage(page, "verified")).toContainText("not checked");
  });

  test("an unsafe call that went through is drawn as a No, never as refused", async ({ page }) => {
    await openCase(page, CASE.unsafeRan);
    await expect(stage(page, "enforced")).toHaveAttribute("data-mark", "no");
    await expect(page.locator(`[data-case-row="${CASE.unsafeRan}"] [data-outcome-words]`)).toHaveText("Judged unsafe, and it ran");
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
    const row = page.locator(`[data-case-row="${id}"]`);
    await expect(row.locator("[data-outcome-words]")).toHaveText("Outcome not recorded");
    await expect(row).not.toContainText("Allowed");
    await expect(stage(page, "enforced")).toHaveAttribute("data-mark", "unknown");
    await expect(stage(page, "enforced")).toContainText("not recorded");
    await expect(page.locator(`section[data-case="${id}"]`)).not.toContainText("Allowed");
  });
});
