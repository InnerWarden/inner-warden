import { expect, test } from "@playwright/test";
import { action, casesPage, fulfillJson, installMachineDefaults, session } from "./support";

test.describe("CJC-090-J002 deterministic action screening", () => {
  test("keeps verdict, policy source, enforcement attempt, and verified outcome independent", async ({ page }) => {
    const blocked = action({
      id: "blocked-decision",
      command: "dangerous --verified",
      recommendation: "deny",
      risk: 91,
      outcome: "blocked",
      mode_at_decision: "enforce",
      categories: ["privilege-escalation"],
    });
    const wouldBlock = action({
      id: "monitor-decision",
      seq: 2,
      command: "dangerous --monitor",
      recommendation: "deny",
      outcome: "would_block",
      mode_at_decision: "monitor",
    });
    const unknown = action({
      id: "legacy-decision",
      seq: 3,
      command: "legacy --no-evidence",
      recommendation: undefined,
      outcome: undefined,
      mode_at_decision: undefined,
      decided_by: "unknown",
    });

    await page.route("**/api/guard/overview", (route) => fulfillJson(route, {
      sessions: 1,
      commands: 3,
      blocked: 2,
      review: 0,
      allowed: 0,
      deny_verdicts: 2,
      review_verdicts: 0,
      allow_verdicts: 0,
      unknown_verdicts: 1,
      actual_blocks: 1,
      would_block: 1,
      screened: 0,
      outcomes_unknown: 1,
      top_categories: [{ name: "privilege-escalation", count: 1 }],
      recent_blocks: [blocked, wouldBlock, unknown],
      recent_decisions: [blocked, wouldBlock, unknown],
    }));
    await page.route("**/api/cases**", (route) => fulfillJson(route, casesPage({
      sessions: [session({
        id: "verified-session",
        label: "verified-session",
        commands: 1,
        blocked: 1,
        allowed: 0,
        deny_verdicts: 1,
        allow_verdicts: 0,
        actual_blocks: 1,
        screened: 0,
        items: [blocked],
      })],
    })));
    await installMachineDefaults(page);
    await page.goto("/");

    const verifiedRow = page.getByRole("button", { name: "Open deny decision for dangerous --verified" });
    await expect(verifiedRow).toContainText("Deny");
    await expect(verifiedRow).toContainText("Rule engine");
    await expect(verifiedRow).toContainText("Blocked");

    const monitorRow = page.getByRole("button", { name: "Open deny decision for dangerous --monitor" });
    await expect(monitorRow).toContainText("Deny");
    await expect(monitorRow).toContainText("Would block");
    await expect(monitorRow).not.toContainText("Blocked");

    const legacyRow = page.getByRole("button", { name: "Open unknown decision for legacy --no-evidence" });
    await expect(legacyRow).toContainText("Unknown");
    await expect(legacyRow).toContainText("Outcome unknown");
    await expect(legacyRow).not.toContainText("Allowed");

    await verifiedRow.click();
    const dialog = page.getByRole("dialog", { name: "Decision details" });
    await expect(dialog).toContainText("Verdict");
    await expect(dialog).toContainText("Deny");
    await expect(dialog).toContainText("Execution outcome");
    await expect(dialog).toContainText("Blocked");
    await expect(dialog).toContainText("Decision mode");
    await expect(dialog).toContainText("Enforce mode");
  });
});
