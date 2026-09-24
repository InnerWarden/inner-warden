import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const fixture = (name: string) => JSON.parse(readFileSync(
  new URL(`../fixtures/enterprise/${name}.json`, import.meta.url),
  "utf8",
));

// A paid host with Cases, two agent actions the guardrail flagged for review
// (one of them in Recent activity), and eight addresses on the HOST side
// waiting on a decision today.
const casesBootstrap = fixture("cases-bootstrap");
const hostWaitingOverview = fixture("overview-host-waiting");
const pageOne = fixture("cases-page-1");

/**
 * The paid Overview, read by someone who does not know the product's insides.
 *
 * Two numbers on this page used to share the words "Needs review": the agent
 * guardrail's `review` verdicts on a tile and on each Recent activity chip,
 * and a case status on the Cases screen. One paid Overview read 0 beside
 * hundreds of cases waiting. The tile and the chips now say "flagged for
 * review", and the headline sends the reader to a control this shell really
 * has, never to Activity, which it does not have.
 *
 * Then the way through. "8 addresses are waiting on you" counts distinct
 * ADDRESSES seen TODAY; its link opens every waiting CASE of ALL time, which is
 * the contract with the paid server (`status=waiting&window=all`). The link
 * must land there, the list request must carry that status, and the words
 * must not promise the list is the eight.
 */
test("the Overview says what each number counts, and the waiting link opens the queue", async ({ page }) => {
  const listRequests: URL[] = [];
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/guard/overview", (route) => route.fulfill({ json: hostWaitingOverview }));
  await page.route("**/api/dashboard/v1/cases?*", (route) => {
    listRequests.push(new URL(route.request().url()));
    return route.fulfill({ json: pageOne });
  });

  await page.goto("/");

  // The guardrail's number is labelled as the guardrail's, and so is the
  // review verdict in Recent activity. The fixture carries one on purpose:
  // with no recent decisions the "no Needs review" check below passes
  // whatever the chip says.
  await expect(page.getByText("Agent actions flagged for review", { exact: true })).toBeVisible();
  const recent = page.getByRole("region", { name: "Recent activity" });
  await expect(recent.getByText("Flagged for review", { exact: true })).toBeVisible();
  await expect(page.getByText("Needs review", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "2 agent actions were flagged for review" })).toBeVisible();
  const remedy = page.getByText("These are the agent guardrail's verdicts, not host cases.", { exact: false });
  await expect(remedy).toContainText("View all in Cases");
  await expect(remedy).toContainText("The agent guardrail");
  await expect(remedy).not.toContainText("Activity");

  // The host's number, and a link that says what it opens.
  const waiting = page.getByRole("region", { name: "8 addresses are waiting on you" });
  await expect(waiting).toBeVisible();
  await expect(waiting).toContainText("cases rather than addresses");
  await expect(waiting).toContainText("the agent's cases as well as the host's");
  await expect(waiting.getByRole("button", { name: "See what is waiting" })).toHaveCount(0);
  // The Overview itself never asks for the case list.
  expect(listRequests).toEqual([]);

  const queueRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/dashboard/v1/cases" && url.searchParams.get("status") === "waiting";
  });
  await waiting.getByRole("button", { name: "See all waiting cases, from any day" }).click();

  const requested = new URL((await queueRequest).url());
  expect(requested.searchParams.get("status")).toBe("waiting");
  expect(requested.searchParams.get("window")).toBe("all");

  await expect(page).toHaveURL(/[?&]view=cases(?:&|$)/);
  await expect(page).toHaveURL(/[?&]status=waiting(?:&|$)/);
  await expect(page).toHaveURL(/[?&]window=all(?:&|$)/);
  await expect(page.getByRole("heading", { name: "Case results" })).toBeVisible();
  // Every list request the Cases screen made on arrival asked for the queue.
  expect(listRequests.length).toBeGreaterThan(0);
  for (const url of listRequests) {
    expect(url.searchParams.get("status")).toBe("waiting");
    expect(url.searchParams.get("window")).toBe("all");
  }
});
