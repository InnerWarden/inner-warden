import { readFileSync } from "node:fs";
import { expect, test, type Page, type Request } from "@playwright/test";

const fixture = (name: string) => JSON.parse(readFileSync(
  new URL(`../fixtures/enterprise/${name}.json`, import.meta.url),
  "utf8",
));

// These journeys need the paid Cases screen, which is not in this repository:
// they run in the paid bundle after composition, once its Cases screen draws
// the kit's `CaseLaneTabs` from the list's `lane_counts`.
const casesBootstrap = fixture("cases-bootstrap");
const lanesOverview = fixture("overview-lanes");
const lanesPage = fixture("cases-page-lanes");
const pageOne = fixture("cases-page-1");
const caseDetail = fixture("case-agent-host-001");

const UNKNOWN_PARAMETER = {
  status: 400,
  json: { code: "enterprise_cases_query_invalid", message: "The cases query contains an unknown or malformed parameter.", retryable: false },
};

const includes = (url: URL) => (url.searchParams.get("include") ?? "").split(",").filter((name) => name.length > 0);

/**
 * A host that files cases into lanes. Every list answer carries the lane
 * counts when asked, and the rows it lists do not depend on the lane: these
 * journeys are about what the screen ASKS for and what it shows around the
 * list, not about the host's filing.
 */
async function lanesHost(page: Page, requests: URL[]) {
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/guard/overview", (route) => route.fulfill({ json: lanesOverview }));
  await page.route("**/api/dashboard/v1/cases?*", (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    const { lane_counts: counts, ...page } = lanesPage;
    return route.fulfill({ json: includes(url).includes("lane_counts") ? { ...page, lane_counts: counts } : page });
  });
  await page.route(/\/api\/dashboard\/v1\/cases\/[^/?]+(\?.*)?$/, (route) => route.fulfill({ json: caseDetail }));
}

function listRequest(page: Page, lane: string | null, extra: (url: URL) => boolean = () => true): Promise<Request> {
  return page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/dashboard/v1/cases" && url.searchParams.get("lane") === lane && extra(url);
  });
}

/**
 * The Overview's card is the question; Cases holds the evidence for it. The
 * card's link opens Cases on its own lane, in the window the card counted,
 * with that lane's tab chosen, so the reader lands on the cases behind the
 * number they just read rather than on every case the host has.
 */
test("a lane card opens Cases on its lane, with its tab chosen", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);
  await page.goto("/");

  const asked = listRequest(page, "agent");
  await page.getByRole("region", { name: "What your AI agent did" }).getByRole("button", { name: "See every command" }).click();
  const url = new URL((await asked).url());
  expect(url.searchParams.get("window")).toBe("24h");
  expect(includes(url)).toContain("lane_counts");

  await expect(page).toHaveURL(/[?&]view=cases(?:&|$)/);
  await expect(page).toHaveURL(/[?&]lane=agent(?:&|$)/);
  await expect(page).toHaveURL(/[?&]window=24h(?:&|$)/);
  const tabs = page.getByRole("tablist", { name: "Case lanes" });
  await expect(tabs.getByRole("tab", { name: /What your AI agent did/ })).toHaveAttribute("aria-selected", "true");
  // Each tab carries the host's own count for its lane.
  await expect(tabs.getByRole("tab", { name: /Attacks on this server, 823 cases/ })).toBeVisible();
  await expect(tabs.getByRole("tab", { name: /Messages to your AI agent, 3 cases/ })).toBeVisible();
  await expect(page.getByText("Every command your AI agent tried to run", { exact: false })).toBeVisible();
});

/** A tab is a filter like any other: it is asked of the host and kept in the address. */
test("choosing a tab asks the host for that lane and keeps it in the address", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);
  await page.goto("/?view=cases&lane=agent&window=24h");
  const tabs = page.getByRole("tablist", { name: "Case lanes" });
  await expect(tabs.getByRole("tab", { name: /What your AI agent did/ })).toHaveAttribute("aria-selected", "true");

  const asked = listRequest(page, "host");
  await tabs.getByRole("tab", { name: /Attacks on this server/ }).click();
  const url = new URL((await asked).url());
  expect(url.searchParams.get("window")).toBe("24h");
  await expect(page).toHaveURL(/[?&]lane=host(?:&|$)/);
  await expect(tabs.getByRole("tab", { name: /Attacks on this server/ })).toHaveAttribute("aria-selected", "true");

  // The arrow keys move along the row, as tabs do.
  await tabs.getByRole("tab", { name: /Attacks on this server/ }).focus();
  const left = listRequest(page, "agent");
  await page.keyboard.press("ArrowLeft");
  await left;
  await expect(tabs.getByRole("tab", { name: /What your AI agent did/ })).toBeFocused();
  await expect(page).toHaveURL(/[?&]lane=agent(?:&|$)/);
});

/**
 * With no lane in the address, Cases opens the lane this viewer last used,
 * and on a first visit the agent's lane where the host has agent records.
 */
test("Cases opens the lane this viewer last used, and the agent's lane the first time", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);

  const first = listRequest(page, "agent");
  await page.goto("/?view=cases");
  await first;
  await expect(page.getByRole("tab", { name: /What your AI agent did/ })).toHaveAttribute("aria-selected", "true");

  const chosen = listRequest(page, "prompt");
  await page.getByRole("tab", { name: /Messages to your AI agent/ }).click();
  await chosen;

  const again = listRequest(page, "prompt");
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  await again;
  await expect(page.getByRole("tab", { name: /Messages to your AI agent/ })).toHaveAttribute("aria-selected", "true");
});

/**
 * "Everything" lists raw telemetry and bookkeeping beside the lanes. It is a
 * technical view's question: offered behind "Show technical detail", and
 * asked of the host as no lane at all.
 */
test("every case is offered in the technical view, as a request with no lane", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);
  await page.goto("/?view=cases&lane=host");
  const tabs = page.getByRole("tablist", { name: "Case lanes" });
  await expect(tabs.getByRole("tab", { name: "Everything" })).toHaveCount(0);

  await page.getByLabel("Show technical detail").check();
  const everything = listRequest(page, null, (url) => includes(url).includes("lane_counts"));
  await tabs.getByRole("tab", { name: "Everything" }).click();
  await everything;
  await expect(page).toHaveURL(/[?&]lane=everything(?:&|$)/);
  await page.getByLabel("Show technical detail").uncheck();
});

/** What is waiting on a person opens inside the lane it was counted in. */
test("the waiting count on a card opens what is waiting in that lane", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);
  await page.goto("/");

  const asked = listRequest(page, "host", (url) => url.searchParams.get("status") === "waiting");
  await page.getByRole("region", { name: "Attacks on this server" }).getByRole("button", { name: "32 waiting on you" }).click();
  const url = new URL((await asked).url());
  expect(url.searchParams.get("window")).toBe("all");
  await expect(page).toHaveURL(/[?&]status=waiting(?:&|$)/);
  await expect(page.getByRole("tab", { name: /Attacks on this server/ })).toHaveAttribute("aria-selected", "true");
});

test("the newest case on a card opens inside its lane", async ({ page }) => {
  const requests: URL[] = [];
  await lanesHost(page, requests);
  await page.goto("/");

  const asked = listRequest(page, "agent");
  await page.getByRole("region", { name: "What your AI agent did" })
    .getByRole("button", { name: /AI agent session wren-visitor-28eb7f9c/ })
    .click();
  await asked;
  await expect(page).toHaveURL(/[?&]case=case%3Acommunity-session%3Alane-agent-1(?:&|$)/);
  await expect(page).toHaveURL(/[?&]lane=agent(?:&|$)/);
});

/**
 * A paid server from before lanes refuses `lane` as an unknown parameter.
 * The screen still lists the cases, asked again without the lane, and draws
 * no tabs: the list is every case, and a tab row over it would claim a filter
 * nothing applied.
 */
test("a server that files no cases into lanes lists them all, with no tabs", async ({ page }) => {
  const requests: URL[] = [];
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: casesBootstrap }));
  await page.route("**/api/dashboard/v1/cases?*", (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    if (url.searchParams.has("lane") || includes(url).includes("lane_counts")) return route.fulfill(UNKNOWN_PARAMETER);
    return route.fulfill({ json: pageOne });
  });
  await page.route(/\/api\/dashboard\/v1\/cases\/[^/?]+(\?.*)?$/, (route) => route.fulfill({ json: caseDetail }));

  await page.goto("/?view=cases&lane=agent");
  await expect(page.getByRole("heading", { name: "Case results" })).toBeVisible();
  await expect(page.getByRole("tablist", { name: "Case lanes" })).toHaveCount(0);
  await expect(page.getByText("Agent attempted to read a production signing key", { exact: false })).toBeVisible();
  const last = requests[requests.length - 1];
  expect(last.searchParams.has("lane")).toBe(false);
  expect(includes(last)).not.toContain("lane_counts");
});
