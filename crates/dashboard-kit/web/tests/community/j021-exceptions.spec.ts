import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, COMMUNITY_TABS, PAGE_READY } from "./support";

/**
 * Your exceptions, on Protection (spec 6.2, section 5; CJC-090-J006): the
 * allow patterns and mutes as the CLI serves them, read only while the
 * section is on screen. A pattern that held a secret or a hidden character
 * has no remove step (the step would not remove it); a pattern that matches
 * more than one command says so; a dashboard open to the network keeps the
 * lists in the terminal; an older InnerWarden that does not serve them is
 * said, with the counts it does send. And the whole dashboard only reads:
 * no page sends anything but GET.
 */

async function useScenario(page: Page, baseURL: string | undefined, scenario: string) {
  await page.context().addCookies([{ name: "iw-fixture", value: scenario, url: baseURL ?? "http://127.0.0.1:4173" }]);
}

const RULES = [
  "An allow pattern lets through only the commands it matches, and the record says you allowed it.",
  "A mute clears a flag only when every rule behind it is muted and no other danger signal remains.",
  "These change only from a terminal you type in. An agent that runs them is refused.",
];

test("lists the exceptions as the CLI serves them, with the rules said once", async ({ page }) => {
  await page.goto("/?view=posture");
  const section = page.locator("#exceptions");
  await expect(section.locator("[data-exception-counts]")).toHaveText("5 allow patterns, 1 muted rule, 1 muted category.");
  const allow = section.locator("[data-allow-list] > li");
  await expect(allow).toHaveCount(5);
  await expect(allow.nth(0).locator("[data-command]")).toHaveText("innerwarden allow --remove 'npm run * --silent'");
  await expect(section.locator("[data-dropped]")).toContainText("Ignored: matches every command. Use innerwarden dry-run instead.");
  await expect(section.locator('[data-mute="ATR-2026-030"]')).toContainText("ATR-2026-030: cross-agent attack detection");
  await expect(section.locator('[data-mute="ATR-2026-030"] [data-command]')).toHaveText("innerwarden mute --remove ATR-2026-030");
  await expect(section.locator('[data-mute="data-poisoning"] [data-command]')).toHaveText("innerwarden mute --remove data-poisoning");
  await expect(section.locator("[data-exception-changes]")).toHaveText(/^3 changes since 30 Jul, the last on 10 Sept at \d\d:\d\d\.$/);
  for (const line of RULES) await expect(section.getByText(line, { exact: true })).toHaveCount(1);
  // The rule about terminals is said once on the page.
  expect((await page.locator("main").innerText()).split(RULES[2]).length - 1).toBe(1);
});

test("marks a pattern that matches more than one command, and only that one", async ({ page }) => {
  await page.goto("/?view=posture");
  const chips = page.locator("#exceptions [data-unanchored]");
  await expect(chips).toHaveCount(1);
  await expect(chips).toHaveText("Matches more than one command");
  const row = page.locator("#exceptions [data-allow-list] > li").filter({ has: page.locator("[data-unanchored]") });
  await expect(row.locator("code").first()).toHaveText("* --dry-run");
  // It is still the reader's to remove.
  await expect(row.locator("[data-command]")).toHaveText("innerwarden allow --remove '* --dry-run'");
});

test("offers no copy for a pattern that held a secret or a hidden character", async ({ page }) => {
  await page.goto("/?view=posture");
  const redacted = page.locator('#exceptions [data-allow="redacted"]');
  await expect(redacted).toContainText("deploy-cli --token=[REDACTED]");
  await expect(redacted).toContainText("Contains a secret, hidden here.");
  await expect(redacted).toContainText("Remove it from a terminal: innerwarden allow --list shows it.");
  await expect(redacted.locator("[data-command]")).toHaveCount(0);
  await expect(redacted.getByRole("button", { name: /Copy/ })).toHaveCount(0);
  const hidden = page.locator('#exceptions [data-allow="hidden"]');
  await expect(hidden.locator("[data-hidden-characters]")).toBeVisible();
  await expect(hidden.locator("[data-command]")).toHaveCount(0);
  await expect(hidden.getByRole("button", { name: /Copy/ })).toHaveCount(0);
  await expect(hidden).toContainText("Remove it from a terminal: innerwarden allow --list shows it.");
});

test("keeps the lists in the terminal when this dashboard is open to the network", async ({ page, baseURL }) => {
  await useScenario(page, baseURL, "exposed");
  await page.goto("/?view=posture");
  const section = page.locator("#exceptions");
  await expect(section.locator("[data-withheld]")).toHaveText(
    "Hidden because this dashboard is open to the network. See them in a terminal: innerwarden allow --list.",
  );
  // The counts still show; no pattern does.
  await expect(section.locator("[data-exception-counts]")).toHaveText("5 allow patterns, 1 muted rule, 1 muted category.");
  await expect(section.locator("[data-allow-list]")).toHaveCount(0);
  await expect(section).not.toContainText("npm run");
  await expect(section).not.toContainText("ATR-2026-030");
});

test("says the counts only, from an older InnerWarden that does not list them", async ({ page, baseURL }) => {
  await useScenario(page, baseURL, "older-cli");
  await page.goto("/?view=posture");
  const section = page.locator("#exceptions");
  await expect(section.locator("[data-exceptions-older]")).toContainText("This InnerWarden lists only the counts. Run innerwarden allow --list to see them.");
  await expect(section.locator("[data-exception-counts]")).toHaveText("5 allow patterns, 1 muted rule, 1 muted category.");
  await expect(section.locator("[data-allow-list]")).toHaveCount(0);
  // Never an empty list said as none.
  await expect(section).not.toContainText("No allow pattern.");
  for (const line of RULES) await expect(section.getByText(line, { exact: true })).toHaveCount(1);
});

test("reads the exceptions only on Protection, and no page sends anything but GET", async ({ page }) => {
  const requests: { method: string; path: string }[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) requests.push({ method: request.method(), path: url.pathname });
  });
  for (const [label, path] of COMMUNITY_TABS) {
    const from = requests.length;
    await page.goto(path);
    await expect(page.locator(PAGE_READY[label])).toBeVisible();
    // Every control a reader can press here that is not a link out: the
    // technical view, and each "show more" (a few per page is enough).
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    for (const summary of (await page.locator("main summary").all()).slice(0, 6)) await summary.click();
    await page.getByRole("checkbox", { name: "Show technical detail" }).uncheck();
    const suppress = requests.slice(from).filter((request) => request.path === "/api/guard/suppress");
    if (label === "Protection") expect(suppress.length, "Protection reads the exceptions").toBeGreaterThan(0);
    else expect(suppress, `${label} reads the exceptions`).toEqual([]);
  }
  await page.goto(`/?view=activity&decision=${encodeURIComponent(CASE.wouldRefuse)}`);
  await expect(page.locator(`[data-decision="${CASE.wouldRefuse}"]`)).toBeVisible();
  await page.goto("/?view=activity&lens=reason");
  await expect(page.locator("#decisions-title")).toBeVisible();
  await page.goto("/?view=activity&lens=session");
  await expect(page.locator("#decisions-title")).toBeVisible();
  // Anti-vacuous: the pages were read, and every request was a read.
  expect(requests.length).toBeGreaterThan(20);
  expect(requests.filter((request) => request.method !== "GET")).toEqual([]);
});
