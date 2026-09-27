import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const bootstrap = JSON.parse(readFileSync(new URL("../fixtures/community/bootstrap.json", import.meta.url), "utf8"));
const enterpriseBootstrap = JSON.parse(readFileSync(new URL("../fixtures/enterprise/bootstrap.json", import.meta.url), "utf8"));

/**
 * A phone, 320 px wide. The page scrolled sideways (scrollWidth 337) and the
 * header took 175 of 640 px before anything the reader came for. Every
 * Community screen now fits the width, and the header is one row over the
 * nav, with the technical switch and the tour behind one button.
 */

test.use({ viewport: { width: 320, height: 640 } });

// A synthetic build id as long as a real one, which is what pushed the live
// header past the edge.
const LONG_VERSION = "0.16.99+g00000000";

async function pageWidth(page: Page) {
  return page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
}

for (const [name, path, drawn] of [
  ["Overview", "/", "#posture-title"],
  ["Activity", "/?view=activity", '[data-tour="activity"]'],
] as const) {
  test(`${name} fits a 320 px screen without scrolling sideways`, async ({ page }) => {
    await page.route("**/api/dashboard/v1/bootstrap", (route) =>
      route.fulfill({ json: { ...bootstrap, product_version: LONG_VERSION } }));
    await page.goto(path);
    // Wait for the screen itself, not the shell, before measuring it.
    await expect(page.locator(drawn)).toBeVisible();
    const width = await pageWidth(page);
    expect(width.scroll).toBe(width.client);
  });
}

test("the header is one row over the nav, with the switch and the tour behind the menu", async ({ page }) => {
  await page.goto("/");
  const header = page.locator("header");
  await expect(page.getByRole("navigation", { name: "Dashboard views" })).toBeVisible();
  const height = await header.evaluate((element) => element.getBoundingClientRect().height);
  expect(height).toBeLessThan(120);

  const toggle = page.getByRole("checkbox", { name: "Show technical detail" });
  await expect(toggle).toBeHidden();
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(toggle).toBeVisible();
  await expect(page.getByRole("button", { name: "Open the product tour" })).toBeVisible();
});

/**
 * The menu floats over the page, so it closes the ways a floating menu does.
 * It stayed open after Escape, after a press outside it and after going to
 * another tab, covering the page it had just opened.
 */
test("the menu closes on Escape, on a press outside it, and on going to another screen", async ({ page }) => {
  await page.goto("/");
  const menu = page.getByRole("button", { name: "Menu" });
  const toggle = page.getByRole("checkbox", { name: "Show technical detail" });

  await menu.click();
  await expect(toggle).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toBeHidden();
  await expect(menu).toBeFocused();

  await menu.click();
  await expect(toggle).toBeVisible();
  await page.mouse.click(160, 500);
  await expect(menu).toHaveAttribute("aria-expanded", "false");

  // A press inside the menu keeps it open.
  await menu.click();
  await toggle.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await toggle.click();

  await page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button", { name: "Activity" }).click();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toBeHidden();
});

test.describe("on a wide screen", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("keeps the switch and the tour in the header, with no menu", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("checkbox", { name: "Show technical detail" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open the product tour" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Menu" })).toBeHidden();
  });
});

// ─────────────────── the paid Protection screen on a phone ───────────────────
//
// Served from this Community fixture server with the paid bootstrap and a
// five-control posture routed in, the way the acceptance project does, so it
// runs in this journey.

const observedAt = "2026-07-18T12:00:00Z";
const fresh = { observed_at: observedAt, budget_seconds: 30, state: "fresh", age_seconds: 0 };
const never = { observed_at: null, budget_seconds: 30, state: "missing", age_seconds: null };
const source = { id: "fixture", kind: "runtime_probe", authority: "canonical", version: "1", completeness: "complete", limitations: [] };
const evidence = { id: "fixture-evidence", kind: "runtime_probe", source, observed_at: observedAt, integrity: "verified", redaction: [], freshness: fresh };
const scope = { id: "host:fixture", kind: "host", display_name: "pilot host", verification: "host_verified", evidence: [evidence] };
const stage = (state: string) => ({ state, evidence: state === "yes" ? [evidence] : [], reason_code: null });
const converged = { configured: stage("yes"), loaded: stage("yes"), running: stage("yes"), enforcing: stage("not_applicable"), verified_effective: stage("not_applicable") };

function capability(id: string) {
  return {
    id, tier: "enterprise_core", availability: "available", entitlement: "valid", support: "supported",
    desired_mode: "observe", effective_mode: "observe", convergence: converged, rollout_state: "observing",
    health: "healthy", scope: [scope], covered_action_classes: [], bypass_classes: [], known_uncovered_paths: [],
    freshness: fresh, last_evidence: evidence, sources: [source], claims: [], reason_code: null, summary: `${id} fixture`,
  };
}

function control(id: string, capabilityId: string, label: string, disposition: string, freshness: object = fresh) {
  return {
    id, label, capability_ids: [capabilityId], claim_state: "visibility_only", disposition,
    effective_mode: disposition === "cannot_verify" ? "unknown" : "observe", desired_mode: "observe",
    effective_scope: [scope], covered_action_classes: [], known_gaps: [], freshness, convergence: converged,
    evidence: [evidence],
  };
}

const CONTROLS = [
  control("independent_host_execution", "kernel_execution_control", "Independent host execution", "working_as_configured"),
  control("secret_access_control", "secret_access_control", "Secret access control", "working_as_configured"),
  control("dns_resolution_control", "dns_resolution_control", "DNS resolution control", "cannot_verify", never),
  control("host_visibility", "host_visibility", "Host visibility", "working_as_configured"),
  control("response_controls", "response_controls", "Response controls", "working_as_configured"),
];

async function installProtection(page: Page, actorId = "fixture-operator") {
  const paid = structuredClone(enterpriseBootstrap);
  paid.product_version = LONG_VERSION;
  paid.session = { ...paid.session, actor_id: actorId };
  paid.capabilities = CONTROLS.map((layer) => capability(layer.capability_ids[0]));
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: paid }));
  await page.route("**/api/dashboard/v1/posture", (route) => route.fulfill({
    json: { schema_version: "innerwarden.dashboard.v1", generated_at: observedAt, layers: CONTROLS, gaps: [] },
  }));
}

/**
 * Each control's title broke into a column of fragments ("Ex / ec / uti / on
 * / Ga / te"): the title kept a flex basis of zero beside its badge, scope and
 * time, shrank to what they left (26 px) and split its words. The page did
 * not scroll sideways, so the width check alone passed; this measures the
 * titles themselves.
 */
test("Protection fits a 320 px screen, and no control's title breaks inside a word", async ({ page }) => {
  await installProtection(page);
  await page.goto("/?view=posture");
  const titles = page.locator("article h3");
  await expect(titles).toHaveCount(CONTROLS.length);
  await expect(titles.first()).toHaveText("Execution Gate");

  const width = await pageWidth(page);
  expect(width.scroll).toBe(width.client);

  const measured = await titles.evaluateAll((headings) => headings.map((heading) => {
    const text = heading.firstChild;
    const broken: string[] = [];
    if (text !== null && text.nodeType === Node.TEXT_NODE) {
      const value = text.textContent ?? "";
      let at = 0;
      for (const word of value.split(" ")) {
        const range = document.createRange();
        range.setStart(text, at);
        range.setEnd(text, at + word.length);
        if (word.length > 0 && range.getClientRects().length !== 1) broken.push(word);
        at += word.length + 1;
      }
    }
    return { title: heading.textContent, width: heading.getBoundingClientRect().width, broken };
  }));
  for (const title of measured) {
    expect(title.broken, `${title.title} breaks inside a word`).toEqual([]);
    // The title takes its own row on a phone, not a sliver beside the badge.
    expect(title.width, `${title.title} is squeezed`).toBeGreaterThan(200);
  }

  // What the page cannot confirm is listed as a gap, not under "No gaps".
  await expect(page.getByText("1 control we can't confirm: DNS Guard.", { exact: false })).toBeVisible();
});

/**
 * A 64-character id with no break in it pushed the header sideways between
 * about 400 and 560 px, and below 400 px the badge was a bare check with no
 * words and no title.
 */
for (const viewport of [{ width: 320, height: 640 }, { width: 400, height: 700 }, { width: 480, height: 700 }]) {
  test(`a long signed-in name fits the header at ${viewport.width} px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const actor = `operator-${"0123456789abcdef".repeat(4)}`.slice(0, 64);
    await installProtection(page, actor);
    await page.goto("/?view=posture");
    await expect(page.locator("article h3").first()).toHaveText("Execution Gate");
    const width = await pageWidth(page);
    expect(width.scroll).toBe(width.client);
    const badge = page.locator(`header [title="Signed in as ${actor}"]`);
    await expect(badge).toHaveCount(1);
    if (viewport.width < 400) {
      await page.getByRole("button", { name: "Menu" }).click();
      await expect(page.locator("[data-header-account]")).toHaveText(`Signed in as ${actor}`);
      const open = await pageWidth(page);
      expect(open.scroll).toBe(open.client);
    }
  });
}
