import { expect, type Page } from "@playwright/test";
import { test } from "./clock";
import { CASE, COMMUNITY_TABS, PAGE_READY } from "./support";

/**
 * Community's accessibility journey (WCAG 2.2 AA, spec section 11), on all
 * five pages: the contrast of what is drawn, read from the computed colours
 * the browser paints; one h1 and the landmarks; focus on the page's h1 when
 * the reader moves between pages; a table twin for every chart; no sideways
 * scroll at 320 px; and 44 px targets under a coarse pointer.
 */

/** Every page, and a decision opened, which is a page of its own on a phone. */
const PAGES: readonly [string, string, string][] = [
  ...COMMUNITY_TABS.map(([label, path]) => [label, path, PAGE_READY[label]] as [string, string, string]),
  ["Decision", `/?view=activity&decision=${encodeURIComponent(CASE.wouldRefuse)}`, "section[data-decision] h2"],
];

async function open(page: Page, path: string, ready: string) {
  await page.goto(path);
  await expect(page.locator(ready).first()).toBeVisible();
  // The polled sources settle: no section is still drawing its skeleton.
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0);
}

type Finding = { what: string; text: string; ratio: number; needed: number };

/**
 * The WCAG ratio of every visible text and every outcome mark on the page,
 * against the background actually under it (each translucent layer blended
 * in), with colours read back through a canvas so any CSS colour space reads
 * as sRGB. The formula is the acceptance suite's (`accessibility.spec.ts`).
 * Text needs 4.5:1 (3:1 when large), a mark 3:1 (non-text contrast).
 */
async function contrast(page: Page): Promise<{ findings: Finding[]; texts: number; marks: number }> {
  return page.evaluate(() => {
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("2d canvas unavailable");
    type Rgba = [number, number, number, number];
    const sample = (colour: string): Rgba => {
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = "rgba(0, 0, 0, 0)";
      context.fillStyle = colour;
      context.fillRect(0, 0, 1, 1);
      const [red, green, blue, alpha] = context.getImageData(0, 0, 1, 1).data;
      return [red, green, blue, alpha / 255];
    };
    const over = (top: Rgba, bottom: Rgba): Rgba => {
      const alpha = top[3] + bottom[3] * (1 - top[3]);
      if (alpha === 0) return [0, 0, 0, 0];
      const channel = (index: number) => (top[index] * top[3] + bottom[index] * bottom[3] * (1 - top[3])) / alpha;
      return [channel(0), channel(1), channel(2), alpha];
    };
    const luminance = ([red, green, blue]: Rgba) => {
      const linear = [red, green, blue].map((channel) => {
        const component = channel / 255;
        return component <= 0.04045 ? component / 12.92 : ((component + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    };
    const ratio = (foreground: Rgba, background: Rgba) => {
      const [lighter, darker] = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
      return (lighter + 0.05) / (darker + 0.05);
    };
    /** The opaque colour under an element: its own background and every one behind it. */
    const backgroundOf = (element: Element): Rgba | undefined => {
      const layers: Rgba[] = [];
      for (let node: Element | null = element; node !== null; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (style.backgroundImage !== "none") return undefined;
        const layer = sample(style.backgroundColor);
        if (layer[3] > 0) layers.push(layer);
        if (layer[3] >= 1) break;
      }
      let colour: Rgba = [255, 255, 255, 1];
      for (const layer of layers.reverse()) colour = over(layer, colour);
      return colour;
    };
    const opacityOf = (element: Element) => {
      let opacity = 1;
      for (let node: Element | null = element; node !== null; node = node.parentElement) opacity *= Number(getComputedStyle(node).opacity);
      return opacity;
    };
    const visible = (element: Element) => {
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return box.width > 1 && box.height > 1 && style.visibility !== "hidden" && element.closest("[hidden], details:not([open]) > :not(summary)") === null;
    };
    const findings: { what: string; text: string; ratio: number; needed: number }[] = [];
    let texts = 0;
    let marks = 0;
    for (const element of document.querySelectorAll("header *, main *")) {
      const own = Array.from(element.childNodes).filter((node) => node.nodeType === Node.TEXT_NODE).map((node) => node.textContent ?? "").join("").trim();
      if (own === "" || !visible(element) || (element as HTMLButtonElement).disabled === true) continue;
      const style = getComputedStyle(element);
      const background = backgroundOf(element);
      if (background === undefined) continue;
      const svgText = element instanceof SVGElement;
      const ink = sample(svgText ? style.fill : style.color);
      const foreground = over([ink[0], ink[1], ink[2], ink[3] * opacityOf(element)], background);
      const size = Number.parseFloat(style.fontSize);
      const large = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
      const needed = large ? 3 : 4.5;
      const value = ratio(foreground, background);
      texts += 1;
      if (value < needed) findings.push({ what: element.tagName.toLowerCase(), text: own.slice(0, 60), ratio: Math.round(value * 100) / 100, needed });
    }
    for (const mark of document.querySelectorAll("main svg[data-mark]")) {
      if (!visible(mark)) continue;
      const shape = mark.firstElementChild;
      const background = backgroundOf(mark);
      if (shape === null || background === undefined) continue;
      const stroke = sample(getComputedStyle(shape).stroke);
      const value = ratio(over(stroke, background), background);
      marks += 1;
      if (value < 3) findings.push({ what: `mark ${mark.getAttribute("data-mark")} ${mark.getAttribute("data-mark-tone")}`, text: "", ratio: Math.round(value * 100) / 100, needed: 3 });
    }
    return { findings, texts, marks };
  });
}

for (const [label, path, ready] of PAGES) {
  test(`${label}: every text and every mark meets WCAG AA contrast`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, path, ready);
    const plain = await contrast(page);
    expect(plain.findings).toEqual([]);
    // Anti-vacuous: the page drew words, and where it lists outcomes, marks, all measured.
    expect(plain.texts).toBeGreaterThan(20);
    if (label === "Overview" || label === "Decisions" || label === "Decision") expect(plain.marks).toBeGreaterThan(0);
    await page.getByRole("checkbox", { name: "Show technical detail" }).check();
    await expect(page.locator(ready).first()).toBeVisible();
    const technical = await contrast(page);
    expect(technical.findings, "the technical view").toEqual([]);
    expect(technical.texts).toBeGreaterThanOrEqual(plain.texts);
  });
}

for (const [label, path] of COMMUNITY_TABS) {
  test(`${label}: one h1, a banner, the navigation and one main, and every section named by its heading`, async ({ page }) => {
    await open(page, path, PAGE_READY[label]);
    await expect(page.locator("h1")).toHaveCount(1);
    await expect(page.getByRole("banner")).toHaveCount(1);
    await expect(page.getByRole("navigation", { name: "Dashboard views" })).toHaveCount(1);
    await expect(page.getByRole("main")).toHaveCount(1);
    const unnamed = await page.locator("main section").evaluateAll((sections) => sections
      .filter((section) => {
        const by = section.getAttribute("aria-labelledby");
        const named = by !== null && by.split(" ").every((id) => (document.getElementById(id)?.textContent ?? "").trim() !== "");
        return !named && (section.getAttribute("aria-label") ?? "").trim() === "";
      })
      .map((section) => section.outerHTML.slice(0, 120)));
    expect(unnamed).toEqual([]);
  });
}

test("moving between pages puts focus on the new page's h1, and a first load does not", async ({ page }) => {
  await open(page, "/", PAGE_READY.Overview);
  expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe("H1");
  const nav = page.getByRole("navigation", { name: "Dashboard views" });
  for (const [label] of COMMUNITY_TABS.slice(1)) {
    await nav.getByRole("button", { name: label, exact: true }).click();
    const heading = page.locator(PAGE_READY[label]);
    await expect(heading).toBeFocused();
    await expect(heading).toHaveJSProperty("tagName", "H1");
  }
  await nav.getByRole("button", { name: "Overview", exact: true }).click();
  await expect(page.locator("main h1")).toBeFocused();
});

/**
 * WCAG 1.3.2 and 2.4.3 at a desk: the Overview's sections are read in the
 * order they are drawn, left to right and top to bottom. FAILS ON REVERT of
 * the DOM order: Refused and Needs a look came before Agents, drawn first.
 */
test("the Overview's sections are in the DOM in the order they are drawn at a desk", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, "/", PAGE_READY.Overview);
  await expect(page.locator("#needs-a-look")).toBeVisible();
  const headings = await page.locator("main h2:not(.sr-only)").evaluateAll((elements) =>
    elements
      .filter((element) => element.getBoundingClientRect().height > 0)
      .map((element) => ({ text: element.textContent ?? "", top: Math.round(element.getBoundingClientRect().top), left: Math.round(element.getBoundingClientRect().left) })),
  );
  const drawn = headings.slice().sort((a, b) => (Math.abs(a.top - b.top) < 8 ? a.left - b.left : a.top - b.top));
  expect(headings.map((heading) => heading.text)).toEqual(drawn.map((heading) => heading.text));
  expect(headings.map((heading) => heading.text).slice(0, 3)).toEqual(["Agents", "Refused, or would have been", "Needs a look"]);
});

/** "Copied" is said to a screen reader, politely, while the button's name stays the command. */
test("a copy is announced in a polite live region", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await open(page, "/", PAGE_READY.Overview);
  const box = page.locator("[data-verdict-action] [data-step]").first();
  const button = box.getByRole("button", { name: /^Copy command: / });
  const command = ((await button.getAttribute("aria-label")) ?? "").replace("Copy command: ", "");
  const status = box.locator("[data-copied-status]");
  await expect(status).toHaveAttribute("aria-live", "polite");
  await expect(status).toHaveText("");
  await button.click();
  await expect(status).toHaveText(`Copied: ${command}`);
});

test("every chart has a table twin a screen reader reads and a sighted reader can open", async ({ page }) => {
  let charts = 0;
  for (const [label, path] of [["Overview", "/"], ["Protection", "/?view=posture"], ["Tokens", "/?view=tokens"]] as const) {
    await open(page, path, PAGE_READY[label]);
    for (const figure of await page.locator("main figure[data-chart]").all()) {
      charts += 1;
      const image = figure.locator('svg[role="img"]');
      await expect(image).toHaveAttribute("aria-label", /\d/);
      // The twin for a screen reader: a table with a row per bar, never empty.
      const twin = figure.locator(".sr-only table");
      await expect(twin).toHaveCount(1);
      expect(await twin.locator("tbody tr").count()).toBeGreaterThan(0);
      // And the same table for a sighted reader, one press away.
      const disclosure = figure.locator("details");
      await disclosure.locator("summary", { hasText: "Show as a table" }).click();
      await expect(disclosure.locator("table")).toBeVisible();
      expect(await disclosure.locator("table tbody tr").count()).toBe(await twin.locator("tbody tr").count());
    }
  }
  expect(charts, "anti-vacuous: the 14 days, the 13 weeks and the token bars").toBeGreaterThanOrEqual(3);
});

for (const [label, path] of COMMUNITY_TABS) {
  test(`${label}: no sideways scroll at 320 px`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 700 });
    await open(page, path, PAGE_READY[label]);
    const width = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
    expect(width.scroll).toBeLessThanOrEqual(width.client);
  });
}

test.describe("under a coarse pointer", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });

  for (const [label, path, ready] of PAGES) {
    test(`${label}: every control in the page is at least 44 px tall`, async ({ page }) => {
      await open(page, path, ready);
      expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches), "the pointer is coarse").toBe(true);
      const small = await page.locator("main").evaluate((main) => Array.from(main.querySelectorAll("a[href], button, summary, input, select, [role=tab]"))
        .filter((element) => {
          const box = element.getBoundingClientRect();
          if (box.width === 0 || box.height === 0 || element.closest(".sr-only") !== null) return false;
          // A link inside a sentence is exempt (WCAG 2.5.8, inline): its line sets its height.
          const parent = element.parentElement;
          const inline = element.tagName === "A" && parent !== null && getComputedStyle(element).display === "inline"
            && (parent.textContent ?? "").trim().length > (element.textContent ?? "").trim().length;
          return !inline && box.height < 44;
        })
        .map((element) => `${element.tagName.toLowerCase()} "${(element.textContent ?? element.getAttribute("aria-label") ?? "").trim().slice(0, 40)}" ${Math.round(element.getBoundingClientRect().height)} px`));
      expect(small).toEqual([]);
    });
  }
});
