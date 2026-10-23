import { describe, expect, it } from "vitest";

/**
 * The line between Community's pages and everything the paid bundle shares.
 *
 * The paid bundle composes this kit's `src/` and overlays its OWN entry point,
 * so a Community page reaches its JavaScript only if some shared file imports
 * one. The kit's `main.tsx` is the one file allowed to. These read every
 * source file (through Vite, like `copy.test.ts`, so no node types are
 * needed) and hold that, and the rules the Community pages keep.
 */
const SOURCES: Record<string, string> = import.meta.glob(["../**/*.ts", "../**/*.tsx"], {
  query: "?raw",
  eager: true,
  import: "default",
});

/**
 * Every path relative to `src/`: Vite keys a file in this folder `./x.tsx`
 * and one outside it `../main.tsx`.
 */
const all = Object.entries(SOURCES).map(([path, text]) => ({
  path: path.startsWith("./") ? `community/${path.slice(2)}` : path.replace(/^\.\.\//, ""),
  text,
}));
const community = all.filter((file) => file.path.startsWith("community/"));

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

describe("the Community boundary", () => {
  it("is imported by no shared file: only an entry point may mount it", () => {
    // The kit's own `main.tsx` imports it; a bundle that overlays its own
    // entry point imports nothing from here, and this still holds there.
    const importers = all
      .filter((file) => !file.path.startsWith("community/"))
      .filter((file) => /["'](?:\.\.?\/)+community\//.test(file.text))
      .map((file) => file.path);
    expect(importers.filter((path) => path !== "main.tsx")).toEqual([]);
  });

  it("holds the Community pages themselves", () => {
    expect(community.length).toBeGreaterThan(10);
  });

  it("never blurs and never draws an em or en dash", () => {
    for (const file of community) {
      expect(file.text, file.path).not.toMatch(/className=\{?[`"'][^`"']*\bblur/);
      expect(file.text, file.path).not.toMatch(DASHES);
    }
  });

  it("uses none of the retired internal eyebrows", () => {
    for (const file of community.filter((entry) => !entry.path.includes(".test."))) {
      for (const retired of ["COMMUNITY VISIBILITY", "LOCAL RESOURCE VISIBILITY", "Community visibility", "Local resource visibility"]) {
        expect(file.text, `${file.path} ${retired}`).not.toContain(retired);
      }
    }
  });

  it("never sends anything anywhere: no tracking, no query string on a link out", () => {
    for (const file of community.filter((entry) => !entry.path.includes(".test."))) {
      expect(file.text, file.path).not.toMatch(/navigator\.sendBeacon|XMLHttpRequest|https:\/\/innerwarden\.com\/[^"'`\s]*\?/);
    }
  });
});

/**
 * Community's tokens, read as text from disk. The test runner hands a CSS
 * import back empty (it does not process stylesheets), so this reads the
 * file itself; the module name is a variable so the web tsconfig, which
 * carries no Node types, does not need them.
 */
const NODE_FS = "node:fs";
const { readFileSync } = (await import(/* @vite-ignore */ NODE_FS)) as { readFileSync: (path: URL, encoding: "utf8") => string };
const THEME = readFileSync(new URL("./theme.css", import.meta.url), "utf8");

/** The 9.1 table, exactly. */
const TOKENS: Record<string, string> = {
  "--iw-bg": "#f8fafc",
  "--iw-surface": "#ffffff",
  "--iw-surface-2": "#f1f5f9",
  "--iw-line": "#e2e8f0",
  "--iw-line-strong": "#7c8796",
  "--iw-ink": "#0f172a",
  "--iw-ink-2": "#334155",
  "--iw-ink-3": "#5f6b78",
  "--iw-accent": "#0f6f7a",
  "--iw-stopped": "#0f766e",
  "--iw-stopped-ink": "#115e59",
  "--iw-stopped-bg": "#f0fdfa",
  "--iw-deny": "#be123c",
  "--iw-deny-ink": "#9f1239",
  "--iw-deny-bg": "#fff1f2",
  "--iw-review": "#b45309",
  "--iw-needs-ink": "#92400e",
  "--iw-needs-bg": "#fffbeb",
  "--iw-needs-line": "#f2c46b",
  "--iw-allow": "#64748b",
  "--iw-unknown": "#7c8796",
};

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const value = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(a: string, b: string): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

/** The hue of a colour, in degrees, and whether it has enough colour to have one. */
function hue(hex: string): number | undefined {
  const [r, g, b] = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max - min < 0.08) return undefined;
  const delta = max - min;
  const raw = max === r ? ((g - b) / delta) % 6 : max === g ? (b - r) / delta + 2 : (r - g) / delta + 4;
  return (raw * 60 + 360) % 360;
}

describe("Community's visual tokens (spec 9.1)", () => {
  it("are imported only by the Community shell, so no shared file and no other entry point loads them", () => {
    const importers = all.filter((file) => /["'][./]*(?:community\/)?theme\.css["']/.test(file.text)).map((file) => file.path);
    expect(importers).toEqual(["community/shell.tsx"]);
  });

  it("hold every token at its exact value, as plain custom properties with no @theme and no @apply", () => {
    expect(THEME.length).toBeGreaterThan(0);
    for (const [name, value] of Object.entries(TOKENS)) expect(THEME, name).toMatch(new RegExp(`${name}:\\s*${value};`));
    expect(THEME.replace(/\/\*[\s\S]*?\*\//g, "")).not.toMatch(/@theme|@apply|@import/);
  });

  it("keep every text token readable: 4.5:1 on white and on the inset surface", () => {
    for (const name of ["--iw-ink", "--iw-ink-2", "--iw-ink-3", "--iw-accent"]) {
      expect(contrast(TOKENS[name], "#ffffff"), name).toBeGreaterThanOrEqual(4.5);
      expect(contrast(TOKENS[name], "#f1f5f9"), name).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrast(TOKENS["--iw-stopped-ink"], TOKENS["--iw-stopped-bg"])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(TOKENS["--iw-deny-ink"], TOKENS["--iw-deny-bg"])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(TOKENS["--iw-needs-ink"], TOKENS["--iw-needs-bg"])).toBeGreaterThanOrEqual(4.5);
  });

  it("keep every mark and every border that carries meaning at 3:1 or more", () => {
    for (const name of ["--iw-line-strong", "--iw-stopped", "--iw-deny", "--iw-review", "--iw-allow", "--iw-unknown"]) {
      expect(contrast(TOKENS[name], "#ffffff"), name).toBeGreaterThanOrEqual(3);
      expect(contrast(TOKENS[name], "#f1f5f9"), name).toBeGreaterThanOrEqual(3);
    }
  });

  it("use no green anywhere: no green token, no green utility", () => {
    for (const match of THEME.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
      const degrees = hue(match[0].toLowerCase());
      expect(degrees === undefined || degrees < 75 || degrees > 155, `${match[0]} is green`).toBe(true);
    }
    for (const file of community.filter((entry) => !entry.path.includes(".test."))) {
      expect(file.text, file.path).not.toMatch(/\b(?:bg|text|border|fill|stroke|ring|from|to|via)-(?:green|emerald|lime)-\d/);
    }
  });
});
