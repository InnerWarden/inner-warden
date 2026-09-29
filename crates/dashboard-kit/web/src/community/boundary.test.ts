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
