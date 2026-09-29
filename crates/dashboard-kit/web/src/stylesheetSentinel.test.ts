import { describe, expect, it } from "vitest";
import { SHARED_STYLESHEET_SENTINEL, SHARED_STYLESHEET_SENTINEL_SOURCE } from "./stylesheetSentinel";

// Read through Vite, like `community/boundary.test.ts`: no node types needed.
const HOME = import.meta.glob("./screens/Home.tsx", { query: "?raw", eager: true, import: "default" }) as Record<string, string>;
const SOURCES = import.meta.glob(["./**/*.{ts,tsx,css}", "!./**/node_modules/**"], { query: "?raw", eager: true, import: "default" }) as Record<string, string>;

/** The class the paid build checked before this sentinel, built at run time so this file does not name it. */
const RETIRED = ["h", "16"].join("-");

describe("the stylesheet sentinel a composing build checks for", () => {
  it("is a class the shared Home screen uses", () => {
    expect(SHARED_STYLESHEET_SENTINEL_SOURCE).toBe("src/screens/Home.tsx");
    const home = HOME["./screens/Home.tsx"];
    expect(home).toBeDefined();
    expect(home).toMatch(new RegExp(`["\\s]${SHARED_STYLESHEET_SENTINEL}["\\s]`));
  });

  it("lives outside the Community pages, which a composing build may leave unscanned", () => {
    expect(SHARED_STYLESHEET_SENTINEL_SOURCE.startsWith("src/community/")).toBe(false);
  });

  /**
   * Tailwind reads every token in a scanned file, comments included. When the
   * kit's sentinel note spelled the retired class out, the composed stylesheet
   * still held it, so the paid build's old check passed on a comment.
   */
  it("leaves the retired class unnamed, so the old check cannot pass on a comment", () => {
    expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
    const naming = Object.entries(SOURCES)
      .filter(([, text]) => new RegExp(`(^|[^\\w-])${RETIRED}($|[^\\w-])`).test(text))
      .map(([path]) => path);
    expect(naming).toEqual([]);
  });
});
