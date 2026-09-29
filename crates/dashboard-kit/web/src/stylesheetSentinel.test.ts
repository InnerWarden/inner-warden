import { describe, expect, it } from "vitest";
import { SHARED_STYLESHEET_SENTINEL, SHARED_STYLESHEET_SENTINEL_SOURCE } from "./stylesheetSentinel";

// Read through Vite, like `community/boundary.test.ts`: no node types needed.
const HOME = import.meta.glob("./screens/Home.tsx", { query: "?raw", eager: true, import: "default" }) as Record<string, string>;

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
});
