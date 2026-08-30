import { describe, expect, it } from "vitest";
import type { SessionView } from "../api";

// The heading logic, exercised through the same module the card uses.
import { sessionHeading, shortId } from "./SessionCard";

const session = (over: Partial<SessionView>): SessionView => ({
  id: "s", label: "86498977-2bae-499e-a894-32344a661ed5",
  commands: 3, blocked: 0, review: 0, allowed: 3, items: [], truncated: false,
  ...over,
});

const at = (ms: number) => ({
  seq: 1, command: "ls", risk: null, decided_by: "rules",
  categories: [], asi: [], explanation: "", recorded_at_ms: ms,
});

describe("a session heading a person can navigate by", () => {
  /**
   * THE OPERATOR'S SCREEN. The card printed the raw session UUID as its title,
   * so the Activity list read as five rows of hex. One of them was the run the
   * operator was sitting in.
   *
   * FAILS ON REVERT: put `s.label` back as the heading and the UUID returns.
   */
  it("says when the run happened instead of printing its uuid", () => {
    const day = Date.UTC(2026, 7, 29, 9, 12);
    const h = sessionHeading(session({ items: [at(day), at(day + 3_600_000)] as never }));
    expect(h).not.toContain("86498977");
    expect(h).toContain("Agent session");
    expect(h).toMatch(/\d/);
  });

  it("keeps the id reachable, just not as the headline", () => {
    expect(shortId("86498977-2bae-499e-a894-32344a661ed5")).toBe("86498977...");
  });

  it("still names the local session plainly", () => {
    expect(sessionHeading(session({ label: "local" }))).toBe("Local session");
  });

  /** No timestamps is not a reason to fall back to hex. */
  it("degrades to a plain name when nothing carries a time", () => {
    expect(sessionHeading(session({ items: [] }))).toBe("Agent session");
  });
});
