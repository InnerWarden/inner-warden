import { describe, expect, it } from "vitest";
import { formatAbsolute, formatClock, formatDay, formatDuration, formatTimestamp, freshnessLabel, isoInstant, timeTitle } from "./presentation";

/**
 * MEASURED in the third dashboard audit: one panel read the day first and
 * another the month first, for the same instant, because half the formatters
 * took the viewer's locale and half asked for "en" in UTC. A reader comparing
 * two panels could not tell formatting from a real difference in time.
 *
 * One formatter now, in the reader's own zone, and it says which zone that
 * is; the exact instant rides along in ISO 8601 UTC for a report or a host
 * log.
 */
describe("one absolute timestamp format", () => {
  const instant = Date.UTC(2026, 8, 21, 17, 28, 42);

  /**
   * The reader's own clock, and the zone it is in, printed: a reader in
   * London reads BST, and nobody has to know a rule to read a time.
   *
   * FAILS ON REVERT: pin every time to UTC again and London reads 17:28.
   */
  it("renders the reader's local time and names the zone", () => {
    expect(formatAbsolute(instant, "Europe/London")).toMatch(/^21 Sept? 2026, 18:28 BST$/);
    expect(formatAbsolute(instant, "UTC")).toMatch(/^21 Sept? 2026, 17:28 UTC$/);
    expect(formatAbsolute(instant, "America/New_York")).toMatch(/^21 Sept? 2026, 13:28 GMT-4$/);
    // With no zone handed in it is the machine's own, and still says which.
    expect(formatAbsolute(instant)).toMatch(/^\d{1,2} \S+ 2026, \d{2}:\d{2} \S+$/);
  });

  it("accepts a Date, an epoch and an ISO string alike, with one answer", () => {
    const iso = new Date(instant).toISOString();
    expect(formatAbsolute(instant)).toBe(formatAbsolute(iso));
    expect(formatAbsolute(instant)).toBe(formatAbsolute(new Date(instant)));
  });

  it("is what the older absolute branch now returns", () => {
    // Far enough back that formatTimestamp stops saying "3 days ago".
    const old = Date.now() - 40 * 86_400_000;
    expect(formatTimestamp(old)).toBe(formatAbsolute(old));
  });

  it("refuses a value that is not a time, rather than printing one", () => {
    expect(formatAbsolute("not a date")).toBeUndefined();
    expect(formatAbsolute(Number.NaN)).toBeUndefined();
    expect(isoInstant("not a date")).toBeUndefined();
    expect(timeTitle("not a date")).toBeUndefined();
  });

  it("carries the exact instant in ISO 8601 UTC in the title", () => {
    expect(isoInstant(instant)).toBe("2026-09-21T17:28:42Z");
    expect(isoInstant("2026-09-21T17:28:42.250Z")).toBe("2026-09-21T17:28:42.250Z");
    expect(timeTitle(instant, "Europe/London")).toMatch(/^21 Sept? 2026, 18:28 BST \(2026-09-21T17:28:42Z\)$/);
  });

  it("prints a day in the same words, and a time of day only when it is today", () => {
    expect(formatDay(instant, "UTC")).toMatch(/^21 Sept? 2026$/);
    expect(formatClock(instant, new Date(instant + 3_600_000), "Europe/London")).toBe("18:28 BST");
    expect(formatClock(instant, new Date(instant + 3 * 86_400_000), "Europe/London")).toMatch(/^21 Sept? 2026, 18:28 BST$/);
  });
});

/**
 * A 20-day-old record read "Fresh" beside 3-day-old ones reading "Stale",
 * each judged by a budget the reader could not see. The age and the budget
 * are printed instead, so the word explains itself.
 */
describe("how old a piece of evidence is", () => {
  it("says its age against its producer's budget", () => {
    expect(freshnessLabel({ observed_at: "x", age_seconds: 20 * 86_400, budget_seconds: 90 * 86_400 })).toBe("20 d old, within its 90 d budget");
    expect(freshnessLabel({ observed_at: "x", age_seconds: 3 * 86_400, budget_seconds: 86_400 })).toBe("3 d old, past its 24 h budget");
    expect(freshnessLabel({ observed_at: "x", age_seconds: 12, budget_seconds: 30 })).toBe("12 s old, within its 30 s budget");
  });

  it("says never checked, or that no age was reported, instead of a word it cannot back", () => {
    expect(freshnessLabel({ observed_at: null, age_seconds: null, budget_seconds: 30 })).toBe("never checked");
    expect(freshnessLabel({ observed_at: "x", age_seconds: null, budget_seconds: 30 })).toBe("age not reported");
    expect(freshnessLabel({ observed_at: "x", age_seconds: 300, budget_seconds: 0 })).toBe("5 min old");
  });

  it("names a length in the largest unit that fits", () => {
    expect([59, 119, 120, 7_199, 7_200, 172_799, 172_800].map(formatDuration)).toEqual(["59 s", "119 s", "2 min", "119 min", "2 h", "47 h", "2 d"]);
  });
});
