import { describe, expect, it } from "vitest";
import { formatAbsolute, formatTimestamp } from "./presentation";

/**
 * MEASURED in the third dashboard audit: one panel read the day first and
 * another the month first, for the same instant, because half the formatters
 * took the viewer's locale and half asked for "en" in UTC. A reader comparing
 * two panels could not tell formatting from a real difference in time.
 *
 * These are evidence timestamps. They are quoted in reports, compared against
 * host logs and read by more than one person, so they render the same for
 * everyone and say which zone they are in.
 */
describe("one absolute timestamp format", () => {
  const instant = Date.UTC(2026, 8, 21, 17, 28, 42);

  it("renders in UTC and says so", () => {
    const rendered = formatAbsolute(instant);
    expect(rendered).toContain("UTC");
    expect(rendered).toContain("17:28");
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
  });
});
