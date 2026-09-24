import { describe, expect, it } from "vitest";
import { hostAttentionLine } from "./Home";

/**
 * The operator's standing instruction is that this dashboard must not fill
 * with warnings that mean nothing. Three rules follow from it, and each is
 * pinned here.
 *
 * MEASURED on a production host 2026-09-22: 851 incidents in a day, 42 of them
 * with no decision or awaiting confirmation, behind EIGHT addresses, among
 * them a rootkit finding and a log-tampering one. Eight is something somebody
 * can act on; 851 is a wall, which is why the producer counts subjects.
 */
describe("what the host has waiting", () => {
  it("says nothing at all when the build has no host layer", () => {
    expect(hostAttentionLine(undefined)).toBeUndefined();
  });

  it("treats zero as good news, not as a warning", () => {
    const line = hostAttentionLine({ addresses_waiting: 0, counts: "distinct addresses, today" });
    expect(line?.tone).toBe("quiet");
    expect(line?.title).toBe("Nothing on the host is waiting for you");
  });

  it("names the number and repeats what the producer counted", () => {
    const counts = "distinct external addresses whose latest decision is absent or awaiting confirmation, today";
    const line = hostAttentionLine({ addresses_waiting: 8, counts });
    expect(line?.tone).toBe("waiting");
    expect(line?.title).toBe("8 addresses are waiting on you");
    expect(line?.body).toBe(counts);
  });

  it("offers no way through under good news", () => {
    expect(hostAttentionLine({ addresses_waiting: 0, counts: "x" })?.through).toBeUndefined();
  });

  /**
   * The line counts distinct ADDRESSES seen TODAY. The link opens CASES of ALL
   * time with status `waiting` (the agreed contract with the paid server, not
   * changed here). One address can own many cases and a case waiting since
   * yesterday is still waiting, so the list can be far longer than the number.
   * The link's words used to be "See what is waiting", which under "8
   * addresses" promises those eight.
   */
  it("does not promise the list is the number above it", () => {
    const through = hostAttentionLine({ addresses_waiting: 8, counts: "x" })?.through;
    expect(through).toBeDefined();
    // It names the unit and the span of what it opens...
    expect(through?.label).toBe("See all waiting cases, from any day");
    // ...and never the count, which would say the list IS the eight.
    expect(through?.label).not.toContain("8");
    expect(through?.label).not.toBe("See what is waiting");
    // The note says why the two differ, in the reader's words.
    expect(through?.note).toContain("cases rather than addresses");
    expect(through?.note).toContain("every day rather than only today");
    expect(through?.note).toContain("longer than this number");
  });

  /**
   * On the paid server every agent-session case is created `Open`, and the
   * `waiting` status matches `Open` as well as `NeedsReview`. So the list this
   * link opens, placed under a line about the HOST, holds every agent session
   * too. The note used to give only the address/case and today/any-day
   * reasons, and left out the one that makes the list longest.
   */
  it("says the list holds the agent's cases, not only the host's", () => {
    const through = hostAttentionLine({ addresses_waiting: 8, counts: "x" })?.through;
    expect(through?.note).toContain("the agent's cases as well as the host's");
  });

  it("uses the singular for one", () => {
    expect(hostAttentionLine({ addresses_waiting: 1, counts: "x" })?.title).toBe("1 address is waiting on you");
  });

  it("refuses a value that is not a count rather than rendering one", () => {
    expect(hostAttentionLine({ addresses_waiting: Number.NaN, counts: "x" })).toBeUndefined();
    expect(hostAttentionLine({ addresses_waiting: -3, counts: "x" })).toBeUndefined();
  });
});
