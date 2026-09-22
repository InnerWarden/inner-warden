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

  it("uses the singular for one", () => {
    expect(hostAttentionLine({ addresses_waiting: 1, counts: "x" })?.title).toBe("1 address is waiting on you");
  });

  it("refuses a value that is not a count rather than rendering one", () => {
    expect(hostAttentionLine({ addresses_waiting: Number.NaN, counts: "x" })).toBeUndefined();
    expect(hostAttentionLine({ addresses_waiting: -3, counts: "x" })).toBeUndefined();
  });
});
