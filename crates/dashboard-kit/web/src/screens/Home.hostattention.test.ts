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

  it("treats zero as good news, not as a warning, and says it is today's", () => {
    const line = hostAttentionLine({ addresses_waiting: 0, counts: "distinct addresses, today" });
    expect(line?.tone).toBe("quiet");
    expect(line?.title).toBe("Nothing new on the host today is waiting for you");
  });

  /**
   * The producer's definition is what a reader checks the number against. It
   * is not the answer, and it is written in the producer's terms, so it is
   * handed to the screen as a labelled definition (shown behind "What these
   * numbers count"), not as the sentence under the title. It reads as a
   * sentence there: capital first, full stop last, the producer's words
   * otherwise unchanged.
   */
  it("names the number and keeps what the producer counted as its definition", () => {
    const counts = "distinct external addresses whose latest decision is absent or awaiting confirmation, today";
    const line = hostAttentionLine({ addresses_waiting: 8, counts });
    expect(line?.tone).toBe("waiting");
    expect(line?.title).toBe("8 addresses are waiting on you");
    expect(line?.body).toBeUndefined();
    expect(line?.definitions).toEqual([
      {
        label: "Addresses",
        text: "Distinct external addresses whose latest decision is absent or awaiting confirmation, today.",
      },
    ]);
  });

  it("does not add a second full stop to a definition that already ends a sentence", () => {
    const line = hostAttentionLine({ addresses_waiting: 2, counts: "Addresses, today." });
    expect(line?.definitions[0]?.text).toBe("Addresses, today.");
  });

  /**
   * THE DEFECT THIS PINS
   *
   * Both numbers are TODAY's; the queue behind the link is every day's, and a
   * finding from yesterday that still waits on a person stays in it. The calm
   * line said "Nothing on the host is waiting for you" and hid the link, so
   * one day after an undecided privilege escalation arrived at 23:30 the
   * Overview read nothing waiting over a queue holding it.
   *
   * FAILS ON REVERT: hide `through` under the calm line again, or say
   * "Nothing on the host is waiting for you", and this fails.
   */
  it("still offers the queue under today's good news, in calmer words", () => {
    const line = hostAttentionLine({ addresses_waiting: 0, counts: "x" });
    expect(line?.title).not.toBe("Nothing on the host is waiting for you");
    expect(line?.title).toContain("today");
    expect(line?.through.label).toBe("See the waiting queue, from any day");
    expect(line?.through.note).toContain("today only");
    expect(line?.through.note).toContain("what earlier days left waiting");
    expect(line?.through.note).toContain("may not be empty");
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
    // Not "longer": one case can name several addresses (a distributed SSH
    // attack is one incident naming ten), so the list can be shorter too.
    expect(through?.note).toContain("will not match this number");
    expect(through?.note).toContain("one address can have several cases");
    expect(through?.note).toContain("one case can name several addresses");
    expect(through?.note).not.toContain("longer");
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
    // Half an address is not a count either; "2.5 addresses" would be printed.
    expect(hostAttentionLine({ addresses_waiting: 2.5, counts: "x" })).toBeUndefined();
  });
});

/**
 * THE DEFECT THESE PIN
 *
 * The line counts distinct external ADDRESSES. A finding that names none (a
 * privilege escalation, a lateral movement to an internal address) has
 * nothing for it to count, and the paid host keeps an undecided high one in
 * the waiting queue all the same. With no address waiting the line said
 * "Nothing on the host is waiting for you" over that queue, and hid the way
 * to it. The host now serves those findings beside the addresses
 * (`findings_waiting_off_the_line`), and the title counts both.
 *
 * FAILS ON REVERT: read `addresses_waiting` alone again and every case with
 * findings below reads the addresses only, the 0/m case reads as the calm
 * line, and no way through is offered.
 */
const ADDRESSES = "distinct outside addresses, today, with a finding nothing has decided on";
const FINDINGS = "host findings from today that wait in Cases and that a count of addresses cannot include";
/** How each reads under its label: the producer's words as a sentence. */
const ADDRESSES_DEFINITION = { label: "Addresses", text: "Distinct outside addresses, today, with a finding nothing has decided on." };
const FINDINGS_DEFINITION = { label: "Findings", text: "Host findings from today that wait in Cases and that a count of addresses cannot include." };

function hostLine(addresses: number, findings?: unknown) {
  return hostAttentionLine({
    addresses_waiting: addresses,
    counts: ADDRESSES,
    ...(findings === undefined
      ? {}
      : { findings_waiting_off_the_line: findings as number, findings_waiting_off_the_line_counts: FINDINGS }),
  });
}

describe("what the host has waiting beside the addresses", () => {
  it("reads the addresses alone when an older host does not send the findings", () => {
    const quiet = hostLine(0);
    expect(quiet?.tone).toBe("quiet");
    expect(quiet?.title).toBe("Nothing new on the host today is waiting for you");
    // An older host counted addresses only; its zero says no more than that.
    expect(quiet?.body).toBe("Every address this host saw today has been decided on.");
    expect(quiet?.definitions).toEqual([]);
    const line = hostLine(8);
    expect(line?.title).toBe("8 addresses are waiting on you");
    expect(line?.definitions).toEqual([ADDRESSES_DEFINITION]);
    expect(line?.through.note).toContain("will not match this number");
  });

  /**
   * THE DEFECT THIS PINS
   *
   * The calm body spoke of addresses only ("Every address this host saw today
   * has been decided on.") while the calm state now also needs the findings
   * to be zero. And it was false on its own terms: an internal, allowlisted
   * or research-only address with an undecided low finding is not decided
   * on, the host leaves it out because nobody is asked about it. What a zero
   * from a host that counts both means is that nothing it found today is
   * asking for a person.
   *
   * FAILS ON REVERT: keep the address sentence for a host that sends the
   * findings and this fails.
   */
  it("is the calm line only when neither addresses nor findings wait, and says what that zero means", () => {
    const line = hostLine(0, 0);
    expect(line?.tone).toBe("quiet");
    expect(line?.title).toBe("Nothing new on the host today is waiting for you");
    expect(line?.body).toBe("Nothing the host found today is asking for a person.");
    expect(line?.definitions).toEqual([]);
    expect(line?.through.label).toBe("See the waiting queue, from any day");
  });

  it("names the addresses alone, and does not define findings it did not count, when none wait", () => {
    const line = hostLine(8, 0);
    expect(line?.tone).toBe("waiting");
    expect(line?.title).toBe("8 addresses are waiting on you");
    expect(line?.definitions).toEqual([ADDRESSES_DEFINITION]);
    expect(line?.through.note).toContain("will not match this number");
  });

  /**
   * The case that hid the queue: no address waits, a finding does. The line
   * must say so, and name findings rather than addresses.
   */
  it("says findings are waiting when no address is", () => {
    const line = hostLine(0, 3);
    expect(line?.tone).toBe("waiting");
    expect(line?.title).toBe("3 findings are waiting on you");
    // Only the definition of what the title counts: there is no address in it.
    expect(line?.definitions).toEqual([FINDINGS_DEFINITION]);
    expect(line?.through.label).toBe("See all waiting cases, from any day");
  });

  /**
   * A finding is one case, so the note must not tell the reader the list
   * shows "cases rather than addresses" when the title named no address. It
   * still says the list holds every day and the agent's cases, which is why
   * it can be longer.
   */
  it("explains the list in the units the title used when only findings wait", () => {
    const note = hostLine(0, 3)?.through?.note;
    expect(note).not.toContain("addresses");
    expect(note).toContain("every day rather than only today");
    expect(note).toContain("the agent's cases as well as the host's");
    expect(note).toContain("longer than this number");
  });

  /**
   * THE DEFECT THIS PINS
   *
   * "8 addresses and 3 other findings are waiting on you" read as if the
   * addresses were findings too. They are not, and the three are the findings
   * the address count left out, one of which can stand behind one of the
   * eight addresses. The note said the list "can be longer than these two
   * numbers together", and it can also be shorter: one incident naming
   * several addresses is one case.
   *
   * FAILS ON REVERT: the old title ("and 3 other findings") or the old note
   * ("longer than these two numbers together") fails this.
   */
  it("counts both, and names the findings as the ones the address count leaves out, when both wait", () => {
    const line = hostLine(8, 3);
    expect(line?.tone).toBe("waiting");
    expect(line?.title).toBe("8 addresses, and 3 findings the address count leaves out, are waiting on you");
    expect(line?.title).not.toContain("other");
    // Each number keeps its own definition, in the order the title names them.
    expect(line?.definitions).toEqual([ADDRESSES_DEFINITION, FINDINGS_DEFINITION]);
    const note = line?.through.note;
    expect(note).toContain("cases rather than addresses");
    expect(note).toContain("will not match these numbers");
    expect(note).toContain("one address can have several cases");
    expect(note).toContain("one case can name several addresses");
    expect(note).not.toContain("longer");
  });

  it("uses the singular and the plural where each belongs", () => {
    expect(hostLine(1, 0)?.title).toBe("1 address is waiting on you");
    expect(hostLine(0, 1)?.title).toBe("1 finding is waiting on you");
    expect(hostLine(0, 2)?.title).toBe("2 findings are waiting on you");
    expect(hostLine(1, 1)?.title).toBe("1 address, and 1 finding the address count leaves out, are waiting on you");
    expect(hostLine(2, 1)?.title).toBe("2 addresses, and 1 finding the address count leaves out, are waiting on you");
    expect(hostLine(1, 2)?.title).toBe("1 address, and 2 findings the address count leaves out, are waiting on you");
  });

  /**
   * A findings value that is not a count is read as not sent, the way an
   * older host reads, rather than printed ("-3 findings", "2.5 findings") or
   * allowed to turn the calm line into a warning.
   */
  it("ignores a findings value that is not a non-negative whole number", () => {
    for (const bad of [-3, 2.5, Number.NaN, Number.POSITIVE_INFINITY, "3", null]) {
      expect(hostLine(0, bad), String(bad)).toEqual(hostLine(0));
      expect(hostLine(8, bad), String(bad)).toEqual(hostLine(8));
    }
  });

  /**
   * The count without its definition still counts: the finding is waiting
   * whatever the sentence beside it says. The line then says what it counts
   * in its own words rather than printing nothing, or an empty paragraph.
   */
  it("still says what the findings are when the host sends the count without its definition", () => {
    for (const counts of [undefined, "", "   "]) {
      const line = hostAttentionLine({
        addresses_waiting: 0,
        counts: ADDRESSES,
        findings_waiting_off_the_line: 2,
        ...(counts === undefined ? {} : { findings_waiting_off_the_line_counts: counts }),
      });
      expect(line?.title).toBe("2 findings are waiting on you");
      expect(line?.definitions).toHaveLength(1);
      expect(line?.definitions[0]?.label).toBe("Findings");
      expect(line?.definitions[0]?.text).toContain("a count of addresses cannot include");
    }
  });
});
