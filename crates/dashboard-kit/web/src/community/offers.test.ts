import { describe, expect, it } from "vitest";

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);
import { CASE_OFFER_MAX, caseOffer, EDITIONS_URL, INSTALLED_LINE, messageOffer, NOT_IN_COMMUNITY, paidRowFact, paidRowLines, PRICING_URL, protectionOffer, serverOffer } from "./offers";
import { DECISION_OUTCOMES, MESSAGE_OUTCOMES } from "./words";

const CONCERNS = ["credential_read", "domain_fetch", "other"] as const;

describe("which offer a case gets", () => {
  it("offers nothing where Community did its job or nothing ran", () => {
    for (const concern of CONCERNS) {
      expect(caseOffer({ outcomeKey: "refused_before_run", concern }, "linux")).toBeUndefined();
      expect(caseOffer({ outcomeKey: "checked_only", concern }, "linux")).toBeUndefined();
    }
    // A message InnerWarden stopped: the same rule as a command it refused.
    expect(messageOffer("linux", "stopped_by_innerwarden")).toBeUndefined();
    expect(messageOffer("linux", "declined_by_agent")?.body).toContain("Execution Gate");
  });

  it("names the capability for what the command reached for", () => {
    expect(caseOffer({ outcomeKey: "would_have_refused", concern: "credential_read" }, "macos")?.body).toContain("Secret Read Guard");
    expect(caseOffer({ outcomeKey: "flagged_ran", concern: "domain_fetch" }, "macos")?.body).toContain("DNS Guard");
    expect(caseOffer({ outcomeKey: "unsafe_may_have_run", concern: "other" }, "macos")?.body).toContain("Execution Gate");
    expect(caseOffer({ outcomeKey: "allowed", concern: "other" }, "macos")).toBeUndefined();
    expect(caseOffer({ outcomeKey: "unplaced", concern: "other" }, "macos")).toBeUndefined();
  });

  it("never says the paid edition would have stopped THIS command", () => {
    for (const outcomeKey of DECISION_OUTCOMES) {
      for (const concern of CONCERNS) {
        const body = caseOffer({ outcomeKey, concern }, "linux")?.body ?? "";
        expect(body).not.toMatch(/would have/i);
      }
    }
    for (const count of [0, 1, 761]) {
      const offer = serverOffer("macos", { count, span: "since 25 Sept" });
      expect(`${offer.lead} ${offer.body}`).not.toMatch(/would have/i);
    }
  });

  /** An offer under a case sits under the reader's own step: it must never outweigh it. */
  it("keeps every offer under a case short", () => {
    for (const os of ["linux", "macos", "windows", "other"] as const) {
      for (const outcomeKey of DECISION_OUTCOMES) {
        for (const concern of CONCERNS) {
          const body = caseOffer({ outcomeKey, concern }, os)?.body;
          if (body !== undefined) expect(body.length, body).toBeLessThan(CASE_OFFER_MAX);
        }
      }
      for (const outcomeKey of MESSAGE_OUTCOMES) {
        const body = messageOffer(os, outcomeKey)?.body;
        if (body !== undefined) expect(body.length, body).toBeLessThan(CASE_OFFER_MAX);
      }
    }
  });

  it("is platform-honest: only Linux is told it can run it here", () => {
    const mac = caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "macos")?.body ?? "";
    const linux = caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "linux")?.body ?? "";
    expect(mac).toContain("On a Linux server,");
    expect(linux).toContain("On this Linux machine,");
    expect(serverOffer("windows").body).toContain("On a Linux server,");
    expect(serverOffer("linux").body).toContain("On this Linux machine,");
  });

  it("links to innerwarden.com only, with no query string", () => {
    const offers = [serverOffer("macos"), protectionOffer(), messageOffer("macos")!, caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "macos")!];
    for (const offer of offers) {
      expect([PRICING_URL, EDITIONS_URL]).toContain(offer.href);
      expect(offer.href).not.toContain("?");
      expect(offer.href.startsWith("https://innerwarden.com/")).toBe(true);
    }
  });

  /** Secret Read Guard is a name. No sentence here may say how it works. */
  it("never describes how Secret Read Guard works", () => {
    const mechanism = /kernel|ebpf|lsm|hook|inode|\bopen\b|read call|syscall|file descriptor|intercept/i;
    const guard = NOT_IN_COMMUNITY.find((capability) => capability.key === "secret_read_guard")!;
    expect(guard.line).not.toMatch(mechanism);
    const credential = caseOffer({ outcomeKey: "would_have_refused", concern: "credential_read" }, "linux")!.body;
    const sentence = credential.slice(credential.indexOf("Active Defence"));
    expect(sentence).not.toMatch(mechanism);
    const fact = paidRowFact("secret_read_guard", { ran: 0, credentialRead: 3, domainFetch: 0 }, "25 Sept")!;
    expect(fact).not.toMatch(mechanism);
  });

  it("claims installation, never enforcement, where Active Defence is installed", () => {
    const words = `${INSTALLED_LINE.lead} ${INSTALLED_LINE.body}`;
    for (const forbidden of ["armed", "enforcing", "enforced", "protected"]) expect(words.toLowerCase()).not.toContain(forbidden);
  });

  it("names the paid features with the words already public, and no em or en dash", () => {
    const names = NOT_IN_COMMUNITY.map((capability) => capability.name);
    expect(names).toEqual(["Execution Gate", "Secret Read Guard", "DNS Guard", "Host sensor", "SSH decoy", "Automatic response", "Analyst tools"]);
    const text = JSON.stringify([NOT_IN_COMMUNITY, serverOffer("macos", { count: 3, span: "in the last 7 days" }), protectionOffer(), messageOffer("linux")]);
    expect(text).not.toMatch(DASHES);
  });

  it("does not say the host sensor sees everything", () => {
    const sensor = NOT_IN_COMMUNITY.find((capability) => capability.key === "host_sensor")!;
    expect(sensor.line).not.toMatch(/\bevery\b/i);
  });
});

describe("the Overview's offer", () => {
  /** It leads with the reader's own number, and the one capability about their agent. */
  it("leads with the flagged commands that ran here, then the agent's capability, then the server", () => {
    const offer = serverOffer("macos", { count: 761, span: "since 25 Sept" });
    expect(offer.lead).toBe("761 flagged commands ran here since 25 Sept: Community relies on your agent asking first.");
    expect(offer.body.indexOf("Execution Gate")).toBeLessThan(offer.body.indexOf("host sensor"));
    expect(serverOffer("macos", { count: 1, span: "in the last 7 days" }).lead).toContain("1 flagged command ran here");
    // Nothing ran: no count is invented.
    const none = serverOffer("macos", { count: 0, span: "in the last 7 days" });
    expect(`${none.lead} ${none.body}`).not.toMatch(/\d/);
  });

  /** A paragraph over 160 characters is not read on a card; the two halves each fit. */
  it("says its two halves in two short paragraphs", () => {
    for (const os of ["linux", "macos"] as const) {
      const offer = serverOffer(os, { count: 1_004, span: "since 25 Sept 2026" });
      expect(offer.lead!.length).toBeLessThan(CASE_OFFER_MAX);
      expect(offer.body.length).toBeLessThan(CASE_OFFER_MAX);
    }
  });
});

describe("what a paid row says about this machine", () => {
  const flagged = { ran: 19, credentialRead: 3, domainFetch: 1, since: "2026-09-25T17:33:00Z" };

  it("prints this machine's own count under the row it answers, with its span", () => {
    expect(paidRowFact("execution_gate", flagged, "25 Sept")).toBe("19 flagged commands ran on this machine since 25 Sept.");
    expect(paidRowFact("secret_read_guard", flagged, "25 Sept")).toBe("3 cases here reached for a credential file since 25 Sept.");
    expect(paidRowFact("dns_guard", flagged, undefined)).toBe("1 flagged command here fetched from the internet by name.");
  });

  it("says nothing where there is no fact: a zero, another row, or a record not read", () => {
    expect(paidRowFact("execution_gate", { ...flagged, ran: 0 }, "25 Sept")).toBeUndefined();
    expect(paidRowFact("host_sensor", flagged, "25 Sept")).toBeUndefined();
    expect(paidRowFact("execution_gate", undefined, "25 Sept")).toBeUndefined();
  });

  /**
   * FAILS ON REVERT: Secret Read Guard read "Part of Active Defence." above
   * this machine's own count, a placeholder where the count says more.
   */
  it("gives a name-only row's line up to this machine's fact, and keeps every other line", () => {
    const row = (key: string) => NOT_IN_COMMUNITY.find((capability) => capability.key === key)!;
    const fact = "3 cases here reached for a credential file since 25 Sept.";
    expect(paidRowLines(row("secret_read_guard"), fact)).toEqual({ fact });
    expect(paidRowLines(row("secret_read_guard"), undefined)).toEqual({ line: "Part of Active Defence." });
    const gate = row("execution_gate");
    expect(paidRowLines(gate, "19 flagged commands ran.")).toEqual({ line: gate.line, fact: "19 flagged commands ran." });
    expect(NOT_IN_COMMUNITY.filter((capability) => capability.nameOnly === true).map((capability) => capability.key)).toEqual(["secret_read_guard"]);
  });
});
