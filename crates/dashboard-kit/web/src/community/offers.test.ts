import { describe, expect, it } from "vitest";

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);
import { caseOffer, EDITIONS_URL, INSTALLED_LINE, messageOffer, NOT_IN_COMMUNITY, PRICING_URL, protectionOffer, serverOffer } from "./offers";
import { DECISION_OUTCOMES } from "./words";

describe("which offer a case gets", () => {
  it("offers nothing where Community did its job or nothing ran", () => {
    for (const concern of ["credential_read", "domain_fetch", "other"] as const) {
      expect(caseOffer({ outcomeKey: "refused_before_run", concern }, "linux")).toBeUndefined();
      expect(caseOffer({ outcomeKey: "checked_only", concern }, "linux")).toBeUndefined();
    }
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
      for (const concern of ["credential_read", "domain_fetch", "other"] as const) {
        const body = caseOffer({ outcomeKey, concern }, "linux")?.body ?? "";
        expect(body).not.toMatch(/would have (stopped|refused|blocked)/i);
      }
    }
  });

  it("is platform-honest: only Linux is told it can run it here", () => {
    const mac = caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "macos")?.body ?? "";
    const linux = caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "linux")?.body ?? "";
    expect(mac).toContain("On a Linux server,");
    expect(linux).toContain("On this Linux machine,");
    expect(serverOffer("windows").body).toContain("runs on Linux servers");
    expect(serverOffer("linux").body).toContain("On this Linux machine");
  });

  it("links to innerwarden.com only, with no query string", () => {
    const offers = [serverOffer("macos"), protectionOffer(), messageOffer("macos"), caseOffer({ outcomeKey: "flagged_ran", concern: "other" }, "macos")!];
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
  });

  it("claims installation, never enforcement, where Active Defence is installed", () => {
    const words = `${INSTALLED_LINE.lead} ${INSTALLED_LINE.body}`;
    for (const forbidden of ["armed", "enforcing", "enforced", "protected"]) expect(words.toLowerCase()).not.toContain(forbidden);
  });

  it("names the paid features with the words already public, and no em or en dash", () => {
    const names = NOT_IN_COMMUNITY.map((capability) => capability.name);
    expect(names).toEqual(["Execution Gate", "Secret Read Guard", "DNS Guard", "Host sensor", "SSH decoy", "Automatic response", "Analyst tools"]);
    const text = JSON.stringify([NOT_IN_COMMUNITY, serverOffer("macos"), protectionOffer(), messageOffer("linux")]);
    expect(text).not.toMatch(DASHES);
  });
});
