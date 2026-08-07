import { describe, expect, it } from "vitest";
import {
  AUTO_SETUP_UNKNOWN_FOOTNOTE,
  DISCOVERY_LIMIT_DISCLOSURE,
  autoSetupPlacement,
  discoveryLimitNotice,
} from "./MachineIntelligence";

// The operator's rule: internal implementation caveats never render as
// prominent banners. These two lines were exactly that class: a permanent amber
// role="status" banner for the discovery safety limit, and a header strip
// announcing "Automatic setup is unavailable" on every paid host forever.

describe("the discovery safety limit is a disclosure, not a banner", () => {
  it("renders as a collapsed disclosure when discovery is limited", () => {
    const notice = discoveryLimitNotice(true);
    expect(notice?.kind).toBe("disclosure");
    // The full truth is preserved inside the disclosure body, verbatim enough
    // to answer the operator who opens it.
    expect(notice?.body).toContain("local safety limit");
    expect(notice?.body).toContain("may be omitted");
    // The summary line is calm and says what the USER cares about.
    expect(notice?.summary).toBe("Some integrations may not be listed");
  });

  it("renders nothing when discovery is not limited", () => {
    expect(discoveryLimitNotice(false)).toBeNull();
  });

  it("is never worded as an alarm", () => {
    expect(DISCOVERY_LIMIT_DISCLOSURE.summary).not.toMatch(/limit|error|warn/i);
  });
});

describe("the automatic-setup line earns its header placement", () => {
  it("keeps the header strip only when the policy is actually known", () => {
    expect(autoSetupPlacement(true)).toBe("header");
  });

  it("demotes the unknown case to a quiet footnote", () => {
    expect(autoSetupPlacement(false)).toBe("footnote");
    expect(AUTO_SETUP_UNKNOWN_FOOTNOTE).toContain("not reported");
    // The footnote tells the user where to look, not what the system lacks.
    expect(AUTO_SETUP_UNKNOWN_FOOTNOTE).toContain("CLI");
    expect(AUTO_SETUP_UNKNOWN_FOOTNOTE).not.toMatch(/unavailable/i);
  });
});
