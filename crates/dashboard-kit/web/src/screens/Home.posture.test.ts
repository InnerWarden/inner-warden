import { describe, expect, it } from "vitest";
import { ENTERPRISE_UNKNOWN_POSTURE, POSTURES, postureFor } from "./Home";

describe("the unknown posture on a paid host", () => {
  // REGRESSION ANCHOR. Observed on the production box: the Enterprise Overview
  // led with "0 Decisions recorded" and Community copy saying "this version
  // records guardrail decisions", while 6,047 incidents sat in that host's
  // graph. The zero was correct -- the agent-guard hook is not installed there
  // -- but the sentence around it read as "the product is doing nothing".
  //
  // FAILS ON REVERT: point the enterprise branch back at POSTURES.unknown.
  it("does not reuse the community wording", () => {
    expect(ENTERPRISE_UNKNOWN_POSTURE.title).not.toBe(POSTURES.unknown.title);
    expect(ENTERPRISE_UNKNOWN_POSTURE.body).not.toBe(POSTURES.unknown.body);
    expect(POSTURES.unknown.body).toMatch(/this version/i);
    expect(ENTERPRISE_UNKNOWN_POSTURE.body).not.toMatch(/this version/i);
  });

  it("is the copy an enterprise host actually gets", () => {
    // The behaviour, not just the constants. A test that only compared the two
    // objects passed with the selection reverted.
    expect(postureFor("unknown", "enterprise")).toBe(ENTERPRISE_UNKNOWN_POSTURE);
    expect(postureFor("unknown", "community")).toBe(POSTURES.unknown);
    expect(postureFor("unknown", undefined)).toBe(POSTURES.unknown);
    // Every other mode is shared: only the unknown case was mis-worded.
    expect(postureFor("partial", "enterprise")).toBe(POSTURES.partial);
  });

  it("says why the counter is zero instead of implying nothing is protected", () => {
    const body = ENTERPRISE_UNKNOWN_POSTURE.body.toLowerCase();
    expect(body).toContain("not running on this host");
    expect(body).toContain("posture");
  });
});
