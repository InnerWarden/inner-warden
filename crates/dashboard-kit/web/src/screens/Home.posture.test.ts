import { describe, expect, it } from "vitest";
import { ENTERPRISE_UNKNOWN_POSTURE, POSTURES, editionLabel, enforceCommand, enforceHint, postureFor } from "./Home";

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

describe("the dashboard names the edition that is installed", () => {
  // REGRESSION ANCHOR. The hero eyebrow was the literal string "InnerWarden
  // Community" on every host. A paid box announced itself as the free product,
  // and an operator who upgraded saw no change at all -- which reads as the
  // upgrade not having taken.
  //
  // FAILS ON REVERT: hardcode the label again and the enterprise case trips.
  it("says Enterprise on a paid host and Community on a free one", () => {
    expect(editionLabel("enterprise")).toBe("InnerWarden Enterprise");
    expect(editionLabel("community")).toBe("InnerWarden Community");
  });

  it("follows an upgrade without anything else changing", () => {
    // The whole point: same screen, same code path, edition flips, and the
    // product the operator is looking at is renamed to match.
    const before = editionLabel("community");
    const after = editionLabel("enterprise");
    expect(after).not.toBe(before);
    expect(after).toContain("Enterprise");
  });

  it("claims neither tier before the edition resolves", () => {
    // Guessing here would put a tier on screen we cannot back yet.
    expect(editionLabel(undefined)).toBe("InnerWarden");
  });
});

describe("the enforce step names a command that exists", () => {
  // REGRESSION ANCHOR. Step 3 hardcoded `innerwarden enforce`. That command is
  // real in Community and absent from Enterprise, where enforcement is the
  // kernel exec-gate -- so the last step of the PAID onboarding told the
  // operator to run something that errors out. Verified against both shipped
  // CLIs: Community `main.rs` dispatches "enforce"; the Enterprise ctl exposes
  // `exec-gate {status,arm,rehearse,enforce,disarm}` and no bare `enforce`.
  //
  // FAILS ON REVERT: hardcode either string and the other edition trips.
  it("sends Enterprise to the exec-gate, not to a command it does not have", () => {
    expect(enforceCommand("enterprise")).toBe("innerwarden exec-gate enforce");
  });

  it("keeps the Community command, which is real there", () => {
    expect(enforceCommand("community")).toBe("innerwarden enforce");
  });

  it("falls back to the Community command before the edition resolves", () => {
    // The free CLI is the safe default: naming a paid-only command to someone
    // who does not have it is the failure being fixed.
    expect(enforceCommand(undefined)).toBe("innerwarden enforce");
  });

  it("does not promise a blind flip on the paid gate", () => {
    expect(enforceHint("enterprise")).toContain("rehearsal");
  });
});
