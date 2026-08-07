import { describe, expect, it } from "vitest";
import { capabilityBoundaryMessage } from "./CapabilityBoundary";

const STATES = [
  "adapter_absent",
  "unsupported",
  "authentication_required",
  "forbidden",
  "rate_limited",
  "conflict",
  "error",
  "unavailable",
  "loading",
] as const;

/**
 * These sentences appear exactly when a user is looking at an empty screen and
 * wants to know what to do about it, which is the worst possible moment to
 * describe our own wiring to them.
 */
const OUR_PLUMBING = /\badapter|bootstrap|projection|contract|payload|legacy|schema|same-origin|\bv1\b|mounted|publication gate/i;

describe("an empty screen explains itself in the user's language", () => {
  it.each(STATES)("says why in plain words for %s", (state) => {
    const message = capabilityBoundaryMessage(state, "Cases");
    expect(`${message.title} ${message.body}`).not.toMatch(OUR_PLUMBING);
    expect(message.title.length).toBeGreaterThan(0);
    expect(message.body.length).toBeGreaterThan(0);
  });

  it("uses the capability's own name so the user knows which screen is empty", () => {
    expect(capabilityBoundaryMessage("unavailable", "Agent inventory").title).toContain("Agent inventory");
    expect(capabilityBoundaryMessage("loading", "Agent inventory").title).toBe("Loading agent inventory");
  });

  /**
   * HONESTY ANCHOR. The plain wording changed; the rules did not. Absence is
   * never rendered as zero, as healthy, or as protection from somewhere else.
   */
  it("never turns a missing answer into a reassuring one", () => {
    expect(capabilityBoundaryMessage("unavailable", "Posture").body).toContain("never shown as zero or as healthy");
    expect(capabilityBoundaryMessage("adapter_absent", "Posture").body).toContain("Nothing from another edition is shown in its place");
    expect(capabilityBoundaryMessage("unsupported", "Posture").body).toContain("says nothing either way");
    expect(capabilityBoundaryMessage("error", "Posture").body).toContain("Nothing older is shown in its place");
    expect(capabilityBoundaryMessage("conflict", "Posture").body).toContain("Nothing was applied");
  });

  it("still reports an unsupported capability from the capability record alone", () => {
    expect(capabilityBoundaryMessage("unavailable", "Posture", { availability: "unsupported", support: "supported", reason_code: null }).status)
      .toBe("unsupported");
    expect(capabilityBoundaryMessage("unavailable", "Posture", { availability: "available", support: "unsupported", reason_code: null }).status)
      .toBe("unsupported");
  });
});
