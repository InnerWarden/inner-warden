import { describe, expect, it } from "vitest";
import { automaticSetupLabel } from "./MachineIntelligence";
import type { LocalAgent } from "../api";

function agent(over: Partial<LocalAgent["guardrail"]>, eligible: boolean | null = null): LocalAgent {
  return {
    id: "ag-1",
    display_name: "OpenClaw",
    installed: true,
    running: null,
    detected_by: [],
    auto_connect_eligible: eligible,
    guardrail: { mode: "unknown", mechanism: null, setup_support: "unsupported", ...over },
  } as LocalAgent;
}

describe("automatic setup is never claimed from ignorance", () => {
  // REGRESSION ANCHOR, and the reason this helper exists.
  //
  // The label read `mode !== "not_configured" ? "Already configured"`, so an
  // agent whose guardrail state was UNKNOWN fell into the positive branch. On a
  // live paid host that produced a card reading "Already configured" beside
  // "Mechanism: Not available" and "Setup support: Unsupported", under a banner
  // saying automatic setup was unavailable -- for an agent with no guardrail
  // installed at all.
  //
  // "Already configured" is an assurance and may only come from a mode that
  // positively says so.
  //
  // FAILS ON REVERT: restore the `!== "not_configured"` test and this trips.
  it("does not report an unknown guardrail as configured", () => {
    // Not knowing is still not a kind of being configured, in either register.
    expect(automaticSetupLabel(agent({ mode: "unknown" }))).toBe("No activity seen yet");
    expect(automaticSetupLabel(agent({ mode: "unknown" }), true)).toBe("Not determined");
    expect(automaticSetupLabel(agent({ mode: "unknown" }))).not.toContain("configured");
  });

  it("still reports the modes that really are configured", () => {
    for (const mode of ["monitor", "enforce", "mixed"]) {
      expect(automaticSetupLabel(agent({ mode }))).toBe("Already configured");
    }
  });

  it("keeps the existing not-configured ladder intact", () => {
    // The plain register says what the reader can DO instead of what we failed
    // to learn. Both are true; only one is actionable.
    expect(automaticSetupLabel(agent({ mode: "not_configured" }, null))).toBe("Set up by hand");
    expect(automaticSetupLabel(agent({ mode: "not_configured" }, null), true)).toBe("Eligibility unavailable");
    expect(automaticSetupLabel(agent({ mode: "not_configured" }, true))).toBe("Eligible when enabled");
    expect(automaticSetupLabel(agent({ mode: "not_configured", setup_support: "manual" }, false))).toBe("Manual setup");
    expect(automaticSetupLabel(agent({ mode: "not_configured", setup_support: "unsupported" }, false))).toBe("Not available");
  });

  it("keeps partial as a review prompt", () => {
    expect(automaticSetupLabel(agent({ mode: "partial" }))).toBe("Manual review required");
  });

  it("never claims configured for a mode it does not recognise", () => {
    // A future backend value must default to silence, not to assurance.
    expect(automaticSetupLabel(agent({ mode: "some_new_mode" }))).not.toBe("Already configured");
  });
});
