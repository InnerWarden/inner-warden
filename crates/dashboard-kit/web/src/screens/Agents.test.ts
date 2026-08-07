import { describe, expect, it } from "vitest";
import type { AgentSubject } from "../api/v1";
import {
  EMPTY_STATE,
  IDENTITY_TOOLTIP,
  LIVE_OBSERVATION_MAX_AGE_SECS,
  agentDisplay,
  discoveryFootnote,
  guardrailObservation,
  guardrailStatusLine,
  identityTooltip,
} from "./Agents";

const NOW = Date.UTC(2026, 7, 7, 12, 0, 0);

function subject(overrides: Partial<AgentSubject> = {}): AgentSubject {
  return {
    agent_id: "agent-3f2a9c1d5e8b",
    principal: null,
    product: "OpenClaw",
    provider: "openclaw",
    agent_class: "coding",
    runtime: null,
    model: null,
    identity_confidence: "declared",
    identity_evidence: [],
    sessions: [],
    capabilities: [],
    guardrail_mode: "warn",
    guardrail_configured_at: new Date(NOW - 16 * 86_400_000).toISOString(),
    guardrail_recorded_activity: 0,
    guardrail_last_observed_at: null,
    ...overrides,
  };
}

// Every word that asserts a guardrail is doing something RIGHT NOW. None of
// them may appear without a fresh dated observation.
const POSITIVE_WORDS = /screening|blocking|active|last seen/i;

describe("the sixteen-days lesson: intent is never presented as a running guardrail", () => {
  // REGRESSION ANCHOR (ported from the producer's guard_agents rule). A
  // registry row written by one `agents connect` carried mode "warn" for
  // sixteen days while its OWN counters recorded zero activity, and the card
  // said the agent was guarded. A policy row is intent, not protection.
  it("a subject with recorded_activity 0 and no observation never renders a positive mode word", () => {
    for (const mode of ["warn", "block", "enforce", "monitor", "observe", "custom"]) {
      const line = guardrailStatusLine(subject({ guardrail_mode: mode, guardrail_recorded_activity: 0, guardrail_last_observed_at: null }), NOW);
      expect(line.observed).toBe(false);
      expect(line.text).not.toMatch(POSITIVE_WORDS);
      expect(line.text).toContain("never observed");
      expect(line.text).toMatch(/^Configured/);
    }
  });

  it("activity counters without a timestamp cannot claim recency", () => {
    const line = guardrailStatusLine(subject({ guardrail_recorded_activity: 42, guardrail_last_observed_at: null }), NOW);
    expect(line.observed).toBe(false);
    expect(line.text).toContain("unknown time");
  });

  it("a stale observation is reported with its age, not as live", () => {
    const staleAt = new Date(NOW - (LIVE_OBSERVATION_MAX_AGE_SECS + 3_600) * 1000).toISOString();
    const line = guardrailStatusLine(subject({ guardrail_last_observed_at: staleAt, guardrail_recorded_activity: 7 }), NOW);
    expect(line.observed).toBe(false);
    expect(line.text).toMatch(/^Configured/);
    expect(line.text).toContain("last seen");
    expect(line.text).not.toMatch(/screening|blocking/i);
  });

  it("a future-dated observation is not evidence of anything", () => {
    const future = new Date(NOW + 3_600_000).toISOString();
    expect(guardrailObservation(subject({ guardrail_last_observed_at: future }), NOW)).toBe("not_observed_recently");
    expect(guardrailStatusLine(subject({ guardrail_last_observed_at: future }), NOW).observed).toBe(false);
  });

  it("a fresh dated observation earns the positive mode word and the age", () => {
    const seen = new Date(NOW - 120_000).toISOString();
    const line = guardrailStatusLine(subject({ guardrail_last_observed_at: seen, guardrail_recorded_activity: 12 }), NOW);
    expect(line.observed).toBe(true);
    expect(line.text).toBe("Screening actions, last seen 2m ago");
  });

  it("block mode observed reads as blocking", () => {
    const seen = new Date(NOW - 60_000).toISOString();
    const line = guardrailStatusLine(subject({ guardrail_mode: "block", guardrail_last_observed_at: seen }), NOW);
    expect(line.observed).toBe(true);
    expect(line.text).toMatch(/^Blocking risky actions, last seen/);
  });

  it("a subject with no guardrail fields at all states that, without inventing a state", () => {
    const line = guardrailStatusLine(subject({
      guardrail_mode: null,
      guardrail_configured_at: null,
      guardrail_recorded_activity: null,
      guardrail_last_observed_at: null,
    }), NOW);
    expect(line.observed).toBe(false);
    expect(line.text).toBe("No guardrail recorded for this agent");
  });
});

describe("card identity leads with the human name, not the registry id", () => {
  it("uses the product as the heading and provider plus class as the subtitle", () => {
    expect(agentDisplay(subject())).toEqual({ heading: "OpenClaw", headingIsId: false, subtitle: "openclaw · Coding" });
  });

  it("falls back to the raw id only when no product name exists", () => {
    const display = agentDisplay(subject({ product: null }));
    expect(display.heading).toBe("agent-3f2a9c1d5e8b");
    expect(display.headingIsId).toBe(true);
  });

  it("does not render a lone Unknown class as a subtitle datum", () => {
    expect(agentDisplay(subject({ provider: null, agent_class: "unknown" })).subtitle).toBe("");
  });
});

describe("identity confidence stays honest, quietly", () => {
  it("keeps the not-host-verified truth in the badge tooltip", () => {
    expect(identityTooltip("declared")).toBe(IDENTITY_TOOLTIP);
    expect(identityTooltip("configured")).toBe(IDENTITY_TOOLTIP);
    expect(identityTooltip("conflicting")).toBe(IDENTITY_TOOLTIP);
    expect(identityTooltip("unattributed")).toBe(IDENTITY_TOOLTIP);
  });

  it("drops the tooltip only for a host-verified identity", () => {
    expect(identityTooltip("host_verified")).toBeUndefined();
  });
});

describe("discovery limits are a footnote, not a warning", () => {
  // The producer always bounds discovery, so this text renders on every load
  // forever. A permanent amber banner is the class of copy the redesign
  // removed: the truth stays, as one grey line under the list.
  it("renders as a quiet footnote when discovery is limited", () => {
    const note = discoveryFootnote(true);
    expect(note?.kind).toBe("footnote");
    expect(note?.text).toContain("recorded by the local registry");
  });

  it("renders nothing when discovery is not limited", () => {
    expect(discoveryFootnote(false)).toBeNull();
  });
});

describe("the empty state names the next step", () => {
  it("tells the user the exact command instead of what the system does not infer", () => {
    expect(EMPTY_STATE.title).toBe("No agents connected yet.");
    // Verified against the shipped CLI: `innerwarden agents connect` is the
    // real verb (crates/cli/src/main.rs suggests it verbatim).
    expect(EMPTY_STATE.command).toBe("innerwarden agents connect");
  });
});
