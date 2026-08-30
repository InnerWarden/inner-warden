import { describe, expect, it } from "vitest";
import {
  automaticSetupLabel,
  configuredIntentLabel,
  formatDate,
  formatUnobservedAge,
  guardrailIsConfiguredButUnobserved,
  guardrailIsProtecting,
  guardrailTone,
  guardrailView,
  lastObservedLabel,
  recordedActivityLabel,
} from "./MachineIntelligence";
import type { AgentGuardrail, LocalAgent } from "../api";

const DAY = 86_400;

/// The card formats dates in the VIEWER's locale, so a test that hard-codes
/// "19 Jul 2026" passes in London and fails in CI. The structure around the date
/// is what these tests are actually asserting, so the day itself is rendered the
/// same way the component renders it.
const day = (iso: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso));
const CONFIGURED_DAY = day("2026-07-19T12:00:00Z");

function guardrail(over: Partial<AgentGuardrail> = {}): AgentGuardrail {
  return { mode: "unknown", mechanism: null, setup_support: "unsupported", ...over };
}

/// The payload the producer actually sends for the state this file is about: a
/// policy row written once, sixteen days ago, that nothing has ever gone
/// through.
function silentForSixteenDays(over: Partial<AgentGuardrail> = {}): AgentGuardrail {
  return guardrail({
    mode: "configured_not_observed",
    mechanism: "agent_guard_registry_policy_row",
    configured_mode: "monitor",
    observation: "never_observed",
    recorded_activity: 0,
    configured_at: "2026-07-19T12:00:00Z",
    last_observed_at: null,
    unobserved_for_seconds: 16 * DAY,
    summary:
      "Configured 2026-07-19; not observed since 2026-07-19 (16 days), and the registry row "
      + "records zero activity. A policy row is intent, not a running guardrail.",
    ...over,
  });
}

function agentWith(over: Partial<AgentGuardrail>, eligible: boolean | null = null): LocalAgent {
  return {
    id: "ag-1",
    display_name: "OpenClaw",
    installed: true,
    running: null,
    detected_by: [],
    auto_connect_eligible: eligible,
    guardrail: guardrail(over),
  };
}

/// The words that would be a lie on a card for an agent nothing has been seen
/// going through. The card may not contain any of them anywhere.
const ASSURANCES = ["Already configured", "Protected", "protected", "Active", "Healthy"];

describe("a configured but unobserved guardrail is never rendered as protection", () => {
  // THE CASE THIS FILE EXISTS FOR.
  //
  // The producer ships an honest payload: `configured_not_observed`, a
  // configured date, an age, zero recorded activity and a sentence. The card
  // rendered none of it -- the unknown mode fell through `humanise` to the words
  // "Configured not observed" beside "Eligibility unavailable", with no date and
  // no age. Honest and useless.
  //
  // FAILS ON REVERT: drop `configured_not_observed` out of the unobserved test
  // (or let a positive mode through without checking `observation`) and the view
  // reports `protecting`, the tone goes blue and "Already configured" comes
  // back.
  it("does not claim protection, in any of the words a card can use", () => {
    const view = guardrailView(silentForSixteenDays());
    const agent = agentWith(silentForSixteenDays());
    const surface = [
      view.label,
      view.tone,
      view.intent ?? "",
      view.lastObserved ?? "",
      view.recordedActivity ?? "",
      view.notice ?? "",
      automaticSetupLabel(agent),
    ].join(" | ");

    expect(view.protecting).toBe(false);
    expect(view.unobserved).toBe(true);
    for (const claim of ASSURANCES) {
      expect(surface).not.toContain(claim);
    }
    // Colour is a claim too: the healthy tone is reserved for a guardrail that
    // has been seen working.
    expect(view.tone).not.toContain("blue");
    expect(view.tone).not.toContain("emerald");
    expect(view.tone).not.toContain("green");
  });

  it("reads as configured, not observed since a date, with an age", () => {
    const view = guardrailView(silentForSixteenDays());
    expect(view.label).toBe("Configured, not observed");
    expect(view.notice).toContain("not observed since");
    expect(view.notice).toContain("16 days");
    expect(view.lastObserved).toBe(`Never, 16 days since ${CONFIGURED_DAY}`);
    expect(view.recordedActivity).toBe("None recorded");
    expect(view.intent).toBe("Policy row records monitor");
    // PLAIN by default, and the distinction survives: it still does not say
    // "Already configured", which is the assurance this veto exists to withhold.
    expect(automaticSetupLabel(agentWith(silentForSixteenDays()))).toBe("Set up, waiting for first use");
    expect(automaticSetupLabel(agentWith(silentForSixteenDays()), true)).toBe("Configured, not verified");
    expect(automaticSetupLabel(agentWith(silentForSixteenDays()))).not.toBe("Already configured");
  });

  // The mode is one field. A producer that downgraded it in one code path and
  // forgot another would ship a positive mode next to evidence that flatly
  // contradicts it, and the card must still refuse the assurance.
  it("lets the live half veto a positive mode", () => {
    const contradicted = silentForSixteenDays({ mode: "monitor" });
    expect(guardrailIsProtecting(contradicted)).toBe(false);
    expect(guardrailIsConfiguredButUnobserved(contradicted)).toBe(true);
    expect(guardrailView(contradicted).label).toBe("Configured, not observed");
    expect(automaticSetupLabel(agentWith(contradicted))).toBe("Set up, waiting for first use");
    expect(automaticSetupLabel(agentWith(contradicted), true)).toBe("Configured, not verified");
  });

  it("still says it plainly when the producer sent no prose", () => {
    // Everything except `summary`, which older producers do not send.
    const view = guardrailView(silentForSixteenDays({ summary: undefined }));
    expect(view.notice).toBe(
      `Configured, not observed since ${CONFIGURED_DAY} (16 days). A policy row is intent, not a running guardrail.`,
    );
  });

  it("degrades to a sentence when only the mode arrives", () => {
    // The minimum a producer can send and still mean this state.
    const view = guardrailView(guardrail({ mode: "configured_not_observed" }));
    expect(view.unobserved).toBe(true);
    expect(view.protecting).toBe(false);
    expect(view.notice).toBe(
      "Configured, not observed, and no observation has been recorded. A policy row is intent, not a running guardrail.",
    );
    // Nothing is invented from the fields that did not arrive.
    expect(view.lastObserved).toBeUndefined();
    expect(view.recordedActivity).toBeUndefined();
    expect(view.intent).toBeUndefined();
  });
});

describe("the original contract still renders exactly as it did", () => {
  // The free product serves this endpoint too and sends only mode, mechanism
  // and setup_support. Silence is not evidence of anything, so a payload with no
  // live half must not be dragged into the unobserved state.
  it("treats an absent live half as nothing said, not as not observed", () => {
    for (const mode of ["monitor", "enforce", "mixed"]) {
      const bare = guardrail({ mode, setup_support: "automatic" });
      expect(guardrailIsConfiguredButUnobserved(bare)).toBe(false);
      expect(guardrailIsProtecting(bare)).toBe(true);
      expect(guardrailView(bare).label).toBe(mode[0].toUpperCase() + mode.slice(1));
      expect(guardrailView(bare).notice).toBeUndefined();
      expect(guardrailView(bare).lastObserved).toBeUndefined();
      expect(automaticSetupLabel(agentWith({ mode }))).toBe("Already configured");
    }
  });

  it("keeps the neutral states neutral", () => {
    expect(guardrailView(guardrail({ mode: "not_configured" })).label).toBe("Not configured");
    expect(guardrailView(guardrail({ mode: "unknown" })).label).toBe("Unknown");
    expect(guardrailTone(guardrail({ mode: "not_configured" }))).toBe("text-slate-700");
    expect(guardrailTone(guardrail({ mode: "partial" }))).toBe("text-amber-700");
    expect(guardrailTone(guardrail({ mode: "enforce" }))).toBe("text-blue-700");
  });
});

describe("an observed guardrail is allowed to say so", () => {
  it("keeps the positive rendering and dates the observation", () => {
    const live = guardrail({
      mode: "enforce",
      configured_mode: "enforce",
      observation: "observed",
      recorded_activity: 412,
      configured_at: "2026-07-19T12:00:00Z",
      last_observed_at: "2026-08-04T12:00:00Z",
      unobserved_for_seconds: 3 * 3_600,
      summary: "Configured 2026-07-19; guardrail activity observed 3 hours ago.",
    });
    const view = guardrailView(live);
    expect(view.protecting).toBe(true);
    expect(view.unobserved).toBe(false);
    expect(view.label).toBe("Enforce");
    expect(view.tone).toBe("text-blue-700");
    expect(view.notice).toBeUndefined();
    expect(view.lastObserved).toBe(`${day("2026-08-04T12:00:00Z")} (3 hours ago)`);
    expect(view.recordedActivity).toBe("412 recorded, undated");
    expect(automaticSetupLabel(agentWith(live))).toBe("Already configured");
  });
});

describe("reading fields that may be missing or malformed", () => {
  it("says nothing rather than guessing a date", () => {
    expect(formatDate(null)).toBeUndefined();
    expect(formatDate(undefined)).toBeUndefined();
    expect(formatDate("  ")).toBeUndefined();
    expect(formatDate("not a date")).toBeUndefined();
    expect(formatDate("2026-07-19T12:00:00Z")).toBe(CONFIGURED_DAY);
    // Unparseable by this runtime, but the calendar day is still readable and is
    // better than dropping the fact on the floor.
    expect(formatDate("2026-07-19 not-a-time")).toBe("2026-07-19");
  });

  it("reports an age at the order of magnitude that matters", () => {
    expect(formatUnobservedAge(null)).toBeUndefined();
    expect(formatUnobservedAge(Number.NaN)).toBeUndefined();
    expect(formatUnobservedAge(-5)).toBe("less than a minute");
    expect(formatUnobservedAge(30)).toBe("less than a minute");
    expect(formatUnobservedAge(600)).toBe("10 minutes");
    expect(formatUnobservedAge(7_200)).toBe("2 hours");
    // Under two days the hour count is the more useful number, which is also
    // where the producer's own wording switches over.
    expect(formatUnobservedAge(DAY)).toBe("24 hours");
    expect(formatUnobservedAge(2 * DAY)).toBe("2 days");
    expect(formatUnobservedAge(16 * DAY)).toBe("16 days");
  });

  it("prints a zero counter instead of hiding it", () => {
    expect(recordedActivityLabel(guardrail({ recorded_activity: 0 }))).toBe("None recorded");
    expect(recordedActivityLabel(guardrail({ recorded_activity: null }))).toBeUndefined();
    expect(recordedActivityLabel(guardrail({}))).toBeUndefined();
  });

  it("does not repeat the verdict back as the intent", () => {
    expect(configuredIntentLabel(guardrail({ mode: "monitor", configured_mode: "monitor" }))).toBeUndefined();
    expect(configuredIntentLabel(guardrail({ mode: "configured_not_observed", configured_mode: "enforce" })))
      .toBe("Policy row records enforce");
  });

  it("distinguishes never observed from not observed lately from not told", () => {
    expect(lastObservedLabel(guardrail({ observation: "never_observed" }))).toBe("Never");
    expect(lastObservedLabel(guardrail({ observation: "unknown" }))).toBe("Not recorded");
    expect(lastObservedLabel(guardrail({ observation: "not_observed_recently", unobserved_for_seconds: 2 * DAY })))
      .toBe("Not recorded (2 days since configuration)");
    expect(lastObservedLabel(guardrail({}))).toBeUndefined();
  });
});
