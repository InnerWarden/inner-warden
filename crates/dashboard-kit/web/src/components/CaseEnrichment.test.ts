import { describe, expect, it } from "vitest";
import type { CaseEnrichment } from "../api/cases";
import { ENRICHMENT_ORDER, REPORTED_NOT_VERIFIED, enrichmentOrder } from "./CaseEnrichment";

function enrichment(overrides: Partial<CaseEnrichment> = {}): CaseEnrichment {
  return {
    detection: null,
    ai: null,
    agent_activity: null,
    threat_intel: null,
    honeypot: null,
    rules: [],
    mitre: [],
    dns: [],
    ...overrides,
  } as unknown as CaseEnrichment;
}

const detection = { detector: "reverse_shell", kind: "exec", layer: "ebpf", reason: "", recommended_checks: [] };
const intel = { ip: "203.0.113.9", geo: null, abuseipdb_score: null, dshield: false, dna_fingerprint: null, campaign_ids: [] };

/**
 * The operator's dig-in path: what happened, when, what the system did, whether
 * it blocked, and WHERE IT CAME FROM. The last one was the fifth panel down,
 * below the model verdict and the rule chips, so the question "who is doing
 * this to me" was answered after two panels of our own reasoning.
 */
describe("a case answers where it came from before it explains itself", () => {
  it("puts the source above the model verdict and the rules", () => {
    const order = enrichmentOrder(enrichment({
      detection,
      threat_intel: intel,
      ai: { provider: "warden", model_kind: "local_warden", verdict: "deny", risk_score: 90, reason: "" },
      rules: [{ kind: "sigma", id: "r1", name: "Reverse shell" }],
    } as unknown as Partial<CaseEnrichment>));
    expect(order).toEqual(["detection", "threat_intel", "reasoning"]);
    expect(order.indexOf("threat_intel")).toBeLessThan(order.indexOf("reasoning"));
  });

  it("leads with the flagged agent when there is one", () => {
    const order = enrichmentOrder(enrichment({
      detection,
      threat_intel: intel,
      agent_activity: { agent_name: "OpenClaw", command: "curl evil", atr_rule_ids: [], risk_score: 80, recommendation: null, explanation: null },
    } as unknown as Partial<CaseEnrichment>));
    expect(order[0]).toBe("agent_activity");
  });

  it("renders only the blocks a case actually carries", () => {
    expect(enrichmentOrder(enrichment())).toEqual([]);
    expect(enrichmentOrder(enrichment({ dns: [{ domain: "evil.test", action: "block", reason: null }] } as unknown as Partial<CaseEnrichment>))).toEqual(["dns"]);
    expect(enrichmentOrder(enrichment({ mitre: [{ technique_id: "T1059", technique_name: null, tactic: null }] } as unknown as Partial<CaseEnrichment>))).toEqual(["reasoning"]);
  });

  it("never invents an order beyond the one it declares", () => {
    const everything = enrichmentOrder(enrichment({
      detection,
      threat_intel: intel,
      agent_activity: { agent_name: "a", command: null, atr_rule_ids: [], risk_score: null, recommendation: null, explanation: null },
      ai: { provider: "p", model_kind: "llm", verdict: null, risk_score: null, reason: null },
      dns: [{ domain: "d", action: null, reason: null }],
      honeypot: { protocol: "ssh", credentials_seen: 0, commands: [] },
    } as unknown as Partial<CaseEnrichment>));
    expect(everything).toEqual([...ENRICHMENT_ORDER]);
  });
});

describe("the not-verified truth is a footnote, not a status badge", () => {
  // It was a StatusBadge in the section header on every case: a control styled
  // as something to act on, for a standing property of every case there is.
  it("keeps the honesty and points at where the answer is", () => {
    expect(REPORTED_NOT_VERIFIED).toContain("not been independently verified");
    expect(REPORTED_NOT_VERIFIED).toContain("What the system did about it is below");
  });
});
