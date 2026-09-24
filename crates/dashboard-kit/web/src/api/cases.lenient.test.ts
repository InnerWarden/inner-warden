import { describe, expect, it } from "vitest";

import { parseCaseListPage, parseUnifiedCase } from "./cases";
import caseAgentHost from "../../tests/fixtures/enterprise/case-agent-host-001.json";

/**
 * Two blocks of a case are CONTEXT, not the record: who decided an event
 * (`decision_provenance`) and what was wired around the case (`enrichment`).
 * A missing, partial or malformed block must never take the whole case down,
 * so the parser keeps the parts that hold together and drops the rest, and
 * the screen shows "not reported" where something was dropped.
 *
 * The record itself stays strict; the last test here is the contrast.
 */

function withCase(extra: Record<string, unknown>): Record<string, unknown> {
  return { ...JSON.parse(JSON.stringify(caseAgentHost)), ...extra };
}

function withFirstEvent(extra: Record<string, unknown>): Record<string, unknown> {
  const payload = withCase({});
  const timeline = payload.timeline as Record<string, unknown>[];
  timeline[0] = { ...timeline[0], ...extra };
  return payload;
}

describe("who decided an event", () => {
  it("keeps the authorities that hold together and drops the ones that do not", () => {
    const parsed = parseUnifiedCase(withFirstEvent({
      decision_provenance: {
        rule: { kind: "rule", id: "ssh-brute-force", version: "3", inferred: true },
        model: "not an authority",
        kernel: { kind: 1, id: "exec-gate" },
        operator: { kind: "operator", id: "alice", version: 7, inferred: "yes" },
      },
    }));
    expect(parsed.timeline[0].decision_provenance).toEqual({
      rule: { kind: "rule", id: "ssh-brute-force", version: "3", inferred: true },
      model: null,
      policy: null,
      kernel: null,
      // A version or an inference flag of the wrong type is not reported,
      // rather than the whole authority being dropped.
      operator: { kind: "operator", id: "alice", version: null, inferred: null },
      fallback: null,
    });
  });

  it("reads a block with nothing usable in it as no block", () => {
    for (const decision_provenance of [{ rule: "x", model: null }, "junk", 7, null]) {
      const parsed = parseUnifiedCase(withFirstEvent({ decision_provenance }));
      expect(parsed.timeline[0].decision_provenance).toBeNull();
    }
  });

  it("bounds what it keeps", () => {
    const parsed = parseUnifiedCase(withFirstEvent({
      decision_provenance: { policy: { kind: "k".repeat(500), id: "i".repeat(500) } },
    }));
    expect(parsed.timeline[0].decision_provenance?.policy?.kind).toHaveLength(128);
    expect(parsed.timeline[0].decision_provenance?.policy?.id).toHaveLength(256);
  });
});

describe("what was wired around a case", () => {
  it("reads every block the host reported", () => {
    const parsed = parseUnifiedCase(withCase({
      enrichment: {
        detection: { detector: "ssh_bruteforce", kind: "auth", layer: "host", reason: "12 failures", recommended_checks: ["Check sshd", ""] },
        ai: { provider: "local", model_kind: "classifier", verdict: "block", risk_score: 0.9, reason: "pattern" },
        agent_activity: { agent_name: "claude", command: "cat ~/.ssh/id_rsa", atr_rule_ids: ["ATR-1"], risk_score: 80, recommendation: "deny", explanation: "secret read" },
        rules: [{ kind: "sigma", id: "rule-1", name: "SSH" }, { id: "rule-2" }],
        mitre: [{ technique_id: "T1110", technique_name: "Brute Force", tactic: "credential-access" }],
        threat_intel: {
          ip: "203.0.113.9",
          geo: { country: "NL", city: "Amsterdam", lat: 52.37, lon: 4.9, asn: "AS64500", isp: "Example" },
          abuseipdb_score: 97,
          dshield: true,
          dna_fingerprint: "fp-1",
          campaign_ids: ["c-1"],
        },
        honeypot: { session_id: "hp-1", protocol: "ssh", commands: ["uname -a"], credentials_seen: 3 },
        dns: [{ domain: "example.test", action: "blocked", reason: "feed" }],
        reason_code: "ssh.bruteforce",
      },
    }));
    const enrichment = parsed.enrichment;
    expect(enrichment?.detection).toEqual({ detector: "ssh_bruteforce", kind: "auth", layer: "host", reason: "12 failures", recommended_checks: ["Check sshd"] });
    expect(enrichment?.ai?.verdict).toBe("block");
    expect(enrichment?.agent_activity?.atr_rule_ids).toEqual(["ATR-1"]);
    // A rule with no kind is still a rule the host named.
    expect(enrichment?.rules).toEqual([{ kind: "sigma", id: "rule-1", name: "SSH" }, { kind: "rule", id: "rule-2", name: null }]);
    expect(enrichment?.mitre[0].technique_id).toBe("T1110");
    expect(enrichment?.threat_intel?.geo?.city).toBe("Amsterdam");
    expect(enrichment?.threat_intel?.dshield).toBe(true);
    expect(enrichment?.honeypot?.credentials_seen).toBe(3);
    expect(enrichment?.dns).toEqual([{ domain: "example.test", action: "blocked", reason: "feed" }]);
    expect(enrichment?.reason_code).toBe("ssh.bruteforce");
  });

  it("drops each piece that does not hold together, and keeps the case", () => {
    const parsed = parseUnifiedCase(withCase({
      enrichment: {
        detection: { kind: "auth" },
        ai: { verdict: "block" },
        agent_activity: { command: "ls" },
        rules: [{ name: "no id" }, "junk", null],
        mitre: [{ tactic: "no technique" }],
        threat_intel: { geo: null, campaign_ids: [] },
        honeypot: { protocol: "ssh", commands: [] },
        dns: [{ action: "blocked" }],
        reason_code: "",
      },
    }));
    expect(parsed.id).toBe("case-agent-host-001");
    expect(parsed.enrichment).toEqual({
      detection: null,
      ai: null,
      agent_activity: null,
      rules: [],
      mitre: [],
      threat_intel: null,
      honeypot: null,
      dns: [],
      reason_code: null,
    });
  });

  it("reads threat intel from any one thing it names", () => {
    const byScore = parseUnifiedCase(withCase({ enrichment: { threat_intel: { abuseipdb_score: 0 } } }));
    expect(byScore.enrichment?.threat_intel?.abuseipdb_score).toBe(0);
    expect(byScore.enrichment?.threat_intel?.ip).toBeNull();
    const byCampaign = parseUnifiedCase(withCase({ enrichment: { threat_intel: { campaign_ids: ["c-9"] } } }));
    expect(byCampaign.enrichment?.threat_intel?.campaign_ids).toEqual(["c-9"]);
  });

  it("treats a block that is not an object as not reported", () => {
    for (const enrichment of [null, "junk", 3]) {
      expect(parseUnifiedCase(withCase({ enrichment })).enrichment).toBeUndefined();
    }
  });

  it("keeps only what fits in the bounds it reads", () => {
    const parsed = parseUnifiedCase(withCase({
      enrichment: { detection: { detector: "d".repeat(5_000), recommended_checks: Array.from({ length: 100 }, (_, index) => `check ${index}`) } },
    }));
    expect(parsed.enrichment?.detection?.detector).toHaveLength(4_096);
    expect(parsed.enrichment?.detection?.recommended_checks).toHaveLength(64);
  });
});

describe("the record itself stays strict", () => {
  it("refuses a time that is not an RFC 3339 date-time", () => {
    const page = { schema_version: "innerwarden.dashboard.v1", items: [], next_cursor: null };
    for (const generated_at of ["2026-09-24 08:00", "yesterday", "2026-13-45T99:99:99Z"]) {
      expect(() => parseCaseListPage({ ...page, generated_at })).toThrow("cases.generated_at: expected RFC 3339 date-time");
    }
  });
});
