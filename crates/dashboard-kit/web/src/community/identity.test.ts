import { describe, expect, it } from "vitest";
import type { AgentsResponse } from "../api";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import { agentRows, awaitingApproval, decisionSentence, trustCounts } from "./agentsView";
import { readAgentIdentity, readDecisionIdentity, readHistory, MAX_INSTANCES } from "./api";
import historyFixture from "../../tests/fixtures/community/history.json";
import { agentsOffer, PRICING_URL } from "./offers";
import { OFFER_KEYS } from "./dismiss";
import {
  agentTrustSentence,
  effectiveTrust,
  LAYER_WORDS,
  layerLine,
  LAYERS,
  LAUNCH_MODES,
  LAUNCH_MODE_WORDS,
  REASON_CODES,
  REASON_TRUST,
  REASON_WORDS,
  reasonWords,
  TRUST_WORDS,
  TRUSTS,
  UNKNOWN_REASON_WORDS,
  VERDICTS,
} from "./words";

const ID = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
const agents = agentsFixture as unknown as AgentsResponse;
const instance = (extra: Record<string, unknown> = {}) => ({ instance_id: ID, trust: "host_verified", trust_reason: "confined_by_namespace", live: true, ...extra });

describe("trust never rises above its reason", () => {
  it("shows the reason's trust when a payload claims more", () => {
    expect(effectiveTrust("host_verified", "no_record")).toBe("declared");
    expect(effectiveTrust("host_verified", "launcher_not_trusted")).toBe("observed");
    expect(effectiveTrust("observed", "no_record")).toBe("declared");
    expect(effectiveTrust("host_verified", "confined_by_namespace")).toBe("host_verified");
    // A claim can be lowered by its reason, never raised by it.
    expect(effectiveTrust("declared", "confined_by_namespace")).toBe("declared");
  });

  it("reads a reason it does not know, or none, as declared", () => {
    expect(effectiveTrust("host_verified", "sensor_confirmed")).toBe("declared");
    expect(effectiveTrust("host_verified", "")).toBe("declared");
    expect(effectiveTrust("host_verified", undefined)).toBe("declared");
    expect(reasonWords("sensor_confirmed")).toBe(UNKNOWN_REASON_WORDS);
  });

  it("applies the ceiling to an instance and to a decision as they are read", () => {
    const forged = readAgentIdentity({ id: "x", instances: [instance({ trust_reason: "no_record" })] });
    expect(forged?.instances[0].trust).toBe("declared");
    expect(readDecisionIdentity({ trust: "host_verified", trust_reason: "record_writable" })?.trust).toBe("declared");
  });

  it("does not take an instance whose label names another source as a jail's word", () => {
    const row = readAgentIdentity({ id: "x", instances: [instance({ trust_source: "sensor" })] });
    expect(row?.instances[0].trust).toBe("declared");
  });

  it("has words, a trust and a sentence for every reason code, and every mode, layer and verdict", () => {
    for (const code of REASON_CODES) {
      expect(REASON_WORDS[code].length, code).toBeGreaterThan(10);
      expect(TRUSTS).toContain(REASON_TRUST[code]);
    }
    for (const mode of LAUNCH_MODES) expect(LAUNCH_MODE_WORDS[mode]).toBeTruthy();
    for (const layer of LAYERS) expect(VERDICTS.some((verdict) => (LAYER_WORDS as Record<string, string>)[`${layer}:${verdict}`] !== undefined), layer).toBe(true);
    expect(Object.keys(TRUST_WORDS).sort()).toEqual(["declared:jail", "declared:sensor", "host_verified:jail", "observed:jail"]);
  });

  it("keeps the kit's public words free of the other side's verification and of 'protect'", () => {
    const all = [...Object.values(REASON_WORDS), ...Object.values(LAYER_WORDS), ...Object.values(TRUST_WORDS).flatMap((w) => [w.label, w.tooltip])].join(" ");
    expect(all).not.toMatch(/\bProtect(ed|ing)\b|sensor|kernel/i);
  });
});

describe("the identity fields of an agent row", () => {
  it("reads nothing from the CLI's own agents: no field, no identity", () => {
    expect(agentRows(agents).every((row) => row.who === undefined)).toBe(true);
    for (const agent of agents.agents) expect(readAgentIdentity(agent)).toBeUndefined();
  });

  it("drops an instance whose id is not 32 hex, and caps the list", () => {
    const many = Array.from({ length: 30 }, (_, i) => instance({ instance_id: i.toString(16).padStart(32, "0") }));
    const read = readAgentIdentity({ id: "x", instances: [instance({ instance_id: "../../etc/passwd" }), ...many] });
    expect(read?.instances.length).toBeLessThanOrEqual(MAX_INSTANCES);
    expect(read?.instances.some((i) => i.instanceId.includes("/"))).toBe(false);
  });

  it("takes the worst live trust for the row, with the reason that belongs to it", () => {
    const other = "7a1b2c3d4e5f60718293a4b5c6d7e8f9";
    const read = readAgentIdentity({
      id: "x",
      trust: "host_verified",
      trust_reason: "confined_by_namespace",
      instances: [instance(), instance({ instance_id: other, trust: "observed", trust_reason: "launcher_not_trusted" })],
    });
    expect(read?.trust).toBe("observed");
    expect(read?.trustReason).toBe("launcher_not_trusted");
  });

  it("does not let an ended instance lower or raise the trust of a live one", () => {
    const other = "7a1b2c3d4e5f60718293a4b5c6d7e8f9";
    const read = readAgentIdentity({ id: "x", instances: [instance(), instance({ instance_id: other, trust: "declared", trust_reason: "no_record", live: false })] });
    expect(read?.trust).toBe("host_verified");
  });

  it("counts a live instance by its trust and an active agent without one as declared", () => {
    const rows = agentRows({
      ...agents,
      agents: [
        { ...agents.agents[0], instances: [instance()] },
        { ...agents.agents[1], running: true },
        { ...agents.agents[2], running: false },
      ],
    } as unknown as AgentsResponse);
    expect(trustCounts(rows, Date.parse("2026-10-17T00:00:00Z"))).toEqual({ total: 2, confined: 1, observed: 0, declared: 1 });
  });

  it("counts nothing when no instance exists anywhere", () => {
    expect(trustCounts(agentRows(agents), Date.now())).toBeUndefined();
  });

  it("finds the agents that wait for a person", () => {
    const rows = agentRows({ ...agents, agents: [{ ...agents.agents[0], lifecycle: "discovered" }, { ...agents.agents[1], lifecycle: "approved" }] } as unknown as AgentsResponse);
    expect(awaitingApproval(rows).map((row) => row.id)).toEqual(["claude-code"]);
  });
});

describe("the Overview sentence", () => {
  it("is exact, singular and plural, and leaves out the zero parts", () => {
    expect(agentTrustSentence({ total: 3, confined: 1, observed: 0, declared: 2 }, "this server")).toBe(
      "3 agents on this server. 1 runs confined; 2 run as you, and only their own word says what they are.",
    );
    expect(agentTrustSentence({ total: 1, confined: 0, observed: 0, declared: 1 }, "this Mac")).toBe(
      "1 agent on this Mac. 1 runs as you, and only its own word says what it is.",
    );
    expect(agentTrustSentence({ total: 2, confined: 0, observed: 2, declared: 0 }, "this machine")).toBe(
      "2 agents on this machine. 2 run in a jail whose launcher could be replaced.",
    );
  });
});

describe("the layer that decided", () => {
  it("words each layer and verdict, with the agent's name", () => {
    expect(layerLine("agent_type", "allow", "host_verified", "Claude Code", false)?.text).toBe("Allowed by the Claude Code profile, because this instance runs confined.");
    expect(layerLine("instance", "deny", "host_verified", "Claude Code", false)?.text).toBe("Refused by an exception for this instance.");
    expect(layerLine("general", "allow", "declared", "Claude Code", true)?.text).toContain("The Claude Code profile would allow this, but this instance does not run confined");
    expect(layerLine("hard", "review", "declared", "Claude Code", false)).toBeUndefined();
  });

  it("never words an allowance by confinement for an instance that does not run confined", () => {
    for (const trust of ["declared", "observed"] as const) {
      for (const layer of ["agent_type", "instance"] as const) {
        const line = layerLine(layer, "allow", trust, "Claude Code", false);
        expect(line?.conflict).toBe(true);
        expect(line?.text).not.toContain("runs confined");
      }
    }
  });
});

describe("the Changes list", () => {
  const base = { at: "2026-10-16T10:00:00Z", agent: "claude-code", by: "dev", result: "success" };
  it("says each action in the spec's words", () => {
    expect(decisionSentence({ ...base, action: "allow", rule: "bare_ip_fetch" }, "Claude Code")).toBe("dev allowed bare_ip_fetch for Claude Code (confined instances).");
    expect(decisionSentence({ ...base, action: "allow", rule: "bare_ip_fetch", instanceId: ID }, "Claude Code")).toBe("dev allowed bare_ip_fetch for Claude Code (this instance only).");
    expect(decisionSentence({ ...base, action: "revoke" }, "Claude Code")).toBe("dev revoked Claude Code. Its history stays.");
    expect(decisionSentence({ ...base, action: "revoke", instanceId: ID }, "Claude Code")).toBe("dev revoked instance 3f9a0c1e. Its history stays.");
  });

  it("reads lines from the history, keeps the action's name either way, and drops a malformed one", () => {
    const history = readHistory({
      ...historyFixture,
      agent_decisions: [
        { ts: "2026-10-16T10:00:00Z", action: "agent_revoke", agent: "claude-code", by: "dev", result: "success" },
        { ts: "2026-10-16T10:00:00Z", action: "revoke", agent: "claude-code", by: "dev", result: "success" },
        { ts: "not a time", action: "revoke", agent: "claude-code", by: "dev", result: "success" },
        { ts: "2026-10-16T10:00:00Z", action: "delete_everything", agent: "claude-code", by: "dev", result: "success" },
      ],
    });
    expect(history.agentDecisions?.map((line) => line.action)).toEqual(["revoke", "revoke"]);
  });

  it("leaves the history as it was when the log holds none", () => {
    expect("agentDecisions" in readHistory(historyFixture)).toBe(false);
  });
});

describe("the one Active Defence line", () => {
  it("has its own remembered slot, links to pricing once, and says nothing of this machine", () => {
    const offer = agentsOffer();
    expect(offer).toMatchObject({ slot: "agents", key: "agent_kernel", href: PRICING_URL, body: "Contained agents are checked by the kernel with Active Defence." });
    expect(OFFER_KEYS.agents).toBe("iw-community-offer-v1:agents");
    expect(new Set(Object.values(OFFER_KEYS)).size).toBe(Object.keys(OFFER_KEYS).length);
  });
});
