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
  HOST_LAYER_WORDS,
  HOST_WITHHELD_WORDS,
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
  trustWord,
  TRUSTS,
  UNKNOWN_REASON_WORDS,
  USERNS_OPEN_CODES,
  USERNS_OPEN_WORDS,
  VERDICTS,
  WITHHELD_WORDS,
  withheldWords,
} from "./words";

const ID = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
const agents = agentsFixture as unknown as AgentsResponse;
const instance = (extra: Record<string, unknown> = {}) => ({ instance_id: ID, trust: "host_verified", trust_reason: "confined_by_namespace", live: true, ...extra });

describe("trust never rises above its reason", () => {
  it("shows the reason's trust when a payload claims more", () => {
    expect(effectiveTrust("host_verified", "no_record")).toBe("declared");
    expect(effectiveTrust("host_verified", "launcher_not_trusted")).toBe("observed");
    expect(effectiveTrust("observed", "no_record")).toBe("declared");
    // A reading from inside the jail tops at observed, whatever it found.
    expect(effectiveTrust("host_verified", "confined_by_namespace")).toBe("observed");
    for (const code of REASON_CODES) expect(REASON_TRUST[code], code).not.toBe("host_verified");
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

  it("reads a label from the host at the reason's ceiling, never as host verified", () => {
    const row = readAgentIdentity({ id: "x", instances: [instance({ trust_source: "host", trust_reason: "host_decided" })] });
    expect(row?.instances[0]).toMatchObject({ trust: "observed", trustReason: "host_decided", trustSource: "host" });
    expect(REASON_TRUST.host_decided).toBe("observed");
    expect(reasonWords("host_decided")).toBe("Active Defence on this host decided its rules.");
    expect(trustWord("observed", "host")).toEqual({
      label: "Observed",
      tooltip: "Read from inside the jail; Active Defence on this host decided its rules.",
      tone: "watch",
    });
    // A pair with no words of its own reads as the jail's.
    expect(trustWord("declared", "host")).toEqual(TRUST_WORDS["declared:jail"]);
    const decision = readDecisionIdentity({
      trust: "host_verified",
      trust_reason: "host_decided",
      trust_source: "host",
      host_decision: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
      host_withheld: "a_word_never_heard",
    });
    expect(decision).toMatchObject({ trust: "observed", trustSource: "host", hostDecision: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", hostWithheld: "a_word_never_heard" });
    const odd = readDecisionIdentity({ trust: "observed", trust_reason: "x", trust_source: "kernel", host_decision: "ABC", host_withheld: "Kept, because" });
    expect(odd?.trustSource).toBeUndefined();
    expect(odd?.hostDecision).toBeUndefined();
    expect(odd?.hostWithheld).toBeUndefined();
  });

  it("has words, a trust and a sentence for every reason code, and every mode, layer and verdict", () => {
    for (const code of REASON_CODES) {
      expect(REASON_WORDS[code].length, code).toBeGreaterThan(10);
      expect(TRUSTS).toContain(REASON_TRUST[code]);
    }
    for (const mode of LAUNCH_MODES) expect(LAUNCH_MODE_WORDS[mode]).toBeTruthy();
    for (const layer of LAYERS) expect(VERDICTS.some((verdict) => (LAYER_WORDS as Record<string, string>)[`${layer}:${verdict}`] !== undefined), layer).toBe(true);
    expect(Object.keys(TRUST_WORDS).sort()).toEqual(["declared:jail", "declared:sensor", "host_verified:jail", "observed:host", "observed:jail"]);
  });

  it("keeps the kit's public words free of the other side's verification and of 'protect'", () => {
    const all = [
      ...Object.values(REASON_WORDS),
      ...Object.values(LAYER_WORDS),
      ...Object.values(HOST_LAYER_WORDS),
      ...Object.values(WITHHELD_WORDS),
      HOST_WITHHELD_WORDS,
      ...Object.values(TRUST_WORDS).flatMap((w) => [w.label, w.tooltip]),
    ].join(" ");
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
      instances: [instance(), instance({ instance_id: other, trust: "declared", trust_reason: "no_record" })],
    });
    expect(read?.trust).toBe("declared");
    expect(read?.trustReason).toBe("no_record");
  });

  it("does not let an ended instance lower or raise the trust of a live one", () => {
    const other = "7a1b2c3d4e5f60718293a4b5c6d7e8f9";
    const read = readAgentIdentity({ id: "x", instances: [instance(), instance({ instance_id: other, trust: "declared", trust_reason: "no_record", live: false })] });
    expect(read?.trust).toBe("observed");
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
    expect(trustCounts(rows, Date.parse("2026-10-17T00:00:00Z"))).toEqual({ total: 2, confined: 0, observed: 1, declared: 1 });
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
      "2 agents on this machine. 2 run in a jail nothing outside it has confirmed.",
    );
  });
});

describe("the layer that decided", () => {
  it("words each layer and verdict, with the agent's name", () => {
    expect(layerLine("agent_type", "allow", "host_verified", "Claude Code")?.text).toBe("Allowed by the Claude Code profile, because this instance runs confined.");
    expect(layerLine("instance", "deny", "host_verified", "Claude Code")?.text).toBe("Refused by an exception for this instance.");
    expect(layerLine("general", "review", "observed", "Claude Code")?.text).toBe("Sent for review by your general rules.");
    expect(layerLine("hard", "review", "declared", "Claude Code")).toBeUndefined();
  });

  it("words a profile's allowance the host decided neutrally, as what was recorded", () => {
    expect(layerLine("agent_type", "allow", "observed", "Claude Code", true)).toEqual({
      text: "Allowed by the Claude Code profile, decided by Active Defence on this host.",
      conflict: false,
    });
    expect(layerLine("instance", "allow", "observed", "Claude Code", true)?.text).toBe(
      "Allowed by an exception for this instance, decided by Active Defence on this host.",
    );
    expect(layerLine("agent_type", "deny", "observed", "Claude Code", true)?.text).toBe("Refused by the Claude Code profile.");
  });

  it("chooses why a relaxation did not apply when the page renders", () => {
    expect(withheldWords("linux", false, false)).toBe(
      "Per-agent relaxations apply on Linux with Active Defence, for an agent started with innerwarden contain --identity.",
    );
    expect(withheldWords("linux", true, false)).toBe("Active Defence on this host did not decide this command, so your general rules decided.");
    expect(withheldWords("macos", false, false)).toBe(
      "Per-agent relaxations do not apply on macOS: a jail there has no boundary a witness outside it can check.",
    );
    expect(withheldWords("macos", true, false)).toBe(WITHHELD_WORDS.macos);
    for (const os of ["linux", "macos", "windows", "other"] as const) {
      expect(withheldWords(os, true, true)).toBe("Active Defence on this host kept your general rules for this command.");
    }
    expect(withheldWords("windows", false, false)).toBe(WITHHELD_WORDS.linux);
  });

  it("never words an allowance by confinement for an instance that does not run confined", () => {
    for (const trust of ["declared", "observed"] as const) {
      for (const layer of ["agent_type", "instance"] as const) {
        const line = layerLine(layer, "allow", trust, "Claude Code");
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

describe("the CLI's identity fixtures read as written", () => {
  it("reads every row and instance the CLI serves, and every hook reason has words", async () => {
    const identityAgents = (await import("../../tests/fixtures/community/agents-identity.json")).default as unknown as AgentsResponse;
    const rows = agentRows(identityAgents);
    const claude = rows.find((row) => row.id === "claude-code");
    expect(claude?.who?.trust).toBe("observed");
    expect(claude?.who?.confine?.command).toBe("sudo npm install -g innerwarden");
    // The ended instance's label in the graph says confined: it is served,
    // and read, at observed.
    expect(claude?.who?.instances.map((i) => i.trust)).toEqual(["observed", "observed", "observed"]);
    expect(JSON.stringify(identityAgents)).not.toContain("host_verified");
    expect(claude?.who?.owner).toBe("maria");
    expect(claude?.who?.lifecycleBy).toBe("dev");
    const codex = rows.find((row) => row.id === "codex");
    expect(codex?.who?.instances[0]?.trustReason).toBe("not_checked_yet");
    expect(rows.find((row) => row.id === "cursor")?.who?.trustReason).toBe("no_instance");
    for (const code of ["no_scope", "own_mount_namespace_unreadable", "mount_namespace_mismatch", "agent_mismatch", "agent_not_named"]) {
      expect(reasonWords(code)).not.toBe(UNKNOWN_REASON_WORDS);
    }
    expect(effectiveTrust("host_verified", "no_scope")).toBe("observed");
  });

  it("reads the decisions and the changes the CLI serves", async () => {
    const served = (await import("../../tests/fixtures/community/history-identity.json")).default;
    const history = readHistory(served);
    expect(history.agentDecisions?.map((line) => line.action)).toEqual(["allow", "approve"]);
    expect(history.agentDecisions?.[0]?.rule).toBe("bare_ip_fetch");
    // The rule is `{ kind, value }` on the wire; a bare string or an unknown
    // kind names no rule.
    const line = { ts: "2026-10-16T09:00:00Z", action: "agent_allow", agent: "claude-code", by: "dev", result: "success" };
    const ruleOf = (rule: unknown) => readHistory({ ...served, agent_decisions: [{ ...line, rule }] }).agentDecisions?.[0]?.rule;
    expect(ruleOf({ kind: "mcp_tool", value: "save" })).toBe("save");
    expect(ruleOf("bare_ip_fetch")).toBeUndefined();
    expect(ruleOf({ kind: "shell", value: "rm" })).toBeUndefined();
    const byId = (await import("../../tests/fixtures/community/decisions-identity-by-id.json")).default as Record<string, { item: { identity?: unknown } }>;
    const withheld = readDecisionIdentity(byId["cmd:contain:2"]?.item.identity);
    expect(withheld).toMatchObject({ trust: "observed", layer: "general", relaxationWithheld: true, profile: "claude-code" });
  });

  it("says an unusable profiles file and nothing without one", async () => {
    const { readProfilesFile } = await import("./api");
    expect(readProfilesFile(agents)).toBeUndefined();
    expect(readProfilesFile({ ...agents, profiles_file: { state: "invalid", sentence: "The agent profiles file cannot be used (x)." } })).toEqual({
      sentence: "The agent profiles file cannot be used (x).",
    });
    expect(readProfilesFile({ ...agents, profiles_file: { state: "valid", sentence: "x" } })).toBeUndefined();
  });
});

describe("user namespaces inside the jail are a fact, not a reason", () => {
  it("none of their words is a reason code, and every code has its sentence", () => {
    for (const code of USERNS_OPEN_CODES) {
      expect((REASON_CODES as readonly string[]).includes(code), code).toBe(false);
      expect(USERNS_OPEN_WORDS[code].length, code).toBeGreaterThan(20);
      expect(effectiveTrust("host_verified", code), code).toBe("declared");
    }
  });

  it("is read only as a closed jail or a known reason, and moves no trust", () => {
    const read = (technical: Record<string, unknown>) => readAgentIdentity({ instances: [instance({ technical })] });
    const first = (r: ReturnType<typeof read>) => r?.instances[0];
    expect(first(read({ userns_closed: true }))?.technical.usernsClosed).toBe(true);
    expect(first(read({ userns_closed: "true" }))?.technical.usernsClosed).toBeUndefined();
    expect(first(read({ userns_open_reason: "bwrap_setuid" }))?.technical.usernsOpenReason).toBe("bwrap_setuid");
    expect(first(read({ userns_open_reason: "confined" }))?.technical.usernsOpenReason).toBeUndefined();
    expect(first(read({ userns_closed: true }))?.trust).toBe(first(read({}))?.trust);
  });
});
