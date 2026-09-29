import { describe, expect, it } from "vitest";
import type { AgentsResponse, TokenIntelligenceResponse } from "../api";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import tokensFixture from "../../tests/fixtures/community/token-intelligence.json";
import { agentRows, agentsSummary, agentState, modeLine, modeWord, nameList } from "./agentsView";
import { communityControls, controlCounts, controlRing } from "./controls";
import { share, tokenRow, tokenRows, tokenTotal } from "./tokensView";

const agents = agentsFixture as unknown as AgentsResponse;
const tokens = tokensFixture as unknown as TokenIntelligenceResponse;

describe("agents as rows", () => {
  it("reads each agent's state from the same fields the technical card reads", () => {
    const rows = agentRows(agents);
    expect(rows.map((row) => [row.id, row.state])).toEqual([
      ["claude-code", "watching"],
      ["codex", "partial"],
      ["cursor", "refusing"],
      ["gemini", "refusing"],
    ]);
    expect(rows.find((row) => row.id === "codex")?.needsYou).toBe(true);
    expect(rows.find((row) => row.id === "claude-code")?.next?.command).toBe("innerwarden enforce");
    expect(rows.find((row) => row.id === "claude-code")?.lastScreenedAt).toBeDefined();
  });

  it("never reports a configured but unseen guardrail as working", () => {
    const agent = { ...agents.agents[0], guardrail: { ...agents.agents[0].guardrail, mode: "configured_not_observed" } };
    expect(agentState(agent)).toBe("unknown");
  });

  it("does not turn leftover files into an agent that needs a person", () => {
    const leftover = { ...agents.agents[2], installed: false, detected_by: ["possible_leftover"], guardrail: { ...agents.agents[2].guardrail, mode: "not_configured" } };
    const [row] = agentRows({ ...agents, agents: [leftover] });
    expect(row.state).toBe("not_connected");
    expect(row.needsYou).toBe(false);
    // Nor into one more agent to connect: "0 of 1 connected" beside
    // "Every agent found is connected" was the page contradicting itself.
    expect(agentsSummary([row]).total).toBe(0);
  });

  it("names an agent whose status is not confirmed rather than calling every agent connected", () => {
    const unseen = { ...agents.agents[2], guardrail: { ...agents.agents[2].guardrail, mode: "configured_not_observed" } };
    const summary = agentsSummary(agentRows({ ...agents, agents: [agents.agents[3], unseen] }));
    expect([summary.total, summary.refusing, summary.unconfirmed.map((row) => row.name)]).toEqual([2, 1, ["Cursor"]]);
  });

  it("counts and words the machine's agents", () => {
    const rows = agentRows(agents);
    const summary = agentsSummary(rows);
    expect([summary.total, summary.refusing, summary.watching, summary.needsYou.length]).toEqual([4, 2, 1, 1]);
    expect(modeWord(rows)).toBe("Mixed modes");
    expect(modeLine(rows)).toBe("Claude Code watches only; Cursor and Gemini CLI refuse.");
    expect(nameList(["A", "B", "C"])).toBe("A, B and C");
  });
});

describe("tokens as bars", () => {
  it("stacks only disjoint counters, and the parts add up to the total", () => {
    const [claude, codex, cursor] = tokenRows(tokens);
    expect(claude.parts.map((part) => part.key)).toEqual(["cache_read", "cache_write", "output", "input"]);
    expect(claude.parts.reduce((sum, part) => sum + part.value, 0n)).toBe(claude.total);
    // Codex's cached input is INSIDE its input: never a segment of its own.
    expect(codex.parts.map((part) => part.key)).toEqual(["input", "output"]);
    expect(codex.lines.find((line) => line.key === "cached")?.within).toBe("inside input");
    expect(cursor.available).toBe(false);
  });

  it("never draws a counter the provider did not report as zero", () => {
    const row = tokenRow({ ...tokens.agents[0], input_tokens: null, parts_disjoint: true } as never);
    expect(row.lines.find((line) => line.key === "input")?.value).toBeNull();
    expect(row.parts).toEqual([]);
  });

  it("keeps counts past what a number holds exact", () => {
    const huge = "90071992547409930";
    const row = tokenRow({ ...tokens.agents[1], total_tokens: huge, input_tokens: huge, output_tokens: "0", parts_disjoint: false } as never);
    expect(row.total).toBe(90071992547409930n);
    expect(tokenTotal([row])?.total).toBe(90071992547409930n);
    expect(share(1n, 4n)).toBeCloseTo(0.25);
    expect(share(1n, 0n)).toBe(0);
  });
});

describe("what Community covers", () => {
  it("counts its controls into the ring, and the ring parts say their counts", () => {
    const controls = communityControls({ agents: agentRows(agents), now: Date.parse("2026-09-29T14:05:00Z") });
    const counts = controlCounts(controls);
    expect(counts.needs).toBe(1);
    const ring = controlRing(counts);
    expect(ring.map((part) => part.key)).toEqual(["refusing", "on", "needs", "off"]);
    expect(ring.find((part) => part.key === "needs")?.tone).toBe("attention");
  });

  it("says who is not behind the guard and who is, and never names one agent as both", () => {
    const controls = communityControls({ agents: agentRows(agents), now: Date.parse("2026-09-29T14:05:00Z") });
    const tools = controls.find((control) => control.key === "tool_call_screening");
    expect(tools?.line).toBe("Cursor and Gemini CLI refuse a deny. Codex is not fully behind the guard.");
  });

  it("counts an agent with no connection at all as needing you, and a leftover configuration not at all", () => {
    const base = agents.agents[0];
    const unwired = { ...base, id: "unwired", display_name: "Unwired", installed: true, guardrail: { ...base.guardrail, mode: "not_configured", mechanism: null } };
    const leftover = { ...unwired, id: "leftover", display_name: "Leftover", installed: false, detected_by: ["configuration_file"] };
    const controls = communityControls({ agents: agentRows({ ...agents, agents: [unwired, leftover] }), now: Date.parse("2026-09-29T14:05:00Z") });
    const hook = controls.find((control) => control.key === "command_screening");
    expect(hook?.state).toBe("needs");
    expect(hook?.line).toBe("Unwired is not fully behind the guard.");
    expect(controls.find((control) => control.key === "tool_call_screening")?.state).toBe("none");
  });

  it("marks Seen working only from a decision in the last day, never assumed", () => {
    const now = Date.parse("2026-09-29T14:05:00Z");
    const rows = agentRows(agents);
    const [hook] = communityControls({ agents: rows, now });
    expect(hook.ladder?.find((step) => step.key === "seen")?.mark).toBe("done");
    const [later] = communityControls({ agents: rows, now: now + 3 * 86_400_000 });
    expect(later.ladder?.find((step) => step.key === "seen")?.mark).toBe("unknown");
    for (const control of communityControls({ agents: rows, now })) {
      for (const step of control.ladder ?? []) expect(step.mark).not.toBe("verified");
    }
  });
});
