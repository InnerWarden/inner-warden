import { describe, expect, it } from "vitest";
import type { AgentsResponse, TokenIntelligenceResponse } from "../api";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import tokensFixture from "../../tests/fixtures/community/token-intelligence.json";
import { agentRows, agentsSummary, agentState, modeLine, modeWord, nameList } from "./agentsView";
import { communityControls, controlCounts, controlRing } from "./controls";
import { share, tokenRow, tokenRows, tokenTotal } from "./tokensView";
import historyFixture from "../../tests/fixtures/community/history.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import { readHistory, readProtection, type Protection } from "./api";
import { footerItems, recordSourceLine, refusalSums, shortDay } from "./Overview";

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

  it("marks a capped scan as a sample, and only that", () => {
    const covered = { complete: true, files_read: 9, files_found: 9 };
    expect(tokenRow({ ...tokens.agents[0], coverage: covered }).sample).toBeUndefined();
    expect(tokenRow({ ...tokens.agents[0] }).sample).toBeUndefined();
    const cut = tokenRow({ ...tokens.agents[0], coverage: { complete: false, files_read: 4, files_found: 9 } });
    expect(cut.sample).toBe("A sample, not the total: the newest 4 of 9 history files.");
    const uncounted = tokenRow({ ...tokens.agents[0], coverage: { complete: false, files_read: 9, files_found: 9 } });
    expect(uncounted.sample).toContain("could not be counted");
    expect(tokenTotal([cut, tokenRow(tokens.agents[1])])?.sample).toBe(true);
    expect(tokenTotal([tokenRow(tokens.agents[1])])?.sample).toBe(false);
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

describe("the Overview's counts and lines", () => {
  const history = readHistory(historyFixture);
  const protection = readProtection(protectionFixture);

  it("sums the last 7 UTC days of the guard's log, and keeps today apart as so far", () => {
    const sums = refusalSums(history.refusals.days ?? []);
    expect([sums.blocked, sums.wouldBlock]).toEqual([0, 17]);
    expect(sums.today).toMatchObject({ date: "2026-09-29", blocked: 0, wouldBlock: 2, partial: true });
    // A last day that is whole is not "today so far".
    expect(refusalSums([{ date: "2026-09-28", blocked: 1, wouldBlock: 0, partial: false }]).today).toBeUndefined();
    // No day is no count, never a made-up one.
    expect(refusalSums([])).toEqual({ blocked: 0, wouldBlock: 0 });
  });

  it("says the record's source and span in one line, and the day the log starts in short words", () => {
    const now = Date.parse("2026-09-29T14:05:00Z");
    expect(recordSourceLine({ decisions: 96, flagged: 30, checked: 1, oldestAt: "2026-09-25T17:34:00Z", newestAt: "2026-09-29T14:03:00Z" }, now))
      .toBe("From the decision record: newest 96 decisions, about 4 days.");
    expect(recordSourceLine({ decisions: 1, flagged: 0, checked: 0, oldestAt: "2026-09-29T13:47:00Z" }, now))
      .toBe("From the decision record: newest 1 decision, about 18 minutes.");
    expect(recordSourceLine({ decisions: 5, flagged: 0, checked: 0 }, now)).toBe("From the decision record: newest 5 decisions.");
    expect(shortDay("2026-07-30T00:00:00Z")).toBe("30 Jul");
    expect(shortDay("not a time")).toBeUndefined();
  });

  it("says each control in the footer from what was read, and never guesses what was not", () => {
    const words = (items: ReturnType<typeof footerItems>) => items.map((item) => item.words);
    expect(words(footerItems(undefined, undefined, undefined))).toEqual([
      "Record: not read.",
      "Alerts: not read.",
      "AI Jail: not read.",
      "Second opinion: not read.",
      "Tokens",
    ]);
    const jail = (checksPass: boolean | undefined, available = true): Protection => ({
      ...protection,
      jail: { ...protection.jail, available, ...(checksPass === undefined ? { checksPass: undefined } : { checksPass }) },
    });
    const jailWords = (value: Protection) => footerItems({ recording: true }, value, history).find((item) => item.key === "jail")?.words;
    expect(jailWords(jail(true))).toBe("AI Jail: ready.");
    expect(jailWords(jail(false))).toBe("AI Jail: needs you.");
    // Ready only when the checks passed: not checked is never ready.
    expect(jailWords(jail(undefined))).toBe("AI Jail: not checked here yet.");
    expect(jailWords(jail(true, false))).toBe("AI Jail: not available.");
    const alerts = (channels: number) => footerItems(undefined, { ...protection, alerts: { channels } }, history).find((item) => item.key === "alerts")?.words;
    expect([alerts(0), alerts(1), alerts(3)]).toEqual(["Alerts: off.", "Alerts: 1 channel.", "Alerts: 3 channels."]);
    expect(footerItems({ recording: false }, protection, history)[0].words).toBe("Record: not recording.");
  });

  it("lists messages only where they can be or were recorded", () => {
    const keys = (value: Protection, recorded: number) =>
      footerItems(undefined, value, { ...history, messages: { ...history.messages, recorded } }).map((item) => item.key);
    const off = { ...protection, observe: { installed: false, available: false } };
    expect(keys(off, 0)).not.toContain("messages");
    expect(keys(off, 2)).toContain("messages");
    expect(keys({ ...protection, observe: { installed: false, available: true } }, 0)).toContain("messages");
  });
});
