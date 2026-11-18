import { describe, expect, it } from "vitest";
import type { AgentsResponse, TokenIntelligenceResponse } from "../api";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import tokensFixture from "../../tests/fixtures/community/token-intelligence.json";
import { agentGroups, agentRows, agentState, autoSetupLine, factsOf, nameList, programWords, restartPrompt, runningWords } from "./agentsView";
import { mcpLines, screeningRows, screeningSummary } from "./controls";
import { noCountWords, qualityWords, tokenScales, tokenView, tokenViews, tokenWords } from "./tokensView";
import { share } from "./ui/charts";
import historyFixture from "../../tests/fixtures/community/history.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import { readAgentsFacts, readHistory, readProtection, type Protection } from "./api";
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
    expect(nameList(["A", "B", "C"])).toBe("A, B and C");
  });
});

describe("the Agents page", () => {
  const facts = readAgentsFacts(agentsFixture);
  const now = Date.parse("2026-09-29T14:05:00Z");
  const byId = Object.fromEntries(facts.agents.map((agent) => [agent.id, agent]));

  it("puts each agent in one group: connected, found here, or only the jail's walls", () => {
    const base = agents.agents[0];
    const found = { ...base, id: "found", display_name: "Found", guardrail: { ...base.guardrail, mode: "not_configured", mechanism: null } };
    const jailOnly = { ...found, id: "jail-only", display_name: "Jail only", guardrail: { ...found.guardrail, setup_support: "unsupported" } };
    const groups = agentGroups(readAgentsFacts({ ...agents, agents: [...agents.agents, found, jailOnly] }).agents);
    expect(groups.connected.map((agent) => agent.id)).toEqual(["claude-code", "codex", "cursor", "gemini"]);
    expect(groups.found.map((agent) => agent.id)).toEqual(["found"]);
    expect(groups.jailOnly.map((agent) => agent.id)).toEqual(["jail-only"]);
  });

  it("says automatic setup as the CLI read it, and nothing when it did not say", () => {
    expect(autoSetupLine(facts.autoConnect)).toBe("Automatic setup is on: a new agent joins in monitor, checked every 60 s.");
    expect(autoSetupLine({ enabled: false })).toBe("Automatic setup is off.");
    expect(autoSetupLine(undefined)).toBeUndefined();
  });

  /** FAILS ON REVERT: without the seen rule, a prompt said nothing came through for an agent that was screened. */
  it("asks for a restart only where the settings changed and nothing came through since", () => {
    expect(restartPrompt(byId["claude-code"], facts.unnamed, now)).toBeUndefined();
    expect(restartPrompt(byId.gemini, facts.unnamed, now)).toMatch(/^Its settings changed on 27 Sept at \d\d:\d\d and nothing has come through since\.$/);
    // A screening that names nobody could be this agent's: no prompt.
    expect(restartPrompt(byId.gemini, { mcp: "2026-09-29T13:00:00Z" }, now)).toBeUndefined();
    // Not connected, or no change time: no prompt.
    expect(restartPrompt({ ...byId.gemini, mode: "not_configured" }, facts.unnamed, now)).toBeUndefined();
    expect(restartPrompt({ ...byId.gemini, configChangedAt: undefined }, facts.unnamed, now)).toBeUndefined();
  });

  it("says a running state it did not read as not read, never as not running", () => {
    expect(runningWords(null, "macos")).toBe("Running: not read on macOS");
    expect(runningWords(null, "other")).toBe("Running: not read on this platform");
    expect(runningWords(false, "linux")).toBe("Running: no");
    expect(programWords({ installed: false, detectedBy: ["configuration_file"] })).toBe("Program on PATH: not found (its configuration file was found)");
    expect(programWords({ installed: true, detectedBy: [] })).toBe("Program on PATH: found");
  });

  it("reads an answer still loading as pending, and one it cannot read as failed, never as no agent", () => {
    expect(factsOf(undefined)).toEqual({ unreadable: false, loading: false });
    expect(factsOf({ availability: "loading", agents: [] }).loading).toBe(true);
    expect(factsOf({ nonsense: true }).unreadable).toBe(true);
    expect(factsOf(agentsFixture).facts?.agents).toHaveLength(4);
  });
});

describe("tokens", () => {
  it("leaves cache reads out of the headline where the counters are disjoint, and says them apart", () => {
    const [claude] = tokenViews(tokens);
    // 6,312 input + 2,606,929 output + 38,308,385 written to cache.
    expect(claude.headline).toEqual({ value: 40_921_626n, words: "tokens, not counting cache reads" });
    expect(claude.cacheReads).toBe(1_271_432_724n);
    expect(claude.parts.map((part) => part.key)).toEqual(["input", "output", "cache_write"]);
    expect(tokenWords(claude.cacheReads!)).toBe("1.3 billion");
  });

  /**
   * FAILS ON REVERT: stack Codex's parts and its cached input is counted
   * twice. Its cached input is inside its input, so the headline leaves it
   * out, on the same basis as Claude Code's ("not counting cache reads"),
   * and says it apart: never 25 times another agent's for the cache alone.
   */
  it("never stacks counters that overlap, and puts the headline on one basis: cache reads said apart", () => {
    const codex = tokenViews(tokens)[1];
    const input = BigInt(tokens.agents[1].input_tokens!);
    const output = BigInt(tokens.agents[1].output_tokens!);
    const cached = BigInt(tokens.agents[1].cached_input_tokens!);
    expect(codex.disjoint).toBe(false);
    expect(codex.parts).toEqual([]);
    expect(codex.headline).toEqual({ value: input - cached + output, words: "tokens, not counting cache reads" });
    expect(codex.cacheReads).toBe(cached);
    expect(codex.lines).toEqual(["1.0 billion input, of which 959 million cached", "2.9 million output, of which 844,960 reasoning"]);
    // Without a cached count there is nothing to leave out: the total as sent.
    const plain = tokenView({ ...tokens.agents[1], cached_input_tokens: null } as never);
    expect(plain.headline).toEqual({ value: 1_004_385_989n, words: "tokens in all" });
  });

  it("says a source that does not exist, never a zero", () => {
    const cursor = tokenViews(tokens)[2];
    expect(cursor.status).toBe("no_source");
    expect(cursor.headline).toBeUndefined();
    expect(noCountWords(cursor)).toBe("No local source for Cursor's tokens.");
    expect(cursor.provenance.words).toBe("No local source");
    expect(qualityWords("sample")).toBe("A sample");
    expect(qualityWords("partial")).toBe("Partial");
  });

  it("never draws a counter the provider did not report as zero", () => {
    const view = tokenView({ ...tokens.agents[0], cache_creation_input_tokens: null, parts_disjoint: true } as never);
    expect(view.parts.map((part) => part.key)).toEqual(["input", "output"]);
    expect(view.counters.find((counter) => counter.key === "cache_write")?.value).toBeNull();
    // Input not reported: no headline is made up from the rest.
    const noInput = tokenView({ ...tokens.agents[0], input_tokens: null, parts_disjoint: true } as never);
    expect(noInput.headline?.words).toBe("tokens in all");
  });

  it("says the files read, and a capped scan as the newest history only", () => {
    expect(tokenView({ ...tokens.agents[0], coverage: { complete: true, files_read: 4641, files_found: 4641 } }).coverage).toBe("Read 4,641 of 4,641 files.");
    expect(tokenView({ ...tokens.agents[0], coverage: { complete: false, files_read: 40, files_found: 1879 } }).coverage).toBe(
      "Read 40 of 1,879 files: the newest history only.",
    );
    expect(tokenView({ ...tokens.agents[0] }).coverage).toBeUndefined();
  });

  it("keeps counts past what a number holds exact, and draws every agent on one scale", () => {
    const huge = "90071992547409930";
    const view = tokenView({ ...tokens.agents[1], total_tokens: huge, input_tokens: huge, output_tokens: "0", cached_input_tokens: null, parts_disjoint: false } as never);
    expect(view.headline?.value).toBe(90071992547409930n);
    expect(tokenScales(tokenViews(tokens))).toEqual({ fresh: 40_921_626n, cache: 1_271_432_724n });
    expect(share(1n, 4n)).toBeCloseTo(0.25);
    expect(share(1n, 0n)).toBe(0);
  });
});

describe("Protection's screening rows", () => {
  const facts = readAgentsFacts(agentsFixture);

  it("lists each connected agent with its state, its own switch, or the step that finishes connecting it", () => {
    const rows = screeningRows(facts.agents, facts.unnamed);
    expect(rows.map((row) => [row.agent.id, row.state, row.step?.command])).toEqual([
      ["claude-code", "monitor", "innerwarden agents connect claude-code"],
      ["codex", "needs_you", "innerwarden agents connect codex --monitor"],
      ["cursor", "refusing", "innerwarden agents connect cursor --monitor"],
      ["gemini", "unknown", "innerwarden agents connect gemini --monitor"],
    ]);
    expect(rows[0].restart.how).toBe("In Claude Code, type /exit, then run claude.");
  });

  it("counts the rows by state in one sentence, and says what was not read", () => {
    expect(screeningSummary(screeningRows(facts.agents, facts.unnamed))).toBe(
      "Screening: 1 agent refusing a deny, 1 in monitor, 1 needs you, 1 not yet seen working.",
    );
    expect(screeningSummary([])).toBe("Screening: no agent is connected yet.");
    expect(screeningSummary(undefined)).toBe("Screening: not read.");
  });

  it("says how a proxy's servers are wrapped, and that remote ones are not screened", () => {
    expect(mcpLines({ stdio: 3, wrapped: 2, remote: 1 })).toEqual([
      "2 of 3 local servers wrapped.",
      "1 remote server is not screened (Community wraps local servers only).",
    ]);
    expect(mcpLines({ stdio: 0, wrapped: 0, remote: 0 })).toEqual(["No local MCP server to wrap."]);
    expect(mcpLines(undefined)).toEqual([]);
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
    const alerts = (channels: number | undefined) => footerItems(undefined, { ...protection, alerts: channels === undefined ? {} : { channels } }, history).find((item) => item.key === "alerts")?.words;
    expect([alerts(0), alerts(1), alerts(3)]).toEqual(["Alerts: off.", "Alerts: 1 channel.", "Alerts: 3 channels."]);
    // A CLI that did not say how many: not read, never off.
    expect(alerts(undefined)).toBe("Alerts: not read.");
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
