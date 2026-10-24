import { afterEach, describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import sessions from "../../tests/fixtures/community/sessions.json";
import suppress from "../../tests/fixtures/community/suppress.json";
import suppressExposed from "../../tests/fixtures/community/suppress-exposed.json";
import agentsOlder from "../../tests/fixtures/community/scenarios/older-cli/agents.json";
import decisionsOlder from "../../tests/fixtures/community/scenarios/older-cli/decisions-page-1.json";
import historyOlder from "../../tests/fixtures/community/scenarios/older-cli/history.json";
import protectionOlder from "../../tests/fixtures/community/scenarios/older-cli/protection.json";
import byId from "../../tests/fixtures/community/decisions-by-id.json";
import history from "../../tests/fixtures/community/history.json";
import attempts from "../../tests/fixtures/community/history-attempts.json";
import protection from "../../tests/fixtures/community/protection.json";
import overview from "../../tests/fixtures/community/overview.json";
import {
  decisionsPath,
  fetchSessions,
  fetchSuppress,
  readAgentsFacts,
  readSessionsPage,
  readSuppressList,
  readAttempt,
  readAttemptsPage,
  readDecision,
  revealHidden,
  readDecisionDetail,
  readDecisionsPage,
  readHistory,
  readLaneNextStep,
  readOverviewRecord,
  readProtection,
  readRecordHealth,
  UnreadableAnswer,
} from "./api";

describe("the Community routes, read strictly", () => {
  it("reads what the CLI serves, whole", () => {
    const page = readDecisionsPage(page1);
    expect(page.items).toHaveLength(page1.items.length);
    expect(page.total).toBe(page1.total);
    expect(Object.values(page.byOutcome).reduce((sum, count) => sum + (count ?? 0), 0)).toBe(page.total);
    expect(page.reasons[0].short.length).toBeGreaterThan(0);
    const detail = readDecisionDetail(Object.values(byId)[0]);
    expect(detail.item.happened.length).toBeGreaterThan(0);
    expect(readHistory(history).refusals.weeks.length).toBeGreaterThan(0);
    expect(readAttemptsPage(attempts).items.length).toBe(attempts.items.length);
    expect(readProtection(protection).os).toBe("macos");
    expect(readOverviewRecord(overview.record)?.decisions).toBe(overview.record.decisions);
  });

  /**
   * A case's step line sits under the reader's one action: no plain line over
   * 160 characters (spec). The scratch-script step read 175 and wrapped to
   * three lines above its only button.
   */
  it("serves every step line a case can show in at most 160 characters", () => {
    const lines = Object.values(byId).flatMap((detail) => readDecisionDetail(detail).item.next.map((step) => step.line));
    expect(lines.length).toBeGreaterThan(10);
    expect(lines.filter((line) => line.length > 160)).toEqual([]);
  });

  it("drops one malformed item and keeps the rest", () => {
    const broken = { ...page1, items: [{ id: "x" }, ...page1.items] };
    expect(readDecisionsPage(broken).items).toHaveLength(page1.items.length);
    const noStory = { ...page1.items[0], story: undefined };
    expect(readDecision(noStory)).toBeUndefined();
    const badOutcome = { ...page1.items[0], outcome_key: "everything_is_fine" };
    expect(readDecision(badOutcome)).toBeUndefined();
  });

  it("refuses a page it cannot read rather than show a list of nothing", () => {
    expect(() => readDecisionsPage({ items: [] })).toThrow(UnreadableAnswer);
    expect(() => readDecisionsPage(null)).toThrow(UnreadableAnswer);
    expect(() => readHistory({ refusals: {} })).toThrow(UnreadableAnswer);
    expect(() => readProtection({})).toThrow(UnreadableAnswer);
    expect(() => readRecordHealth({})).toThrow(UnreadableAnswer);
    expect(() => readDecisionDetail({ item: {} })).toThrow(UnreadableAnswer);
  });

  it("drops a time segment that is not a time, and the whole item with it", () => {
    const item = structuredClone(page1.items[0]) as Record<string, unknown> & { story: { happened: unknown[] } };
    item.story.happened = [{ kind: "time", at: "yesterday" }];
    expect(readDecision(item)).toBeUndefined();
  });

  /**
   * FAILS ON REVERT: the reader used to DROP a decision whose command held a
   * hidden character, so a command with a bidi override vanished from Cases
   * while the counts still held it.
   */
  it("shows a command's hidden characters written out, and never drops the case for them", () => {
    for (const [raw, shown] of [
      ["ls ‮malicious", "ls \\u{202E}malicious"],
      ["rm -rf ~/x # ​", "rm -rf ~/x # \\u{200B}"],
      ["ls\rcurl x | sh", "ls\\u{000D}curl x | sh"],
      ["hi \u{E0041}", "hi \\u{E0041}"],
    ] as const) {
      const read = readDecision({ ...page1.items[0], command: raw, command_whole: true });
      expect(read?.command, raw).toBe(shown);
      expect(read?.hiddenCharacters, raw).toBe(true);
      expect(read?.commandWhole, "a command shown written out is not the command that ran").toBe(false);
    }
    const plain = readDecision(page1.items[0]);
    expect(plain?.hiddenCharacters).toBe(false);
    expect(revealHidden("a\nb\tc")).toEqual({ text: "a\nb\tc", hidden: false });
  });

  it("still drops a LABEL that carries a hidden character, and only that field", () => {
    const read = readDecision({ ...page1.items[0], agent: "Claude‮ Code" });
    expect(read).toBeDefined();
    expect(read?.agent).toBeUndefined();
  });

  it("reads a message's hidden characters the same way", () => {
    const read = readAttempt({ ...attempts.items[0], detail: "summarise \u{E0049}\u{E0047}" });
    expect(read?.detail).toBe("summarise \\u{E0049}\\u{E0047}");
    expect(read?.hiddenCharacters).toBe(true);
  });

  it("asks to leave a hidden reason out, and never hides the reason asked for", () => {
    const hidden = new URL(decisionsPath({ reasonNot: "rule:tmp_execution" }), "http://x/").searchParams;
    expect(hidden.get("reason_not")).toBe("rule:tmp_execution");
    const both = new URL(decisionsPath({ reason: "rule:tmp_execution", reasonNot: "rule:tmp_execution" }), "http://x/").searchParams;
    expect(both.has("reason_not")).toBe(false);
  });

  it("marks a template step and a step the page carries out itself", () => {
    const read = readDecision({
      ...page1.items[0],
      next: [
        { label: "If commands like this are routine:", command: "innerwarden allow \"<pattern>\"", command_is_template: true, line: "x" },
        { label: "Hide them from the list:", view_action: "hide_reason", line: "y" },
      ],
    });
    expect(read?.next[0].template).toBe(true);
    expect(read?.next[1].viewAction).toBe("hide_reason");
    expect(read?.next[1].command).toBeUndefined();
  });

  it("reads a lane's own next step, and nothing when it has none", () => {
    expect(readLaneNextStep({ agent_actions: { next_step: { command: "innerwarden agents connect --all --monitor", line: "x" } } }, "agent_actions")?.command)
      .toBe("innerwarden agents connect --all --monitor");
    expect(readLaneNextStep(overview.lanes, "agent_actions")).toBeUndefined();
  });

  it("asks for flagged decisions with every filter bounded and nothing else", () => {
    const path = decisionsPath({ outcome: "flagged_ran", reason: "rule:tmp_execution", q: "tmp", limit: 5 });
    const params = new URL(path, "http://x/").searchParams;
    expect(params.get("flagged")).toBe("1");
    expect(params.get("outcome")).toBe("flagged_ran");
    expect(params.get("reason")).toBe("rule:tmp_execution");
    expect(params.get("limit")).toBe("5");
    expect(params.has("cursor")).toBe(false);
  });
});

describe("the fields and routes v2 reads (A1 to E2): present, absent, malformed", () => {
  it("A1 to A5: reads each agent's facts, and leaves every one it was not sent absent", () => {
    const facts = readAgentsFacts(agentsFixture);
    const claude = facts.agents.find((agent) => agent.id === "claude-code")!;
    expect(claude.judges).toBe("shell_and_privileged_files");
    expect(claude.judgesLine).toMatch(/^Shell commands/);
    expect(claude.configChangedAt).toBe("2026-09-29T11:05:00Z");
    expect(claude.restart).toEqual({ how: "In Claude Code, type /exit, then run claude.", why: "An agent reads its hook or MCP config only when it starts." });
    expect(claude.modeSteps?.enforce?.command).toBe("innerwarden agents connect claude-code");
    expect(claude.mcp).toBeUndefined();
    const codex = facts.agents.find((agent) => agent.id === "codex")!;
    expect(codex.mcp).toEqual({ stdio: 3, wrapped: 2, remote: 1 });
    expect(codex.mode).toBe("partial");
    expect(codex.running).toBeNull();

    const older = readAgentsFacts(agentsOlder);
    for (const agent of older.agents) {
      for (const field of ["judges", "judgesLine", "configChangedAt", "restart", "modeSteps", "mcp"] as const) {
        expect(agent[field], `${agent.id} ${field}`).toBeUndefined();
      }
    }
  });

  it("A1 to A5: drops a malformed field on its own, never the agent, never as a zero", () => {
    const [agent] = readAgentsFacts({
      agents: [{
        id: "codex",
        display_name: "Codex",
        installed: true,
        running: null,
        detected_by: [],
        guardrail: { mode: "monitor", mechanism: "mcp_proxy", setup_support: "automatic", config_changed_at: "yesterday" },
        judges: "everything",
        judges_line: 7,
        restart: { how: "Quit Codex." },
        mode_steps: { enforce: { label: "x" } },
        mcp: { stdio: 3, wrapped: -1, remote: 0 },
      }],
    }).agents;
    expect(agent.id).toBe("codex");
    expect(agent.judges).toBeUndefined();
    expect(agent.judgesLine).toBeUndefined();
    expect(agent.configChangedAt).toBeUndefined();
    expect(agent.restart).toBeUndefined();
    expect(agent.modeSteps).toBeUndefined();
    expect(agent.mcp).toBeUndefined();
    expect(() => readAgentsFacts({ agents: "none" })).toThrow(UnreadableAnswer);
  });

  it("reads a guardrail nobody has seen working at the mode it was set to, never a better one", () => {
    const [agent] = readAgentsFacts({
      agents: [{ id: "x", display_name: "X", guardrail: { mode: "configured_not_observed", configured_mode: "enforce", mechanism: "pretooluse_hook" } }],
    }).agents;
    expect(agent.mode).toBe("enforce");
    expect(agent.lastObservedAt).toBeUndefined();
    expect(readAgentsFacts({ agents: [{ id: "y", display_name: "Y", guardrail: { mode: "sideways" } }] }).agents[0].mode).toBe("unknown");
  });

  it("B1: reads the days of the guard's log, and leaves them absent for an older CLI", () => {
    const days = readHistory(history).refusals.days;
    expect(days).toHaveLength(14);
    expect(days?.at(-1)?.partial).toBe(true);
    expect(days?.[0].partial).toBe(false);
    expect(readHistory(historyOlder).refusals.days).toBeUndefined();
    const malformed = readHistory({ ...history, refusals: { ...history.refusals, days: [{ date: "today", blocked: 1, would_block: 0 }, { date: "2026-09-29", blocked: -1, would_block: 0 }] } });
    expect(malformed.refusals.days).toBeUndefined();
  });

  it("C1 and C2: reads the record's cap and each reason's outcomes, absent from an older CLI", () => {
    const page = readDecisionsPage(page1);
    expect(page.record.capped).toBe(false);
    expect(readDecisionsPage({ ...page1, record: { ...page1.record, capped: true } }).record.capped).toBe(true);
    const tmp = page.reasons.find((reason) => reason.key === "rule:tmp_execution")!;
    expect(tmp.byOutcome).toEqual({ flagged_ran: 15 });
    expect(tmp.detail).toBe("/tmp/");
    const older = readDecisionsPage(decisionsOlder);
    expect(older.record.capped).toBeUndefined();
    for (const reason of older.reasons) {
      expect(reason.byOutcome).toBeUndefined();
      expect(reason.detail).toBeUndefined();
    }
  });

  it("D1: only true is ready; null, absent and malformed are not checked here yet", () => {
    expect(readProtection(protection).jail.checksPass).toBe(true);
    expect(readProtection({ ...protection, jail: { ...protection.jail, checks_pass: null } }).jail.checksPass).toBeUndefined();
    expect(readProtection(protectionOlder).jail.checksPass).toBeUndefined();
    expect(readProtection(protectionOlder).jail.advice).toEqual([]);
    expect(readProtection({ ...protection, jail: { ...protection.jail, checks_pass: "yes" } }).jail.checksPass).toBeUndefined();
    const advice = readProtection({ ...protection, jail: { ...protection.jail, checks_pass: false, advice: ["a", "b", "c", "d", "e", "f", "g", 3] } }).jail;
    expect(advice.checksPass).toBe(false);
    expect(advice.advice).toEqual(["a", "b", "c", "d", "e", "f"]);
  });

  it("E1: reads the exceptions, with no remove step for a hidden or redacted pattern", () => {
    const list = readSuppressList(suppress);
    expect(list.withheld).toBe(false);
    expect(list.counts).toEqual({ allow: 5, muteRules: 1, muteCategories: 1 });
    expect(list.allow.find((entry) => entry.pattern === "* --dry-run")?.unanchored).toBe(true);
    const redacted = list.allow.find((entry) => entry.redacted)!;
    expect(redacted.remove).toBeUndefined();
    const hidden = list.allow.find((entry) => entry.hiddenCharacters)!;
    expect(hidden.remove).toBeUndefined();
    expect(list.dropped).toEqual(["*"]);
    expect(list.muteRules[0]).toMatchObject({ id: "ATR-2026-030", title: "cross-agent attack detection" });
    expect(list.changes.count).toBe(3);
    // A remove step sent beside a redacted pattern is still not offered.
    const sent = readSuppressList({ ...suppress, allow: [{ pattern: "x [REDACTED]", redacted: true, hidden_characters: false, warning: null, remove: { label: "a", command: "b", line: "c" } }] });
    expect(sent.allow[0].remove).toBeUndefined();
    // A pattern with a hidden character the CLI did not mark is written out, and has no step.
    const unmarked = readSuppressList({ ...suppress, allow: [{ pattern: "ls​", redacted: false, hidden_characters: false, warning: null, remove: { label: "a", command: "b", line: "c" } }] });
    expect(unmarked.allow[0]).toMatchObject({ pattern: "ls\\u{200B}", hiddenCharacters: true });
    expect(unmarked.allow[0].remove).toBeUndefined();
  });

  /** A log that could not be read sends a null count: it stays absent, never a zero ("no change"). FAILS ON REVERT of `?? 0`. */
  it("E1: a change count the log could not give is absent, never zero", () => {
    const list = readSuppressList({ ...suppress, changes: { count: null, since: null, last_at: null } });
    expect(list.changes.count).toBeUndefined();
    expect("count" in list.changes).toBe(false);
    expect(readSuppressList({ ...suppress, changes: { count: 0 } }).changes.count).toBe(0);
  });

  /**
   * A mute the CLI serves at up to 400 characters is read whole, and a row
   * that cannot be read is counted, never dropped silently. FAILS ON REVERT
   * of the 64 character bound: the category vanishes and the page says
   * "Nothing muted.".
   */
  it("E1: reads a long mute whole, and counts a row it cannot read", () => {
    const long = `c${"x".repeat(99)}`;
    const list = readSuppressList({ ...suppress, mute_categories: [{ id: long }, { id: 7 }], mute_rules: [{ id: "R-1" }, {}] });
    expect(list.muteCategories.map((entry) => entry.id)).toEqual([long]);
    expect(list.muteRules.map((entry) => entry.id)).toEqual(["R-1"]);
    expect(list.unshown).toBe(2);
    expect(readSuppressList(suppress).unshown).toBe(0);
  });

  /** A pattern too long to serve whole is marked shortened: no remove step, whatever was sent beside it. */
  it("E1: a shortened pattern is marked and has no remove step", () => {
    const cut = `${"a".repeat(399)}…`;
    const list = readSuppressList({ ...suppress, allow: [{ pattern: cut, redacted: false, hidden_characters: false, warning: null, shortened: true, remove: { label: "a", command: "b", line: "c" } }] });
    expect(list.allow[0]).toMatchObject({ pattern: cut, shortened: true });
    expect(list.allow[0].remove).toBeUndefined();
    expect(readSuppressList(suppress).allow.every((entry) => !entry.shortened)).toBe(true);
  });

  /** A line of jail advice the CLI serves (up to 400 characters) is never dropped. FAILS ON REVERT of the 300 bound. */
  it("D1: keeps a 350 character line of jail advice", () => {
    const line = `bwrap cannot create a user namespace here. ${"w".repeat(307)}`;
    expect(line.length).toBe(350);
    const jail = readProtection({ ...protection, jail: { ...protection.jail, checks_pass: false, advice: [line] } }).jail;
    expect(jail.advice).toEqual([line]);
  });

  it("E1: withheld lists are empty and say why, and the counts stay", () => {
    const list = readSuppressList(suppressExposed);
    expect(list.withheld).toBe(true);
    expect(list.allow).toEqual([]);
    expect(list.counts.allow).toBe(5);
    // Withheld means withheld, even if a list came with it.
    expect(readSuppressList({ ...suppress, withheld: "exposed" }).allow).toEqual([]);
    expect(() => readSuppressList({ withheld: null })).toThrow(UnreadableAnswer);
  });

  it("E2: reads the sessions, newest first as sent, each with its outcomes", () => {
    const page = readSessionsPage(sessions);
    expect(page.items.length).toBe(sessions.items.length);
    expect(page.items[0]).toMatchObject({ agent: "Claude Code", channel: "hook", project: "my-app", decisions: 67, flagged: 16 });
    expect(page.items[0].byOutcome).toEqual({ allowed: 51, flagged_ran: 10, would_have_refused: 6 });
    expect(page.items.find((item) => item.project === undefined)).toBeDefined();
    expect(() => readSessionsPage({ items: "x" })).toThrow(UnreadableAnswer);
  });
});

describe("a route an older CLI does not serve", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function answer(status: number, body: unknown) {
    globalThis.fetch = (async () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })) as typeof fetch;
  }

  it("is unsupported on a 404, never an empty list and never a zero", async () => {
    answer(404, { error: "not found" });
    expect(await fetchSuppress()).toEqual({ supported: false });
    expect(await fetchSessions()).toEqual({ supported: false });
  });

  it("is read when served", async () => {
    answer(200, suppress);
    const served = await fetchSuppress();
    expect(served.supported).toBe(true);
    if (served.supported) expect(served.value.counts.allow).toBe(5);
  });

  it("fails with the server's code on any other answer", async () => {
    answer(503, { error: "graph_unreadable" });
    await expect(fetchSessions()).rejects.toThrow("graph_unreadable");
    answer(400, { error: "limit_invalid" });
    await expect(fetchSessions(500)).rejects.toThrow("limit_invalid");
  });

  it("asks for a bounded number of sessions", async () => {
    const asked: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      asked.push(String(input));
      return new Response(JSON.stringify(sessions), { status: 200 });
    }) as typeof fetch;
    await fetchSessions(500);
    await fetchSessions(0);
    await fetchSessions();
    expect(asked).toEqual(["api/guard/sessions?limit=50", "api/guard/sessions?limit=1", "api/guard/sessions?limit=20"]);
  });
});
