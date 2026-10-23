import { describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import agentsBase from "../../tests/fixtures/community/agents.json";
import agentsEnforce from "../../tests/fixtures/community/scenarios/enforce/agents.json";
import historyEnforce from "../../tests/fixtures/community/scenarios/enforce/history.json";
import agentsMixed from "../../tests/fixtures/community/scenarios/mixed/agents.json";
import agentsNoAgents from "../../tests/fixtures/community/scenarios/no-agents/agents.json";
import agentsNeverScreened from "../../tests/fixtures/community/scenarios/never-screened/agents.json";
import agentsOlder from "../../tests/fixtures/community/scenarios/older-cli/agents.json";
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import { readAgentsFacts, readDecisionsPage, readHistory, type AgentFacts } from "./api";
import { lastDays, modeBox, overviewVerdict, recordCounts, spanWords, type Verdict, type VerdictInput } from "./verdict";
import { ENFORCE_MEANS, MONITOR_MEANS } from "./words";

const NOW = Date.parse("2026-09-29T14:05:00Z");
/** A clock in UTC, so the times read the same on every machine. */
const UTC = (ms: number) => new Date(ms).toISOString().slice(11, 16);

function agent(over: Partial<AgentFacts> & Pick<AgentFacts, "id" | "name" | "mode">): AgentFacts {
  return { supported: true, present: true, installed: true, running: null, mechanism: "hook", ...over };
}

const CLAUDE_SEEN = agent({
  id: "claude-code",
  name: "Claude Code",
  mode: "monitor",
  lastObservedAt: "2026-09-29T14:03:00Z",
  configChangedAt: "2026-09-29T11:05:00Z",
  nextStep: { label: "To refuse a deny as well:", command: "innerwarden enforce", line: "Switches every connected agent from Monitor to Enforce: a deny is refused before it runs." },
});
const CODEX_SEEN = agent({
  id: "codex",
  name: "Codex",
  mode: "monitor",
  mechanism: "mcp",
  mcp: { stdio: 2, wrapped: 2, remote: 0 },
  lastObservedAt: "2026-09-29T12:05:00Z",
});

function input(over: Partial<VerdictInput> = {}): VerdictInput {
  return {
    metaStatus: "ready",
    meta: { exposed: false },
    health: { recording: true },
    agents: [CLAUDE_SEEN, CODEX_SEEN],
    agentsFailed: false,
    unnamed: {},
    now: NOW,
    clock: UTC,
    ...over,
  };
}

/** Every word a band prints, in reading order. */
function words(verdict: Verdict): string {
  const action = verdict.action;
  return [
    verdict.headline ?? "",
    ...verdict.lines,
    ...(action?.steps.flatMap(({ step, restarts }) => [step.label, step.command ?? "", step.line ?? "", ...restarts.map((r) => `${r.agent} ${r.words.how} ${r.words.why}`)]) ?? []),
    ...(action?.restarts.map((r) => `${r.agent} ${r.words.how}`) ?? []),
    action?.after ?? "",
    action?.back?.command ?? "",
    action?.nothing ?? "",
  ].join(" \n");
}

describe("the verdict band, row by row (spec 6.1)", () => {
  it("0: draws nothing until the first answers land, never a zero", () => {
    expect(overviewVerdict(input({ metaStatus: "loading", meta: undefined })).row).toBe(0);
    const pendingAgents = overviewVerdict(input({ agents: undefined }));
    expect(pendingAgents.row).toBe(0);
    expect(pendingAgents.headline).toBeUndefined();
    expect(pendingAgents.lines).toEqual([]);
  });

  it("1: open to the network comes first, before anything else that is true", () => {
    const verdict = overviewVerdict(input({ meta: { exposed: true }, health: { recording: false }, agents: undefined }));
    expect(verdict.row).toBe(1);
    expect(verdict.tone).toBe("exposed");
    expect(verdict.headline).toBe("This dashboard is open to the network");
    expect(verdict.action?.steps[0].step).toEqual({
      label: "To close it, stop the dashboard where it runs and start it again with:",
      command: "innerwarden dashboard",
      line: "Without --expose it answers on this machine only.",
    });
  });

  it("2: not recording, with the server's own summary and what was lost", () => {
    const verdict = overviewVerdict(input({ health: { recording: false, summary: "InnerWarden has not recorded for 65 minutes.", sinceUnix: 1_790_686_800, lostActions: 37 } }));
    expect(verdict.row).toBe(2);
    expect(verdict.lines).toEqual(["InnerWarden has not recorded for 65 minutes.", "Since 13:00, 37 actions were not recorded."]);
    expect(verdict.action?.steps[0].step.command).toBe("innerwarden status");
    // One lost action, and no start time: still a sentence.
    expect(overviewVerdict(input({ health: { recording: false, lostActions: 1 } })).lines).toEqual(["1 action was not recorded."]);
  });

  it("3: agents that could not be read are said as such, never as no agent", () => {
    const verdict = overviewVerdict(input({ agents: undefined, agentsFailed: true }));
    expect(verdict.row).toBe(3);
    expect(verdict.tone).toBe("unknown");
    expect(verdict.headline).toBe("Could not read whether your agents are connected");
    expect(verdict.lines).toEqual(["The dashboard did not answer at 14:05. Nothing on this page is counted as zero."]);
    expect(overviewVerdict(input({ metaStatus: "error", meta: undefined })).row).toBe(3);
  });

  it("4: no agent connected names the ones found here and gives the first one's step", () => {
    const verdict = overviewVerdict(input({ agents: readAgentsFacts(agentsNoAgents).agents }));
    expect(verdict.row).toBe(4);
    expect(verdict.lines).toEqual(["Found here: Cursor, Gemini CLI."]);
    expect(verdict.action?.steps).toHaveLength(1);
    expect(verdict.action?.steps[0].step.command).toBe("innerwarden agents connect cursor --monitor");
    expect(verdict.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Cursor"]);
    const none = overviewVerdict(input({ agents: [] }));
    expect(none.lines).toEqual(["No supported agent was found on this machine."]);
    expect(none.action?.steps).toEqual([]);
    expect(none.action?.link).toBe("agents");
  });

  it("5: a partly connected agent is the one step, with its restart", () => {
    const verdict = overviewVerdict(input({ agents: readAgentsFacts(agentsBase).agents }));
    expect(verdict.row).toBe(5);
    expect(verdict.headline).toBe("Codex is only partly connected");
    expect(verdict.action?.steps[0].step.command).toBe("innerwarden agents connect codex --monitor");
    expect(verdict.action?.steps[0].restarts).toEqual([{ agent: "Codex", words: { how: "Quit Codex and start it again.", why: "An agent reads its hook or MCP config only when it starts." } }]);
    // An older CLI sends no restart words: the page's own are the same.
    const older = overviewVerdict(input({ agents: readAgentsFacts(agentsOlder).agents }));
    expect(older.action?.steps[0].restarts[0].words.how).toBe("Quit Codex and start it again.");
  });

  it("6: connected but nothing seen since the settings changed is unknown, and asks for the restart", () => {
    const verdict = overviewVerdict(input({ agents: readAgentsFacts(agentsNeverScreened).agents }));
    expect(verdict.row).toBe(6);
    expect(verdict.tone).toBe("unknown");
    // Both were screened before their settings changed: not "yet".
    expect(verdict.headline).toBe("Connected, but nothing screened since the settings changed");
    expect(verdict.lines).toEqual([
      "Nothing has come through the guard since Claude Code's settings changed at 14:04.",
      "Nothing has come through the guard since Codex's settings changed at 13:35.",
    ]);
    expect(verdict.action?.steps).toEqual([]);
    expect(verdict.action?.restarts.map((restart) => restart.words.how)).toEqual(["In Claude Code, type /exit, then run claude.", "Quit Codex and start it again."]);
    expect(verdict.action?.after).toBe("Then ask it to run any command. It shows here within seconds.");
    const never = overviewVerdict(input({ agents: [agent({ id: "claude-code", name: "Claude Code", mode: "enforce" })] }));
    expect(never.row).toBe(6);
    expect(never.headline).toBe("Connected, but nothing screened yet");
    expect(never.lines).toEqual(["Nothing has come through the guard from Claude Code yet."]);
  });

  it("6 is not claimed where a screening on the channel names nobody: that one could be its own", () => {
    const unnamed = overviewVerdict(input({ agents: [agent({ id: "claude-code", name: "Claude Code", mode: "monitor" })], unnamed: { hook: "2026-09-29T14:00:00Z" } }));
    expect(unnamed.row).toBe(8);
    // And an older CLI that does not say: nothing is concluded either.
    expect(overviewVerdict(input({ agents: [agent({ id: "claude-code", name: "Claude Code", mode: "monitor" })], unnamed: undefined })).row).toBe(8);
  });

  it("7: different modes say who refuses and who only records, with each agent's own switch", () => {
    const verdict = overviewVerdict(input({ agents: readAgentsFacts(agentsMixed).agents }));
    expect(verdict.row).toBe(7);
    expect(verdict.headline).toBe("1 of 2 agents is set to refuse a deny. Claude Code only records.");
    expect(verdict.lines).toEqual([MONITOR_MEANS]);
    expect(verdict.action?.steps.map(({ step }) => step.command)).toEqual(["innerwarden agents connect claude-code"]);
    expect(verdict.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Claude Code"]);
  });

  it("7 without a per-agent switch offers the shared one, and every connected agent's restart", () => {
    const enforcing = agent({ id: "cursor", name: "Cursor", mode: "enforce", mechanism: "mcp", lastObservedAt: "2026-09-29T12:05:00Z" });
    const verdict = overviewVerdict(input({ agents: [CLAUDE_SEEN, enforcing] }));
    expect(verdict.row).toBe(7);
    expect(verdict.action?.steps).toHaveLength(1);
    expect(verdict.action?.steps[0].step.command).toBe("innerwarden enforce");
    expect(verdict.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Claude Code", "Cursor"]);
  });

  /**
   * One monitor agent has its own switch and one does not: the per-agent
   * steps cannot cover both, so the band falls back to the shared switch,
   * with every connected agent's restart. FAILS ON REVERT of `every` to `some`.
   */
  it("7 falls back to the shared step when any recording agent has no switch of its own", () => {
    const enforcing = agent({ id: "cursor", name: "Cursor", mode: "enforce", mechanism: "mcp", lastObservedAt: "2026-09-29T12:05:00Z" });
    const withSwitch = { ...CLAUDE_SEEN, modeSteps: { enforce: { label: "To refuse a deny for this agent only:", command: "innerwarden agents connect claude-code", line: "Switches this agent to Enforce." } } };
    const verdict = overviewVerdict(input({ agents: [enforcing, withSwitch, CODEX_SEEN] }));
    expect(verdict.row).toBe(7);
    expect(verdict.mixed).toBe(true);
    expect(verdict.action?.steps.map(({ step }) => step.command)).toEqual(["innerwarden enforce"]);
    expect(verdict.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Cursor", "Claude Code", "Codex"]);
    const box = modeBox({ agents: [enforcing, withSwitch, CODEX_SEEN], failed: false, now: NOW, clock: UTC });
    expect(box.row).toBe(7);
    expect(box.mixed).toBe(true);
    expect(box.action?.steps.map(({ step }) => step.command)).toEqual(["innerwarden enforce"]);
    expect(box.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Cursor", "Claude Code", "Codex"]);
    expect(box.action?.back?.command).toBe("innerwarden dry-run");
  });

  /**
   * An agent whose hook or MCP config could not be read is set up to reach
   * the guard: it is said by name as not read, never "No AI agent is
   * connected yet" or "No supported agent was found". FAILS ON REVERT of the
   * unread case (row 4).
   */
  it("3: an agent whose mode could not be read is said as not read, never as not connected", () => {
    const unread = agent({ id: "codex", name: "Codex", mode: "unknown", mechanism: "mcp" });
    const verdict = overviewVerdict(input({ agents: [unread] }));
    expect(verdict.row).toBe(3);
    expect(verdict.tone).toBe("unknown");
    expect(verdict.headline).toBe("Could not read Codex's mode");
    expect(verdict.action?.steps[0].step.command).toBe("innerwarden status");
    expect(words(verdict)).not.toMatch(/No AI agent is connected|No supported agent was found|not connected/);
    const box = modeBox({ agents: [unread], failed: false, now: NOW, clock: UTC });
    expect(box.row).toBe(3);
    expect(box.headline).toBe("Could not read Codex's mode");
    expect(words(box)).not.toMatch(/No AI agent is connected/);
    // Beside a connected agent, the band answers for that one and names the unread one.
    const both = overviewVerdict(input({ agents: [CLAUDE_SEEN, unread] }));
    expect(both.row).toBe(8);
    expect(both.headline).toBe("Your AI agent is connected. Monitor: nothing is refused.");
    expect(both.lines).toContain("Could not read Codex's mode: it is counted as neither connected nor off. innerwarden status says why.");
    expect(modeBox({ agents: [CLAUDE_SEEN, unread], failed: false, now: NOW, clock: UTC }).lines).toContain(
      "Could not read Codex's mode: it is counted as neither connected nor off. innerwarden status says why.",
    );
  });

  it("7: an agent whose own wiring differs is never counted as refusing or as only recording", () => {
    const verdict = overviewVerdict(input({ agents: [agent({ id: "gemini", name: "Gemini CLI", mode: "mixed", mechanism: "mcp", lastObservedAt: "2026-09-29T12:05:00Z" })] }));
    expect(verdict.row).toBe(7);
    expect(verdict.headline).toBe("Gemini CLI refuses a deny for some calls only.");
  });

  it("8: all in monitor is fine as it is: what monitor means, the count, and the switch for when they want it", () => {
    const history = readHistory(historyEnforce);
    const verdict = overviewVerdict(input({ days: [{ date: "2026-09-29", blocked: 0, wouldBlock: 412, partial: true }], logReadable: true }));
    expect(verdict.row).toBe(8);
    expect(verdict.tone).toBe("watch");
    expect(verdict.headline).toBe("Your 2 AI agents are connected. Monitor: nothing is refused.");
    expect(verdict.lines).toEqual([MONITOR_MEANS, "Last 7 days: 412 would have been refused."]);
    const [{ step, restarts }] = verdict.action!.steps;
    expect(step).toEqual({ label: "When you want a deny refused:", command: "innerwarden enforce", line: "Switches every connected agent from Monitor to Enforce: a deny is refused before it runs." });
    expect(restarts.map((restart) => restart.agent)).toEqual(["Claude Code", "Codex"]);
    expect(verdict.action?.back).toEqual({ label: "Back to monitor any time:", command: "innerwarden dry-run" });
    expect(words(verdict)).not.toMatch(/\byou should\b/i);
    expect(history.refusals.days).toBeDefined();
    const one = overviewVerdict(input({ agents: [CLAUDE_SEEN] }));
    expect(one.headline).toBe("Your AI agent is connected. Monitor: nothing is refused.");
  });

  it("8 never says refused as a fact: monitor refuses nothing", () => {
    const verdict = overviewVerdict(input({ days: [{ date: "2026-09-29", blocked: 3, wouldBlock: 5, partial: false }] }));
    expect(verdict.lines.join(" ")).not.toMatch(/\b\d[\d,]* refused\b/);
    expect(verdict.lines.join(" ")).toContain("would have been refused");
  });

  it("9: set to refuse (the config) beside a counted number, and an alert step only on a read zero", () => {
    const facts = readAgentsFacts(agentsEnforce).agents;
    const days = readHistory(historyEnforce).refusals.days;
    const verdict = overviewVerdict(input({ agents: facts, days, logReadable: true, alertChannels: 0 }));
    expect(verdict.row).toBe(9);
    expect(verdict.tone).toBe("stopped");
    expect(verdict.headline).toBe("Your 3 AI agents are connected and set to refuse a deny.");
    expect(verdict.lines).toEqual([ENFORCE_MEANS, `Last 7 days: ${lastDays(days ?? []).blocked} refused before they ran.`]);
    expect(verdict.action?.steps[0].step).toEqual({ label: "To hear about a refusal:", command: "innerwarden notify", line: "Sets up a chat or webhook alert for a deny." });
    expect(words(verdict)).not.toMatch(/protected|\bsafe\b|secure|verified|proven/i);
    expect(overviewVerdict(input({ agents: facts, days, alertChannels: 2 })).action?.nothing).toBe("Nothing to do.");
    // Alerts not read: nothing to do, and no claim about alerts at all.
    const unread = overviewVerdict(input({ agents: facts, days }));
    expect(unread.action?.nothing).toBe("Nothing to do.");
    expect(words(unread)).not.toMatch(/alert/i);
    expect(overviewVerdict(input({ agents: facts, days: days?.map((day) => ({ ...day, blocked: 0 })), alertChannels: 1 })).lines[1]).toBe("None refused in the last 7 days.");
  });

  it("falls back to the decision record's own counts when the log's days are not there, and names its span", () => {
    const page = readDecisionsPage(page1);
    const record = recordCounts(page.record, page.byOutcome, NOW);
    expect(record?.span).toBe("about 4 days");
    const monitor = overviewVerdict(input({ days: undefined, record }));
    expect(monitor.lines[1]).toBe(`In the record (about 4 days): ${page.byOutcome.would_have_refused ?? 0} would have been refused.`);
    // An unreadable log is never read as zero refused: the record speaks instead.
    const unreadable = overviewVerdict(input({ days: [{ date: "2026-09-29", blocked: 0, wouldBlock: 0, partial: true }], logReadable: false, record }));
    expect(unreadable.lines[1]).toMatch(/^In the record/);
    // Neither read: no count line at all, never a zero.
    expect(overviewVerdict(input({ days: undefined, record: undefined })).lines).toEqual([MONITOR_MEANS]);
  });

  it("follows every step that changes an agent's config with that agent's restart words", () => {
    const cases = [
      input({ agents: readAgentsFacts(agentsBase).agents }),
      input({ agents: readAgentsFacts(agentsNoAgents).agents }),
      input({ agents: readAgentsFacts(agentsMixed).agents }),
      input(),
    ];
    for (const verdict of cases.map(overviewVerdict)) {
      for (const { step, restarts } of verdict.action?.steps ?? []) {
        if (/innerwarden (enforce|dry-run|install|agents connect)/.test(step.command ?? "")) expect(restarts.length, step.command).toBeGreaterThan(0);
      }
      expect(words(verdict)).not.toMatch(/restarted|reloaded|picked up/i);
    }
  });

  it("never draws an unknown as off or as zero", () => {
    for (const verdict of [
      overviewVerdict(input({ metaStatus: "loading", meta: undefined })),
      overviewVerdict(input({ agents: undefined, agentsFailed: true })),
      overviewVerdict(input({ agents: readAgentsFacts(agentsNeverScreened).agents })),
    ]) {
      expect(words(verdict)).not.toMatch(/\b0\b|\boff\b|\bnone\b/i);
    }
  });
});

describe("spans and sums", () => {
  it("says a span in the largest unit that reads naturally", () => {
    expect(spanWords(0, 60_000)).toBe("about a minute");
    expect(spanWords(0, 45 * 60_000)).toBe("about 45 minutes");
    expect(spanWords(0, 18 * 3_600_000)).toBe("about 18 hours");
    expect(spanWords(0, 4 * 86_400_000)).toBe("about 4 days");
  });

  it("sums the last seven days, not all fourteen", () => {
    const days = Array.from({ length: 14 }, (_, index) => ({ date: `2026-09-${String(index + 10).padStart(2, "0")}`, blocked: 1, wouldBlock: index, partial: index === 13 }));
    expect(lastDays(days)).toEqual({ blocked: 7, wouldBlock: 7 + 8 + 9 + 10 + 11 + 12 + 13 });
  });
});
