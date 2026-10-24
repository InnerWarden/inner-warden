import { describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import agentsFixture from "../../tests/fixtures/community/agents.json";
import { changesEveryAgent, RESTART_WHY, restartFor, restartNote, restartsAfter, restartWords } from "./restart";
import { overviewVerdict } from "./verdict";
import { readAgentsFacts } from "./api";
import agentsNeverScreened from "../../tests/fixtures/community/scenarios/never-screened/agents.json";

const BANNED = /restarted|reloaded|picked (it |the change )?up|now protected/i;

describe("restarting an agent is the person's step (T5)", () => {
  it("says how for Claude Code, Codex, and any other agent by its name, and why", () => {
    expect(restartWords("claude-code", "Claude Code")).toEqual({ how: "In Claude Code, type /exit, then run claude.", why: RESTART_WHY });
    expect(restartWords("codex", "Codex")).toEqual({ how: "Quit Codex and start it again.", why: RESTART_WHY });
    expect(restartWords("cursor", "Cursor")).toEqual({ how: "Quit Cursor and start it again.", why: RESTART_WHY });
    expect(RESTART_WHY).toBe("An agent reads its hook or MCP config only when it starts.");
  });

  it("prints the CLI's words when it sends them, and its own are the same words", () => {
    for (const agent of agentsFixture.agents) {
      const served = (agent as { restart?: { how: string; why: string } }).restart;
      if (served === undefined) continue;
      expect(restartFor(agent.id, agent.display_name, served)).toEqual(served);
      expect(restartWords(agent.id, agent.display_name), agent.id).toEqual(served);
    }
    expect(restartFor("codex", "Codex", undefined).how).toBe("Quit Codex and start it again.");
  });

  it("asks for the restart, and never says it happened", () => {
    const note = restartNote("Codex", restartWords("codex", "Codex"));
    expect(note).toBe("If Codex is running, restart it after this step. Quit Codex and start it again. An agent reads its hook or MCP config only when it starts.");
    for (const [id, name] of [["claude-code", "Claude Code"], ["codex", "Codex"], ["gemini", "Gemini CLI"]]) {
      expect(restartNote(name, restartWords(id, name))).not.toMatch(BANNED);
    }
  });

  /**
   * "After this step" only where a step comes first. Where the restart is
   * the step (a band with no command, a prompt to restart), it is "now".
   * FAILS ON REVERT of the `when` argument.
   */
  it("says now where there is no step before the restart, and after this step only under one", () => {
    const words = restartWords("codex", "Codex");
    expect(restartNote("Codex", words, "now")).toBe("If Codex is running, restart it now. Quit Codex and start it again. An agent reads its hook or MCP config only when it starts.");
    expect(restartNote("Codex", words, "after_step")).toContain("restart it after this step.");
    expect(restartNote("Codex", words)).toContain("restart it after this step.");
    // Row 6 has restarts and no command: the band draws them with "now".
    const row6 = overviewVerdict({ metaStatus: "ready", meta: { exposed: false }, health: { recording: true }, agents: readAgentsFacts(agentsNeverScreened).agents, agentsFailed: false, unnamed: {}, now: Date.parse("2026-09-29T14:05:00Z") });
    expect(row6.row).toBe(6);
    expect(row6.action?.steps).toEqual([]);
    expect(row6.action?.restarts.length).toBeGreaterThan(0);
  });

  /** A switch for every agent restarts every connected agent; a switch for one restarts that one. */
  it("restarts every connected agent after a switch for all, and one agent after its own", () => {
    const one = { agent: "Claude Code", words: restartWords("claude-code", "Claude Code") };
    const every = [one, { agent: "Codex", words: restartWords("codex", "Codex") }];
    for (const command of ["innerwarden enforce", "innerwarden dry-run", "innerwarden install", "innerwarden agents connect --all --monitor"]) {
      expect(changesEveryAgent(command), command).toBe(true);
      expect(restartsAfter(command, one, every).map((restart) => restart.agent), command).toEqual(["Claude Code", "Codex"]);
    }
    expect(changesEveryAgent("innerwarden agents connect codex --monitor")).toBe(false);
    expect(restartsAfter("innerwarden agents connect codex --monitor", one, every)).toEqual([one]);
    expect(restartsAfter("innerwarden allow 'x'", one, every)).toEqual([]);
    // The agents were not read: the one agent named, never nobody.
    expect(restartsAfter("innerwarden enforce", one, undefined)).toEqual([one]);
  });
});
