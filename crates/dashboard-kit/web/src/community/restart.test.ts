import { describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import agentsFixture from "../../tests/fixtures/community/agents.json";
import { RESTART_WHY, restartFor, restartNote, restartWords } from "./restart";

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
});
