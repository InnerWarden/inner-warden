import { describe, expect, it } from "vitest";
import type { AgentsResponse } from "../api";
// Written by the CLI's own fixture writer, not by hand.
import agentsFixture from "../../tests/fixtures/community/agents.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import { agentRows } from "./agentsView";
import { readProtection } from "./api";
import { communityControls, controlCounts, someRefuse } from "./controls";
import { legendWords } from "./Protection";

const NOW = Date.parse("2026-09-29T14:05:00Z");
const agents = agentsFixture as unknown as AgentsResponse;

describe("a screening control over agents that differ", () => {
  // The fixture's MCP agents: Cursor and Gemini CLI refuse, Codex is partly
  // connected. The control's one state is "needs you" for Codex.
  const controls = communityControls({ agents: agentRows(agents), now: NOW });
  const tools = controls.find((control) => control.key === "tool_call_screening")!;

  /**
   * FAILS ON REVERT: the ladder marked Refusing done only when EVERY agent
   * refused, and said "watching only: nothing is refused" beside Cursor and
   * Gemini CLI refusing.
   */
  it("never says nothing refuses while an agent under it refuses", () => {
    expect(tools.state).toBe("needs");
    const refusing = tools.ladder?.find((step) => step.key === "refusing");
    expect(refusing?.mark).not.toBe("not_applicable");
    expect(refusing?.mark).toBe("done");
    expect(refusing?.words).toBe("Cursor and Gemini CLI refuse a deny; Codex does not");
    const words = [tools.line, ...(tools.ladder ?? []).map((step) => step.words)].join(" ");
    expect(words).not.toMatch(/nothing is refused/);
    expect(tools.refusingAgents).toEqual(["Cursor", "Gemini CLI"]);
  });

  it("says Some refuse in the ring's legend, never 0 Refusing beside refusing agents", () => {
    const counts = controlCounts(controls);
    expect(counts.refusing).toBe(0);
    expect(someRefuse(controls)).toBe(true);
    expect(legendWords("refusing", counts, true)).toEqual({ words: "Some refuse" });
    expect(legendWords("refusing", counts, false)).toEqual({ count: 0, words: "Refusing" });
  });
});

describe("Seen working", () => {
  const rows = agentRows(agents).map((row) => ({ ...row, lastScreenedAt: undefined }));

  it("reads the channel's newest decision, for a hook that does not name its agent", () => {
    const [hook] = communityControls({ agents: rows, channelSeen: { hook: "2026-09-29T13:05:00Z" }, now: NOW });
    const seen = hook.ladder?.find((step) => step.key === "seen");
    expect(seen?.mark).toBe("done");
    expect(seen?.words).not.toMatch(/build/);
  });

  it("says what the record shows when nothing was screened lately, and never blames the build", () => {
    const [stale] = communityControls({ agents: rows, channelSeen: { hook: "2026-09-20T13:05:00Z" }, now: NOW });
    expect(stale.ladder?.find((step) => step.key === "seen")).toMatchObject({ mark: "unknown", words: "nothing screened in the last 24 hours" });
    const [never] = communityControls({ agents: rows, channelSeen: {}, now: NOW });
    expect(never.ladder?.find((step) => step.key === "seen")).toMatchObject({ mark: "unknown", words: "nothing screened yet" });
  });
});

describe("the other controls", () => {
  const protection = readProtection(protectionFixture);

  it("offers a template, never a command to copy as it is, where the reader must fill something in", () => {
    const controls = communityControls({ agents: agentRows(agents), protection, now: NOW });
    const jail = controls.find((control) => control.key === "ai_jail")!;
    expect(jail.command).toMatchObject({ command: "innerwarden contain -- <command>", template: true });
    expect(jail.line).toContain("for Claude Code; other agents get the walls");
    const second = communityControls({ agents: [], protection: { ...protection, secondOpinion: { configured: false } }, now: NOW })
      .find((control) => control.key === "second_opinion")!;
    expect(second.command).toMatchObject({ command: "innerwarden llm set --url <URL> --model <MODEL>", template: true });
  });

  /** `observe install` exits 1 with no OpenClaw config: never offered, never counted as off. */
  it("never offers observe install where there is no OpenClaw, and leaves it out of the ring", () => {
    const none = { ...protection, observe: { installed: false, available: false } };
    const messages = communityControls({ agents: [], protection: none, now: NOW }).find((control) => control.key === "messages")!;
    expect(messages.command).toBeUndefined();
    expect(messages.state).toBe("none");
    expect(messages.status).toBe("Needs OpenClaw");
    const here = { ...protection, observe: { installed: false, available: true } };
    const offered = communityControls({ agents: [], protection: here, now: NOW }).find((control) => control.key === "messages")!;
    expect(offered.command?.command).toBe("innerwarden observe install");
    expect(offered.state).toBe("off");
  });

  it("says no count of messages it did not read", () => {
    const installed = { ...protection, observe: { installed: true, available: true } };
    const unread = communityControls({ agents: [], protection: installed, now: NOW }).find((control) => control.key === "messages")!;
    expect(unread.line).not.toMatch(/\d/);
    const read = communityControls({ agents: [], protection: installed, messagesRecorded: 4, now: NOW }).find((control) => control.key === "messages")!;
    expect(read.line).toContain("4 recorded");
  });
});
