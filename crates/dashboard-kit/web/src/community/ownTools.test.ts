import { describe, expect, it } from "vitest";
import { readAgentFacts, readOwnTools } from "./api";
import { ownToolsLine, PRO_PRICING_URL, suggestionParts } from "./ownTools";

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

const ROW = {
  id: "openclaw",
  display_name: "OpenClaw",
  guardrail: { mode: "monitor", mechanism: "mcp_proxy" },
  own_tools: {
    screened: true,
    mode: "monitor",
    turned_off: false,
    pro_installed: false,
    pro_line: null,
    suggestion: "InnerWarden Pro adds a kernel gate on Linux: a program this agent was never allowed to run does not start. https://www.innerwarden.com/pricing",
  },
};

describe("OpenClaw's own tools on its card", () => {
  it("are read from the OpenClaw row only", () => {
    expect(readAgentFacts(ROW)?.ownTools).toEqual({
      screened: true,
      mode: "monitor",
      turnedOff: false,
      suggestion: ROW.own_tools.suggestion,
    });
    expect(readAgentFacts({ ...ROW, id: "claude-code", display_name: "Claude Code" })?.ownTools).toBeUndefined();
  });

  it("are not read from an answer that is not their shape", () => {
    expect(readOwnTools(undefined)).toBeUndefined();
    expect(readOwnTools({ mode: "enforce" })).toBeUndefined();
    expect(readOwnTools({ screened: true, mode: "loud" })).toEqual({ screened: true, turnedOff: false });
  });

  it("say what is screened, in which mode, and never more", () => {
    expect(ownToolsLine({ screened: true, mode: "monitor", turnedOff: false })).toContain("recorded, never refused");
    expect(ownToolsLine({ screened: true, mode: "enforce", turnedOff: false })).toContain("a deny is refused, a review asks you");
    expect(ownToolsLine({ screened: false, turnedOff: false })).toContain("innerwarden agents connect openclaw");
    expect(ownToolsLine({ screened: false, turnedOff: true })).toContain("turned off");
    for (const tools of [
      { screened: true, mode: "monitor" as const, turnedOff: false },
      { screened: true, mode: "enforce" as const, turnedOff: false },
      { screened: false, turnedOff: false },
      { screened: false, turnedOff: true },
    ]) {
      expect(ownToolsLine(tools)).not.toMatch(DASHES);
      expect(ownToolsLine(tools)).not.toMatch(/\bblocked\b|protected\b|open source/i);
    }
  });

  it("show the suggestion's one link as a link, to the pricing page and nowhere else", () => {
    expect(suggestionParts(ROW.own_tools.suggestion)).toEqual({
      words: "InnerWarden Pro adds a kernel gate on Linux: a program this agent was never allowed to run does not start.",
      href: PRO_PRICING_URL,
    });
    expect(PRO_PRICING_URL).toBe("https://www.innerwarden.com/pricing");
    expect(suggestionParts("Next step for InnerWarden Pro: rehearse.")).toEqual({ words: "Next step for InnerWarden Pro: rehearse." });
  });
});
