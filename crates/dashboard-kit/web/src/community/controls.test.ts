import { describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import agentsFixture from "../../tests/fixtures/community/agents.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import { readAgentsFacts, readHistory, readProtection, type AgentFacts, type Protection } from "./api";
import historyFixture from "../../tests/fixtures/community/history.json";
import {
  agentSeen,
  alertsControl,
  countsAsRefusing,
  JAIL_ALIAS_WORDS,
  jailControl,
  messagesControl,
  optionalSummary,
  SCREENING_PILL,
  SCREENING_STATES,
  SCREENING_WORDS,
  screeningRows,
  screeningState,
  secondOpinionControl,
} from "./controls";
import { modeBox } from "./verdict";
import { ENFORCE_MEANS, MONITOR_MEANS } from "./words";

const NOW = Date.parse("2026-09-29T14:05:00Z");
const facts = readAgentsFacts(agentsFixture);

describe("the mode box (spec 6.2, section 1)", () => {
  const clock = () => "14:05";
  const monitorOnly = facts.agents.filter((agent) => agent.id === "claude-code");
  const enforceOnly = facts.agents.filter((agent) => agent.id === "cursor" || agent.id === "gemini");

  it("says monitor for every agent, the switch with every agent's restart, and the way back", () => {
    const box = modeBox({ agents: monitorOnly, failed: false, now: NOW, clock });
    expect(box.headline).toBe("Monitor for Claude Code.");
    expect(box.action?.steps[0].step.command).toBe("innerwarden enforce");
    expect(box.action?.steps[0].restarts.map((restart) => restart.agent)).toEqual(["Claude Code"]);
    expect(box.action?.back?.command).toBe("innerwarden dry-run");
    const two = modeBox({ agents: [...monitorOnly, { ...monitorOnly[0], id: "codex", name: "Codex" }], failed: false, now: NOW, clock });
    expect(two.headline).toBe("Monitor for all 2 agents.");
  });

  it("says enforce for every agent, with the way back to monitor as the step", () => {
    const box = modeBox({ agents: enforceOnly, failed: false, now: NOW, clock });
    expect(box.headline).toBe("Enforce for all 2 agents.");
    expect(box.tone).toBe("stopped");
    expect(box.action?.steps[0].step.command).toBe("innerwarden dry-run");
    expect(box.action?.back?.command).toBe("innerwarden enforce");
  });

  it("names who refuses and who records when the modes differ, and a partly connected agent apart", () => {
    const box = modeBox({ agents: facts.agents, failed: false, now: NOW, clock });
    expect(box.headline).toBe("Mixed: Cursor and Gemini CLI are set to refuse a deny, Claude Code is in monitor.");
    expect(box.lines).toEqual(["Codex is only partly connected. Its step is under Screening."]);
    // Claude Code has a switch of its own: it is offered, and the way back for
    // every agent carries every agent's restart words.
    const steps = box.action?.steps ?? [];
    expect(steps.map(({ step }) => step.command)).toEqual(["innerwarden agents connect claude-code", "innerwarden dry-run"]);
    expect(steps[0].restarts.map((restart) => restart.agent)).toEqual(["Claude Code"]);
    expect(steps[1].restarts).toHaveLength(4);
  });

  it("never counts what it could not read as monitor or enforce", () => {
    expect(modeBox({ agents: undefined, failed: false, now: NOW }).row).toBe(0);
    const failed = modeBox({ agents: undefined, failed: true, now: NOW, clock });
    expect(failed.tone).toBe("unknown");
    expect(failed.headline).toBe("The mode could not be read");
    expect(failed.lines.join(" ")).not.toMatch(/monitor\.|Monitor for|Enforce for/);
    expect(modeBox({ agents: [], failed: false, now: NOW }).headline).toBe("No AI agent is connected yet");
    // The two definitions are the page's, said beside the box, word for word.
    expect(MONITOR_MEANS).toBe("Monitor is a dry run: every command is checked and recorded, and none is stopped.");
    expect(ENFORCE_MEANS).toContain("a deny is refused before it runs");
  });
});

describe("the screening rows", () => {
  it("offers each agent its own switch only where the CLI sends one, with its restart words", () => {
    const rows = screeningRows(facts.agents, facts.unnamed);
    const without = screeningRows(facts.agents.map((agent) => ({ ...agent, modeSteps: undefined })), facts.unnamed);
    expect(rows.find((row) => row.agent.id === "cursor")?.step?.command).toBe("innerwarden agents connect cursor --monitor");
    expect(without.find((row) => row.agent.id === "cursor")?.step).toBeUndefined();
    // A partly connected agent still gets the step that finishes connecting it.
    expect(without.find((row) => row.agent.id === "codex")?.step?.command).toBe("innerwarden agents connect codex --monitor");
    expect(rows.find((row) => row.agent.id === "codex")?.restart.how).toBe("Quit Codex and start it again.");
  });
});

describe("the optional defences", () => {
  const protection = readProtection(protectionFixture);
  const history = readHistory(historyFixture);

  /** FAILS ON REVERT: read an absent `checks_pass` as true and an unchecked jail is called ready. */
  it("calls the jail ready only when its checks passed, and not checked here yet otherwise", () => {
    const jail = (checksPass: boolean | undefined, available = true): Protection["jail"] => ({
      ...protection.jail,
      available,
      ...(checksPass === undefined ? { checksPass: undefined } : { checksPass }),
    });
    expect(jailControl(jail(true), false)).toMatchObject({ pill: "on", words: "Ready", line: "Ready: the checks a jail needs pass on this machine (sandbox-exec)." });
    expect(jailControl(jail(undefined), false)).toMatchObject({ pill: "unknown", words: "Not checked here yet", line: "Not checked here yet (sandbox-exec found)." });
    const failing = jailControl({ ...jail(false), advice: ["Install bubblewrap."] }, false);
    expect(failing).toMatchObject({ pill: "needs", line: "Needs you: a jail does not start here yet.", more: ["Install bubblewrap."] });
    expect(jailControl(jail(true, false), true)).toMatchObject({ pill: "not_available", line: "Not available on this system." });
    expect(jailControl(jail(true, false), true).step).toBeUndefined();
    expect(jailControl(undefined, true).words).toBe("Not read");
  });

  it("offers a template, never a command to copy as it is, and the Claude Code alias only where Claude Code is", () => {
    const ready = jailControl(protection.jail, true);
    expect(ready.step?.command).toBe("innerwarden contain -- <command>");
    expect(ready.step?.line).toContain("The guard runs inside the jail for Claude Code; other agents get the jail's walls.");
    expect(ready.tip).toBe(JAIL_ALIAS_WORDS);
    expect(jailControl(protection.jail, false).tip).toBeUndefined();
    expect(secondOpinionControl({ configured: false }).step?.command).toBe("innerwarden llm set --url <URL> --model <MODEL>");
  });

  /** CJC-090-J012: a count only, never a channel's name. */
  it("says alerts as a count, off as neutral, and an unsaid count as not read", () => {
    expect(alertsControl({ channels: 0 })).toMatchObject({ pill: "off", line: "Off: no alert channel is set up." });
    expect(alertsControl({ channels: 0 }).step?.command).toBe("innerwarden notify");
    expect(alertsControl({ channels: 2 }).line).toBe("On: 2 channels set up. A deny is sent; reviews only if you set that up.");
    expect(alertsControl({}).words).toBe("Not read");
    expect(alertsControl(undefined).pill).toBe("unknown");
  });

  it("offers observe install only where OpenClaw is, with the gateway's restart, and counts only what it read", () => {
    const none = messagesControl({ ...protection, observe: { installed: false, available: false } }, history);
    expect(none).toMatchObject({ pill: "not_available", line: "Not available here: needs OpenClaw." });
    expect(none.step).toBeUndefined();
    const off = messagesControl({ ...protection, observe: { installed: false, available: true } }, history);
    expect(off.step?.command).toBe("innerwarden observe install");
    expect(off.restarts.map((restart) => restart.agent)).toEqual(["the OpenClaw gateway"]);
    expect(messagesControl(protection, history).line).toBe("Recording: 4 messages since 30 Jul.");
    expect(messagesControl(protection, undefined).line).toBe("Recording.");
  });

  it("names the optional defences in one sentence, and messages only where they can be recorded", () => {
    const controls = [jailControl(protection.jail, false), alertsControl(protection.alerts), secondOpinionControl(protection.secondOpinion)];
    expect(optionalSummary(controls)).toBe("Optional: AI Jail ready, alerts off, second opinion off.");
    const none = messagesControl({ ...protection, observe: { installed: false, available: false } }, history);
    expect(optionalSummary([...controls, none])).toBe("Optional: AI Jail ready, alerts off, second opinion off.");
  });
});

describe("one agent's screening, in six states (spec 6.2)", () => {
  const base: AgentFacts = {
    id: "claude-code",
    name: "Claude Code",
    mode: "enforce",
    mechanism: "hook",
    supported: true,
    present: true,
    installed: true,
    running: null,
    configChangedAt: "2026-09-29T11:05:00Z",
    lastObservedAt: "2026-09-29T14:03:00Z",
  };
  const byId = Object.fromEntries(facts.agents.map((agent) => [agent.id, agent]));

  it("refuses a deny only in enforce and seen working since its settings changed", () => {
    expect(screeningState(base, {})).toBe("refusing");
    expect(screeningState(byId.cursor, facts.unnamed)).toBe("refusing");
  });

  /** FAILS ON REVERT: without the seen rule, a connected agent nothing came through read as refusing. */
  it("calls a connected agent nothing came through unknown, never refusing and never on", () => {
    const never = { ...base, lastObservedAt: undefined };
    expect(screeningState(never, {})).toBe("unknown");
    expect(screeningState(byId.gemini, facts.unnamed)).toBe("unknown");
    // Seen, but before its settings changed: not seen since.
    expect(screeningState({ ...base, lastObservedAt: "2026-09-29T11:00:00Z" }, {})).toBe("unknown");
    // A screening on its channel that names nobody could be its own: still not counted.
    expect(screeningState(never, { hook: "2026-09-29T14:00:00Z" })).toBe("unknown");
    expect(agentSeen(never, { hook: "2026-09-29T14:00:00Z" })).toBe("not_reported");
    expect(agentSeen(never, { hook: "2026-09-29T10:00:00Z" })).toBe("not_seen");
    expect(agentSeen(never, undefined)).toBe("not_reported");
  });

  it("never counts monitor as refusing", () => {
    const monitor = { ...base, mode: "monitor" as const };
    expect(screeningState(monitor, {})).toBe("monitor");
    expect(countsAsRefusing(screeningState(monitor, {}))).toBe(false);
    expect(countsAsRefusing(screeningState({ ...base, mode: "mixed" }, {}))).toBe(false);
    expect(screeningState(byId["claude-code"], facts.unnamed)).toBe("monitor");
  });

  it("needs a person for a partial connection or a local server left unwrapped", () => {
    expect(screeningState(byId.codex, facts.unnamed)).toBe("needs_you");
    expect(screeningState({ ...base, mechanism: "mcp", mcp: { stdio: 3, wrapped: 2, remote: 0 } }, {})).toBe("needs_you");
  });

  it("draws off as neutral, unsupported as not available, and an unreadable row as unknown", () => {
    expect(screeningState({ ...base, mode: "not_configured" }, {})).toBe("off");
    expect(SCREENING_PILL.off).toBe("off");
    expect(screeningState({ ...base, mode: "not_configured", supported: false }, {})).toBe("not_available");
    expect(screeningState({ ...base, mode: "unknown" }, {})).toBe("unknown");
    expect(screeningState(undefined, {})).toBe("unknown");
    expect(SCREENING_PILL.unknown).toBe("unknown");
  });

  it("says a proxy with no local MCP server has nothing to screen, a fact and not a fault", () => {
    expect(agentSeen({ ...base, mechanism: "mcp", mcp: { stdio: 0, wrapped: 0, remote: 2 } }, {})).toBe("nothing_to_screen");
  });

  it("has words and a pill for every state", () => {
    for (const state of SCREENING_STATES) {
      expect(SCREENING_WORDS[state]).toBeTruthy();
      expect(SCREENING_PILL[state]).toBeTruthy();
    }
  });
});
