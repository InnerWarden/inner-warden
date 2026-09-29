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
  readAttemptsPage,
  readDecision,
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

  it("refuses text carrying control characters", () => {
    const item = { ...page1.items[0], command: "ls‮malicious" };
    expect(readDecision(item)).toBeUndefined();
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
