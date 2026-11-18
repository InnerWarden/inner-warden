import { describe, expect, it } from "vitest";
import openapi from "../../../contracts/v1/dashboard-core-v1.openapi.yaml?raw";
import { PLAN_LINE_MAX, PLAN_STATES, PLAN_STEP_MAX } from "./v1";

/**
 * The plan notice's words, held to the contract the paid side validates its
 * bootstrap against: the same states and the same bounds, so a notice the
 * host may send is never one this reader drops, and the other way round.
 */
function planNoticeSchema(): string {
  const start = openapi.indexOf("    PlanNotice:\n");
  expect(start, "the contract names PlanNotice").toBeGreaterThan(-1);
  const rest = openapi.slice(start + 1);
  const end = rest.search(/\n {4}[A-Za-z]+:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

describe("the plan notice and its contract", () => {
  it("lists the same states, in the same order, as PLAN_STATES", () => {
    const states = /state: \{ type: string, enum: \[([^\]]+)\] \}/.exec(planNoticeSchema())?.[1].split(",").map((state) => state.trim());
    expect(states).toEqual([...PLAN_STATES]);
  });

  it("bounds the line and the step as the reader does", () => {
    const schema = planNoticeSchema();
    expect(/line: \{ type: string, minLength: 1, maxLength: (\d+) \}/.exec(schema)?.[1]).toBe(String(PLAN_LINE_MAX));
    expect(/step: \{ type: string, minLength: 1, maxLength: (\d+) \}/.exec(schema)?.[1]).toBe(String(PLAN_STEP_MAX));
    expect(schema).toContain("additionalProperties: false");
  });
});
