import { describe, expect, it } from "vitest";
import type { PlanNotice, PlanState } from "./api/v1";
import {
  PLAN_RECHECK_MS,
  RENEWED_SHOW_MS,
  bootstrapRefreshMs,
  editionLabelFor,
  hidePlan,
  planStep,
  type PlanMemory,
  type PlanView,
} from "./plan";

const BASE = 5 * 60_000;
const T0 = Date.parse("2026-10-23T14:02:00Z");

function notice(state: PlanState): PlanNotice {
  return { state, line: `The host says ${state}.`, step: "fixture-licence renew" };
}

/** Feeds a sequence of readings through `planStep`, as the shell does, one minute apart. */
function run(states: readonly (PlanState | undefined)[], start: PlanMemory = {}): { views: PlanView[]; memory: PlanMemory } {
  let memory = start;
  const views: PlanView[] = [];
  states.forEach((state, index) => {
    const next = planStep("enterprise", state === undefined ? undefined : notice(state), memory, T0 + index * 60_000);
    memory = next.memory;
    views.push(next.view);
  });
  return { views, memory };
}

describe("the plan notice follows the host's state", () => {
  it("draws nothing while the plan is absent, active or unknown", () => {
    const { views } = run([undefined, "active", "unknown", "active", undefined]);
    expect(views.map((view) => view.kind)).toEqual(["none", "none", "none", "none", "none"]);
  });

  it("draws the host's notice while the licence ends soon, and free mode after it", () => {
    const { views } = run(["active", "ending_soon", "free_mode"]);
    expect(views.map((view) => view.kind)).toEqual(["none", "ending_soon", "free_mode"]);
    expect(views[2]).toEqual({ kind: "free_mode", notice: notice("free_mode") });
  });

  it("confirms a renewal from free mode, read at the time it was read, and never twice", () => {
    const { views } = run(["free_mode", "active", "active"]);
    expect(views[1]).toEqual({ kind: "renewed", readAt: T0 + 60_000 });
    expect(views[2]).toEqual({ kind: "renewed", readAt: T0 + 60_000 });
  });

  it("confirms a renewal from ending soon", () => {
    expect(run(["ending_soon", "active"]).views[1].kind).toBe("renewed");
  });

  it("drops the renewal after RENEWED_SHOW_MS", () => {
    const first = run(["free_mode", "active"]);
    const later = planStep("enterprise", notice("active"), first.memory, T0 + 60_000 + RENEWED_SHOW_MS);
    expect(later.view.kind).toBe("none");
  });

  it("never reads unknown, or a plan that stops being sent, as a renewal", () => {
    expect(run(["free_mode", "unknown"]).views[1].kind).toBe("none");
    expect(run(["free_mode", undefined]).views[1].kind).toBe("none");
    expect(run(["free_mode", "unknown", "active"]).views[2].kind).toBe("none");
  });

  it("keeps the last view when a read fails: the shell feeds the reading it retained", () => {
    // The renewal was read at T0 + 1 min; the next reads fail and the shell
    // hands the same retained bootstrap again. The confirmation keeps the
    // time it was read, and a hidden notice stays hidden.
    const renewed = run(["free_mode", "active"]);
    const retained = planStep("enterprise", notice("active"), renewed.memory, T0 + 5 * 60_000);
    expect(retained.view).toEqual({ kind: "renewed", readAt: T0 + 60_000 });

    const soon = run(["ending_soon"]);
    const hidden = hidePlan({ view: soon.views[0], memory: soon.memory }).memory;
    const again = planStep("enterprise", notice("ending_soon"), hidden, T0 + 60_000);
    expect(again.view.kind).toBe("none");
    expect(again.memory.hidden).toBe("ending_soon");
  });
});

describe("hiding a notice", () => {
  it("hides ending soon until the state changes", () => {
    const soon = run(["ending_soon"]);
    const hidden = hidePlan({ view: soon.views[0], memory: soon.memory }).memory;
    expect(planStep("enterprise", notice("free_mode"), hidden, T0 + 60_000).view.kind).toBe("free_mode");
  });

  it("hides the renewal", () => {
    const renewed = run(["free_mode", "active"]);
    const hidden = hidePlan({ view: renewed.views[1], memory: renewed.memory }).memory;
    expect(planStep("enterprise", notice("active"), hidden, T0 + 2 * 60_000).view.kind).toBe("none");
  });

  it("cannot hide free mode", () => {
    const free = run(["free_mode"]);
    const step = hidePlan({ view: free.views[0], memory: free.memory });
    expect(step.view.kind).toBe("free_mode");
    const hidden = step.memory;
    expect(hidden).toEqual(free.memory);
    expect(planStep("enterprise", notice("free_mode"), hidden, T0 + 60_000).view.kind).toBe("free_mode");
  });
});

describe("Community ignores a plan", () => {
  it("draws nothing and remembers nothing for a Community or unread edition", () => {
    for (const edition of ["community", undefined] as const) {
      const result = planStep(edition, notice("free_mode"), {}, T0);
      expect(result.view.kind).toBe("none");
      expect(result.memory).toEqual({});
      expect(bootstrapRefreshMs(result.memory, T0, BASE)).toBe(BASE);
    }
  });
});

describe("how often the bootstrap is read", () => {
  it("keeps the base cadence for a host that never sent a plan", () => {
    expect(bootstrapRefreshMs({}, T0, BASE)).toBe(BASE);
    expect(bootstrapRefreshMs(run([undefined, undefined]).memory, T0, BASE)).toBe(BASE);
    expect(bootstrapRefreshMs(run(["active"]).memory, T0, BASE)).toBe(BASE);
  });

  it("re-reads every minute while the licence ends soon, in free mode, or while a renewal shows", () => {
    expect(bootstrapRefreshMs(run(["ending_soon"]).memory, T0, BASE)).toBe(PLAN_RECHECK_MS);
    expect(bootstrapRefreshMs(run(["free_mode"]).memory, T0, BASE)).toBe(PLAN_RECHECK_MS);
    const renewed = run(["free_mode", "active"]).memory;
    expect(bootstrapRefreshMs(renewed, T0 + 2 * 60_000, BASE)).toBe(PLAN_RECHECK_MS);
    expect(bootstrapRefreshMs(renewed, T0 + 60_000 + RENEWED_SHOW_MS, BASE)).toBe(BASE);
  });
});

describe("the edition label", () => {
  it("says free mode only in free mode", () => {
    expect(editionLabelFor("Enterprise", { kind: "free_mode", notice: notice("free_mode") })).toBe("Enterprise, free mode");
    expect(editionLabelFor("Enterprise", { kind: "ending_soon", notice: notice("ending_soon") })).toBe("Enterprise");
    expect(editionLabelFor("Enterprise", { kind: "renewed", readAt: T0 })).toBe("Enterprise");
    expect(editionLabelFor("Community", { kind: "none" })).toBe("Community");
  });
});
