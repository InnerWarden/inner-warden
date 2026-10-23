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

function notice(state: PlanState, until?: string): PlanNotice {
  return { state, line: `The host says ${state}.`, step: "fixture-licence renew", ...(until === undefined ? {} : { until }) };
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
  it("draws nothing while the plan is absent or active", () => {
    const { views } = run([undefined, "active", "active", undefined]);
    expect(views.map((view) => view.kind)).toEqual(["none", "none", "none", "none"]);
  });

  /**
   * A licence state the host could not read is said as not read: never the
   * silence of a licensed host. Absent (an older host) stays silent. FAILS
   * ON REVERT of the unknown view.
   */
  it("says a licence state that was not read, and keeps silent for a host that never sends one", () => {
    const { views } = run([undefined, "unknown", "active"]);
    expect(views.map((view) => view.kind)).toEqual(["none", "unknown", "none"]);
    expect(views[1]).toEqual({ kind: "unknown", notice: notice("unknown") });
  });

  it("draws a valid licence that does not cover every paid function as its own notice", () => {
    const { views } = run(["active", "partly_covered", "active"]);
    expect(views.map((view) => view.kind)).toEqual(["none", "partly_covered", "none"]);
  });

  it("keeps free mode when the host's line was not usable", () => {
    const step = planStep("enterprise", { state: "free_mode" }, {}, T0);
    expect(step.view).toEqual({ kind: "free_mode", notice: { state: "free_mode" } });
    expect(editionLabelFor("Enterprise", step.view)).toBe("Enterprise, free mode");
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
    expect(run(["free_mode", "unknown"]).views[1].kind).toBe("unknown");
    expect(run(["free_mode", undefined]).views[1].kind).toBe("none");
    expect(run(["free_mode", "unknown", "active"]).views[2].kind).toBe("none");
    expect(run(["partly_covered", "active"]).views[1].kind).toBe("none");
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

  it("hides a state that was not read, and a partial grant, until the state changes", () => {
    for (const state of ["unknown", "partly_covered"] as const) {
      const shown = run([state]);
      const step = hidePlan({ view: shown.views[0], memory: shown.memory });
      expect(step.view.kind).toBe("none");
      expect(planStep("enterprise", notice(state), step.memory, T0 + 60_000).view.kind).toBe("none");
      expect(planStep("enterprise", notice("free_mode"), step.memory, T0 + 2 * 60_000).view.kind).toBe("free_mode");
    }
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

  it("re-reads every minute in free mode, while a licence state is not read, or while a renewal shows", () => {
    expect(bootstrapRefreshMs(run(["free_mode"]).memory, T0, BASE)).toBe(PLAN_RECHECK_MS);
    expect(bootstrapRefreshMs(run(["unknown"]).memory, T0, BASE)).toBe(PLAN_RECHECK_MS);
    const renewed = run(["free_mode", "active"]).memory;
    expect(bootstrapRefreshMs(renewed, T0 + 2 * 60_000, BASE)).toBe(PLAN_RECHECK_MS);
    expect(bootstrapRefreshMs(renewed, T0 + 60_000 + RENEWED_SHOW_MS, BASE)).toBe(BASE);
    expect(bootstrapRefreshMs(run(["partly_covered"]).memory, T0, BASE)).toBe(BASE);
  });

  /**
   * A licence that ends soon moves to free mode at a known time: the base
   * cadence until shortly after `until`, never every minute for a whole
   * trial, and never faster than a minute.
   */
  it("keeps the base cadence while the licence ends soon, and reads again soon after it ends", () => {
    const far = planStep("enterprise", notice("ending_soon", "2026-11-23T00:00:00Z"), {}, T0).memory;
    expect(bootstrapRefreshMs(far, T0, BASE)).toBe(BASE);
    const until = T0 + 2 * 60_000;
    const near = planStep("enterprise", notice("ending_soon", new Date(until).toISOString()), {}, T0).memory;
    expect(bootstrapRefreshMs(near, T0, BASE)).toBe(until - T0 + 5_000);
    expect(bootstrapRefreshMs(near, until + 60 * 60_000, BASE)).toBe(PLAN_RECHECK_MS);
    expect(bootstrapRefreshMs(run(["ending_soon"]).memory, T0, BASE)).toBe(BASE);
  });
});

describe("the edition label", () => {
  it("says free mode only in free mode", () => {
    expect(editionLabelFor("Enterprise", { kind: "free_mode", notice: notice("free_mode") })).toBe("Enterprise, free mode");
    expect(editionLabelFor("Enterprise", { kind: "ending_soon", notice: notice("ending_soon") })).toBe("Enterprise");
    expect(editionLabelFor("Enterprise", { kind: "unknown", notice: notice("unknown") })).toBe("Enterprise");
    expect(editionLabelFor("Enterprise", { kind: "partly_covered", notice: notice("partly_covered") })).toBe("Enterprise");
    expect(editionLabelFor("Enterprise", { kind: "renewed", readAt: T0 })).toBe("Enterprise");
    expect(editionLabelFor("Community", { kind: "none" })).toBe("Community");
  });
});
