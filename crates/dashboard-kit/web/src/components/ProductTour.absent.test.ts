import { describe, expect, it } from "vitest";
import {
  COMMUNITY_TOUR_STEPS,
  OVERVIEW_AGENTS_TOUR_STEP_KEY,
  OVERVIEW_SENSOR_TOUR_STEP_KEY,
  PAID_SCREEN_TOUR_STEPS,
  TOUR_ABSENT_ATTRIBUTE,
  TOUR_FINISH_STEP_KEY,
  TOUR_WELCOME_STEP_KEY,
  declaredAbsent,
  dropStep,
  withoutAbsentSteps,
  type TourStep,
} from "./ProductTour";

/**
 * Three of the paid tour's nine steps pointed at nothing: "Agents on this
 * machine" and "Sensor activity" on an Overview that keeps both panels
 * behind the technical switch, and one on a screen the paid bundle adds. The
 * card floated over the page reading copy about panels that were not there,
 * and the counter counted them. A screen now says which steps it does not
 * render, and the tour drops them, from the walk and from the counter.
 */

const paidLike: readonly TourStep[] = [
  COMMUNITY_TOUR_STEPS[0],
  COMMUNITY_TOUR_STEPS[1],
  ...COMMUNITY_TOUR_STEPS.filter((step) => step.key === OVERVIEW_AGENTS_TOUR_STEP_KEY),
  ...PAID_SCREEN_TOUR_STEPS,
  COMMUNITY_TOUR_STEPS[COMMUNITY_TOUR_STEPS.length - 1],
];

function page(absent: string): Pick<ParentNode, "querySelector"> {
  const keys = absent.split(" ").filter((key) => key.length > 0);
  return {
    querySelector: (selector: string) => {
      const match = selector.match(new RegExp(`^\\[${TOUR_ABSENT_ATTRIBUTE}~="([^"]+)"\\]$`));
      return match !== null && keys.includes(match[1]) ? ({} as Element) : null;
    },
  };
}

describe("a step the screen says it does not render", () => {
  it("is read off the screen's own marker, by key", () => {
    const root = page(`${OVERVIEW_AGENTS_TOUR_STEP_KEY} ${OVERVIEW_SENSOR_TOUR_STEP_KEY}`);
    expect(declaredAbsent(OVERVIEW_AGENTS_TOUR_STEP_KEY, root)).toBe(true);
    expect(declaredAbsent(OVERVIEW_SENSOR_TOUR_STEP_KEY, root)).toBe(true);
    expect(declaredAbsent("posture", root)).toBe(false);
  });

  it("never splices a key that is not a plain token into a selector", () => {
    expect(declaredAbsent('x"] , [id="y', page("x"))).toBe(false);
  });

  /**
   * FAILS ON REVERT: open the tour on the table the shell offers alone and
   * the two Overview panels behind the switch are counted as steps.
   */
  it("is left out of the table the tour opens with, and the counter counts what is left", () => {
    const absent = new Set([OVERVIEW_AGENTS_TOUR_STEP_KEY, OVERVIEW_SENSOR_TOUR_STEP_KEY]);
    const table = withoutAbsentSteps(paidLike, (key) => absent.has(key));
    expect(table.map((step) => step.key)).not.toContain(OVERVIEW_AGENTS_TOUR_STEP_KEY);
    expect(table.map((step) => step.key)).not.toContain(OVERVIEW_SENSOR_TOUR_STEP_KEY);
    expect(table).toHaveLength(paidLike.length - 2);
  });

  it("never drops the opening or closing card, which point at nothing by design", () => {
    const table = withoutAbsentSteps(paidLike, () => true);
    expect(table.map((step) => step.key)).toEqual([TOUR_WELCOME_STEP_KEY, TOUR_FINISH_STEP_KEY]);
  });
});

describe("dropping a step on arrival", () => {
  const keys = (table: readonly TourStep[]) => table.map((step) => step.key);

  it("going forward, shows the next step in the same place and counts one fewer", () => {
    const at = paidLike.findIndex((step) => step.key === OVERVIEW_SENSOR_TOUR_STEP_KEY);
    const after = dropStep(paidLike, at, 1);
    expect(after.table).toHaveLength(paidLike.length - 1);
    expect(after.index).toBe(at);
    expect(after.table[after.index].key).toBe(paidLike[at + 1].key);
  });

  it("going back, shows the step before it", () => {
    const at = paidLike.findIndex((step) => step.key === OVERVIEW_SENSOR_TOUR_STEP_KEY);
    const after = dropStep(paidLike, at, -1);
    expect(after.table[after.index].key).toBe(paidLike[at - 1].key);
    expect(keys(after.table)).not.toContain(OVERVIEW_SENSOR_TOUR_STEP_KEY);
  });

  it("stays inside the table at either end, and ignores a position outside it", () => {
    const last = paidLike.length - 1;
    expect(dropStep(paidLike, last, 1).index).toBe(last - 1);
    expect(dropStep(paidLike, 0, -1).index).toBe(0);
    expect(dropStep(paidLike, 99, 1)).toEqual({ table: paidLike, index: 99 });
  });
});
