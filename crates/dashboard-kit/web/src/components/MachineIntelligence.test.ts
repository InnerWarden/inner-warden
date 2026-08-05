import { describe, expect, it } from "vitest";
import {
  ERROR_BACKOFF_MAX_MS,
  ERROR_BACKOFF_START_MS,
  nextErrorDelay,
  shouldSurfaceError,
} from "./MachineIntelligence";

describe("polling against a failing endpoint", () => {
  it("gets quieter instead of louder", () => {
    // The reported symptom: the whole panel pulsed every few seconds, forever,
    // because a failure retried at a flat 5s and flipped the panel to an error
    // box each time. Backing off turns a permanently broken endpoint from
    // twelve requests a minute into one.
    let backoff = ERROR_BACKOFF_START_MS;
    const delays: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      const step = nextErrorDelay(backoff);
      delays.push(step.delay);
      backoff = step.next;
    }
    expect(delays).toEqual([5_000, 10_000, 20_000, 40_000, 60_000, 60_000]);
  });

  it("never waits longer than the cap", () => {
    expect(nextErrorDelay(ERROR_BACKOFF_MAX_MS * 10).delay).toBe(ERROR_BACKOFF_MAX_MS);
  });

  it("keeps what is on screen rather than emptying the panel", () => {
    // With data already rendered a transient failure must change nothing: the
    // numbers stay, slightly older, and the operator sees no event at all.
    expect(shouldSurfaceError(true)).toBe(false);
    // With nothing to show, "unavailable" is the honest state.
    expect(shouldSurfaceError(false)).toBe(true);
  });
});
