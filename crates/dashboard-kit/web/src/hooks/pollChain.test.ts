import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pollChain } from "./pollChain";
import { META_POLL_MS } from "../App";

/**
 * The shell's `guard/meta` poll, and every Community page's, is a CHAIN: the
 * next request is asked for exactly the interval after the previous one
 * settles. The old `setInterval` with an in-flight guard dropped the tick that
 * fired while a slow answer was in flight, so the second request came at
 * 5,876 ms instead of 5,000, and a journey counting one request per interval
 * failed at random.
 */
describe("a poll that waits for its answer", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("asks again exactly one interval after the previous answer, never two at once", async () => {
    const started: number[] = [];
    let inFlight = 0;
    let most = 0;
    const load = () => {
      started.push(Date.now());
      inFlight += 1;
      most = Math.max(most, inFlight);
      // A slow answer: 600 ms, longer than any tick could wait.
      return new Promise<void>((resolve) => setTimeout(() => {
        inFlight -= 1;
        resolve();
      }, 600));
    };
    const t0 = Date.now();
    const stop = pollChain(load, META_POLL_MS);
    await vi.advanceTimersByTimeAsync(600 + META_POLL_MS + 600 + META_POLL_MS + 10);
    stop();
    expect(started.map((at) => at - t0)).toEqual([0, 5_600, 11_200]);
    expect(most).toBe(1);
  });

  it("keeps going after a failed answer, and stops when asked", async () => {
    let calls = 0;
    const stop = pollChain(() => {
      calls += 1;
      return Promise.reject(new Error("no answer"));
    }, 1_000);
    await vi.advanceTimersByTimeAsync(2_500);
    expect(calls).toBe(3);
    stop();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(calls).toBe(3);
  });

  it("never schedules after being stopped mid-request", async () => {
    let calls = 0;
    const stop = pollChain(() => {
      calls += 1;
      return new Promise<void>((resolve) => setTimeout(resolve, 100));
    }, 1_000);
    stop();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toBe(1);
  });
});
