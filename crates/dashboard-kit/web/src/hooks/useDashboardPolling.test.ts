import { afterEach, describe, expect, it, vi } from "vitest";
import {
  calculatePollingDelay,
  createDashboardPoller,
  type DashboardPollingState,
} from "./useDashboardPolling";

type Projection = { value: number; fresh: boolean };

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function settlePromises() {
  await Promise.resolve();
  await Promise.resolve();
}

function pollerOptions(
  fetcher: (signal: AbortSignal) => Promise<Projection>,
  onState?: (state: DashboardPollingState<Projection>) => void,
) {
  return {
    fetcher,
    isFresh: (projection: Projection) => projection.fresh,
    onState,
    baseIntervalMs: 1_000,
    maxBackoffMs: 8_000,
    jitterRatio: 0,
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("calculatePollingDelay", () => {
  it("keeps jitter within the configured bounds", () => {
    expect(calculatePollingDelay(1, 1_000, 30_000, 0.2, () => 0)).toBe(800);
    expect(calculatePollingDelay(1, 1_000, 30_000, 0.2, () => 1)).toBe(1_200);
    expect(calculatePollingDelay(4, 1_000, 30_000, 0.2, () => 0)).toBe(6_400);
    expect(calculatePollingDelay(4, 1_000, 30_000, 0.2, () => 1)).toBe(9_600);
  });

  it("caps exponential backoff after applying bounded jitter", () => {
    expect(calculatePollingDelay(6, 1_000, 30_000, 0.2, () => 0)).toBe(24_000);
    expect(calculatePollingDelay(6, 1_000, 30_000, 0.2, () => 1)).toBe(30_000);
    expect(calculatePollingDelay(100, 1_000, 30_000, 0, () => 0.5)).toBe(30_000);
  });

  it("rejects invalid attempts, timing, jitter and injected randomness", () => {
    expect(() => calculatePollingDelay(0, 1_000, 30_000, 0.2, () => 0.5)).toThrow(/attempt/);
    expect(() => calculatePollingDelay(1, 0, 30_000, 0.2, () => 0.5)).toThrow(/base/);
    expect(() => calculatePollingDelay(1, 1_000, 500, 0.2, () => 0.5)).toThrow(/maximum/);
    expect(() => calculatePollingDelay(1, 1_000, 30_000, 1.1, () => 0.5)).toThrow(/jitter/);
    expect(() => calculatePollingDelay(1, 1_000, 30_000, 0.2, () => -0.1)).toThrow(/random/);
  });
});

describe("createDashboardPoller", () => {
  it("starts immediately and never overlaps an in-flight request", async () => {
    vi.useFakeTimers();
    const first = deferred<Projection>();
    const second = deferred<Projection>();
    const fetcher = vi.fn()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const poller = createDashboardPoller(pollerOptions(fetcher));

    poller.start();
    expect(fetcher).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetcher).toHaveBeenCalledTimes(1);

    first.resolve({ value: 1, fresh: true });
    await settlePromises();
    expect(poller.snapshot()).toMatchObject({
      data: { value: 1, fresh: true },
      status: "fresh",
      inFlight: false,
      nextDelayMs: 1_000,
    });

    await vi.advanceTimersByTimeAsync(999);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetcher).toHaveBeenCalledTimes(2);

    poller.stop("test-complete");
  });

  it("aborts the active request on cleanup and ignores its late completion", async () => {
    const request = deferred<Projection>();
    let signal: AbortSignal | undefined;
    const states: DashboardPollingState<Projection>[] = [];
    const poller = createDashboardPoller(pollerOptions((requestSignal) => {
      signal = requestSignal;
      return request.promise;
    }, (state) => states.push(state)));

    poller.start();
    const emissionsBeforeStop = states.length;
    poller.stop("unmount");

    expect(signal?.aborted).toBe(true);
    expect(poller.snapshot()).toMatchObject({ inFlight: false, nextDelayMs: null });

    request.resolve({ value: 99, fresh: true });
    await settlePromises();
    expect(states).toHaveLength(emissionsBeforeStop);
    expect(poller.snapshot().data).toBeUndefined();
  });

  it("cancels an already scheduled refresh during cleanup", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn().mockResolvedValue({ value: 1, fresh: true });
    const poller = createDashboardPoller(pollerOptions(fetcher));

    poller.start();
    await settlePromises();
    expect(fetcher).toHaveBeenCalledTimes(1);

    poller.stop("unmount");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("aborts the old navigation scope without leaking its response into the new scope", async () => {
    const oldRequest = deferred<Projection>();
    const newRequest = deferred<Projection>();
    let oldSignal: AbortSignal | undefined;
    const oldStates: DashboardPollingState<Projection>[] = [];
    const newStates: DashboardPollingState<Projection>[] = [];
    const oldPoller = createDashboardPoller(pollerOptions((signal) => {
      oldSignal = signal;
      return oldRequest.promise;
    }, (state) => oldStates.push(state)));

    oldPoller.start();
    oldPoller.stop("navigation");
    const oldEmissionCount = oldStates.length;

    const newPoller = createDashboardPoller(pollerOptions(() => newRequest.promise, (state) => newStates.push(state)));
    newPoller.start();
    newRequest.resolve({ value: 2, fresh: true });
    await settlePromises();

    oldRequest.resolve({ value: 1, fresh: true });
    await settlePromises();

    expect(oldSignal?.aborted).toBe(true);
    expect(oldStates).toHaveLength(oldEmissionCount);
    expect(oldPoller.snapshot().data).toBeUndefined();
    expect(newPoller.snapshot()).toMatchObject({ data: { value: 2, fresh: true }, status: "fresh" });

    newPoller.stop("test-complete");
  });

  it("backs off to the cap and resets only after a fresh producer response", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn()
      .mockRejectedValueOnce(new Error("offline-1"))
      .mockResolvedValueOnce({ value: 2, fresh: false })
      .mockRejectedValueOnce(new Error("offline-3"))
      .mockResolvedValueOnce({ value: 4, fresh: false })
      .mockResolvedValueOnce({ value: 5, fresh: true });
    const poller = createDashboardPoller(pollerOptions(fetcher));

    poller.start();
    await settlePromises();
    expect(poller.snapshot()).toMatchObject({ status: "degraded", backoffAttempt: 1, nextDelayMs: 1_000 });

    await vi.advanceTimersByTimeAsync(1_000);
    expect(poller.snapshot()).toMatchObject({ status: "stale", backoffAttempt: 2, nextDelayMs: 2_000 });

    await vi.advanceTimersByTimeAsync(2_000);
    expect(poller.snapshot()).toMatchObject({ status: "stale", backoffAttempt: 3, nextDelayMs: 4_000 });

    await vi.advanceTimersByTimeAsync(4_000);
    expect(poller.snapshot()).toMatchObject({ status: "stale", backoffAttempt: 4, nextDelayMs: 8_000 });

    await vi.advanceTimersByTimeAsync(8_000);
    expect(poller.snapshot()).toMatchObject({
      data: { value: 5, fresh: true },
      status: "fresh",
      backoffAttempt: 0,
      nextDelayMs: 1_000,
      error: null,
    });

    poller.stop("test-complete");
  });

  it("uses the injected random source for deterministic controller jitter", async () => {
    const random = vi.fn(() => 0);
    const poller = createDashboardPoller({
      ...pollerOptions(() => Promise.reject(new Error("offline"))),
      jitterRatio: 0.2,
      random,
    });

    poller.start();
    await settlePromises();

    expect(random).toHaveBeenCalledOnce();
    expect(poller.snapshot()).toMatchObject({ backoffAttempt: 1, nextDelayMs: 800 });
    poller.stop("test-complete");
  });

  it("retains the last validated payload as explicitly stale after a refresh failure", async () => {
    vi.useFakeTimers();
    const failure = new Error("refresh failed");
    const fetcher = vi.fn()
      .mockResolvedValueOnce({ value: 41, fresh: true })
      .mockRejectedValueOnce(failure);
    const states: DashboardPollingState<Projection>[] = [];
    const poller = createDashboardPoller(pollerOptions(fetcher, (state) => states.push(state)));

    poller.start();
    await settlePromises();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(poller.snapshot()).toMatchObject({
      data: { value: 41, fresh: true },
      status: "stale",
      error: failure,
      backoffAttempt: 1,
    });
    expect(states.some((state) => state.status === "degraded")).toBe(false);

    poller.stop("test-complete");
  });

  it("uses degraded only when no validated last-known payload exists", async () => {
    const failure = new Error("initial request failed");
    const poller = createDashboardPoller(pollerOptions(() => Promise.reject(failure)));

    poller.start();
    await settlePromises();

    expect(poller.snapshot()).toMatchObject({
      data: undefined,
      status: "degraded",
      error: failure,
      backoffAttempt: 1,
    });
    poller.stop("test-complete");
  });
});
