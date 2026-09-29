/**
 * A poll that waits for its answer before it schedules the next request.
 *
 * `setInterval` with an in-flight guard looks equivalent and is not: when an
 * answer lands just after a tick, that tick is dropped while the request is
 * in flight and the next one comes a whole interval later, so the gap between
 * two requests could be almost twice the interval, and a reader counting
 * requests saw "one per five seconds" fail at 5,876 ms. Here the next request
 * is scheduled exactly `delayMs` after the previous one SETTLES (answer or
 * failure), so there is never more than one in flight, and the cadence is the
 * one written down.
 *
 * `stop` clears the pending timer; an answer that lands after it is ignored
 * by the caller's own `active` check, and nothing is scheduled after it.
 */
export type PollTimers = {
  setTimeout: (callback: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
};

const defaultTimers: PollTimers = {
  setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

export function pollChain(load: () => Promise<unknown>, delayMs: number, timers: PollTimers = defaultTimers): () => void {
  let stopped = false;
  let handle: unknown;
  const run = () => {
    if (stopped) return;
    let settled: Promise<unknown>;
    try {
      settled = load();
    } catch {
      settled = Promise.resolve();
    }
    void Promise.resolve(settled)
      .catch(() => undefined)
      .then(() => {
        if (!stopped) handle = timers.setTimeout(run, delayMs);
      });
  };
  run();
  return () => {
    stopped = true;
    if (handle !== undefined) timers.clearTimeout(handle);
  };
}
