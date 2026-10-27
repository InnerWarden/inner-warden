import { describe, expect, it } from "vitest";
import type { PollTimers } from "../hooks/pollChain";
import { createSourceStore, MAX_BACKOFF_MS, SOURCES, type Visibility } from "./store";

/** Timers a test moves by hand: `advance(ms)` runs everything due. */
function manualTimers() {
  let now = 0;
  let nextId = 0;
  const pending = new Map<number, { at: number; callback: () => void }>();
  const timers: PollTimers = {
    setTimeout: (callback, ms) => {
      const id = nextId++;
      pending.set(id, { at: now + ms, callback });
      return id;
    },
    clearTimeout: (handle) => {
      pending.delete(handle as number);
    },
  };
  const delays: number[] = [];
  const wrapped: PollTimers = {
    setTimeout: (callback, ms) => {
      delays.push(ms);
      return timers.setTimeout(callback, ms);
    },
    clearTimeout: timers.clearTimeout,
  };
  async function advance(ms: number) {
    const until = now + ms;
    for (;;) {
      const due = [...pending.entries()].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (due === undefined) break;
      pending.delete(due[0]);
      now = due[1].at;
      due[1].callback();
      await settle();
    }
    now = until;
  }
  return { timers: wrapped, advance, delays, pending };
}

/** Let every promise that is ready settle. */
async function settle() {
  for (let index = 0; index < 10; index += 1) await Promise.resolve();
}

function visibility(hidden = false) {
  let isHidden = hidden;
  const waiting = new Set<() => void>();
  const value: Visibility = {
    hidden: () => isHidden,
    onVisible: (callback) => {
      waiting.add(callback);
      return () => waiting.delete(callback);
    },
  };
  return {
    value,
    show() {
      isHidden = false;
      for (const callback of [...waiting]) callback();
    },
  };
}

function counter(answers: (() => Promise<unknown>)[] = []) {
  let calls = 0;
  return {
    load: () => {
      calls += 1;
      const answer = answers.shift();
      return answer === undefined ? Promise.resolve({ n: calls }) : answer();
    },
    calls: () => calls,
  };
}

describe("one poller per source (spec 5.3)", () => {
  it("asks once per interval however many readers there are", async () => {
    const clock = manualTimers();
    const source = counter();
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    const stops = [store.subscribe("s", 15_000, () => undefined), store.subscribe("s", 15_000, () => undefined), store.subscribe("s", 15_000, () => undefined)];
    await settle();
    expect(source.calls()).toBe(1);
    await clock.advance(15_000);
    expect(source.calls()).toBe(2);
    await clock.advance(15_000);
    expect(source.calls()).toBe(3);
    for (const stop of stops) stop();
  });

  it("asks as often as the reader that asked most often", async () => {
    const clock = manualTimers();
    const source = counter();
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    store.subscribe("s", 60_000, () => undefined);
    store.subscribe("s", 15_000, () => undefined);
    await settle();
    await clock.advance(15_000);
    expect(clock.delays.at(-1)).toBe(15_000);
  });

  it("stops when the last reader leaves, and starts again with the next", async () => {
    const clock = manualTimers();
    const source = counter();
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    const first = store.subscribe("s", 15_000, () => undefined);
    const second = store.subscribe("s", 15_000, () => undefined);
    await settle();
    first();
    await clock.advance(15_000);
    expect(source.calls()).toBe(2);
    second();
    await clock.advance(60_000);
    expect(source.calls()).toBe(2);
    expect(clock.pending.size).toBe(0);
    // The last answer is still there for the next reader, and it asks again.
    expect(store.snapshot("s").data).toEqual({ n: 2 });
    store.subscribe("s", 15_000, () => undefined);
    await settle();
    expect(source.calls()).toBe(3);
  });

  it("asks nothing while the tab is hidden, and asks when it shows", async () => {
    const clock = manualTimers();
    const source = counter();
    const tab = visibility(true);
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: tab.value });
    store.subscribe("s", 15_000, () => undefined);
    await settle();
    await clock.advance(120_000);
    expect(source.calls()).toBe(0);
    expect(store.snapshot("s").loading).toBe(true);
    tab.show();
    await settle();
    expect(source.calls()).toBe(1);
  });

  it("keeps the last answer through failures and calls it stale only after three in a row", async () => {
    const clock = manualTimers();
    const fail = () => Promise.reject(new Error("down"));
    const source = counter([() => Promise.resolve({ ok: 1 }), fail, fail, fail]);
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    let told = 0;
    store.subscribe("s", 15_000, () => {
      told += 1;
    });
    await settle();
    expect(store.snapshot("s")).toEqual({ data: { ok: 1 }, loading: false, stale: false });
    await clock.advance(15_000);
    expect(store.snapshot("s").data).toEqual({ ok: 1 });
    expect(store.snapshot("s").stale).toBe(false);
    await clock.advance(30_000);
    expect(store.snapshot("s").stale).toBe(false);
    await clock.advance(60_000);
    expect(source.calls()).toBe(4);
    expect(store.snapshot("s").stale).toBe(true);
    expect(store.snapshot("s").data).toEqual({ ok: 1 });
    expect(told).toBeGreaterThan(0);
  });

  it("never makes up an answer: a source that never answered has an error and no data", async () => {
    const clock = manualTimers();
    const source = counter([() => Promise.reject(new Error("down"))]);
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    store.subscribe("s", 15_000, () => undefined);
    await settle();
    const snapshot = store.snapshot("s");
    expect(snapshot.data).toBeUndefined();
    expect(snapshot.error).toBeInstanceOf(Error);
    expect(snapshot.stale).toBe(false);
    expect(snapshot.loading).toBe(false);
  });

  it("backs off after a failure, twice the wait each time, two minutes at most", async () => {
    const clock = manualTimers();
    const fail = () => Promise.reject(new Error("down"));
    const source = counter([fail, fail, fail, fail, fail, fail]);
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    store.subscribe("s", 15_000, () => undefined);
    await settle();
    for (let index = 0; index < 5; index += 1) await clock.advance(MAX_BACKOFF_MS);
    expect(clock.delays.slice(0, 5)).toEqual([30_000, 60_000, 120_000, 120_000, 120_000]);
    // A success puts the cadence back.
    await clock.advance(MAX_BACKOFF_MS);
    await clock.advance(MAX_BACKOFF_MS);
    expect(clock.delays.at(-1)).toBe(15_000);
  });

  it("asks again now on refresh, keeping the answer on screen meanwhile", async () => {
    const clock = manualTimers();
    const source = counter();
    const store = createSourceStore({ s: source.load }, { timers: clock.timers, visibility: visibility().value });
    store.subscribe("s", 60_000, () => undefined);
    await settle();
    store.refresh("s");
    expect(store.snapshot("s").data).toEqual({ n: 1 });
    await settle();
    expect(source.calls()).toBe(2);
    expect(store.snapshot("s").data).toEqual({ n: 2 });
  });

  it("names every source the spec lists, at its interval", () => {
    expect(Object.fromEntries(Object.entries(SOURCES).map(([key, source]) => [key, source.intervalMs]))).toEqual({
      "record-health": 15_000,
      agents: 30_000,
      history: 60_000,
      protection: 60_000,
      overview: 30_000,
      suppress: 60_000,
      tokens: 300_000,
    });
  });
});
