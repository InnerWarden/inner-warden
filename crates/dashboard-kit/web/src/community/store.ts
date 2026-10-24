import { useCallback, useSyncExternalStore } from "react";
import { fetchAgents, fetchOverview, fetchTokenIntelligence, type AgentsResponse, type Overview, type TokenIntelligenceResponse } from "../api";
import { pollChain, type PollTimers } from "../hooks/pollChain";
import { fetchHistory, fetchProtection, fetchRecordHealth, fetchSuppress, type History, type Protection, type RecordHealth, type Served, type SuppressList } from "./api";
import type { Polled } from "./poll";

/**
 * One poller per source, shared by every reader on the page (spec 5.3).
 *
 * The header, the notices and a page all read `record-health`; each used to
 * poll it for itself. Here a source is read by one chain (`pollChain`: the
 * next request is asked for a delay after the previous one settles, so a slow
 * answer never piles requests up), with:
 *  - reference-counted readers: the first starts it, the last stops it;
 *  - the smallest interval any reader asked for;
 *  - no request while the tab is hidden;
 *  - a backoff after a failure (twice the wait each time, at most 2 min);
 *  - the last answer kept through failures, and marked stale after 3 in a row
 *    following a success, so a page says it could not refresh instead of
 *    dropping what it showed.
 *
 * A read that depends on its own arguments (a filter, a cursor, an id) keeps
 * `usePolled` from `poll.ts`, so a new question drops the old answer.
 */

export type SourceData = {
  "record-health": RecordHealth;
  agents: AgentsResponse;
  history: History;
  protection: Protection;
  overview: Overview;
  suppress: Served<SuppressList>;
  tokens: TokenIntelligenceResponse;
};
export type SourceKey = keyof SourceData;

/** Each source's reader and its interval (spec 5.3). */
export const SOURCES: { [K in SourceKey]: { load: () => Promise<SourceData[K]>; intervalMs: number } } = {
  "record-health": { load: fetchRecordHealth, intervalMs: 15_000 },
  agents: { load: fetchAgents, intervalMs: 30_000 },
  history: { load: fetchHistory, intervalMs: 60_000 },
  protection: { load: fetchProtection, intervalMs: 60_000 },
  overview: { load: fetchOverview, intervalMs: 30_000 },
  suppress: { load: fetchSuppress, intervalMs: 60_000 },
  tokens: { load: fetchTokenIntelligence, intervalMs: 300_000 },
};

/** The longest a failing source waits before it asks again. */
export const MAX_BACKOFF_MS = 120_000;
/** Failures in a row, after a success, before the kept answer is called stale. */
export const STALE_AFTER_FAILURES = 3;

export type Snapshot<T> = { data?: T; error?: unknown; loading: boolean; stale: boolean };

/** Whether the page is hidden, and a way to wait until it is not. Injected for tests. */
export type Visibility = { hidden: () => boolean; onVisible: (callback: () => void) => () => void };

const documentVisibility: Visibility = {
  hidden: () => typeof document !== "undefined" && document.hidden,
  onVisible: (callback) => {
    if (typeof document === "undefined") return () => undefined;
    const onChange = () => {
      if (!document.hidden) callback();
    };
    document.addEventListener("visibilitychange", onChange);
    return () => document.removeEventListener("visibilitychange", onChange);
  },
};

const defaultTimers: PollTimers = {
  setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

type Entry = {
  load: () => Promise<unknown>;
  readers: Map<number, number>;
  listeners: Set<() => void>;
  snapshot: Snapshot<unknown>;
  failures: number;
  answered: boolean;
  stop?: () => void;
  /** Bumped when a chain stops, so an answer from an old chain is ignored. */
  generation: number;
  waitingForVisible?: () => void;
};

export type SourceStore = {
  /** Add a reader asking every `intervalMs`; returns the call that removes it. */
  subscribe: (key: string, intervalMs: number, listener: () => void) => () => void;
  snapshot: (key: string) => Snapshot<unknown>;
  /** Ask again now, keeping the answer on screen meanwhile. */
  refresh: (key: string) => void;
};

const INITIAL: Snapshot<unknown> = { loading: true, stale: false };

export function createSourceStore(
  loaders: Record<string, () => Promise<unknown>>,
  options: { timers?: PollTimers; visibility?: Visibility } = {},
): SourceStore {
  const timers = options.timers ?? defaultTimers;
  const visibility = options.visibility ?? documentVisibility;
  const entries = new Map<string, Entry>();
  let nextReader = 0;

  const entryFor = (key: string): Entry => {
    let entry = entries.get(key);
    if (entry === undefined) {
      const load = loaders[key];
      if (load === undefined) throw new Error(`no source named ${key}`);
      entry = { load, readers: new Map(), listeners: new Set(), snapshot: INITIAL, failures: 0, answered: false, generation: 0 };
      entries.set(key, entry);
    }
    return entry;
  };

  const publish = (entry: Entry, snapshot: Snapshot<unknown>) => {
    entry.snapshot = snapshot;
    for (const listener of [...entry.listeners]) listener();
  };

  const interval = (entry: Entry) => Math.min(...entry.readers.values());

  /** The wait before the next request: the interval, doubled per failure, at most `MAX_BACKOFF_MS`. */
  const delay = (entry: Entry) =>
    entry.failures === 0 ? interval(entry) : Math.min(MAX_BACKOFF_MS, interval(entry) * 2 ** entry.failures);

  const whenVisible = (entry: Entry): Promise<void> => {
    if (!visibility.hidden()) return Promise.resolve();
    return new Promise((resolve) => {
      const stopWaiting = visibility.onVisible(() => {
        stopWaiting();
        entry.waitingForVisible = undefined;
        resolve();
      });
      entry.waitingForVisible = () => {
        stopWaiting();
        resolve();
      };
    });
  };

  const once = (entry: Entry, generation: number) => async () => {
    await whenVisible(entry);
    if (entry.generation !== generation) return;
    try {
      const data = await entry.load();
      if (entry.generation !== generation) return;
      entry.failures = 0;
      entry.answered = true;
      publish(entry, { data, loading: false, stale: false });
    } catch (error) {
      if (entry.generation !== generation) return;
      entry.failures += 1;
      const previous = entry.snapshot;
      publish(
        entry,
        previous.data === undefined
          ? { error, loading: false, stale: false }
          : { data: previous.data, error, loading: false, stale: entry.answered && entry.failures >= STALE_AFTER_FAILURES },
      );
    }
  };

  const start = (entry: Entry) => {
    entry.generation += 1;
    const generation = entry.generation;
    // `pollChain` schedules each request after the last settles; the wait is
    // decided at that moment, so a new reader's interval and a backoff apply
    // from the next request on.
    entry.stop = pollChain(once(entry, generation), interval(entry), {
      setTimeout: (callback) => timers.setTimeout(callback, delay(entry)),
      clearTimeout: timers.clearTimeout,
    });
  };

  const halt = (entry: Entry) => {
    entry.generation += 1;
    entry.stop?.();
    entry.stop = undefined;
    entry.waitingForVisible?.();
    entry.waitingForVisible = undefined;
  };

  return {
    subscribe(key, intervalMs, listener) {
      const entry = entryFor(key);
      const id = nextReader++;
      entry.readers.set(id, intervalMs);
      entry.listeners.add(listener);
      if (entry.stop === undefined) start(entry);
      return () => {
        entry.readers.delete(id);
        entry.listeners.delete(listener);
        if (entry.readers.size === 0) halt(entry);
      };
    },
    snapshot: (key) => entries.get(key)?.snapshot ?? INITIAL,
    refresh(key) {
      const entry = entries.get(key);
      if (entry === undefined || entry.readers.size === 0) return;
      halt(entry);
      publish(entry, { ...entry.snapshot, loading: true });
      start(entry);
    },
  };
}

const store = createSourceStore(Object.fromEntries(Object.entries(SOURCES).map(([key, source]) => [key, source.load])));

/**
 * Read one shared source. `intervalMs` defaults to the source's own; a reader
 * that asks for less gets it for every reader. `enabled: false` reads nothing
 * (a section that is not mounted does not poll).
 */
export function useSource<K extends SourceKey>(key: K, options: { intervalMs?: number; enabled?: boolean } = {}): Polled<SourceData[K]> {
  const intervalMs = options.intervalMs ?? SOURCES[key].intervalMs;
  const enabled = options.enabled ?? true;

  const subscribe = useCallback(
    (listener: () => void) => {
      if (!enabled) return () => undefined;
      return store.subscribe(key, intervalMs, listener);
    },
    [key, intervalMs, enabled],
  );
  const snapshot = useSyncExternalStore(subscribe, () => store.snapshot(key), () => INITIAL);
  const refresh = useCallback(() => store.refresh(key), [key]);
  const current = snapshot as Snapshot<SourceData[K]>;
  return {
    ...(current.data === undefined ? {} : { data: current.data }),
    ...(current.error === undefined ? {} : { error: current.error }),
    loading: current.loading,
    stale: current.stale,
    refresh,
  };
}
