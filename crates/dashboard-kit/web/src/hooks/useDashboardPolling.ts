import { useEffect, useRef, useState } from "react";

const DEFAULT_INTERVAL_MS = 5_000;
const DEFAULT_MAX_BACKOFF_MS = 30_000;
const DEFAULT_JITTER_RATIO = 0.2;

export type DashboardPollingStatus = "idle" | "loading" | "fresh" | "stale" | "degraded";
export type DashboardPollingReason =
  | "producer_not_fresh"
  | "request_failed"
  | "retained_after_navigation"
  | "polling_disabled"
  | null;

export type DashboardPollingState<T> = {
  /** Last validated projection. It is never replaced with a synthesized empty value. */
  data: T | undefined;
  hasData: boolean;
  status: DashboardPollingStatus;
  reason: DashboardPollingReason;
  error: unknown | null;
  inFlight: boolean;
  backoffAttempt: number;
  nextDelayMs: number | null;
  /** Consumer receipt time for diagnostics only; this does not establish producer freshness. */
  lastResponseAtMs: number | null;
  /** Consumer receipt time for the last response that passed `isFresh`. */
  lastFreshResponseAtMs: number | null;
};

type TimerHandle = ReturnType<typeof globalThis.setTimeout>;

export type DashboardPollingScheduler = {
  now: () => number;
  setTimeout: (callback: () => void, delayMs: number) => TimerHandle;
  clearTimeout: (handle: TimerHandle) => void;
};

export type DashboardPollerOptions<T> = {
  fetcher: (signal: AbortSignal) => Promise<T>;
  /** Must inspect producer evidence. HTTP success alone must not return true. */
  isFresh: (projection: T) => boolean;
  onState?: (state: DashboardPollingState<T>) => void;
  initialData?: T;
  baseIntervalMs?: number;
  maxBackoffMs?: number;
  jitterRatio?: number;
  random?: () => number;
  scheduler?: DashboardPollingScheduler;
};

export type DashboardPoller<T> = {
  start: () => void;
  stop: (reason?: unknown) => void;
  snapshot: () => Readonly<DashboardPollingState<T>>;
};

export type UseDashboardPollingOptions<T> = Omit<DashboardPollerOptions<T>, "onState" | "initialData"> & {
  enabled?: boolean;
  /** Changing this key aborts the old request before starting the new navigation scope. */
  navigationKey?: string | number;
  initialData?: T;
  onState?: (state: DashboardPollingState<T>) => void;
};

const defaultScheduler: DashboardPollingScheduler = {
  now: () => Date.now(),
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) => globalThis.clearTimeout(handle),
};

function assertFinitePositive(value: number, name: string) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a finite positive number`);
  }
}

function validateTiming(baseIntervalMs: number, maxBackoffMs: number, jitterRatio: number) {
  assertFinitePositive(baseIntervalMs, "base interval");
  assertFinitePositive(maxBackoffMs, "maximum backoff");
  if (maxBackoffMs < baseIntervalMs) {
    throw new Error("maximum backoff must be greater than or equal to the base interval");
  }
  if (!Number.isFinite(jitterRatio) || jitterRatio < 0 || jitterRatio >= 1) {
    throw new Error("jitter ratio must be in the range [0, 1)");
  }
}

/**
 * Calculates a symmetric-jitter delay for a one-based unsuccessful-fresh attempt.
 * The maximum is a hard ceiling even when the injected random value selects +jitter.
 */
export function calculatePollingDelay(
  attempt: number,
  baseIntervalMs: number,
  maxBackoffMs: number,
  jitterRatio: number,
  random: () => number = Math.random,
): number {
  validateTiming(baseIntervalMs, maxBackoffMs, jitterRatio);
  if (!Number.isSafeInteger(attempt) || attempt < 1) {
    throw new Error("backoff attempt must be a positive safe integer");
  }

  const randomValue = random();
  if (!Number.isFinite(randomValue) || randomValue < 0 || randomValue > 1) {
    throw new Error("random source must return a finite value in [0, 1]");
  }

  const exponent = Math.min(attempt - 1, 52);
  const exponentialDelay = Math.min(maxBackoffMs, baseIntervalMs * (2 ** exponent));
  const jitterMultiplier = 1 - jitterRatio + (2 * jitterRatio * randomValue);
  return Math.min(maxBackoffMs, Math.round(exponentialDelay * jitterMultiplier));
}

function initialPollingState<T>(initialData?: T): DashboardPollingState<T> {
  const hasData = initialData !== undefined;
  return {
    data: initialData,
    hasData,
    status: hasData ? "stale" : "idle",
    reason: hasData ? "retained_after_navigation" : null,
    error: null,
    inFlight: false,
    backoffAttempt: 0,
    nextDelayMs: null,
    lastResponseAtMs: null,
    lastFreshResponseAtMs: null,
  };
}

export function createDashboardPoller<T>(options: DashboardPollerOptions<T>): DashboardPoller<T> {
  const baseIntervalMs = options.baseIntervalMs ?? DEFAULT_INTERVAL_MS;
  const maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS;
  const jitterRatio = options.jitterRatio ?? DEFAULT_JITTER_RATIO;
  const random = options.random ?? Math.random;
  const scheduler = options.scheduler ?? defaultScheduler;
  validateTiming(baseIntervalMs, maxBackoffMs, jitterRatio);

  let state = initialPollingState(options.initialData);
  let stopped = true;
  let timer: TimerHandle | null = null;
  let requestController: AbortController | null = null;
  let generation = 0;

  const emit = (next: DashboardPollingState<T>) => {
    state = next;
    options.onState?.(state);
  };

  const schedule = (delayMs: number, run: () => Promise<void>) => {
    if (stopped) return;
    timer = scheduler.setTimeout(() => {
      timer = null;
      void run();
    }, delayMs);
  };

  const scheduleBackoff = (error: unknown | null, reason: Exclude<DashboardPollingReason, "retained_after_navigation" | "polling_disabled" | null>, now: number, run: () => Promise<void>) => {
    const backoffAttempt = state.backoffAttempt + 1;
    const nextDelayMs = calculatePollingDelay(
      backoffAttempt,
      baseIntervalMs,
      maxBackoffMs,
      jitterRatio,
      random,
    );
    emit({
      ...state,
      status: state.hasData ? "stale" : "degraded",
      reason,
      error,
      inFlight: false,
      backoffAttempt,
      nextDelayMs,
      lastResponseAtMs: reason === "producer_not_fresh" ? now : state.lastResponseAtMs,
    });
    schedule(nextDelayMs, run);
  };

  const run = async () => {
    if (stopped || state.inFlight) return;

    const runGeneration = generation;
    const controller = new AbortController();
    requestController = controller;
    emit({
      ...state,
      status: state.hasData ? state.status : "loading",
      inFlight: true,
      nextDelayMs: null,
    });

    let projection: T;
    try {
      projection = await options.fetcher(controller.signal);
    } catch (error) {
      if (stopped || generation !== runGeneration) return;
      requestController = null;
      scheduleBackoff(error, "request_failed", scheduler.now(), run);
      return;
    }

    if (stopped || generation !== runGeneration) return;
    requestController = null;

    let producerIsFresh: boolean;
    try {
      producerIsFresh = options.isFresh(projection);
    } catch (error) {
      scheduleBackoff(error, "request_failed", scheduler.now(), run);
      return;
    }

    const now = scheduler.now();
    if (!producerIsFresh) {
      state = { ...state, data: projection, hasData: true };
      scheduleBackoff(null, "producer_not_fresh", now, run);
      return;
    }

    emit({
      data: projection,
      hasData: true,
      status: "fresh",
      reason: null,
      error: null,
      inFlight: false,
      backoffAttempt: 0,
      nextDelayMs: baseIntervalMs,
      lastResponseAtMs: now,
      lastFreshResponseAtMs: now,
    });
    schedule(baseIntervalMs, run);
  };

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      generation += 1;
      void run();
    },
    stop(reason = "polling-stopped") {
      if (stopped) return;
      stopped = true;
      generation += 1;
      if (timer !== null) {
        scheduler.clearTimeout(timer);
        timer = null;
      }
      requestController?.abort(reason);
      requestController = null;
      state = { ...state, inFlight: false, nextDelayMs: null };
    },
    snapshot() {
      return state;
    },
  };
}

/**
 * Shared dashboard polling primitive. Producer freshness is supplied explicitly;
 * navigation and unmount cleanup abort the active request and suppress late writes.
 */
export function useDashboardPolling<T>({
  enabled = true,
  navigationKey = "default",
  initialData,
  fetcher,
  isFresh,
  onState,
  baseIntervalMs = DEFAULT_INTERVAL_MS,
  maxBackoffMs = DEFAULT_MAX_BACKOFF_MS,
  jitterRatio = DEFAULT_JITTER_RATIO,
  random,
  scheduler,
}: UseDashboardPollingOptions<T>): DashboardPollingState<T> {
  const [state, setState] = useState<DashboardPollingState<T>>(() => initialPollingState(initialData));
  const stateRef = useRef(state);
  const fetcherRef = useRef(fetcher);
  const freshnessRef = useRef(isFresh);
  const observerRef = useRef(onState);
  const randomRef = useRef(random);

  stateRef.current = state;
  fetcherRef.current = fetcher;
  freshnessRef.current = isFresh;
  observerRef.current = onState;
  randomRef.current = random;

  useEffect(() => {
    const publish = (next: DashboardPollingState<T>) => {
      stateRef.current = next;
      setState(next);
      observerRef.current?.(next);
    };

    if (!enabled) {
      const retained = stateRef.current;
      publish({
        ...retained,
        status: retained.hasData ? "stale" : "idle",
        reason: retained.hasData ? "polling_disabled" : null,
        inFlight: false,
        nextDelayMs: null,
      });
      return undefined;
    }

    const retained = stateRef.current;
    const poller = createDashboardPoller<T>({
      fetcher: (signal) => fetcherRef.current(signal),
      isFresh: (projection) => freshnessRef.current(projection),
      onState: publish,
      initialData: retained.hasData ? retained.data : undefined,
      baseIntervalMs,
      maxBackoffMs,
      jitterRatio,
      random: () => (randomRef.current ?? Math.random)(),
      scheduler,
    });
    poller.start();

    return () => poller.stop("navigation-or-unmount");
  }, [baseIntervalMs, enabled, jitterRatio, maxBackoffMs, navigationKey, scheduler]);

  return state;
}
