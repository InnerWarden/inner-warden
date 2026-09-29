import { useCallback, useEffect, useRef, useState } from "react";
import { pollChain } from "../hooks/pollChain";

/**
 * One source a Community page reads, polled as a chain (`pollChain`): the
 * next request is asked for a fixed delay after the previous one settles, so
 * a slow answer never piles requests up, and nothing is asked for while the
 * tab is hidden.
 *
 * What the page is told, and what each state means:
 *  - `data` absent, `error` absent: the first answer has not come.
 *  - `data` absent, `error` set: the source could not be read, and nothing
 *    was ever shown; the page says so in its own words, never as a zero.
 *  - `data` set, `stale` true: a later read failed; the last answer is kept
 *    and the page says it could not refresh.
 */
export type Polled<T> = {
  data?: T;
  error?: unknown;
  loading: boolean;
  stale: boolean;
  refresh: () => void;
};

function whenVisible(): Promise<void> {
  if (typeof document === "undefined" || !document.hidden) return Promise.resolve();
  return new Promise((resolve) => {
    const onChange = () => {
      if (document.hidden) return;
      document.removeEventListener("visibilitychange", onChange);
      resolve();
    };
    document.addEventListener("visibilitychange", onChange);
  });
}

/**
 * Poll `load` every `delayMs` after each answer. `key` names what is being
 * read: when it changes (a filter, a page), the old answer is dropped rather
 * than shown under the new question. `refresh` asks again now and keeps the
 * answer on screen meanwhile. A `delayMs` of 0 reads once.
 */
export function usePolled<T>(load: () => Promise<T>, delayMs: number, key = ""): Polled<T> {
  const [state, setState] = useState<{ key: string; data?: T; error?: unknown; loading: boolean; stale: boolean }>({
    key,
    loading: true,
    stale: false,
  });
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    let active = true;
    setState((previous) => (previous.key === key ? { ...previous, loading: true } : { key, loading: true, stale: false }));
    const once = async () => {
      await whenVisible();
      if (!active) return;
      try {
        const data = await loadRef.current();
        if (active) setState({ key, data, loading: false, stale: false });
      } catch (error) {
        if (active) {
          setState((previous) =>
            previous.key === key && previous.data !== undefined
              ? { ...previous, error, loading: false, stale: true }
              : { key, error, loading: false, stale: false },
          );
        }
      }
    };
    if (delayMs <= 0) {
      void once();
      return () => {
        active = false;
      };
    }
    const stop = pollChain(once, delayMs);
    return () => {
      active = false;
      stop();
    };
  }, [key, nonce, delayMs]);

  const refresh = useCallback(() => setNonce((value) => value + 1), []);
  const current = state.key === key ? state : { key, loading: true, stale: false };
  return {
    ...(current.data === undefined ? {} : { data: current.data }),
    ...(current.error === undefined ? {} : { error: current.error }),
    loading: current.loading,
    stale: current.stale,
    refresh,
  };
}
