import { useCallback, useEffect, useRef, useState } from "react";
import { fetchCases, type ActionView, type CasesPage } from "../api";
import { Detail } from "../components/Detail";
import { SessionCard } from "../components/SessionCard";

const LIMIT = 12;
const VERDICTS: [string, string][] = [
  ["", "All decisions"],
  ["deny", "Deny verdicts"],
  ["review", "Needs review"],
  ["allow", "Allowed"],
  ["unknown", "Unknown"],
];

export type ActivityTarget = {
  requestId: number;
  id?: string;
  session?: string;
  verdict?: string;
  action?: string;
};

export function Activity({ initialTarget }: { initialTarget?: ActivityTarget }) {
  const [verdict, setVerdict] = useState(initialTarget?.verdict ?? "");
  // A recent-activity deep link carries the action too. Starting with that
  // server-side filter guarantees the target remains reachable even when its
  // session contains more than the per-response action cap.
  const [query, setQuery] = useState(initialTarget?.action ?? "");
  const [debouncedQuery, setDebouncedQuery] = useState(initialTarget?.action ?? "");
  const [offset, setOffset] = useState(0);
  const [focus, setFocus] = useState<string | undefined>(initialTarget?.session);
  const [page, setPage] = useState<CasesPage>();
  const [error, setError] = useState<string>();
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [detail, setDetail] = useState<{ action: ActionView; session: string }>();
  const [fetching, setFetching] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const targetHandled = useRef(false);
  const activityTitleRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    targetHandled.current = false;
  }, [initialTarget?.requestId]);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      setFetching(true);
      fetchCases({ verdict, q: debouncedQuery, session: focus, offset, limit: LIMIT })
        .then((next) => {
          if (!active) return;
          if (next.sessions.length === 0 && next.total_sessions > 0 && offset > 0) {
            setOffset(Math.max(0, (Math.ceil(next.total_sessions / LIMIT) - 1) * LIMIT));
            return;
          }
          setPage(next);
          setError(undefined);
        })
        .catch((reason) => {
          if (active) setError(String(reason));
        })
        .finally(() => {
          inFlight = false;
          if (active) setFetching(false);
        });
    };
    load();
    const timer = setInterval(load, 5_000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [verdict, debouncedQuery, offset, focus, refreshKey]);

  useEffect(() => {
    if (!page || !initialTarget || targetHandled.current) return;
    const matches = (action: ActionView) =>
      initialTarget.id ? action.id === initialTarget.id : initialTarget.action ? action.command === initialTarget.action : false;
    // The owning session travels with the action, because "where did this come
    // from" is one of the questions the detail dialog now answers.
    const owner = page.sessions.find((session) => session.items.some(matches));
    const match = owner?.items.find(matches);
    if (owner && match) setDetail({ action: match, session: owner.label });
    targetHandled.current = true;
  }, [page, initialTarget]);

  const closeDetail = useCallback(() => setDetail(undefined), []);
  const focusActivityTitle = useCallback(() => activityTitleRef.current?.focus(), []);
  const totalPages = page ? Math.max(1, Math.ceil(page.total_sessions / LIMIT)) : 1;
  const pageNumber = page ? Math.floor(page.offset / Math.max(1, page.limit)) + 1 : Math.floor(offset / LIMIT) + 1;
  const filtering = verdict !== "" || debouncedQuery !== "" || focus != null;

  const toggle = (id: string) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const reset = () => {
    setVerdict("");
    setQuery("");
    setDebouncedQuery("");
    setFocus(undefined);
    setOffset(0);
    setExpanded(new Set());
  };

  return (
    <div className="space-y-5" aria-busy={fetching}>
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between" data-tour="activity">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Decision record</p>
          <h1 ref={activityTitleRef} tabIndex={-1} className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Activity</h1>
          <p className="mt-1 max-w-2xl text-sm text-slate-600">Inspect recorded actions, understand each verdict and distinguish observed risk from proven enforcement.</p>
        </div>
        {page && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-600" aria-live="polite">
            {fetching && <span className="text-xs font-semibold text-cyan-800" aria-hidden="true">Updating…</span>}
            <span><span className="font-semibold tabular-nums text-slate-900">{page.total_commands.toLocaleString()}</span> {filtering ? "matching " : ""}decision{page.total_commands === 1 ? "" : "s"}</span>
            <span aria-hidden="true"> · </span>
            <span><span className="font-semibold tabular-nums text-slate-900">{page.total_sessions.toLocaleString()}</span> session{page.total_sessions === 1 ? "" : "s"}</span>
          </div>
        )}
      </header>

      <section className="rounded-xl border border-slate-200 bg-white p-3 shadow-sm" aria-label="Activity filters">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
          <div className="grid w-full grid-cols-2 gap-1 sm:flex sm:w-auto sm:flex-wrap" role="group" aria-label="Filter by verdict">
            {VERDICTS.map(([value, label]) => (
              <button
                type="button"
                key={value}
                aria-pressed={verdict === value}
                onClick={() => {
                  setVerdict(value);
                  setOffset(0);
                }}
                className={`w-full rounded-lg px-3 py-2 text-xs font-semibold transition-colors sm:w-auto ${
                  verdict === value ? "bg-slate-900 text-white" : "bg-slate-50 text-slate-600 hover:bg-slate-100 hover:text-slate-950"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="relative min-w-0 flex-1">
            <label htmlFor="activity-search" className="sr-only">Search recorded actions</label>
            <svg className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" viewBox="0 0 20 20" fill="none" aria-hidden="true">
              <circle cx="8.5" cy="8.5" r="5.5" stroke="currentColor" strokeWidth="1.7" />
              <path d="m13 13 4 4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
            </svg>
            <input
              id="activity-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search recorded actions"
              className="w-full rounded-lg border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-slate-900 placeholder:text-slate-500 hover:border-slate-400"
            />
          </div>
          {filtering && (
            <button type="button" onClick={reset} className="self-start rounded-lg px-3 py-2 text-xs font-semibold text-cyan-800 hover:bg-cyan-50 xl:shrink-0">
              Clear filters
            </button>
          )}
        </div>
        {focus && (
          <div className="mt-3 flex items-center justify-between gap-3 border-t border-slate-100 pt-3 text-xs">
            <span className="min-w-0 truncate text-slate-600">Focused session: <strong className="font-semibold text-slate-900">{focus === "local" ? "Local session" : focus}</strong></span>
            <button
              type="button"
              onClick={() => {
                setFocus(undefined);
                setOffset(0);
              }}
              className="shrink-0 font-semibold text-cyan-800 hover:text-cyan-950"
            >
              Show all sessions
            </button>
          </div>
        )}
      </section>

      {error && (
        <div role={page ? "status" : "alert"} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <span>{page ? "Could not refresh. Showing the last available result." : "Could not load activity from the local dashboard."}</span>
          <button type="button" onClick={() => setRefreshKey((value) => value + 1)} className="rounded-md px-2 py-1 text-xs font-semibold text-amber-900 hover:bg-amber-100">Try again</button>
        </div>
      )}

      {!page && !error && <ActivitySkeleton />}

      {page && page.sessions.length === 0 && (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center">
          <h2 className="text-lg font-semibold text-slate-950">{filtering ? "No matching activity" : "No activity recorded yet"}</h2>
          <p className="mx-auto mt-2 max-w-lg text-sm text-slate-600">
            {filtering ? "Try a broader search or clear the active filters." : "Use innerwarden check for a one-off decision. Configured shell hooks and MCP proxies also add captured decisions."}
          </p>
          {filtering && <button type="button" onClick={reset} className="mt-4 rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800">Clear filters</button>}
        </div>
      )}

      <div className="space-y-3">
        {page?.sessions.map((session) => (
          <SessionCard
            key={session.id}
            s={session}
            open={Boolean(focus) || expanded.has(session.id)}
            focused={Boolean(focus)}
            onToggle={() => toggle(session.id)}
            onFocus={() => {
              setFocus(session.label);
              setOffset(0);
            }}
            onPick={(action) => setDetail({ action, session: session.label })}
          />
        ))}
      </div>

      {page && totalPages > 1 && (
        <nav className="flex items-center justify-center gap-3 pt-2 text-sm" aria-label="Activity pages">
          <button
            type="button"
            disabled={fetching || offset === 0}
            onClick={() => setOffset(Math.max(0, offset - LIMIT))}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 font-semibold text-slate-700 shadow-sm hover:bg-slate-50 disabled:opacity-40"
            aria-label="Previous activity page"
          >
            <span aria-hidden="true">←</span> Previous
          </button>
          <span className="min-w-24 text-center text-slate-600">Page {pageNumber} of {totalPages}</span>
          <button
            type="button"
            disabled={fetching || pageNumber >= totalPages}
            onClick={() => setOffset(offset + LIMIT)}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 font-semibold text-slate-700 shadow-sm hover:bg-slate-50 disabled:opacity-40"
            aria-label="Next activity page"
          >
            Next <span aria-hidden="true">→</span>
          </button>
        </nav>
      )}

      {detail && <Detail action={detail.action} session={detail.session} onClose={closeDetail} fallbackFocus={focusActivityTitle} />}
    </div>
  );
}

function ActivitySkeleton() {
  return (
    <div role="status" aria-label="Loading activity" className="space-y-3">
      {[0, 1, 2].map((item) => <div key={item} className="h-16 animate-pulse rounded-xl border border-slate-200 bg-white" />)}
      <span className="sr-only">Loading activity…</span>
    </div>
  );
}
