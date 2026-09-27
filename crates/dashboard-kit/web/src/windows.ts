import type { CaseListWindow } from "./api/cases";

/**
 * The spans a case list can be counted over, and every word the dashboard
 * prints for them, in one place.
 *
 * The span with no bound had three names in plain view: "All loaded time"
 * in the window select, "any day" in a tab badge, and "everything this host
 * has kept" in the count line and the Overview's intro, so the count line
 * read "4 cases in everything this host has kept". The bounded spans were
 * written out again in four tables and the list of spans in five. A reader
 * who compares two screens must be able to see that they name the same
 * span, so each span has one name, "all time" for the unbounded one, and
 * each form of it is written here once.
 */

/** Every span, in the order the window controls offer them. */
export const CASE_LIST_WINDOWS: readonly CaseListWindow[] = ["all", "1h", "24h", "7d", "30d"];

export function isCaseListWindow(value: unknown): value is CaseListWindow {
  return typeof value === "string" && (CASE_LIST_WINDOWS as readonly string[]).includes(value);
}

export type WindowWords = {
  /** A control's option: "Last 7 days", "All time". */
  label: string;
  /** Beside a count in a badge: "7 days", "all time". */
  short: string;
  /** The span by name, after "over" or "count": "the last 7 days", "all time". */
  span: string;
  /** After a count: "in the last 7 days", "over all time". */
  during: string;
};

export const WINDOW_WORDS: Record<CaseListWindow, WindowWords> = {
  all: { label: "All time", short: "all time", span: "all time", during: "over all time" },
  "1h": { label: "Last hour", short: "1 hour", span: "the last hour", during: "in the last hour" },
  "24h": { label: "Last 24 hours", short: "24 hours", span: "the last 24 hours", during: "in the last 24 hours" },
  "7d": { label: "Last 7 days", short: "7 days", span: "the last 7 days", during: "in the last 7 days" },
  "30d": { label: "Last 30 days", short: "30 days", span: "the last 30 days", during: "in the last 30 days" },
};

/** One form of every span, keyed by span: `windowWords("during")`. */
export function windowWords(form: keyof WindowWords): Record<CaseListWindow, string> {
  return Object.fromEntries(CASE_LIST_WINDOWS.map((window) => [window, WINDOW_WORDS[window][form]])) as Record<CaseListWindow, string>;
}

/** How long each bounded span is, in milliseconds; the unbounded one has no length. */
const WINDOW_MS: Record<Exclude<CaseListWindow, "all">, number> = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 7 * 86_400_000,
  "30d": 30 * 86_400_000,
};

/**
 * Whether an instant falls inside a span that ends now. An instant that
 * cannot be read is inside none but the unbounded one. One a little after
 * now (the host's clock ahead of the reader's) is inside: the host counted
 * it in the span, and it is not older than the span's start.
 */
export function withinWindow(at: string | number, window: CaseListWindow, now: number): boolean {
  if (window === "all") return true;
  const instant = typeof at === "number" ? at : Date.parse(at);
  if (!Number.isFinite(instant) || !Number.isFinite(now)) return false;
  return now - instant <= WINDOW_MS[window];
}
