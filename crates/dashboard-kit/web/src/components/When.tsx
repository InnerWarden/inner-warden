import { formatAbsolute, formatTimestamp, isoInstant, timeTitle } from "../presentation";

/**
 * One time on screen, by the dashboard's one rule: the reader's local time
 * with its zone (or "3 hours ago" where the screen reads better relative),
 * and the exact instant, local and ISO 8601 UTC, in the title.
 *
 * `dateTime` carries the producer's own string when it sent one, so the
 * element points at the value the host wrote, not a re-rendering of it.
 */
export function When({ at, relative = false, className }: { at: string | number | Date; relative?: boolean; className?: string }) {
  const iso = isoInstant(at);
  if (iso === undefined) return null;
  const text = relative ? formatTimestamp(new Date(at).getTime()) : formatAbsolute(at);
  return (
    <time dateTime={typeof at === "string" ? at : iso} title={timeTitle(at)} className={className}>
      {text}
    </time>
  );
}
