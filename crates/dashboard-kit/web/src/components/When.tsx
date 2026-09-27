import { formatAbsolute, formatTimestamp, isoInstant, timeTitle } from "../presentation";
import { useTechnicalDetail } from "./TechnicalDetail";

/**
 * The words a time is printed in, for the view on screen.
 *
 * The plain view reads the reader's local time with its zone ("21 Sept 2026,
 * 18:28 BST"), or "3 hours ago" where the screen reads better relative. The
 * technical view is the investigator's, who lines a time up with a host log
 * or a report written in UTC: it prints UTC, labelled, and never a relative
 * time ("21 Sept 2026, 17:28 UTC"). The instant was one hover away before,
 * and a hover is out of reach on a touch screen.
 */
export function whenText(at: string | number | Date, relative: boolean, technical: boolean): string | undefined {
  if (technical) return formatAbsolute(at, "UTC");
  return relative ? formatTimestamp(new Date(at).getTime()) : formatAbsolute(at);
}

/**
 * One time on screen, by the dashboard's one rule (`whenText`), with the
 * exact instant, local and ISO 8601 UTC, in the title.
 *
 * `dateTime` carries the producer's own string when it sent one, so the
 * element points at the value the host wrote, not a re-rendering of it.
 */
export function When({ at, relative = false, className }: { at: string | number | Date; relative?: boolean; className?: string }) {
  const [technical] = useTechnicalDetail();
  const iso = isoInstant(at);
  if (iso === undefined) return null;
  return (
    <time dateTime={typeof at === "string" ? at : iso} title={timeTitle(at)} className={className}>
      {whenText(at, relative, technical)}
    </time>
  );
}
