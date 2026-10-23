import { formatCount } from "../../presentation";
import type { RefusalDay, RefusalWeek } from "../api";
import { HATCH_PATTERN } from "../outcomeStyle";
import { Disclosure, META_TEXT, SMALL_TEXT } from "./blocks";
import { MarkSwatch } from "./marks";

/**
 * Community's charts, in hand-written SVG (spec 9.6). Each one is an image
 * with a numeric name, a table twin a screen reader reads, and "Show as a
 * table" for anyone who would rather read the numbers. A zero is an empty
 * track with "0", never a missing chart.
 *
 * Refused before it ran is solid teal at the bottom of a bar; would have been
 * refused is hatched rose on top, and the words say "would have".
 */

const DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });

/** "16 Sept", for a UTC date written "2026-09-16". */
export function dayLabel(date: string): string {
  return DAY.format(Date.parse(`${date}T00:00:00Z`));
}

type Bar = { key: string; label: string; blocked: number; wouldBlock: number; partial: boolean };

/** The table every bar chart has a twin of: one row per bar, its two counts. */
function BarTable({ bars, first, caption }: { bars: readonly Bar[]; first: string; caption: string }) {
  return (
    <table className={`w-full text-left ${SMALL_TEXT} text-(--iw-ink-2)`}>
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr className="text-(--iw-ink-3)">
          <th scope="col" className="py-1 pr-3 font-medium">{first}</th>
          <th scope="col" className="py-1 pr-3 text-right font-medium">Refused before they ran</th>
          <th scope="col" className="py-1 text-right font-medium">Would have been refused</th>
        </tr>
      </thead>
      <tbody>
        {bars.map((bar) => (
          <tr key={bar.key} className="border-t border-(--iw-line)">
            <th scope="row" className="py-1 pr-3 font-normal">{bar.label}</th>
            <td className="py-1 pr-3 text-right tabular-nums">{formatCount(bar.blocked)}</td>
            <td className="py-1 text-right tabular-nums">{formatCount(bar.wouldBlock)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const WIDTH = 280;
const HEIGHT = 120;

/**
 * The stacked bars, scaled to the largest; a partial bar (today, or the week
 * under way) is drawn at half strength and its words say "so far". Never
 * dashed: a dashed line on these pages means a value that was not read.
 */
function StackedBars({
  bars,
  name,
  start,
  end,
  first,
  caption,
}: {
  bars: readonly Bar[];
  name: string;
  /** The words under the first bar and under the last. */
  start: string;
  end: string;
  first: string;
  caption: string;
}) {
  const max = Math.max(0, ...bars.map((bar) => bar.blocked + bar.wouldBlock));
  const slot = WIDTH / Math.max(1, bars.length);
  const width = Math.max(2, slot * 0.68);
  const scale = (value: number) => (max === 0 ? 0 : (value / max) * (HEIGHT - 2));
  return (
    <figure data-chart className="min-w-0 space-y-2">
      <div className="flex min-w-0 gap-2">
        <div aria-hidden="true" className={`flex flex-col justify-between text-right tabular-nums ${META_TEXT}`}>
          <span>{formatCount(max)}</span>
          <span>0</span>
        </div>
        <svg role="img" aria-label={name} viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none" className="h-24 min-w-0 flex-1 sm:h-[120px]">
          {bars.map((bar, index) => {
            const x = index * slot + (slot - width) / 2;
            const blocked = scale(bar.blocked);
            const would = scale(bar.wouldBlock);
            const faded = bar.partial;
            return (
              <g key={bar.key} data-bar={bar.key} data-partial={bar.partial ? "" : undefined} opacity={faded ? 0.5 : 1}>
                <rect x={x} y={HEIGHT - 1} width={width} height={1} style={{ fill: "var(--iw-line-strong)" }} />
                {blocked > 0 ? <rect x={x} y={HEIGHT - 1 - blocked} width={width} height={blocked} style={{ fill: "var(--iw-stopped)" }} /> : null}
                {would > 0 ? (
                  <rect
                    x={x}
                    y={HEIGHT - 1 - blocked - would}
                    width={width}
                    height={would}
                    style={{ fill: `url(#${HATCH_PATTERN.deny}) var(--iw-deny)`, stroke: "var(--iw-deny)" }}
                    strokeWidth={0.75}
                    vectorEffect="non-scaling-stroke"
                  />
                ) : null}
              </g>
            );
          })}
        </svg>
      </div>
      <figcaption className={`space-y-1 ${META_TEXT}`}>
        <span className="flex justify-between gap-4">
          <span>{start}</span>
          <span>{end}</span>
        </span>
        <Key />
      </figcaption>
      <div className="sr-only">
        <BarTable bars={bars} first={first} caption={caption} />
      </div>
      <Disclosure summary="Show as a table">
        <BarTable bars={bars} first={first} caption={caption} />
      </Disclosure>
    </figure>
  );
}

function sums(bars: readonly Bar[]): { blocked: number; wouldBlock: number } {
  return bars.reduce((sum, bar) => ({ blocked: sum.blocked + bar.blocked, wouldBlock: sum.wouldBlock + bar.wouldBlock }), { blocked: 0, wouldBlock: 0 });
}

function Key() {
  return (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="inline-flex items-center gap-1.5"><MarkSwatch tone="stopped" fill="solid" />Refused before they ran</span>
      <span className="inline-flex items-center gap-1.5"><MarkSwatch tone="deny" fill="hatched" />Would have been refused</span>
    </span>
  );
}

/** The last 14 UTC days of the guard's log, today drawn lighter and labelled "so far". */
export function DayBars({ days }: { days: readonly RefusalDay[] }) {
  const bars: Bar[] = days.map((day) => ({
    key: day.date,
    label: day.partial ? `${dayLabel(day.date)} (so far)` : dayLabel(day.date),
    blocked: day.blocked,
    wouldBlock: day.wouldBlock,
    partial: day.partial,
  }));
  const total = sums(bars);
  const name = `Last ${bars.length} days: ${formatCount(total.blocked)} refused, ${formatCount(total.wouldBlock)} would have been refused`;
  const last = days.at(-1);
  return (
    <StackedBars
      bars={bars}
      name={name}
      first="Day (UTC)"
      caption={name}
      start={days.length === 0 ? "" : `From ${dayLabel(days[0].date)}`}
      end={last === undefined ? "" : last.partial ? "Today, so far" : dayLabel(last.date)}
    />
  );
}

/** Weeks of the guard's log; the week still under way is drawn at half strength and says so, never dropped. */
export function WeekBars({ weeks }: { weeks: readonly RefusalWeek[] }) {
  const bars: Bar[] = weeks.map((week) => ({
    key: week.start,
    label: week.partial ? `Week of ${dayLabel(week.start)} (this week so far)` : `Week of ${dayLabel(week.start)}`,
    blocked: week.blocked,
    wouldBlock: week.wouldBlock,
    partial: week.partial,
  }));
  const total = sums(bars);
  const name = `Last ${bars.length} weeks: ${formatCount(total.blocked)} refused, ${formatCount(total.wouldBlock)} would have been refused`;
  const last = weeks.at(-1);
  return (
    <StackedBars
      bars={bars}
      name={name}
      first="Week (UTC)"
      caption={name}
      start={weeks.length === 0 ? "" : `From ${dayLabel(weeks[0].start)}`}
      end={last?.partial === true ? "This week so far" : ""}
    />
  );
}

/** One part of an agent's token use, as the decimal string the CLI sends, read as a BigInt. */
export type TokenPart = { key: string; label: string; value: bigint };

/** A share of a whole, as a fraction for a bar width, computed without losing precision. */
export function share(value: bigint, whole: bigint): number {
  if (whole <= 0n || value <= 0n) return 0;
  return Number((value * 10_000n) / whole) / 10_000;
}

const TOKEN_SHADES = ["var(--iw-ink)", "var(--iw-ink-2)", "var(--iw-ink-3)", "var(--iw-allow)"];
/** The cache reads' own track. */
const CACHE_SHADE = "var(--iw-line-strong)";

/** A key square in a shade, beside its words: the shades alone are never the signal. */
function ShadeKey({ shade, label }: { shade: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden="true" className="h-2.5 w-2.5 shrink-0 rounded-[2px]" style={{ background: shade }} />
      {label}
    </span>
  );
}

/**
 * One agent's tokens: the parts that are not cache reads stacked in ink
 * shades, and cache reads on a lighter track of their own, so a re-read
 * prompt does not dwarf what was new. `scale` and `cacheScale` let a page
 * draw every agent on one scale; each defaults to the agent's own.
 */
export function TokenBars({
  agent,
  parts,
  cacheReads,
  scale,
  cacheScale,
}: {
  agent: string;
  parts: readonly TokenPart[];
  cacheReads?: bigint;
  scale?: bigint;
  cacheScale?: bigint;
}) {
  const total = parts.reduce((sum, part) => sum + part.value, 0n);
  const whole = scale ?? total;
  const cacheWhole = cacheScale ?? cacheReads ?? 0n;
  const words = parts.map((part) => `${formatCount(part.value)} ${part.label.toLowerCase()}`).join(", ");
  const name = `${agent}: ${words}${cacheReads === undefined ? "" : `; ${formatCount(cacheReads)} re-read from cache`}`;
  let offset = 0;
  return (
    <figure data-chart="tokens" className="min-w-0 space-y-2">
      <svg role="img" aria-label={name} viewBox="0 0 100 14" preserveAspectRatio="none" className="h-5 w-full">
        <rect x={0} y={0} width={100} height={cacheReads === undefined ? 14 : 8} style={{ fill: "var(--iw-surface-2)" }} />
        {parts.map((part, index) => {
          const width = share(part.value, whole) * 100;
          const x = offset;
          offset += width;
          return width === 0 ? null : (
            <rect key={part.key} data-part={part.key} x={x} y={0} width={width} height={cacheReads === undefined ? 14 : 8} style={{ fill: TOKEN_SHADES[index % TOKEN_SHADES.length] }} />
          );
        })}
        {cacheReads === undefined ? null : (
          <>
            <rect x={0} y={10} width={100} height={4} style={{ fill: "var(--iw-surface-2)" }} />
            <rect data-part="cache_reads" x={0} y={10} width={share(cacheReads, cacheWhole) * 100} height={4} style={{ fill: CACHE_SHADE }} />
          </>
        )}
      </svg>
      <figcaption data-token-key className={`flex flex-wrap gap-x-3 gap-y-1 ${META_TEXT}`}>
        {parts.map((part, index) => <ShadeKey key={part.key} shade={TOKEN_SHADES[index % TOKEN_SHADES.length]} label={part.label} />)}
        {cacheReads === undefined ? null : <ShadeKey shade={CACHE_SHADE} label="Re-read from cache" />}
      </figcaption>
      {/* A table sizes to its content whatever its width says: the wrapper is what hides it. */}
      <div className="sr-only">
        <table>
          <caption>{name}</caption>
          <tbody>
            {parts.map((part) => (
              <tr key={part.key}>
                <th scope="row">{part.label}</th>
                <td>{formatCount(part.value)}</td>
              </tr>
            ))}
            {cacheReads === undefined ? null : (
              <tr>
                <th scope="row">Re-read from cache</th>
                <td>{formatCount(cacheReads)}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Disclosure summary="Show as a table">
        <table className={`w-full text-left ${SMALL_TEXT} text-(--iw-ink-2)`}>
          <tbody>
            {parts.map((part) => (
              <tr key={part.key} className="border-t border-(--iw-line)">
                <th scope="row" className="py-1 pr-3 font-normal">{part.label}</th>
                <td className="py-1 text-right tabular-nums">{formatCount(part.value)}</td>
              </tr>
            ))}
            {cacheReads === undefined ? null : (
              <tr className="border-t border-(--iw-line)">
                <th scope="row" className="py-1 pr-3 font-normal">Re-read from cache</th>
                <td className="py-1 text-right tabular-nums">{formatCount(cacheReads)}</td>
              </tr>
            )}
          </tbody>
        </table>
      </Disclosure>
    </figure>
  );
}
