import type { ReactNode } from "react";

/**
 * The drawing primitives every screen shares: a ring, a proportional bar and
 * a sparkline. Hand-written SVG and HTML, no chart library.
 *
 * Colour is set by the job a mark does, never by its rank, and each job has
 * one colour here (`TONE_HEX`), so a state reads the same on every screen:
 *
 *  - `proven`: confirmed by evidence on this host. Nothing else is emerald.
 *  - `working`: doing what it was set up to do, or on.
 *  - `attention`: a person is needed. Amber means that and only that.
 *  - `bad`: a bad thing that happened.
 *  - `unknown`: not confirmed. Always drawn hollow, never filled.
 *  - `off`: off by setting, not applicable, free space.
 *
 * A mark never carries identity by colour alone: every visual here has a
 * label, and the callers print a legend with the counts beside it.
 */
export type Tone =
  | "proven"
  | "working"
  | "attention"
  | "bad"
  | "unknown"
  | "off"
  | "fact"
  | "accent"
  | "accentLight"
  | "watch"
  | "watchLight"
  | "other";

export const TONE_HEX: Record<Tone, string> = {
  proven: "#10b981",
  working: "#0891b2",
  attention: "#f59e0b",
  bad: "#f43f5e",
  unknown: "#94a3b8",
  off: "#e2e8f0",
  fact: "#1e293b",
  accent: "#0e7490",
  accentLight: "#67e8f9",
  watch: "#475569",
  watchLight: "#cbd5e1",
  other: "#94a3b8",
};

export type Part = {
  key: string;
  value: number;
  tone: Tone;
  label: string;
  /** Not confirmed: drawn as an outline, never as a fill. */
  hollow?: boolean;
  /** Unanswered or unplaced: a 45 degree hatch, so it is not read as a solid state. */
  hatched?: boolean;
};

/** The parts worth drawing: finite, positive values only. */
export function drawnParts(parts: readonly Part[]): Part[] {
  return parts.filter((part) => Number.isFinite(part.value) && part.value > 0);
}

const TAU = Math.PI * 2;

/** A clockwise arc from 12 o'clock, `from` and `to` in turns of the circle. */
export function arcPath(c: number, r: number, from: number, to: number): string {
  const point = (turn: number) => {
    const angle = turn * TAU - Math.PI / 2;
    return `${(c + r * Math.cos(angle)).toFixed(2)} ${(c + r * Math.sin(angle)).toFixed(2)}`;
  };
  return `M${point(from)}A${r} ${r} 0 ${to - from > 0.5 ? 1 : 0} 1 ${point(to)}`;
}

/**
 * A ring of parts, drawn from 12 o'clock clockwise in the order given, with
 * a 2 px surface gap between segments. The centre says what the ring counts.
 */
export function Ring({
  parts,
  size = 96,
  stroke = 10,
  label,
  children,
}: {
  parts: readonly Part[];
  size?: number;
  stroke?: number;
  label: string;
  children?: ReactNode;
}) {
  const shown = drawnParts(parts);
  const total = shown.reduce((sum, part) => sum + part.value, 0);
  const c = size / 2;
  const r = (size - stroke) / 2 - 1;
  const gap = shown.length > 1 ? 2 / (TAU * r) : 0;
  let at = 0;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full" role="img" aria-label={label}>
        <circle cx={c} cy={c} r={r} fill="none" stroke="#f1f5f9" strokeWidth={stroke} />
        {total > 0 &&
          shown.map((part) => {
            const share = part.value / total;
            const from = at + gap / 2;
            const to = Math.max(from + 0.001, at + share - gap / 2);
            at += share;
            const whole = shown.length === 1;
            const colour = TONE_HEX[part.tone];
            return (
              <g key={part.key} data-segment={part.key}>
                <title>{part.label}</title>
                {part.hollow ? (
                  [r - stroke / 2 + 1, r + stroke / 2 - 1].map((edge) =>
                    whole ? (
                      <circle key={edge} cx={c} cy={c} r={edge} fill="none" stroke={colour} strokeWidth={1.5} strokeDasharray="3 2.5" />
                    ) : (
                      <path key={edge} d={arcPath(c, edge, from, to)} fill="none" stroke={colour} strokeWidth={1.5} strokeDasharray="3 2.5" />
                    ),
                  )
                ) : whole ? (
                  <circle cx={c} cy={c} r={r} fill="none" stroke={colour} strokeWidth={stroke} />
                ) : (
                  <path d={arcPath(c, r, from, to)} fill="none" stroke={colour} strokeWidth={stroke} />
                )}
              </g>
            );
          })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center leading-tight">{children}</div>
    </div>
  );
}

/** A 0..1 share as a gauge: the share filled, the rest a light track. */
export function Gauge({ share, label, size = 72, children }: { share: number | null; label: string; size?: number; children?: ReactNode }) {
  const value = share === null || !Number.isFinite(share) ? 0 : Math.min(1, Math.max(0, share));
  return (
    <Ring size={size} stroke={8} label={label} parts={value > 0 ? [{ key: "used", value, tone: "working", label }] : []}>
      {children}
    </Ring>
  );
}

/** The background of a part in an HTML bar: a fill, or a hatch. */
export function partFill(part: Pick<Part, "tone" | "hatched" | "hollow">): string {
  const colour = TONE_HEX[part.tone];
  return part.hatched || part.hollow
    ? `repeating-linear-gradient(135deg,${colour} 0 2px,transparent 2px 5px)`
    : colour;
}

/**
 * A proportional bar of parts, in HTML: one segment per part with a value,
 * 2 px of surface between segments, a title on each.
 */
export function Bar({ parts, label, className = "h-3" }: { parts: readonly Part[]; label: string; className?: string }) {
  const shown = drawnParts(parts);
  const total = shown.reduce((sum, part) => sum + part.value, 0);
  return (
    <div role="img" aria-label={label} className={`flex w-full gap-[2px] overflow-hidden rounded bg-slate-100 ${className}`}>
      {shown.map((part) => (
        <span
          key={part.key}
          data-segment={part.key}
          title={part.label}
          className="h-full min-w-[2px] first:rounded-l last:rounded-r"
          style={{ width: `${(part.value / total) * 100}%`, background: partFill(part) }}
        />
      ))}
    </div>
  );
}

/** A small square key for a legend, the part's own fill. */
export function Swatch({ part, className = "h-2.5 w-2.5" }: { part: Pick<Part, "tone" | "hatched" | "hollow">; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block shrink-0 rounded-sm ${className}`}
      style={part.hollow ? { border: `1.5px dashed ${TONE_HEX[part.tone]}` } : { background: partFill(part) }}
    />
  );
}

/** Points of a series on its own scale, in a 100 by `height` box. Silence sits on the baseline. */
export function sparkPoints(values: readonly number[], height = 24): string {
  const max = Math.max(0, ...values.filter(Number.isFinite));
  const n = values.length;
  return values
    .map((value, index) => {
      const x = n <= 1 ? 0 : (index * 100) / (n - 1);
      const y = max <= 0 || !Number.isFinite(value) ? height : height - (value / max) * (height - 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

/**
 * A sparkline on its own scale: the number beside it carries the value. A
 * series of zeros is a flat line on the baseline, never interpolated.
 */
export function Spark({
  values,
  label,
  tone = "working",
  className = "h-6 w-full",
  height = 24,
}: {
  values: readonly number[];
  label: string;
  tone?: Tone;
  className?: string;
  height?: number;
}) {
  const points = sparkPoints(values, height);
  const colour = TONE_HEX[tone];
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className={className} role="img" aria-label={label}>
      <title>{label}</title>
      {values.length > 1 ? (
        <>
          <polygon points={`0,${height} ${points} 100,${height}`} fill={colour} fillOpacity={0.12} />
          <polyline points={points} fill="none" stroke={colour} strokeWidth={1.5} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        </>
      ) : null}
    </svg>
  );
}
