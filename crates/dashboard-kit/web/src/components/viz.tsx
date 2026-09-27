import { useId, type ReactNode } from "react";

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

/** An off part on a ring: slate-300, visible on the slate-100 track. */
export const RING_OFF = "#cbd5e1";

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
            // Off is drawn a shade darker on a ring than in a bar: the bar's
            // off (slate-200) on the ring's slate-100 track could not be seen.
            const colour = part.tone === "off" ? RING_OFF : TONE_HEX[part.tone];
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

/**
 * How one step of a ladder is drawn, the same marks wherever a ladder is:
 * a filled dot for a step that is so, emerald only for one read back and
 * confirmed, a hollow dot for what is not known (or not checked by anything
 * else), a dash for a step that does not apply, a red ring for a factual No,
 * a faint outline on a read that is not current, and amber only for a step
 * that waits on a person.
 */
export type StepMark = "done" | "verified" | "unproven" | "unknown" | "not_applicable" | "no" | "stale" | "waiting";

export const STEP_MARK_CLASS: Record<StepMark, string> = {
  done: "h-2.5 w-2.5 rounded-full bg-slate-800",
  verified: "h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-emerald-100",
  unproven: "h-2.5 w-2.5 rounded-full border-[1.5px] border-slate-400 bg-white",
  unknown: "h-2.5 w-2.5 rounded-full border-[1.5px] border-slate-400 bg-white",
  // slate-400, not 300: the dash has to survive a projector.
  not_applicable: "h-0.5 w-2.5 bg-slate-400",
  no: "h-2.5 w-2.5 rounded-full border-2 border-rose-500 bg-white",
  stale: "h-2.5 w-2.5 rounded-full border border-slate-300 bg-white",
  waiting: "h-2.5 w-2.5 rounded-full bg-amber-500 ring-2 ring-amber-100",
};

/**
 * A shape inside the two marks whose colour carries a claim, so the claim is
 * never colour alone: a check on the confirmed mark and "!" on the one that
 * waits on a person (SPEC 2.1). Every other mark is told apart by its shape.
 */
export function StepMarkGlyph({ mark }: { mark: StepMark }) {
  if (mark === "verified") {
    return (
      <svg viewBox="0 0 10 10" aria-hidden="true" className="absolute inset-0 h-full w-full" fill="none" stroke="#ffffff" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
        <path d="M2.7 5.2 4.4 6.8 7.4 3.4" />
      </svg>
    );
  }
  if (mark === "waiting") {
    return (
      <svg viewBox="0 0 10 10" aria-hidden="true" className="absolute inset-0 h-full w-full" fill="#ffffff">
        <rect x="4.35" y="2" width="1.3" height="4" rx="0.5" />
        <circle cx="5" cy="7.6" r="0.75" />
      </svg>
    );
  }
  return null;
}

export type Step = {
  key: string;
  label: string;
  mark: StepMark;
  /** What the mark means, said aloud and in the title: "Enforced: yes, by the kernel". */
  words: string;
  /** Under the label when captions are drawn: a time, a gap. */
  caption?: ReactNode;
  /**
   * The caption in words, for a screen reader: the drawn caption is hidden
   * from one (it is a picture of a time), so without this "Seen: on record"
   * was said with no time at all.
   */
  captionWords?: string;
};

/** The Protection ladder keeps its literal five columns; any other ladder shares its columns evenly. */
const STEP_COLUMNS: Record<number, string> = { 5: "grid-cols-5" };

/** Two neighbouring steps are joined by a dark line only when both are so. */
export function stepsJoined(left: StepMark, right: StepMark): boolean {
  const solid = (mark: StepMark) => mark === "done" || mark === "verified";
  return solid(left) && solid(right);
}

/**
 * A ladder of steps: one mark per step, joined where two neighbours are both
 * so. Without captions it is the Protection ladder's row exactly; with them
 * each step's label and caption sit under its mark.
 */
export function Steps({
  steps,
  label,
  captions = false,
  compact = false,
  className = "max-w-72",
}: {
  steps: readonly Step[];
  label: string;
  captions?: boolean;
  /**
   * With captions, the tight form a case's summary card draws: a 12 px mark
   * row and 12 px lines, so the ladder costs the decision under it as little
   * height as it can (about 38 px, from about 54).
   */
  compact?: boolean;
  className?: string;
}) {
  const columns = STEP_COLUMNS[steps.length] ?? "grid-flow-col auto-cols-fr";
  return (
    <ol aria-label={label} className={`grid w-full ${className} ${columns}`}>
      {steps.map((step, index) => {
        const line =
          index < steps.length - 1 ? (
            <span
              aria-hidden="true"
              className={`absolute left-1/2 top-1/2 h-px w-full ${stepsJoined(step.mark, steps[index + 1].mark) ? "bg-slate-800" : "bg-slate-200"}`}
            />
          ) : null;
        const mark = (
          <span aria-hidden="true" className={`relative block ${STEP_MARK_CLASS[step.mark]}`}>
            <StepMarkGlyph mark={step.mark} />
          </span>
        );
        const said = <span className="sr-only">{`${step.label}: ${step.words}${step.captionWords === undefined ? "" : `, ${step.captionWords}`}`}</span>;
        const title = `${step.label}: ${step.words}`;
        if (!captions) {
          return (
            <li key={step.key} data-stage={step.key} data-mark={step.mark} title={title} className="relative flex h-5 items-center justify-center">
              {line}
              {mark}
              {said}
            </li>
          );
        }
        return (
          <li key={step.key} data-stage={step.key} data-mark={step.mark} title={title} className="flex min-w-0 flex-col items-center">
            <span className={`relative flex w-full items-center justify-center ${compact ? "h-3" : "h-5"}`}>
              {line}
              {mark}
            </span>
            {said}
            <span aria-hidden="true" className={`max-w-full text-center text-[11px] text-slate-600 ${compact ? "mt-px leading-3" : "mt-0.5 leading-4"}`}>
              <span className="block font-semibold text-slate-800">{step.label}</span>
              {step.caption === undefined ? null : <span className="block tabular-nums">{step.caption}</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

/** The share of a spark's box left above its highest point, so a peak never reads as a ceiling. */
export const SPARK_HEADROOM = 0.25;

/** Below this spread, (max - min) / max, a series is steady and drawn as a level line at mid-height. */
export const SPARK_STEADY = 0.1;

/**
 * Points of a series on its own scale, in a 100 by `height` box, the top
 * quarter left empty. Silence sits on the baseline. A steady series (it
 * varies by under a tenth of its peak) is a level line at mid-height: scaled
 * to its peak it filled the box and read as a solid slab, a glitch rather
 * than a flow.
 */
export function sparkPoints(values: readonly number[], height = 24): string {
  const finite = values.filter(Number.isFinite);
  const max = Math.max(0, ...finite);
  const min = finite.length === 0 ? 0 : Math.min(...finite);
  const steady = max > 0 && (max - min) / max < SPARK_STEADY;
  const n = values.length;
  const span = (height - 1) * (1 - SPARK_HEADROOM);
  return values
    .map((value, index) => {
      const x = n <= 1 ? 0 : (index * 100) / (n - 1);
      const y = max <= 0 || !Number.isFinite(value)
        ? height
        : steady
          ? height / 2
          : height - (value / max) * span;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}



/**
 * A sparkline on its own scale: the number beside it carries the value. A
 * series of zeros is a flat line on the baseline, never interpolated; the
 * area under the line fades to nothing, as the day's plot does.
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
  // One gradient per drawing, under React's own id for it, reduced to the
  // characters an SVG url() reference takes.
  const fill = `spark-fill-${useId().replace(/[^A-Za-z0-9_-]/g, "")}`;
  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className={className} role="img" aria-label={label}>
      <title>{label}</title>
      {values.length > 1 ? (
        <>
          <defs>
            <linearGradient id={fill} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor={colour} stopOpacity={0.28} />
              <stop offset="100%" stopColor={colour} stopOpacity={0} />
            </linearGradient>
          </defs>
          <polygon points={`0,${height} ${points} 100,${height}`} fill={`url(#${fill})`} />
          <polyline points={points} fill="none" stroke={colour} strokeWidth={1.5} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        </>
      ) : null}
    </svg>
  );
}
