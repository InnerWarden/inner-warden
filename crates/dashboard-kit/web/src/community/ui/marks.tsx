import type { ReactElement } from "react";
import { HATCH_PATTERN, hatchFor, outcomeStyle, TONE_COLOUR, type MarkFill, type MarkShape, type MarkTone } from "../outcomeStyle";
import { Icon, type IconName } from "./Icon";

/**
 * The marks and pills every Community page draws with.
 *
 * A mark's shape says what the rules decided, its colour what happened, and
 * hatching that it ran in monitor ("would have"). A mark is decoration for
 * the words beside it, so it is hidden from screen readers; a pill carries
 * its words itself.
 */

const MARK_PATHS: Record<MarkShape, (props: Record<string, unknown>) => ReactElement> = {
  octagon: (props) => <path d="M3.3.9h3.4l2.4 2.4v3.4L6.7 9.1H3.3L.9 6.7V3.3Z" {...props} />,
  diamond: (props) => <path d="M5 .9 9.1 5 5 9.1.9 5Z" {...props} />,
  circle: (props) => <circle cx="5" cy="5" r="4" {...props} />,
  square: (props) => <rect x="1" y="1" width="8" height="8" rx="1" {...props} />,
};

function paint(tone: MarkTone, fill: MarkFill): Record<string, unknown> {
  const colour = TONE_COLOUR[tone];
  switch (fill) {
    case "solid":
      return { style: { fill: colour, stroke: colour }, strokeWidth: 1 };
    case "hatched":
      // The fallback colour draws a solid mark where the pattern is not mounted.
      return { style: { fill: `url(#${hatchFor(tone)}) ${colour}`, stroke: colour }, strokeWidth: 1.2 };
    case "hollow":
      return { style: { fill: "var(--iw-surface)", stroke: colour }, strokeWidth: 1.5 };
    case "dashed":
      return { style: { fill: "none", stroke: colour }, strokeWidth: 1.3, strokeDasharray: "2 1.5" };
  }
}

/** A mark of a shape, tone and fill, 10 px. */
export function Mark({ shape, tone, fill, className = "" }: { shape: MarkShape; tone: MarkTone; fill: MarkFill; className?: string }) {
  const Shape = MARK_PATHS[shape];
  return (
    <svg
      data-mark={shape}
      data-mark-tone={tone}
      data-mark-fill={fill}
      viewBox="0 0 10 10"
      aria-hidden="true"
      focusable="false"
      className={`h-2.5 w-2.5 shrink-0 ${className}`}
    >
      <Shape {...paint(tone, fill)} />
    </svg>
  );
}

/** The mark of an outcome (`OUTCOME_STYLE`); a key it does not know draws as "not recorded". */
export function OutcomeMark({ outcome, className }: { outcome: string; className?: string }) {
  const style = outcomeStyle(outcome);
  return <Mark {...style} className={className} />;
}

/** A square swatch for a legend or a chart key: a tone, solid or hatched. */
export function MarkSwatch({ tone, fill, className = "" }: { tone: MarkTone; fill: "solid" | "hatched"; className?: string }) {
  return <Mark shape="square" tone={tone} fill={fill} className={className} />;
}

/**
 * The two hatch patterns, defined once in a zero-size SVG the Community page
 * mounts: 135 degrees, a 2 px line every 5 px. Hatching always comes with
 * "would have" written beside it.
 */
export function HatchDefs() {
  return (
    <svg aria-hidden="true" focusable="false" width="0" height="0" className="absolute h-0 w-0 overflow-hidden">
      <defs>
        <pattern id={HATCH_PATTERN.deny} width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(135)">
          <rect width="5" height="5" style={{ fill: "var(--iw-deny-bg)" }} />
          <line x1="1" y1="0" x2="1" y2="5" style={{ stroke: "var(--iw-deny)" }} strokeWidth="2" />
        </pattern>
        <pattern id={HATCH_PATTERN.ink} width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(135)">
          <rect width="5" height="5" style={{ fill: "var(--iw-surface)" }} />
          <line x1="1" y1="0" x2="1" y2="5" style={{ stroke: "var(--iw-ink-2)" }} strokeWidth="2" />
        </pattern>
      </defs>
    </svg>
  );
}

/**
 * Every state a pill can show. `checking` is drawn as unknown and says so.
 * `on` is an optional defence that is on or ready: neutral, like monitor, and
 * never green, because Community reads nothing back after a command ran.
 */
export const PILL_STATES = ["enforce", "monitor", "mixed", "needs", "on", "off", "not_available", "unknown", "exposed", "checking"] as const;
export type PillState = (typeof PILL_STATES)[number];

const PILL_ICON: Record<PillState, IconName> = {
  enforce: "shield",
  monitor: "eye",
  mixed: "half-shield",
  needs: "triangle",
  on: "circle",
  off: "hollow-circle",
  not_available: "slashed-circle",
  unknown: "dashed-circle",
  exposed: "globe",
  checking: "dashed-circle",
};

/** Icons that carry their own colour; the rest take the pill's ink. */
const PILL_ICON_COLOUR: Partial<Record<PillState, string>> = {
  enforce: "var(--iw-stopped)",
  needs: "var(--iw-review)",
  exposed: "var(--iw-deny)",
};

export const PILL_BASE = "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold";

/**
 * A state in words, with an icon so colour is never the only signal. `label`
 * is the accessible name when it says more than the words (the header's
 * pill): the words are then hidden from screen readers and the label read
 * instead, once.
 */
export function StatusPill({
  state,
  words,
  label,
  title,
  className = "",
}: {
  state: PillState;
  words: string;
  label?: string;
  title?: string;
  className?: string;
}) {
  const colour = PILL_ICON_COLOUR[state];
  return (
    <span data-pill={state === "checking" ? "unknown" : state} data-state={state} title={title} className={`${PILL_BASE} ${className}`}>
      <span className="inline-flex" style={colour === undefined ? undefined : { color: colour }}>
        <Icon name={PILL_ICON[state]} className={`h-3.5 w-3.5 ${state === "on" ? "fill-current" : ""}`} />
      </span>
      {label === undefined ? (
        <span className="whitespace-nowrap">{words}</span>
      ) : (
        <>
          <span aria-hidden="true" className="whitespace-nowrap">{words}</span>
          <span className="sr-only">{label}</span>
        </>
      )}
    </span>
  );
}

/** The mode a decision was made in (`mode_at_decision`). */
export function ModePill({ mode }: { mode: string }) {
  if (mode === "enforce") return <StatusPill state="enforce" words="Decided in enforce" />;
  if (mode === "monitor") return <StatusPill state="monitor" words="Decided in monitor" />;
  return <StatusPill state="unknown" words="Mode not recorded" />;
}
