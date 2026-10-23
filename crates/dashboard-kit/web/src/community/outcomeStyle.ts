import type { DecisionOutcomeKey, MessageOutcomeKey } from "./words";

/**
 * How every outcome is drawn. The shape says what the rules decided
 * (octagon a deny, diamond a review, circle an allow), the colour says what
 * happened, and hatching means monitor: it "would have". The words always
 * travel with the mark (`OUTCOME_WORDS`), so colour is never the only signal.
 *
 * Typed as a `Record` over every key the CLI sends: a key with no style fails
 * the build rather than drawing nothing.
 */
export type MarkShape = "octagon" | "diamond" | "circle" | "square";
export type MarkTone = "stopped" | "deny" | "review" | "allow" | "ink" | "unknown";
export type MarkFill = "solid" | "hatched" | "hollow" | "dashed";
export type OutcomeStyle = { shape: MarkShape; tone: MarkTone; fill: MarkFill };

export type OutcomeKey = DecisionOutcomeKey | MessageOutcomeKey;

export const OUTCOME_STYLE: Record<OutcomeKey, OutcomeStyle> = {
  refused_before_run: { shape: "octagon", tone: "stopped", fill: "solid" },
  would_have_refused: { shape: "octagon", tone: "deny", fill: "hatched" },
  unsafe_may_have_run: { shape: "octagon", tone: "deny", fill: "solid" },
  flagged_ran: { shape: "diamond", tone: "review", fill: "solid" },
  allowed: { shape: "circle", tone: "allow", fill: "hollow" },
  checked_only: { shape: "square", tone: "ink", fill: "hollow" },
  unplaced: { shape: "circle", tone: "unknown", fill: "dashed" },
  stopped_by_innerwarden: { shape: "octagon", tone: "stopped", fill: "solid" },
  declined_by_agent: { shape: "circle", tone: "allow", fill: "solid" },
  answered: { shape: "diamond", tone: "review", fill: "solid" },
  not_seen: { shape: "circle", tone: "unknown", fill: "dashed" },
};

/** The token each tone draws with. `ink` is the muted ink: a check by hand is neither good nor bad. */
export const TONE_COLOUR: Record<MarkTone, string> = {
  stopped: "var(--iw-stopped)",
  deny: "var(--iw-deny)",
  review: "var(--iw-review)",
  allow: "var(--iw-allow)",
  ink: "var(--iw-ink-3)",
  unknown: "var(--iw-unknown)",
};

/** The two hatch patterns `HatchDefs` mounts once per page. */
export const HATCH_PATTERN = { deny: "iw-hatch-deny", ink: "iw-hatch-ink" } as const;

/** The hatch a hatched mark of this tone is filled with. */
export function hatchFor(tone: MarkTone): string {
  return tone === "deny" ? HATCH_PATTERN.deny : HATCH_PATTERN.ink;
}

/** An outcome's style; a key this table does not know is drawn as "not recorded", never as allowed. */
export function outcomeStyle(key: string): OutcomeStyle {
  return (OUTCOME_STYLE as Record<string, OutcomeStyle | undefined>)[key] ?? OUTCOME_STYLE.unplaced;
}

/** Which outcome a set of counts is mostly made of, the most severe winning a tie. */
export const SEVERITY_ORDER: readonly OutcomeKey[] = [
  "unsafe_may_have_run",
  "refused_before_run",
  "would_have_refused",
  "flagged_ran",
  "stopped_by_innerwarden",
  "answered",
  "declined_by_agent",
  "checked_only",
  "allowed",
  "not_seen",
  "unplaced",
];

export function dominantOutcome(counts: Partial<Record<OutcomeKey, number>>): OutcomeKey | undefined {
  let best: OutcomeKey | undefined;
  let bestCount = 0;
  for (const key of SEVERITY_ORDER) {
    const count = counts[key] ?? 0;
    if (count > bestCount) {
      best = key;
      bestCount = count;
    }
  }
  return best;
}
