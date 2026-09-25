/**
 * The three questions a reader brings to this dashboard, as the host files
 * them: messages sent to the agent (`prompt`), what the agent tried to do
 * (`agent`), and what came at the server itself (`host`).
 *
 * The HOST decides which lane a case belongs to, and each case belongs to at
 * most one. The screen never guesses: a case the host puts in no lane (raw
 * telemetry, response bookkeeping) is listed only when no lane is asked for.
 * These are wire values; the names a person reads live in `src/lanes.ts`.
 */
export const CASE_LANES = ["prompt", "agent", "host"] as const;
export type CaseLane = (typeof CASE_LANES)[number];

/** How many cases each lane holds, for the window and filters of the request
 * with the lane itself left out. A lane the host did not count is absent. */
export type CaseLaneCounts = Partial<Record<CaseLane, number>>;

export function isCaseLane(value: unknown): value is CaseLane {
  return typeof value === "string" && (CASE_LANES as readonly string[]).includes(value);
}
