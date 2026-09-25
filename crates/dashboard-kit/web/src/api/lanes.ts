/**
 * The three questions a reader brings to this dashboard, as the host files
 * them: messages sent to the AI agent (`agent_messages`), what the agent
 * tried to do (`agent_actions`), and what came at the server itself
 * (`server_attacks`).
 *
 * These are WIRE values, exactly as the server spells them: the `lane` query
 * value, the `lane_counts` keys, the `overview.lanes` keys and the `lane` in
 * a Cases address. The server refuses any other `lane` value outright
 * (`enterprise_cases_filter_invalid`), so a spelling of our own here would
 * fail every lane request on a real host. The names a person reads live in
 * `src/lanes.ts`.
 *
 * The HOST decides which lane a case belongs to, and each case belongs to at
 * most one. The screen never guesses: a case the host puts in no lane (raw
 * telemetry, response bookkeeping, sources it could not read) is counted as
 * `other` and listed only when no lane is asked for.
 */
export const CASE_LANES = ["agent_messages", "agent_actions", "server_attacks"] as const;
export type CaseLane = (typeof CASE_LANES)[number];

/** The `lane_counts` key for the cases no lane holds. */
export const OTHER_LANE_COUNT = "other";

/**
 * How many cases each lane holds, for the window and filters of the request
 * with the lane itself set aside, and how many belong to no lane (`other`).
 * A key the host did not send, or sent malformed, is absent, never zero.
 */
export type CaseLaneCounts = Partial<Record<CaseLane | typeof OTHER_LANE_COUNT, number>>;

export function isCaseLane(value: unknown): value is CaseLane {
  return typeof value === "string" && (CASE_LANES as readonly string[]).includes(value);
}

/**
 * Every case the request's filters and window hold, lanes or none: the four
 * counts added up, which the host guarantees equals the same request's
 * `total_in_window` without a lane. Only when all four arrived, because a sum
 * with a part missing would be a smaller number presented as the whole.
 */
export function everythingCount(counts: CaseLaneCounts | undefined): number | undefined {
  if (counts === undefined) return undefined;
  let total = 0;
  for (const key of [...CASE_LANES, OTHER_LANE_COUNT] as const) {
    const count = counts[key];
    if (count === undefined) return undefined;
    total += count;
  }
  return Number.isSafeInteger(total) ? total : undefined;
}
