import type { DashboardBootstrap, PlanNotice, PlanState } from "./api/v1";

/**
 * The shell's notice about the host's licence, as a pure state machine.
 *
 * The shell feeds it the last bootstrap it read well (a failed read keeps
 * the retained one), so a read that fails never changes what the notice
 * says: it keeps the last state, and never turns into `active` or
 * `free_mode` on its own.
 *
 *  - `ending_soon`, `partly_covered` and `free_mode` draw the host's
 *    sentence and its step.
 *  - `unknown` is a licence state the host could not read: it is said, as
 *    not read, and never looks like a licensed host.
 *  - A move from `ending_soon` or `free_mode` to `active` draws a short
 *    confirmation for `RENEWED_SHOW_MS`, or until hidden. It says the
 *    licence reads valid again, never that anything is back on.
 *  - Absent and `active` (outside that confirmation) draw nothing. Absent
 *    (an older host) is never read as `active`.
 *  - Community draws nothing, whatever the bootstrap carries.
 *
 * It ships in every bundle that composes this kit, so it is kept small.
 */

/** How often the shell re-reads the bootstrap while the plan needs watching. */
export const PLAN_RECHECK_MS = 60_000;
/** How long the confirmation that the licence reads valid again stays. */
export const RENEWED_SHOW_MS = 10 * 60_000;

/** The notices a reader may hide until the state changes; free mode is never one. */
type Hideable = "renewed" | "ending_soon" | "partly_covered" | "unknown";

export type PlanMemory = { last?: PlanState; renewedAt?: number; hidden?: Hideable; until?: number };

export type PlanView =
  | { kind: "none" }
  | { kind: "ending_soon" | "partly_covered" | "free_mode" | "unknown"; notice: PlanNotice }
  | { kind: "renewed"; readAt: number };

/** The renewal's read time while its confirmation shows, else `undefined`. */
function renewal(memory: PlanMemory, now: number): number | undefined {
  const at = memory.renewedAt;
  return at !== undefined && memory.hidden !== "renewed" && now - at < RENEWED_SHOW_MS ? at : undefined;
}

/** The notice for one bootstrap reading, and what to remember for the next. */
export function planStep(
  edition: DashboardBootstrap["edition"] | undefined,
  notice: PlanNotice | undefined,
  memory: PlanMemory,
  now: number,
): PlanStep {
  if (edition !== "enterprise") return { view: { kind: "none" }, memory };
  const state = notice?.state;
  // The same state as last time keeps what was remembered: a read that
  // failed hands the same reading again, and must change nothing. A new
  // state forgets what was hidden.
  if (state !== memory.last) {
    memory = state === "active" && (memory.last === "ending_soon" || memory.last === "free_mode")
      ? { last: state, renewedAt: now }
      : { last: state };
  }
  // When the licence ends, so the shell reads again by then (`bootstrapRefreshMs`).
  const until = state === "ending_soon" && notice?.until !== undefined ? Date.parse(notice.until) : undefined;
  memory = { ...memory, until };
  const readAt = renewal(memory, now);
  const view: PlanView = notice !== undefined && state !== undefined && state !== "active" && (state === "free_mode" || memory.hidden === undefined)
    ? { kind: state, notice }
    : readAt !== undefined
      ? { kind: "renewed", readAt }
      : { kind: "none" };
  return { view, memory };
}

export type PlanStep = { view: PlanView; memory: PlanMemory };

/** The reader hid the notice: nothing is drawn until the state changes. `free_mode` cannot be hidden. */
export function hidePlan({ view, memory }: PlanStep): PlanStep {
  return view.kind === "none" || view.kind === "free_mode"
    ? { view, memory }
    : { view: { kind: "none" }, memory: { ...memory, hidden: view.kind } };
}

/**
 * How long until the shell reads the bootstrap again: `PLAN_RECHECK_MS`
 * while the host is in free mode, its licence state was not read, or the
 * confirmation shows. While the licence ends soon the move to free mode
 * comes at a known time, so the shell keeps `base` and reads again soon
 * after `until`, never more often than `PLAN_RECHECK_MS`. A host that never
 * sends a plan keeps `base`.
 */
export function bootstrapRefreshMs(memory: PlanMemory, now: number, base: number): number {
  if (memory.last === "free_mode" || memory.last === "unknown" || renewal(memory, now) !== undefined) return Math.min(PLAN_RECHECK_MS, base);
  if (memory.last === "ending_soon" && memory.until !== undefined && Number.isFinite(memory.until)) {
    return Math.min(base, Math.max(PLAN_RECHECK_MS, memory.until - now + 5_000));
  }
  return base;
}

/** The header's edition words: "Enterprise, free mode" only in free mode, never for a state that was not read. */
export function editionLabelFor(label: string, view: PlanView): string {
  return view.kind === "free_mode" ? `${label}, free mode` : label;
}
