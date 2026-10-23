import type { DashboardBootstrap, PlanNotice, PlanState } from "./api/v1";

/**
 * The shell's notice about the host's licence, as a pure state machine.
 *
 * The shell feeds it the last bootstrap it read well (a failed read keeps
 * the retained one), so a read that fails never changes what the notice
 * says: it keeps the last state, and never turns into `active` or
 * `free_mode` on its own.
 *
 *  - `ending_soon` and `free_mode` draw the host's sentence and its step.
 *  - A move from either of them to `active` draws a short confirmation for
 *    `RENEWED_SHOW_MS`, or until hidden. It says the licence reads valid
 *    again, never that anything is back on.
 *  - Absent, `active` (outside that confirmation) and `unknown` draw
 *    nothing. Absent or `unknown` is never read as `active`.
 *  - Community draws nothing, whatever the bootstrap carries.
 *
 * It ships in every bundle that composes this kit, so it is kept small.
 */

/** How often the shell re-reads the bootstrap while the plan needs watching. */
export const PLAN_RECHECK_MS = 60_000;
/** How long the confirmation that the licence reads valid again stays. */
export const RENEWED_SHOW_MS = 10 * 60_000;

export type PlanMemory = { last?: PlanState; renewedAt?: number; hidden?: "renewed" | "ending_soon" };

export type PlanView =
  | { kind: "none" }
  | { kind: "ending_soon"; notice: PlanNotice }
  | { kind: "free_mode"; notice: PlanNotice }
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
  const readAt = renewal(memory, now);
  const view: PlanView = notice !== undefined && (state === "free_mode" || (state === "ending_soon" && memory.hidden === undefined))
    ? { kind: state, notice }
    : readAt !== undefined
      ? { kind: "renewed", readAt }
      : { kind: "none" };
  return { view, memory };
}

export type PlanStep = { view: PlanView; memory: PlanMemory };

/** The reader hid the notice: nothing is drawn until the state changes. `free_mode` cannot be hidden. */
export function hidePlan({ view, memory }: PlanStep): PlanStep {
  return view.kind === "renewed" || view.kind === "ending_soon"
    ? { view: { kind: "none" }, memory: { ...memory, hidden: view.kind } }
    : { view, memory };
}

/**
 * How long until the shell reads the bootstrap again: `PLAN_RECHECK_MS` while
 * the licence ends soon, the host is in free mode, or the confirmation
 * shows; `base` otherwise. A host that never sends a plan keeps `base`.
 */
export function bootstrapRefreshMs(memory: PlanMemory, now: number, base: number): number {
  return memory.last === "ending_soon" || memory.last === "free_mode" || renewal(memory, now) !== undefined
    ? Math.min(PLAN_RECHECK_MS, base)
    : base;
}

/** The header's edition words: "Enterprise, free mode" only in free mode. */
export function editionLabelFor(label: string, view: PlanView): string {
  return view.kind === "free_mode" ? `${label}, free mode` : label;
}
