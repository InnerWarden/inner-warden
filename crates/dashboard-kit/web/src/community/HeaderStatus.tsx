import { memo } from "react";
import type { DashboardMeta } from "../api";
import { normaliseMode } from "../presentation";
import type { RecordHealth } from "./api";
import { useSource } from "./store";
import { StatusPill, type PillState } from "./ui/marks";
import { ENFORCE_MEANS, MONITOR_MEANS } from "./words";

type MetaStatus = "loading" | "ready" | "error";

/**
 * The header's one status (spec 5.1): the first row of this table that is
 * true, drawn as a pill with an icon and words. The page's own band and
 * banners say the rest in full.
 */
export type HeaderRow = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

export const HEADER_ROWS: Record<HeaderRow, { words: string; state: PillState; label: string }> = {
  0: { words: "Checking", state: "checking", label: "Status: checking" },
  1: { words: "Open to network", state: "exposed", label: "Open to the network: anyone who can reach this machine can read these pages" },
  2: { words: "Not recording", state: "needs", label: "Not recording: decisions are not being written down" },
  3: { words: "Needs you", state: "needs", label: "Needs you: an agent is not connected, or only partly" },
  4: { words: "Unknown", state: "unknown", label: "Mode unknown: it could not be read, so this page claims none" },
  5: { words: "Mixed", state: "mixed", label: "Mixed: some agents are set to refuse a deny, some are in monitor" },
  // Both sentences already open with the mode's own word ("Monitor is a dry
  // run", "Enforce: a deny is refused"), so the name is the sentence alone
  // rather than the word said twice.
  6: { words: "Monitor", state: "monitor", label: MONITOR_MEANS },
  7: { words: "Enforce", state: "enforce", label: ENFORCE_MEANS },
};

/**
 * Which row is true. A mode read from an answer that has since failed is not
 * a mode: a failed read is row 4, never the last mode it said.
 */
export function headerRow(meta: DashboardMeta | undefined, metaStatus: MetaStatus, health: RecordHealth | undefined): HeaderRow {
  if (metaStatus === "loading" && meta === undefined) return 0;
  if (meta?.exposed === true) return 1;
  if (health?.recording === false) return 2;
  const mode = metaStatus === "error" ? "unknown" : normaliseMode(meta);
  if (mode === "not_configured" || mode === "partial") return 3;
  if (mode === "unknown") return 4;
  if (mode === "mixed") return 5;
  if (mode === "monitor") return 6;
  return 7;
}

/**
 * The pill for one row. Memoised on the row, so a poll that lands on the
 * same row re-renders nothing and the live region announces nothing.
 */
export const HeaderPill = memo(function HeaderPill({ row }: { row: HeaderRow }) {
  const { words, state, label } = HEADER_ROWS[row];
  return <StatusPill state={state} words={words} label={label} title={label} />;
});

/**
 * The header's status on Community: one pill, in an `aria-live="polite"`
 * region, at every width. Whether the dashboard answers only on this machine
 * is the technical view's, said once at the foot of each page.
 */
export function HeaderStatus({ meta, metaStatus }: { meta?: DashboardMeta; metaStatus: MetaStatus }) {
  const health = useSource("record-health");
  return (
    <span aria-live="polite" aria-atomic="true" data-header-status className="inline-flex min-w-0">
      <HeaderPill row={headerRow(meta, metaStatus, health.data)} />
    </span>
  );
}
