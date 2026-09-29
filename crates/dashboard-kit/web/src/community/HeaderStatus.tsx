import type { DashboardMeta } from "../api";
import { normaliseMode } from "../presentation";
import { fetchRecordHealth, type RecordHealth } from "./api";
import { RECORD_HEALTH_POLL_MS } from "./Notices";
import { Chip, type ChipTone } from "./parts";
import { usePolled } from "./poll";
import { MODE_WORDS } from "./words";

type MetaStatus = "loading" | "ready" | "error";

const MODE_TONE: Record<keyof typeof MODE_WORDS, ChipTone> = {
  enforce: "accent",
  monitor: "watch",
  mixed: "watch",
  // A person is needed: an agent is not, or only partly, in front of the guard.
  partial: "needs",
  not_configured: "needs",
  unknown: "watch",
};

export type HeaderChip = { tone: ChipTone; label: string; title?: string };

/**
 * The ONE chip the header carries: the most severe thing that is true, in
 * this order. The dashboard open to the network (rose), decisions not being
 * recorded (amber), an agent not or partly connected (amber), then the mode
 * in words. The page's own banners say the rest in full; a second chip made
 * the header two rows at 1440, where the paid header is always one.
 */
export function headerChip(meta: DashboardMeta | undefined, metaStatus: MetaStatus, health: RecordHealth | undefined): HeaderChip {
  if (metaStatus === "loading" && meta === undefined) return { tone: "watch", label: "Checking" };
  if (meta?.exposed === true) {
    return { tone: "exposed", label: "Open to the network", title: "Anyone who can reach this machine can read this dashboard" };
  }
  if (health?.recording === false) return { tone: "needs", label: "Not recording", title: "Decisions are not being written down; the notice on the page says why" };
  const mode = metaStatus === "error" ? "unknown" : normaliseMode(meta);
  return { tone: MODE_TONE[mode], label: MODE_WORDS[mode] };
}

/**
 * The header's status on Community: one chip, in words, at every width (a
 * phone used to see only a check mark). Whether the dashboard answers only on
 * this machine is the technical view's, said once at the foot of each page.
 */
export function HeaderStatus({ meta, metaStatus }: { meta?: DashboardMeta; metaStatus: MetaStatus }) {
  const health = usePolled(fetchRecordHealth, RECORD_HEALTH_POLL_MS, "record-health");
  const chip = headerChip(meta, metaStatus, health.data);
  return <Chip tone={chip.tone} label={chip.label} title={chip.title} className="whitespace-nowrap" />;
}
