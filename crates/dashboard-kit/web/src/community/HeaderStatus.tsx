import type { DashboardMeta } from "../api";
import { useTechnicalDetail } from "../components/TechnicalDetail";
import { normaliseMode } from "../presentation";
import { Chip, type ChipTone } from "./parts";
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

/**
 * The header's status on Community: ONE chip saying what the guard does
 * here, in words, at every width (a phone used to see only a check mark),
 * and a rose chip when the dashboard is open to the network with no sign-in.
 * A local dashboard says nothing about exposure in the plain view; the
 * technical view adds "Local only".
 */
export function HeaderStatus({ meta, metaStatus }: { meta?: DashboardMeta; metaStatus: MetaStatus }) {
  const [technical] = useTechnicalDetail();
  if (metaStatus === "loading" && meta === undefined) return <Chip tone="watch" label="Checking" />;
  const exposed = meta?.exposed === true;
  const mode = metaStatus === "error" ? "unknown" : normaliseMode(meta);
  return (
    <>
      {exposed ? <Chip tone="exposed" label="Open to the network" title="Anyone who can reach this machine can read this dashboard" /> : null}
      <Chip tone={MODE_TONE[mode]} label={MODE_WORDS[mode]} className="whitespace-nowrap" />
      {technical && meta?.exposed === false ? <Chip tone="off" label="Local only" /> : null}
    </>
  );
}
