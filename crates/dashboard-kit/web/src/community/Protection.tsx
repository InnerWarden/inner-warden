import { useState } from "react";
import type { CommunityScreenContext } from "../App";
import { fetchAgents, fetchOverview } from "../api";
import { Glyph } from "../components/icons";
import { Ring, Spark, Steps, STEP_MARK_CLASS, Swatch } from "../components/viz";
import { formatCount, formatDay } from "../presentation";
import { agentRows } from "./agentsView";
import { fetchHistory, fetchProtection, fetchRecordHealth, readOverviewRecord, readScreenedByChannel, type FlaggedConcerns, type History } from "./api";
import { communityControls, controlCounts, controlRing, someRefuse, type Control, type ControlCounts, type ControlState } from "./controls";
import { dismissed } from "./dismiss";
import { InstalledLine, OfferBox } from "./Offer";
import { NOT_IN_COMMUNITY, paidRowFact, protectionOffer } from "./offers";
import { CARD, Chip, CopyCommand, PageHeader, Skeleton, StaleLine, Unreadable, type ChipTone } from "./parts";
import { usePolled } from "./poll";
import { asPlatform, PLATFORM_WORDS } from "./words";

export const PROTECTION_POLL_MS = 30_000;
export const HISTORY_POLL_MS = 60_000;

const STATE_TONE: Record<ControlState | "none", ChipTone> = {
  refusing: "accent",
  on: "watch",
  needs: "needs",
  off: "off",
  none: "watch",
};

const LEGEND: { key: ControlState; words: string }[] = [
  { key: "refusing", words: "Refusing" },
  { key: "on", words: "On" },
  { key: "needs", words: "Needs you" },
  { key: "off", words: "Off" },
];

export function protectionHeadline(counts: ControlCounts): string {
  const total = counts.refusing + counts.on + counts.needs + counts.off;
  const on = counts.refusing + counts.on;
  const parts = [`${on} on`];
  if (counts.needs > 0) parts.push(`${counts.needs} ${counts.needs === 1 ? "needs" : "need"} you`);
  parts.push(`${counts.off} off`);
  return `${total} Community controls: ${parts.join(", ")}.`;
}

/**
 * The legend's words for one state. No control counts as refusing while an
 * agent under a mixed control does refuse: "Some refuse", never "0 Refusing"
 * beside a row that says Cursor refuses.
 */
export function legendWords(key: ControlState, counts: ControlCounts, partly: boolean): { count?: number; words: string } {
  if (key === "refusing" && counts.refusing === 0 && partly) return { words: "Some refuse" };
  return { count: counts[key], words: LEGEND.find((entry) => entry.key === key)?.words ?? key };
}

/**
 * Community's Protection: what it covers on this machine, then what it did
 * (the proof it is worth keeping), then control by control, then what it does
 * not cover, tied to this machine's own counts.
 */
export function CommunityProtection({ context }: { context: CommunityScreenContext }) {
  const protection = usePolled(fetchProtection, PROTECTION_POLL_MS, "protection");
  const agents = usePolled(fetchAgents, PROTECTION_POLL_MS, "agents");
  const health = usePolled(fetchRecordHealth, PROTECTION_POLL_MS, "record-health");
  const history = usePolled(fetchHistory, HISTORY_POLL_MS, "history");
  const overview = usePolled(fetchOverview, PROTECTION_POLL_MS, "overview-record");
  const os = asPlatform(protection.data?.os ?? context.bootstrap?.platform.os);
  const installed = context.meta?.active_defence_installed === true;
  const record = readOverviewRecord((overview.data as { record?: unknown } | undefined)?.record);
  const now = Date.now();
  const controls = communityControls({
    agents: agentRows(agents.data),
    ...(protection.data === undefined ? {} : { protection: protection.data }),
    ...(health.data === undefined ? {} : { health: health.data }),
    ...(record === undefined ? {} : { record }),
    ...(record?.oldestAt === undefined ? {} : { sinceWords: formatDay(record.oldestAt) }),
    ...(history.data === undefined || !history.data.readable ? {} : { messagesRecorded: history.data.messages.recorded }),
    channelSeen: readScreenedByChannel(agents.data),
    now,
  });
  const counts = controlCounts(controls);
  const partly = someRefuse(controls);
  const on = counts.refusing + counts.on;
  const total = counts.refusing + counts.on + counts.needs + counts.off;
  const loading = protection.data === undefined && protection.error === undefined;
  const flagged = protection.data?.flagged;

  return (
    <div className="min-w-0 space-y-6">
      <PageHeader eyebrow="Protection" title={`What Community covers on ${PLATFORM_WORDS[os]}`} titleId="protection-title" />
      {protection.stale ? <StaleLine onRetry={protection.refresh} /> : null}
      {loading ? (
        <Skeleton className="h-28" />
      ) : protection.data === undefined ? (
        <Unreadable title="What Community covers could not be read" body="The controls below come from their own sources." onRetry={protection.refresh} />
      ) : (
        <section aria-labelledby="coverage-title" data-tour="community-protection" className={CARD}>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
            <Ring parts={controlRing(counts)} size={88} stroke={10} label={`${on} of ${total} Community controls on`}>
              <span className="text-2xl font-semibold text-slate-950">{on}</span>{" "}
              <span className="text-[11px] text-slate-500">of {total} on</span>
            </Ring>
            <div className="min-w-0 flex-1">
              <h2 id="coverage-title" className="text-lg font-semibold text-slate-950">{protectionHeadline(counts)}</h2>
              <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm text-slate-700">
                {LEGEND.map(({ key }) => {
                  const legend = legendWords(key, counts, partly);
                  return (
                    <li key={key} data-legend={key} className="inline-flex items-center gap-1.5" {...(key === "needs" && counts.needs > 0 ? { "data-needs-you": "" } : {})}>
                      <Swatch part={{ tone: controlRing(counts).find((part) => part.key === key)?.tone ?? "off" }} className="h-2.5 w-2.5" />
                      {legend.count === undefined ? null : <span className="font-semibold tabular-nums text-slate-950">{legend.count}</span>} {legend.words}
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        </section>
      )}

      <DidForYou history={history.data} failed={history.data === undefined && history.error !== undefined} />

      <section aria-labelledby="controls-title" className={CARD}>
        <h2 id="controls-title" className="sr-only">Controls</h2>
        <ul className="divide-y divide-slate-100">
          {controls.map((control) => <ControlRow key={control.key} control={control} />)}
        </ul>
      </section>

      <NotInCommunity installed={installed} flagged={flagged} />
    </div>
  );
}

function ControlRow({ control }: { control: Control }) {
  return (
    <li data-control={control.key} data-control-state={control.state} className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 lg:flex-row lg:items-start lg:gap-6">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="flex items-center gap-2 text-sm font-semibold text-slate-950">
            {control.glyph === undefined ? <span className="inline-block h-4 w-4" aria-hidden="true" /> : <Glyph name={control.glyph} className="h-4 w-4 text-slate-500" />}
            {control.name}
          </span>
          <Chip tone={STATE_TONE[control.state]} label={control.status} />
        </div>
        <p className="mt-1 text-sm leading-6 text-slate-600 sm:pl-6">{control.line}</p>
        {control.command === undefined ? null : (
          <div className="mt-1.5 max-w-xl sm:pl-6">
            <p className="text-xs font-semibold text-slate-700">{control.command.label}</p>
            <CopyCommand command={control.command.command} template={control.command.template === true} className="mt-1" />
          </div>
        )}
      </div>
      {control.ladder === undefined ? null : (
        <div className="w-full shrink-0 rounded-xl border border-slate-200 bg-slate-50 px-3 pb-2 pt-3 lg:w-72">
          <Steps steps={control.ladder} label={`${control.name}: how far it goes`} captions compact className="w-full" />
        </div>
      )}
    </li>
  );
}

/** The weeks a line may draw: whole ones. The week under way would read as a fall. */
export function fullWeeks(history: History | undefined): History["refusals"]["weeks"] {
  return (history?.refusals.weeks ?? []).filter((week) => !week.partial);
}

function DidForYou({ history, failed }: { history?: History; failed: boolean }) {
  const weeks = fullWeeks(history);
  const since = history?.since === undefined ? undefined : formatDay(history.since);
  return (
    <section aria-labelledby="did-title">
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
        <h2 id="did-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">What Community did for you</h2>
        {since === undefined ? null : <p className="text-xs text-slate-500">since {since}, from the guard's event log</p>}
      </div>
      <div className={`mt-3 ${CARD}`}>
        {history === undefined ? (
          failed ? <p className="text-sm text-slate-600">The guard's event log could not be read.</p> : <Skeleton className="h-20 border-0" />
        ) : !history.readable ? (
          <p className="text-sm text-slate-600">The guard's event log could not be read.</p>
        ) : history.refusals.blocked + history.refusals.wouldBlock === 0 ? (
          <p className="text-sm text-slate-600">No command has been refused or flagged for refusal yet.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-x-8 gap-y-4">
            <p className="flex flex-wrap items-baseline gap-x-1.5">
              <span className="text-3xl font-semibold text-slate-950">{formatCount(history.refusals.blocked)}</span>{" "}
              <span className="text-sm text-slate-600">refused before they ran</span>
            </p>
            <p className="flex flex-wrap items-baseline gap-x-1.5">
              <span className="text-3xl font-semibold text-slate-950">{formatCount(history.refusals.wouldBlock)}</span>{" "}
              <span className="text-sm text-slate-600">would have been refused (monitor mode)</span>
            </p>
            {weeks.length < 2 ? null : (
              <div className="min-w-0 grow basis-[15rem]">
                <Spark
                  values={weeks.map((week) => week.blocked + week.wouldBlock)}
                  tone="watch"
                  className="h-10 w-full"
                  height={32}
                  label={`Refused and would-have-refused commands per full week since ${formatDay(`${weeks[0].start}T00:00:00Z`) ?? weeks[0].start}`}
                />
                <p className="mt-1 text-xs text-slate-500">Refused and would-refuse, per full week</p>
              </div>
            )}
          </div>
        )}
        {history === undefined || !history.readable || history.suppressionChanges === 0 ? null : (
          <p className="mt-3 text-xs leading-5 text-slate-500">
            {formatCount(history.suppressionChanges)} {history.suppressionChanges === 1 ? "change" : "changes"} to your allow and mute list.
          </p>
        )}
      </div>
    </section>
  );
}

function NotInCommunity({ installed, flagged }: { installed: boolean; flagged?: FlaggedConcerns }) {
  const [gone, setGone] = useState(() => dismissed("protection"));
  if (installed) {
    return (
      <section aria-labelledby="not-in-community-title" data-tour="upgrade">
        <h2 id="not-in-community-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Active Defence is installed on this host</h2>
        <div className="mt-3"><InstalledLine /></div>
      </section>
    );
  }
  const sinceWords = flagged?.since === undefined ? undefined : formatDay(flagged.since);
  return (
    <section aria-labelledby="not-in-community-title" data-tour="upgrade">
      <h2 id="not-in-community-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Not in Community</h2>
      <div className={`mt-3 ${CARD}`}>
        <ul className="divide-y divide-slate-100">
          {NOT_IN_COMMUNITY.map((capability) => {
            const fact = paidRowFact(capability.key, flagged, sinceWords);
            return (
              <li key={capability.key} data-paid={capability.key} className="flex items-start gap-3 py-2.5 first:pt-0">
                <Glyph name={capability.glyph} className="mt-0.5 h-4 w-4 text-slate-400" />
                <div className="min-w-0 flex-1 sm:flex sm:gap-4">
                  <p className="flex shrink-0 items-center gap-2 text-sm font-semibold text-slate-900 sm:w-48">
                    {capability.name}
                    <span className="flex h-3 w-3 shrink-0 items-center justify-center" title="Not in Community">
                      <span aria-hidden="true" data-mark="not_applicable" className={`block ${STEP_MARK_CLASS.not_applicable}`} />
                      <span className="sr-only">Not in Community</span>
                    </span>
                  </p>
                  <div className="min-w-0 text-sm leading-6">
                    <p className="text-slate-600">{capability.line}</p>
                    {fact === undefined ? null : <p data-paid-fact className="text-slate-800">{fact}</p>}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
        <div className="mt-4">
          {gone ? (
            <p className="text-sm text-slate-600">These are Active Defence, for Linux servers.</p>
          ) : (
            <OfferBox offer={protectionOffer()} installed={false} onDismissed={() => setGone(true)} />
          )}
        </div>
      </div>
    </section>
  );
}
