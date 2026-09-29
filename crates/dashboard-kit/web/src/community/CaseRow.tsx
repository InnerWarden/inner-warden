import type { KeyboardEvent } from "react";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { Glyph, type GlyphName } from "../components/icons";
import { When } from "../components/When";
import type { Attempt, Decision } from "./api";
import { OutcomeDot } from "./parts";
import { OUTCOME_WORDS, WHO_WORDS, type Channel } from "./words";

export const CHANNEL_GLYPH: Record<Channel, GlyphName> = {
  hook: "prompt",
  mcp: "plug",
  check: "person",
  unknown: "prompt",
};

/** Who asked, in words: the agent the record names, or the channel's words. Never a session id. */
export function whoWords(item: Pick<Decision, "agent" | "channel">): string {
  return item.agent ?? WHO_WORDS[item.channel];
}

/**
 * Arrow keys move the open case from a focused row, inside the list only:
 * never a global key, so typing in a search box moves nothing.
 */
export function rowKeys(event: KeyboardEvent<HTMLButtonElement>, move: (delta: number) => void) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  event.preventDefault();
  move(event.key === "ArrowDown" ? 1 : -1);
}

/**
 * One flagged decision in a list: the command (as recorded, whole on hover),
 * what happened to it, when, who asked, in which folder, and the rule's few
 * words. No step number, no session id, no score: those are the technical
 * view's, in the case itself.
 */
export function CaseRow({
  item,
  open,
  onOpen,
  onMove,
}: {
  item: Decision;
  open: boolean;
  onOpen: (id: string) => void;
  onMove?: (delta: number) => void;
}) {
  const meta = [whoWords(item), item.project, item.reason.short].filter((part): part is string => part !== undefined && part.length > 0);
  return (
    <li data-case-row={item.id}>
      <button
        type="button"
        data-row-id={item.id}
        aria-current={open ? "true" : undefined}
        onClick={() => onOpen(item.id)}
        onKeyDown={onMove === undefined ? undefined : (event) => rowKeys(event, onMove)}
        className={`relative flex w-full min-w-0 gap-3 px-4 py-2.5 text-left transition-colors ${open ? "bg-slate-50" : "hover:bg-slate-50"}`}
      >
        {open ? <span aria-hidden="true" className="absolute inset-y-0 left-0 w-1 bg-cyan-700" /> : null}
        <Glyph name={CHANNEL_GLYPH[item.channel]} className="mt-0.5 h-4 w-4 text-slate-500" />
        <span className="min-w-0 flex-1">
          <span
            className="block truncate font-mono text-sm leading-5 text-slate-950"
            title={item.commandWhole ? item.command : `${item.command} (shortened when it was recorded)`}
          >
            {item.command}
          </span>
          <span className="mt-1 flex min-w-0 items-center gap-x-3 text-xs">
            <span className="inline-flex min-w-0 items-center gap-1.5 text-slate-700" data-outcome-words={item.outcomeKey}>
              <OutcomeDot outcome={item.outcomeKey} />
              <span className="truncate">{OUTCOME_WORDS[item.outcomeKey]}</span>
            </span>
            {item.recordedAt === undefined ? null : (
              <span className="ml-auto whitespace-nowrap tabular-nums text-slate-500"><When at={item.recordedAt} relative /></span>
            )}
          </span>
          <span className="mt-0.5 block truncate text-xs text-slate-600">{meta.join(" · ")}</span>
          <TechnicalOnly>
            <span className="mt-1 flex min-w-0 flex-wrap items-center gap-x-2 text-[11px] text-slate-500">
              <span className="truncate font-mono">{item.id}</span>
              <span>{item.recommendation}</span>
              <span>{item.mode}</span>
            </span>
          </TechnicalOnly>
        </span>
      </button>
    </li>
  );
}

/** One message someone sent the agent, in the same row shape. */
export function MessageRow({ item, open, onOpen, onMove }: { item: Attempt; open: boolean; onOpen: (id: string) => void; onMove?: (delta: number) => void }) {
  return (
    <li data-case-row={item.id}>
      <button
        type="button"
        data-row-id={item.id}
        aria-current={open ? "true" : undefined}
        onClick={() => onOpen(item.id)}
        onKeyDown={onMove === undefined ? undefined : (event) => rowKeys(event, onMove)}
        className={`relative flex w-full min-w-0 gap-3 px-4 py-2.5 text-left transition-colors ${open ? "bg-slate-50" : "hover:bg-slate-50"}`}
      >
        {open ? <span aria-hidden="true" className="absolute inset-y-0 left-0 w-1 bg-cyan-700" /> : null}
        <Glyph name="chat" className="mt-0.5 h-4 w-4 text-slate-500" />
        <span className="min-w-0 flex-1">
          <span className="line-clamp-2 break-words text-sm leading-5 text-slate-950 [overflow-wrap:anywhere]">{item.detail}</span>
          <span className="mt-1 flex min-w-0 items-center gap-x-3 text-xs">
            <span className="inline-flex min-w-0 items-center gap-1.5 text-slate-700">
              <OutcomeDot outcome={item.outcomeKey} />
              <span className="truncate">{OUTCOME_WORDS[item.outcomeKey]}</span>
            </span>
            <span className="ml-auto whitespace-nowrap tabular-nums text-slate-500"><When at={item.at} relative /></span>
          </span>
          <span className="mt-0.5 block truncate text-xs text-slate-600">Someone on {item.channelWords}</span>
        </span>
      </button>
    </li>
  );
}
