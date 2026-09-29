import { useEffect, useRef, useState, type ReactNode } from "react";
import { outcomeTone } from "../components/LaneCards";
import { Glyph, type GlyphName } from "../components/icons";
import { partFill } from "../components/viz";

/**
 * The small pieces every Community page is built from, in the paid redesign's
 * vocabulary: one card shell, one eyebrow, one chip, one command box.
 *
 * Colour has a job and only that job (spec M5): amber appears only inside an
 * element marked `data-needs-you`, rose only on an outcome that happened
 * (`data-outcome="unsafe_may_have_run"`), a factual No on a ladder
 * (`data-mark="no"`) or a dashboard open to the network (`data-exposed`), and
 * emerald never: Community reads nothing back after the fact.
 */

export const CARD = "min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5";
export const EYEBROW = "text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700";
export const LINK = "text-sm font-semibold text-cyan-700 hover:text-cyan-900";

export function Eyebrow({ children, glyph, id }: { children: ReactNode; glyph?: GlyphName; id?: string }) {
  return (
    <p id={id} className={`flex items-center gap-1.5 ${EYEBROW}`}>
      {glyph === undefined ? null : <Glyph name={glyph} className="h-3.5 w-3.5" />}
      <span className="min-w-0">{children}</span>
    </p>
  );
}

/** A page's heading: what the page is, its name, and one line on what it answers. */
export function PageHeader({
  eyebrow,
  title,
  description,
  aside,
  titleId,
  tour,
}: {
  eyebrow: string;
  title: string;
  description?: ReactNode;
  aside?: ReactNode;
  titleId: string;
  tour?: string;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-3" data-tour={tour}>
      <div className="min-w-0">
        <p className={EYEBROW}>{eyebrow}</p>
        <h1 id={titleId} className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">{title}</h1>
        {description === undefined ? null : <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{description}</p>}
      </div>
      {aside === undefined ? null : <div className="flex flex-wrap items-center gap-2">{aside}</div>}
    </div>
  );
}

export type ChipTone = "accent" | "watch" | "needs" | "exposed" | "off";

const CHIP_CLASS: Record<ChipTone, string> = {
  accent: "border-cyan-200 bg-cyan-50 text-cyan-900",
  watch: "border-slate-200 bg-slate-50 text-slate-700",
  needs: "border-amber-200 bg-amber-50 text-amber-900",
  exposed: "border-rose-200 bg-rose-50 text-rose-800",
  off: "border-slate-200 bg-white text-slate-500",
};

const CHIP_SYMBOL: Record<ChipTone, string> = {
  accent: "i",
  watch: "i",
  needs: "!",
  exposed: "×",
  off: "-",
};

/**
 * A state in words, with a symbol so the colour is never the only signal:
 * "i" for a state that is so, "!" for one that needs a person, "×" for a
 * dashboard open to the network, "-" for off.
 */
export function Chip({ tone, label, title, className = "" }: { tone: ChipTone; label: string; title?: string; className?: string }) {
  const marks = tone === "needs" ? { "data-needs-you": "" } : tone === "exposed" ? { "data-exposed": "" } : {};
  return (
    <span
      {...marks}
      data-chip={tone}
      title={title}
      className={`inline-flex w-fit max-w-full items-start gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold leading-4 ${CHIP_CLASS[tone]} ${className}`}
    >
      <span className="shrink-0 font-bold" aria-hidden="true">{CHIP_SYMBOL[tone]}</span>
      <span className="min-w-0 break-words">{label}</span>
    </span>
  );
}

/**
 * The dot an outcome is drawn with, in the one outcome palette
 * (`outcomeTone`). An outcome that happened and was bad (judged unsafe, and it
 * ran) is a rose RING, so it reads apart from every fill.
 */
export function OutcomeDot({ outcome, className = "" }: { outcome: string; className?: string }) {
  if (outcome === "unsafe_may_have_run") {
    return <span aria-hidden="true" data-outcome={outcome} className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full border-2 border-rose-500 bg-white ${className}`} />;
  }
  return (
    <span
      aria-hidden="true"
      data-outcome={outcome}
      className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${className}`}
      style={{ background: partFill(outcomeTone(outcome)) }}
    />
  );
}

/**
 * A command to copy, whole, in a box that wraps inside itself and never
 * scrolls the page sideways. Printed exactly as the CLI sent it: the page
 * never builds a command from parts.
 */
export function CopyCommand({ command, className = "" }: { command: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const copy = () => {
    const done = () => {
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1_500);
    };
    try {
      void navigator.clipboard?.writeText(command).then(done, () => undefined);
    } catch {
      // No clipboard in this browser: the command is still on screen to select.
    }
  };
  return (
    <div className={`flex min-w-0 items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-3 pr-1.5 ${className}`}>
      <code data-command className="min-w-0 flex-1 break-words py-0.5 font-mono text-[13px] leading-5 text-slate-900 [overflow-wrap:anywhere]">{command}</code>
      <button
        type="button"
        onClick={copy}
        aria-label={`Copy the command ${command}`}
        className="shrink-0 rounded-md border border-slate-300 bg-white px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-100"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

/** A block shown while the first answer is on its way, the height of what it stands for. */
export function Skeleton({ className = "h-24" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-2xl border border-slate-200 bg-white ${className}`} />;
}

/**
 * Something could not be read. Slate, never amber: nobody has to decide
 * anything, and the page must not look like it is asking.
 */
export function Unreadable({ title, body, onRetry }: { title: string; body?: ReactNode; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
      <p className="font-semibold text-slate-900">{title}</p>
      {body === undefined ? null : <p className="mt-1 leading-6 text-slate-600">{body}</p>}
      {onRetry === undefined ? null : (
        <button type="button" onClick={onRetry} className={`mt-2 ${LINK}`}>Try again</button>
      )}
    </div>
  );
}

/** A line saying the last answer is kept because a newer read failed. */
export function StaleLine({ onRetry }: { onRetry?: () => void }) {
  return (
    <p role="status" className="flex flex-wrap items-center gap-x-3 text-xs text-slate-600">
      <span>Could not refresh. Showing the last answer.</span>
      {onRetry === undefined ? null : <button type="button" onClick={onRetry} className="font-semibold text-cyan-700 hover:text-cyan-900">Try again</button>}
    </p>
  );
}

/** "See all" and every other in-app link: a button, an arrow the screen reader skips. */
export function Go({ children, onClick, className = "" }: { children: ReactNode; onClick: () => void; className?: string }) {
  return (
    <button type="button" onClick={onClick} className={`${LINK} ${className}`}>
      {children} <span aria-hidden="true">→</span>
    </button>
  );
}
