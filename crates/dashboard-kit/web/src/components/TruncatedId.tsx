import { useState } from "react";

// A long content-addressed id (case:incident:<64-hex>, event:sqlite-incident:<hash>)
// is essential for audit but dominates the UI and reads as noise day-to-day. This
// shows a friendly form — the readable type label + a short hash tail — while
// keeping the FULL id one interaction away (native tooltip on hover + copy button
// to clipboard). Depth preserved, clutter removed.

function CopyIcon() {
  return (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
      <path d="M10.5 5.5V4A1.5 1.5 0 0 0 9 2.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" />
    </svg>
  );
}
function CheckIcon() {
  return (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M3.5 8.5l3 3 6-6.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const HASH = /^[0-9a-f]{12,}$/i;

/** Split "case:incident:<hash>" / "event:sqlite-incident:<hash>" into a readable
 * label + short hash tail. Non-hash ids are shown verbatim (truncated). */
export function friendlyId(value: string): { label: string; short: string | null; full: string } {
  const parts = value.split(":");
  const tail = parts[parts.length - 1] ?? value;
  if (parts.length >= 2 && HASH.test(tail)) {
    return {
      label: parts.slice(0, -1).join(" ").replace(/[-_]/g, " "),
      short: `${tail.slice(0, 8)}…`,
      full: value,
    };
  }
  return { label: value, short: null, full: value };
}

/** A standalone "copy full id" affordance. Kept separate from the label so a
 * caller can render the label inside a semantic element (e.g. an <h3> heading)
 * whose accessible name stays the id itself — not "id Copy full id: id" — while
 * still offering copy-to-clipboard next to it. */
export function CopyIdButton({ value, className = "" }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      })
      .catch(() => {});
  };
  return (
    <button
      type="button"
      onClick={copy}
      className={`shrink-0 rounded p-0.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 ${className}`}
      aria-label={copied ? "Copied full id" : `Copy full id: ${value}`}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </button>
  );
}

export function TruncatedId({
  value,
  className = "",
  labelClassName = "text-slate-500",
}: {
  value: string;
  className?: string;
  labelClassName?: string;
}) {
  const { label, short, full } = friendlyId(value);
  return (
    <span className={`inline-flex max-w-full items-center gap-1.5 ${className}`} title={full}>
      <span className={`truncate font-mono text-xs ${labelClassName}`}>
        {label}
        {short && <span className="text-slate-400"> · {short}</span>}
      </span>
      <CopyIdButton value={full} />
    </span>
  );
}
