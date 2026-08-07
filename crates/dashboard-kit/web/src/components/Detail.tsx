import { useEffect, useMemo, useRef, type ReactNode } from "react";
import type { ActionView } from "../api";
import { formatTimestamp, humanizeToken, modeAtDecisionLabel } from "../presentation";
import { DecidedBy } from "./DecidedBy";
import { Outcome } from "./Outcome";
import { Verdict } from "./Verdict";

/**
 * The rows of the decision dialog, in the order the operator asks for them.
 *
 * What was the verdict, was it actually stopped, when, where did it come from,
 * who decided, and only then the score. Before this the order was the payload's:
 * risk score third, "Sequence #12" fifth, and the timestamp last. Sequence
 * counts our own rows, is already printed on the list behind this dialog, and
 * answers none of those questions, so it is gone rather than reordered.
 */
export function detailRowLabels(present: { when: boolean; session: boolean; mode: boolean }): string[] {
  const labels = ["Verdict", "Execution outcome"];
  if (present.when) labels.push("Recorded");
  if (present.session) labels.push("Session");
  labels.push("Decision source");
  if (present.mode) labels.push("Decision mode");
  labels.push("Risk score");
  return labels;
}

/** An accessible, focus-trapped explanation of one recorded guardrail decision. */
export function Detail({
  action,
  session,
  onClose,
  fallbackFocus,
}: {
  action: ActionView;
  /** Which session this action came out of. The dig-in question "where from"
   * had no answer in this dialog at all: the operator had to close it and read
   * the row behind it. */
  session?: string;
  onClose: () => void;
  fallbackFocus?: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
        'a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => {
      window.removeEventListener("keydown", handleKey);
      document.body.style.overflow = previousOverflow;
      if (
        previousFocus
        && previousFocus.isConnected
        && previousFocus !== document.body
        && previousFocus !== document.documentElement
      ) {
        previousFocus.focus();
      } else {
        fallbackFocus?.();
      }
    };
  }, [fallbackFocus, onClose]);

  const when = formatTimestamp(action.recorded_at_ms);
  const decisionMode = modeAtDecisionLabel(action.mode_at_decision);
  const isMcpAction = /^MCP\s*·/i.test(action.command.trimStart());
  const rows: [string, ReactNode][] = useMemo(() => {
    const rendered: Record<string, ReactNode> = {
      Verdict: <Verdict rec={action.recommendation} />,
      "Execution outcome": <Outcome value={action.outcome ?? "unknown"} />,
      Recorded: when,
      Session: session === "local" ? "Local session" : session,
      "Decision source": <DecidedBy by={action.decided_by} />,
      "Decision mode": decisionMode,
      "Risk score": action.risk == null ? "Not reported" : String(action.risk),
    };
    return detailRowLabels({ when: Boolean(when), session: Boolean(session), mode: Boolean(decisionMode) })
      .map((label): [string, ReactNode] => [label, rendered[label]]);
  }, [action, decisionMode, session, when]);

  return (
    <div className="fixed inset-0 z-20 flex items-start justify-center overflow-y-auto bg-slate-950/40 p-3 pt-8 backdrop-blur-[1px] sm:p-6 sm:pt-16" onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className="flex max-h-[calc(100vh-4rem)] w-full max-w-2xl flex-col overflow-hidden rounded-2xl bg-white shadow-2xl ring-1 ring-slate-300 sm:max-h-[85vh]"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="decision-detail-title"
        aria-describedby={action.explanation ? "decision-explanation" : undefined}
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-200 px-5 py-4 sm:px-6">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Recorded evidence</p>
            <h2 id="decision-detail-title" className="mt-1 text-lg font-semibold text-slate-950">Decision details</h2>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-slate-900"
            aria-label="Close decision details"
          >
            <svg className="h-5 w-5" viewBox="0 0 20 20" fill="none" aria-hidden="true">
              <path d="m5 5 10 10M15 5 5 15" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5 sm:px-6">
          <div>
            <div className="mb-2 text-xs font-semibold text-slate-600">{isMcpAction ? "Recorded MCP tool call" : "Recorded action"}</div>
            <code className="block max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-950 px-4 py-3 text-sm leading-6 text-slate-100">
              {action.command}
            </code>
          </div>

          <dl className="grid gap-3 sm:grid-cols-2">
            {rows.map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5">
                <dt className="text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-500">{label}</dt>
                <dd className="mt-1 text-sm font-medium text-slate-800">{value}</dd>
              </div>
            ))}
          </dl>

          {action.explanation && (
            <section id="decision-explanation" aria-labelledby="why-title">
              <h3 id="why-title" className="text-sm font-semibold text-slate-900">Why it was classified this way</h3>
              <p className="mt-2 rounded-xl border border-slate-200 bg-white p-4 text-sm leading-6 text-slate-700">{action.explanation}</p>
            </section>
          )}

          {action.categories.length > 0 && <Chips label="Risk categories" items={action.categories.map(humanizeToken)} cls="bg-slate-100 text-slate-700" />}
          {action.asi.length > 0 && <Chips label="OWASP Agentic mapping" items={action.asi} cls="border-blue-200 bg-blue-50 text-blue-700" />}

          {isMcpAction ? (
            <p className="border-t border-slate-100 pt-4 text-xs leading-5 text-slate-500">
              This bounded, secret-redacted summary was captured by the guarded MCP proxy. Consult the originating agent or MCP server logs for full protocol context.
            </p>
          ) : (
            <p className="border-t border-slate-100 pt-4 text-xs leading-5 text-slate-500">
              Need a fresh machine-readable verdict? Run <code className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">innerwarden check &quot;&lt;shell-action&gt;&quot; --json</code> in your terminal.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function Chips({ label, items, cls }: { label: string; items: string[]; cls: string }) {
  return (
    <section>
      <h3 className="text-sm font-semibold text-slate-900">{label}</h3>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {items.map((item) => (
          <span key={item} className={`rounded-full border border-transparent px-2.5 py-1 text-xs font-medium ${cls}`}>{item}</span>
        ))}
      </div>
    </section>
  );
}
