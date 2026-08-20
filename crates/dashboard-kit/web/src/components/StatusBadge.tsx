export type StatusTone = "positive" | "informational" | "attention" | "critical" | "neutral";

export type StatusPresentation = {
  label: string;
  tone: StatusTone;
  symbol: string;
};

const PRESENTATIONS: Record<string, Omit<StatusPresentation, "label"> & { label?: string }> = {
  available: { tone: "positive", symbol: "✓" },
  active: { tone: "positive", symbol: "✓" },
  healthy: { tone: "positive", symbol: "✓" },
  host_verified: { tone: "positive", symbol: "✓", label: "Host verified" },
  allowed: { tone: "positive", symbol: "✓" },
  contained: { tone: "positive", symbol: "✓" },
  blocked_before_execution: { tone: "critical", symbol: "×", label: "Blocked before execution" },
  failed: { tone: "critical", symbol: "×" },
  contradicted: { tone: "critical", symbol: "×" },
  conflicting: { tone: "critical", symbol: "×", label: "Conflicting identity" },
  unsupported: { tone: "critical", symbol: "–" },
  degraded: { tone: "attention", symbol: "!" },
  stale: { tone: "attention", symbol: "!" },
  would_block: { tone: "attention", symbol: "!", label: "Would block" },
  not_covered: { tone: "attention", symbol: "!", label: "Not covered" },
  not_configured: { tone: "neutral", symbol: "–", label: "Not configured" },
  unavailable: { tone: "neutral", symbol: "–" },
  missing: { tone: "neutral", symbol: "–" },
  unattributed: { tone: "neutral", symbol: "?", label: "Unattributed" },
  unknown: { tone: "neutral", symbol: "?" },
  declared: { tone: "informational", symbol: "i", label: "Declared only" },
  configured: { tone: "informational", symbol: "i", label: "Configured identity" },
  observed_only: { tone: "informational", symbol: "i", label: "Observed only" },
  visibility_only: { tone: "informational", symbol: "i", label: "Visibility only" },
  readiness_only: { tone: "informational", symbol: "i", label: "Readiness only" },
  observe: { tone: "informational", symbol: "i" },
  rehearse: { tone: "informational", symbol: "i" },
  loading: { tone: "informational", symbol: "…" },
  reverted: { tone: "informational", symbol: "↺" },
  pending: { tone: "attention", symbol: "…" },
  requested: { tone: "attention", symbol: "…" },
  applied: { tone: "attention", symbol: "!" },
  verified: { tone: "positive", symbol: "✓" },
  expired: { tone: "neutral", symbol: "–" },
  rejected: { tone: "critical", symbol: "×" },
  not_observed: { tone: "neutral", symbol: "–", label: "Not observed" },

  // ── Dispositions ──────────────────────────────────────────────────────────
  //
  // Only `proven` gets the positive tone. `working_as_configured` is
  // informational, not emerald: "no action needed" and "we proved this
  // protects you" are different claims, and collapsing them is the over-claim
  // the posture model exists to prevent.
  //
  // `not_enabled` and `cannot_verify` are NEUTRAL on purpose. Both used to
  // arrive here as `not_covered`, which is `attention` — so a correct fresh
  // install, which arms nothing by design, rendered the whole page amber and
  // taught the operator that amber means nothing.
  proven: { tone: "positive", symbol: "✓", label: "Protecting" },
  working_as_configured: { tone: "informational", symbol: "i", label: "Working as set up" },
  not_enabled: { tone: "neutral", symbol: "–", label: "Not turned on" },
  cannot_verify: { tone: "neutral", symbol: "?", label: "Can't confirm" },
  needs_operator: { tone: "attention", symbol: "!", label: "Needs you" },

  // The 5-stage convergence strip rendered every stage in the fallback grey
  // because these keys were missing, so a converged control looked identical
  // to an unmeasured one.
  disabled: { tone: "neutral", symbol: "–", label: "Off" },
  learning: { tone: "informational", symbol: "i", label: "Learning" },
  mixed: { tone: "attention", symbol: "!", label: "Partly on" },
  enforce: { tone: "informational", symbol: "i", label: "Enforcing (declared)" },
  yes: { tone: "positive", symbol: "✓", label: "Yes" },
  no: { tone: "neutral", symbol: "–", label: "No" },
  not_applicable: { tone: "neutral", symbol: "–", label: "Not applicable" },
};

function humanize(value: string): string {
  const spaced = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : "Unknown";
}

export function statusPresentation(status: string, label?: string, tone?: StatusTone): StatusPresentation {
  const known = PRESENTATIONS[status];
  return {
    label: label ?? known?.label ?? humanize(status),
    tone: tone ?? known?.tone ?? "neutral",
    symbol: known?.symbol ?? "•",
  };
}

export function StatusBadge({
  status,
  label,
  tone,
  className = "",
}: {
  status: string;
  label?: string;
  tone?: StatusTone;
  className?: string;
}) {
  const presentation = statusPresentation(status, label, tone);
  const classes: Record<StatusTone, string> = {
    positive: "border-emerald-200 bg-emerald-50 text-emerald-800",
    informational: "border-blue-200 bg-blue-50 text-blue-800",
    attention: "border-amber-200 bg-amber-50 text-amber-900",
    critical: "border-red-200 bg-red-50 text-red-800",
    neutral: "border-slate-200 bg-slate-50 text-slate-700",
  };

  return (
    <span
      data-status={status}
      className={`inline-flex w-fit max-w-full items-start gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold leading-4 ${classes[presentation.tone]} ${className}`}
    >
      <span className="shrink-0 font-bold" aria-hidden="true">{presentation.symbol}</span>
      {/* break-words (not overflow-wrap:anywhere): a squeezed badge wraps at word
          boundaries and keeps its min-content width at the longest word, so a
          short single-word label like "medium" never shatters into a vertical
          char stack when a sibling flex item is wide. */}
      <span className="min-w-0 break-words">{presentation.label}</span>
    </span>
  );
}
