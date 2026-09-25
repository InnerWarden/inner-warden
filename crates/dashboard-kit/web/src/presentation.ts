import type { DashboardMeta, GuardrailMode } from "./api";

const CATEGORY_LABELS: Record<string, string> = {
  "credential-access": "Credential access",
  "data-exfiltration": "Data exfiltration",
  "download-and-execute": "Download and execute",
  "prompt-injection": "Prompt injection",
  "privilege-escalation": "Privilege escalation",
  "reverse-shell": "Reverse shell",
  "supply-chain": "Supply-chain risk",
  "tool-poisoning": "Tool poisoning",
};

export function humanizeToken(value: string): string {
  const clean = value.replace(/^atr:/i, "").trim();
  if (!clean) return "Uncategorised";
  const known = CATEGORY_LABELS[clean.toLowerCase()];
  if (known) return known;
  const words = clean.replace(/[-_]+/g, " ").replace(/\s+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1).toLowerCase();
}

export function verdictLabel(value?: string): string {
  if (value === "deny") return "Deny";
  if (value === "review") return "Needs review";
  if (value === "allow") return "Allowed";
  return "Unknown";
}

export function decidedByLabel(value?: string): string {
  const labels: Record<string, string> = {
    rules: "Rule engine",
    graph: "Session graph",
    warden: "On-device Warden",
    llm: "Your model",
    human: "Human review",
    user: "User decision",
    "host-edr": "Host defence",
  };
  if (!value || value === "unknown") return "Source unknown";
  return labels[value] ?? "Source unknown";
}

export function normaliseMode(meta?: DashboardMeta): GuardrailMode {
  const raw = meta?.guardrail?.mode;
  if (raw === "dry-run") return "monitor";
  if (raw === "enforcing") return "enforce";
  if (raw === "not_configured" || raw === "monitor" || raw === "enforce" || raw === "mixed" || raw === "partial") return raw;
  return "unknown";
}

/**
 * One absolute timestamp format for the whole dashboard, in UTC.
 *
 * MEASURED in the third dashboard audit: one screen read "21/09/2026, 17:28"
 * and another "Sep 21, 2026, 17:28" for the same instant, because half the
 * formatters passed `undefined` (the viewer's locale and zone) and half passed
 * "en" with `timeZone: "UTC"`. A reader comparing two panels could not tell
 * whether the difference was formatting or a different time.
 *
 * UTC is the side to standardise on, not the viewer's zone. These are evidence
 * timestamps: they are quoted in incident reports, compared against host logs
 * and read by more than one operator, and every one of those uses breaks when
 * the same instant renders differently per reader. The zone is named in the
 * string rather than assumed, so nobody has to know this rule to read one.
 *
 * Relative wording ("2 hours ago") is unaffected: it has no zone to get wrong.
 */
export function formatAbsolute(value: Date | number | string): string | undefined {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  const rendered = new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date);
  return `${rendered} UTC`;
}

export function formatTimestamp(value?: number): string | undefined {
  if (value == null || !Number.isFinite(value)) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  const delta = date.getTime() - Date.now();
  const abs = Math.abs(delta);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60_000) return "Just now";
  if (abs < 3_600_000) return rtf.format(Math.round(delta / 60_000), "minute");
  if (abs < 86_400_000) return rtf.format(Math.round(delta / 3_600_000), "hour");
  if (abs < 604_800_000) return rtf.format(Math.round(delta / 86_400_000), "day");
  return formatAbsolute(date);
}

export function modeAtDecisionLabel(value?: string): string | undefined {
  if (value === "monitor") return "Monitor mode";
  if (value === "enforce") return "Enforce mode";
  if (value === "check") return "One-off check";
  return undefined;
}

/**
 * Can a producer's own text be shown in the plain view as it is?
 *
 * The plain view carries no internal token: that is the rule every sentence a
 * reader sees is held to, and producer text is where tokens leak in. Text is
 * refused when it carries any of:
 *
 *  - an identifier with an underscore (`ssh_bruteforce`, `allowed_skills`),
 *    a path separator of code (`::`) or a `key=value` marker;
 *  - a digest (twelve or more hex characters);
 *  - a hyphenated lowercase identifier (`kill-process`, `block-ip-ufw`), the
 *    way skill and component ids are spelled;
 *  - a camel-case identifier (`BlockIp`); our own name is the one exception;
 *  - a bare number in brackets (`(0.42)`), which is a raw score, not a reason;
 *  - a control character.
 *
 * A refusal costs the reader nothing: the caller shows its own plain words
 * instead, and the text itself is kept for the technical view.
 */
export function readsAsPlainWords(text: string, maximum = 600): boolean {
  return text.length > 0
    && text.length <= maximum
    && !/_|::|=|[0-9a-f]{12,}/i.test(text)
    && !/\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b/.test(text)
    && !/\b(?!InnerWarden\b)[A-Za-z]*[a-z][A-Z][A-Za-z]*\b/.test(text)
    && !/\(\s*[<>~]?\s*\d+(?:\.\d+)?\s*%?\s*\)/.test(text)
    && !/[\u0000-\u001f\u007f]/.test(text);
}
