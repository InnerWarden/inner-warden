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
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function modeAtDecisionLabel(value?: string): string | undefined {
  if (value === "monitor") return "Monitor mode";
  if (value === "enforce") return "Enforce mode";
  if (value === "check") return "One-off check";
  return undefined;
}
