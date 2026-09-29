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
 * One absolute timestamp format for the whole dashboard: the reader's own
 * clock, with the zone printed, "21 Sept 2026, 18:28 BST". The exact instant
 * travels with it, in ISO 8601 UTC, in the element's title (`timeTitle`).
 *
 * The third dashboard audit found one screen reading "21/09/2026, 17:28" and
 * another "Sep 21, 2026, 17:28" for the same instant, because half the
 * formatters took the viewer's locale and zone and half asked for UTC, and
 * the fix then was UTC everywhere. The next walk found the cost of that: one
 * event read in local time on one panel and in unlabelled UTC on another, on
 * two calendar dates, and a reader in London had to know the rule to read
 * any of them. One rule now: every absolute time is the reader's local time
 * and says which zone that is, every panel uses this one function, and the
 * zone-free instant is one hover away for a report or a host log.
 *
 * `timeZone` is for tests and for a caller that must print another zone; the
 * dashboard itself never passes it.
 *
 * Relative wording ("2 hours ago") is unaffected: it has no zone to get wrong.
 */
export function formatAbsolute(value: Date | number | string, timeZone?: string): string | undefined {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZoneName: "short",
    timeZone,
  }).format(date);
}

/** A calendar day in the same words as `formatAbsolute`: "21 Sept 2026". */
export function formatDay(value: Date | number | string, timeZone?: string): string | undefined {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone }).format(date);
}

/** The instant in ISO 8601 UTC, to the second: "2026-09-21T17:28:42Z". */
export function isoInstant(value: Date | number | string): string | undefined {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString().replace(/\.000Z$/, "Z");
}

/**
 * What a time's title says on hover: the reader's local time with its zone,
 * and the ISO instant, "21 Sept 2026, 18:28 BST (2026-09-21T17:28:42Z)".
 */
export function timeTitle(value: Date | number | string, timeZone?: string): string | undefined {
  const local = formatAbsolute(value, timeZone);
  const iso = isoInstant(value);
  return local === undefined || iso === undefined ? undefined : `${local} (${iso})`;
}

/**
 * A time of day when it is today where the reader is, and the full absolute
 * time otherwise: "01:21 BST", "24 Sept 2026, 01:21 BST". An "as of 01:21"
 * with no date read the same on a check from this morning and one from last
 * week.
 */
export function formatClock(value: Date | number | string, now: Date = new Date(), timeZone?: string): string | undefined {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  if (formatDay(date, timeZone) !== formatDay(now, timeZone)) return formatAbsolute(date, timeZone);
  return new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZoneName: "short", timeZone }).format(date);
}

/** A length of time in the largest unit that fits: "12 s", "5 min", "3 h", "20 d". */
export function formatDuration(seconds: number): string {
  const secs = Math.max(0, Math.floor(seconds));
  if (secs < 120) return `${secs} s`;
  if (secs < 7_200) return `${Math.floor(secs / 60)} min`;
  if (secs < 172_800) return `${Math.floor(secs / 3_600)} h`;
  return `${Math.floor(secs / 86_400)} d`;
}

/**
 * How old a piece of evidence is, against the budget its producer set, in
 * place of a bare "Fresh" or "Stale": "20 d old, within its 90 d budget",
 * "3 d old, past its 1 d budget". A 20-day-old record read "Fresh" beside
 * 3-day-old ones reading "Stale", because each was judged by a budget the
 * reader could not see. With the age and the budget printed, the word
 * explains itself. No age reported says so, and a record never observed
 * says "never checked".
 */
export function freshnessLabel(freshness: {
  observed_at: string | null;
  age_seconds: number | null;
  budget_seconds: number;
}): string {
  if (freshness.observed_at === null) return "never checked";
  if (freshness.age_seconds === null || !Number.isFinite(freshness.age_seconds)) return "age not reported";
  const age = `${formatDuration(freshness.age_seconds)} old`;
  if (!Number.isFinite(freshness.budget_seconds) || freshness.budget_seconds <= 0) return age;
  const budget = formatDuration(freshness.budget_seconds);
  return freshness.age_seconds <= freshness.budget_seconds
    ? `${age}, within its ${budget} budget`
    : `${age}, past its ${budget} budget`;
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

/**
 * One way to print a count, everywhere: "1,298", for every viewer.
 *
 * Counts went through the viewer's locale in most places and a fixed one in
 * others, so one card could print "1,298" beside "1298", and the same number
 * read "1.298" on a German machine in one panel and "1,298" in the next. A
 * fixed locale makes a count read the same on every screen, in every test
 * and in a quoted report. `+ 0` turns -0 into 0, which would print "-0".
 */
const COUNT_FORMAT = new Intl.NumberFormat("en-GB");

export function formatCount(value: number | bigint): string {
  return COUNT_FORMAT.format(typeof value === "bigint" ? value : value + 0);
}

/**
 * A large count in words, for a tile where the exact figure would not be read
 * as a number: "2.3 billion", "38 million", "412 thousand". Below 100,000 it
 * is the exact figure (`formatCount`), because a count a reader can hold whole
 * is not rounded.
 *
 * Below ten of a million or more it always keeps one decimal, so two counts
 * side by side read at the same precision ("1.3 billion" beside "1.0
 * billion", never beside "1 billion", which looks rounder and less exact than
 * it is). A count that rounds up to a thousand of one scale is said in the
 * next one: 999,960 is "1.0 million", never "1,000 thousand".
 */
export function compactCount(value: number | bigint): string {
  const exact = typeof value === "bigint" ? value : BigInt(Math.max(0, Math.round(Number.isFinite(value) ? value : 0)));
  if (exact < 100_000n) return formatCount(exact);
  const scales: [bigint, string][] = [
    [1_000n, "thousand"],
    [1_000_000n, "million"],
    [1_000_000_000n, "billion"],
    [1_000_000_000_000n, "trillion"],
  ];
  // The largest scale the count reaches, then up while the rounded figure
  // would say a thousand of it.
  let at = scales.length - 1;
  while (at > 0 && exact < scales[at][0]) at -= 1;
  for (; at < scales.length; at += 1) {
    const [scale, word] = scales[at];
    // Tenths, computed in integers so a count past 2^53 is not rounded twice.
    const tenths = (exact * 10n + scale / 2n) / scale;
    if (tenths < 100n && scale >= 1_000_000n) return `${tenths / 10n}.${tenths % 10n} ${word}`;
    const whole = (exact + scale / 2n) / scale;
    if (whole < 1_000n || at === scales.length - 1) return `${formatCount(whole)} ${word}`;
  }
  return formatCount(exact);
}

/**
 * Whether host text carries a character that is not text: a control
 * character (C0, DEL or C1) or a format character, which includes the bidi
 * overrides and isolates (U+202A to U+202E, U+2066 to U+2069).
 *
 * The first rule rejected C0 and DEL only, so a label carrying U+202E (right
 * to left override) passed and could reorder the words printed after it on
 * the badge, and C1 controls passed as well. Text that must be printed as
 * the host sent it is refused whole instead.
 */
export function hasControlCharacters(text: string): boolean {
  return /[\p{Cc}\p{Cf}]/u.test(text);
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
