/**
 * Every closed word table the Community pages print from.
 *
 * Typed as `Record<Key, string>` over the key sets the CLI sends, so a key the
 * CLI starts sending that has no words here fails the build rather than
 * printing a token. Sentences about what HAPPENED are the CLI's (`story`,
 * lane sentences, next steps); these are labels.
 */

/** What finally happened to one flagged decision (`outcome_key`). */
export const DECISION_OUTCOMES = [
  "refused_before_run",
  "unsafe_may_have_run",
  "would_have_refused",
  "flagged_ran",
  "allowed",
  "checked_only",
  "unplaced",
] as const;
export type DecisionOutcomeKey = (typeof DECISION_OUTCOMES)[number];

/**
 * What finally happened to one message someone sent the agent. `not_seen` is
 * an outcome the record could not see (a chat that does not report the
 * agent's reply), never a recording fault, so it has its own words rather
 * than borrowing a decision's "not recorded". `unplaced` is still read, from
 * a CLI that predates `not_seen`.
 */
export const MESSAGE_OUTCOMES = ["stopped_by_innerwarden", "declined_by_agent", "answered", "not_seen", "unplaced"] as const;
export type MessageOutcomeKey = (typeof MESSAGE_OUTCOMES)[number];

export const OUTCOME_WORDS: Record<DecisionOutcomeKey | MessageOutcomeKey, string> = {
  refused_before_run: "Refused before it ran",
  would_have_refused: "Would have been refused",
  flagged_ran: "Flagged, and it ran",
  unsafe_may_have_run: "Judged unsafe, and it ran",
  allowed: "Allowed",
  checked_only: "Checked by hand",
  unplaced: "Outcome not recorded",
  stopped_by_innerwarden: "Stopped by InnerWarden",
  declined_by_agent: "Declined by your agent",
  answered: "Answered",
  not_seen: "Outcome not seen",
};

export function isDecisionOutcome(value: unknown): value is DecisionOutcomeKey {
  return typeof value === "string" && (DECISION_OUTCOMES as readonly string[]).includes(value);
}

export function isMessageOutcome(value: unknown): value is MessageOutcomeKey {
  return typeof value === "string" && (MESSAGE_OUTCOMES as readonly string[]).includes(value);
}

/**
 * Who made the decision (`decided_by`). A token this table does not know has
 * no words in the plain view; the technical view prints the token.
 */
export const DECIDER_WORDS: Record<string, string> = {
  rules: "InnerWarden's rules",
  graph: "a pattern across the session",
  warden: "the local model",
  llm: "your model's second opinion",
  user: "you",
  host: "Active Defence on this host",
};

export const CHANNELS = ["hook", "mcp", "check", "unknown"] as const;
export type Channel = (typeof CHANNELS)[number];

export function asChannel(value: unknown): Channel {
  return typeof value === "string" && (CHANNELS as readonly string[]).includes(value) ? (value as Channel) : "unknown";
}

/** What kind of thing was screened, for a case's eyebrow. */
export const CHANNEL_WORDS: Record<Channel, string> = {
  hook: "Shell command",
  mcp: "MCP tool call",
  check: "Checked by hand",
  unknown: "Command",
};

/** Who asked, when the record names no agent. Never a session id. */
export const WHO_WORDS: Record<Channel, string> = {
  hook: "An agent's shell hook",
  mcp: "An MCP connection",
  check: "You",
  unknown: "An agent",
};

/** One agent's state, or one control's. */
export const AGENT_STATES = ["refusing", "watching", "partial", "not_connected", "unsupported", "unknown"] as const;
export type AgentState = (typeof AGENT_STATES)[number];

export const STATE_WORDS: Record<AgentState, string> = {
  refusing: "Refusing",
  watching: "Watching only",
  partial: "Partly connected",
  not_connected: "Not connected",
  unsupported: "Cannot be connected yet",
  unknown: "Status unknown",
};

/**
 * What monitor means, said once on every screen that shows a mode. Monitor is
 * the default and a fine place to stay; the words never ask anyone to leave it.
 */
export const MONITOR_MEANS = "Monitor is a dry run: every command is checked and recorded, and none is stopped.";

/** What enforce means. "Set to refuse" is the config; a refusal is only what was counted. */
export const ENFORCE_MEANS = "Enforce: a deny is refused before it runs. A review is recorded and, by default, still runs.";

/** One vocabulary for the mode, everywhere: Monitor and Enforce (`guard/meta`, an agent's row). */
export const MODE_WORDS: Record<"enforce" | "monitor" | "mixed" | "partial" | "not_configured" | "unknown", string> = {
  enforce: "Enforce",
  monitor: "Monitor",
  mixed: "Mixed",
  partial: "Partly connected",
  not_configured: "Not connected",
  unknown: "Unknown",
};

/**
 * Every product command the pages print that carries no per-agent argument.
 * A per-agent command comes only from the CLI. A Rust test reads this list
 * (`dashboard_fixed_commands_are_real_cli_verbs`) and holds each verb and
 * flag to one the CLI answers, so keep one quoted command per line. The last
 * two are templates: a `<placeholder>` is shown to fill in, never copied.
 */
export const FIXED_COMMANDS = [
  "innerwarden status",
  "innerwarden enforce",
  "innerwarden dry-run",
  "innerwarden notify",
  "innerwarden dashboard",
  "innerwarden observe install",
  "innerwarden agents connect --all --monitor",
  "innerwarden agents auto-connect --monitor",
  "innerwarden allow --list",
  "innerwarden mute --list",
  "innerwarden contain -- <command>",
  "innerwarden llm set --url <URL> --model <MODEL>",
] as const;
export type FixedCommand = (typeof FIXED_COMMANDS)[number];

/** Whether a fixed command is a template: it holds a `<placeholder>`. */
export function isTemplate(command: string): boolean {
  return /<[^<>]+>/.test(command);
}

export type PlatformOs = "macos" | "linux" | "windows" | "other";

export const PLATFORM_WORDS: Record<PlatformOs, string> = {
  macos: "this Mac",
  linux: "this Linux machine",
  windows: "this PC",
  other: "this machine",
};

export function asPlatform(value: unknown): PlatformOs {
  return value === "macos" || value === "linux" || value === "windows" ? value : "other";
}

/** A session label, at most its first eight characters: never a whole UUID. */
export function shortSession(label: string): string {
  const clean = label.replace(/^session:/, "");
  return clean.length <= 8 ? clean : clean.slice(0, 8);
}

// ---------------------------------------------------------------------------
// Agent identity: how far an agent's own word is backed, and what was decided
// ---------------------------------------------------------------------------

/**
 * How much stands behind who an agent says it is. One set of words on every
 * screen: `host_verified` (a jail it cannot leave, confirmed by a witness
 * outside the jail), `observed` (in a jail, as read from inside it, or with a
 * launcher that could be replaced) and `declared` (only its own word).
 *
 * Everything this page reads is a reading from inside the jail, which an
 * agent could stage for itself, so every reason code here tops at
 * `observed`: this page never shows `host_verified`.
 */
export const TRUSTS = ["declared", "observed", "host_verified"] as const;
export type Trust = (typeof TRUSTS)[number];

/** Worst first, so `TRUSTS.indexOf` orders them. */
export function worseTrust(a: Trust, b: Trust): Trust {
  return TRUSTS.indexOf(a) <= TRUSTS.indexOf(b) ? a : b;
}

export type TrustWord = { label: string; tooltip: string; tone: "watch" };

/**
 * Keyed `${trust}:${source}`. This page reads from inside the jail, so its
 * source is always `jail`; `declared` has the same words from any source.
 * Typed as a `Record` over the keys: a key with no words fails the build.
 * `host_verified:jail` is there for the type only: no reason code lets a
 * jail reading reach it (`REASON_TRUST`).
 */
export type TrustWordKey = "host_verified:jail" | "observed:jail" | "observed:host" | "declared:jail" | "declared:sensor";

export const TRUST_WORDS: Record<TrustWordKey, TrustWord> = {
  "host_verified:jail": {
    label: "Confined",
    tooltip: "Runs inside a jail it cannot leave, confirmed by a witness outside the jail.",
    tone: "watch",
  },
  "observed:jail": {
    label: "Observed",
    tooltip: "Runs in a jail, as read from inside it: nothing outside the jail has confirmed it.",
    tone: "watch",
  },
  "observed:host": {
    label: "Observed",
    tooltip: "Read from inside the jail; Active Defence on this host decided its rules.",
    tone: "watch",
  },
  "declared:jail": { label: "Declared only", tooltip: "Only its own word says what it is.", tone: "watch" },
  "declared:sensor": { label: "Declared only", tooltip: "Only its own word says what it is.", tone: "watch" },
};

/**
 * Who a label says was asked: the hook's own reading of its jail, or
 * Active Defence on its host. A label the hook wrote, never a level: the
 * trust beside it is capped by its reason all the same.
 */
export type TrustSource = "jail" | "host";

export function asTrustSource(value: unknown): TrustSource | undefined {
  return value === "jail" || value === "host" ? value : undefined;
}

/** The words for a trust from a source; a pair with no words of its own reads as the jail's. */
export function trustWord(trust: Trust, source: TrustSource | undefined): TrustWord {
  const own = (TRUST_WORDS as Record<string, TrustWord | undefined>)[`${trust}:${source ?? "jail"}`];
  return own ?? TRUST_WORDS[`${trust}:jail`];
}

/**
 * Why an instance has the trust it has, by the code the hook wrote. The
 * trust each code can support is the ceiling: a payload that pairs a higher
 * trust with a code is read at the code's trust, and a code this table does
 * not know reads as `declared` with `UNKNOWN_REASON_WORDS`.
 */
export const REASON_CODES = [
  "confined_by_namespace",
  "launcher_not_trusted",
  "no_record",
  "record_unreadable",
  "record_writable",
  "no_namespace_on_backend",
  "host_namespace_recorded",
  "own_namespace_unreadable",
  "namespace_mismatch",
  "no_instance",
  "not_checked_yet",
  "no_scope",
  "own_mount_namespace_unreadable",
  "mount_namespace_mismatch",
  "agent_mismatch",
  "agent_not_named",
  "host_decided",
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export const REASON_TRUST: Record<ReasonCode, Trust> = {
  confined_by_namespace: "observed",
  launcher_not_trusted: "observed",
  no_record: "declared",
  record_unreadable: "declared",
  record_writable: "declared",
  no_namespace_on_backend: "declared",
  host_namespace_recorded: "declared",
  own_namespace_unreadable: "declared",
  namespace_mismatch: "declared",
  no_instance: "declared",
  not_checked_yet: "declared",
  no_scope: "observed",
  own_mount_namespace_unreadable: "declared",
  mount_namespace_mismatch: "declared",
  agent_mismatch: "declared",
  agent_not_named: "declared",
  host_decided: "observed",
};

export const REASON_WORDS: Record<ReasonCode, string> = {
  confined_by_namespace: "Runs in the jail its launcher recorded, as read from inside the jail. An agent could stage that reading for itself, so it counts as observed until a witness outside the jail confirms it.",
  launcher_not_trusted: "The launcher is installed in your home folder, so any program you run could replace it: install it system-wide.",
  no_record: "Started without a jail: only its own word says what it is.",
  record_unreadable: "Its jail record could not be read, so it counts as unverified.",
  record_writable: "Its jail record could be changed from inside the jail, so it proves nothing.",
  no_namespace_on_backend: "A jail on macOS has no process namespace to check, so only its own word says what it is.",
  host_namespace_recorded: "Its jail record names the host's own namespace, so it describes no jail.",
  own_namespace_unreadable: "The hook could not read its own namespace, so it counts as unverified.",
  namespace_mismatch: "Its jail record belongs to another jail.",
  no_instance: "Started without a jail: only its own word says what it is.",
  not_checked_yet: "Not checked yet: nothing was screened since it started.",
  no_scope: "The jail runs without a scope of its own: start it from a terminal login, where your user session can create one.",
  own_mount_namespace_unreadable: "The hook could not read its own mount namespace, so it counts as unverified.",
  mount_namespace_mismatch: "It sees a filesystem its launcher did not build, so its jail record proves nothing.",
  agent_mismatch: "Its jail record names another kind of agent than its hook serves.",
  agent_not_named: "Neither its hook nor its launcher named the agent, so its jail record proves nothing about it.",
  host_decided: "Active Defence on this host decided its rules.",
};

export const UNKNOWN_REASON_WORDS = "Why it is unverified was not recorded.";

export function isReasonCode(value: unknown): value is ReasonCode {
  return typeof value === "string" && (REASON_CODES as readonly string[]).includes(value);
}

/** The trust a payload may be shown at: never above what its reason supports. */
export function effectiveTrust(claimed: Trust, reason: unknown): Trust {
  return isReasonCode(reason) ? worseTrust(claimed, REASON_TRUST[reason]) : "declared";
}

export function reasonWords(reason: unknown): string {
  return isReasonCode(reason) ? REASON_WORDS[reason] : UNKNOWN_REASON_WORDS;
}

/**
 * The technical view's line for a jail started with user namespaces closed
 * (the identified jail's sandbox filter). A fact about how the jail was
 * built, shown as it is: it is not a reason code, and it never changes a
 * trust, a badge or a reason. A jail that did not close them shows nothing:
 * the launcher said why when it started it.
 */
export const USERNS_CLOSED_WORDS = "User namespaces closed inside the jail (sandbox filter).";

/** The second axis: what the person decided about a type of agent. */
export const LIFECYCLES = ["discovered", "approved", "revoked"] as const;
export type Lifecycle = (typeof LIFECYCLES)[number];

/** `approved` has no chip: it is a line, "Approved by {who}, {when}". */
export const LIFECYCLE_WORDS: Record<Lifecycle, string | undefined> = {
  discovered: "Waits for your approval",
  approved: undefined,
  revoked: "Revoked",
};

export function asLifecycle(value: unknown): Lifecycle | undefined {
  return typeof value === "string" && (LIFECYCLES as readonly string[]).includes(value) ? (value as Lifecycle) : undefined;
}

/** How a launched agent's guard answers: `LaunchRecord.mode`. */
export const LAUNCH_MODES = ["monitor", "enforce", "block-review"] as const;
export type LaunchMode = (typeof LAUNCH_MODES)[number];

export const LAUNCH_MODE_WORDS: Record<LaunchMode, string> = {
  monitor: "Records only",
  enforce: "Refuses",
  "block-review": "Refuses, reviews too",
};

export function asLaunchMode(value: unknown): LaunchMode | undefined {
  return typeof value === "string" && (LAUNCH_MODES as readonly string[]).includes(value) ? (value as LaunchMode) : undefined;
}

/** Which rule layer decided, and its verdict. */
export const LAYERS = ["hard", "general", "agent_type", "instance"] as const;
export type Layer = (typeof LAYERS)[number];
export const VERDICTS = ["allow", "review", "deny"] as const;
export type Verdict = (typeof VERDICTS)[number];

export function asLayer(value: unknown): Layer | undefined {
  return typeof value === "string" && (LAYERS as readonly string[]).includes(value) ? (value as Layer) : undefined;
}

export function asVerdict(value: unknown): Verdict | undefined {
  return typeof value === "string" && (VERDICTS as readonly string[]).includes(value) ? (value as Verdict) : undefined;
}

export type LayerKey = "hard:deny" | "general:deny" | "general:review" | "general:allow" | "agent_type:allow" | "agent_type:deny" | "instance:allow" | "instance:deny";

/** `{agent}` is the agent's name as the page shows it. A pair not listed has no words. */
export const LAYER_WORDS: Record<LayerKey, string> = {
  "hard:deny": "Refused by a product rule no setting changes. Nothing to change here.",
  "general:deny": "Refused by your general rules.",
  "general:review": "Sent for review by your general rules.",
  "general:allow": "Allowed by your general rules.",
  "agent_type:allow": "Allowed by the {agent} profile, because this instance runs confined.",
  "agent_type:deny": "Refused by the {agent} profile.",
  "instance:allow": "Allowed by an exception for this instance only.",
  "instance:deny": "Refused by an exception for this instance.",
};

/**
 * Why a relaxation was not applied, chosen when the page renders (never when
 * the hook ran): by where the page runs and whether Active Defence is
 * installed there.
 */
export const WITHHELD_WORDS = {
  linux: "Per-agent relaxations apply on Linux with Active Defence, for an agent started with innerwarden contain --identity.",
  linuxWithActiveDefence: "Active Defence on this host did not decide this command, so your general rules decided.",
  macos: "Per-agent relaxations do not apply on macOS: a jail there has no boundary a witness outside it can check.",
} as const;

/** Any word the host recorded for not relaxing, whatever it is: one sentence. */
export const HOST_WITHHELD_WORDS = "Active Defence on this host kept your general rules for this command.";

/**
 * A refusal of the host's own that stood: the hook recorded the host's answer
 * and that the host decided the refusal (`decided_by: host`). Never worded as
 * one of the general rules, which may have allowed the command.
 */
export const HOST_REFUSED_WORDS = "Refused by Active Defence on this host.";

export function hostRefused(trustSource: TrustSource | undefined, decidedBy: string, verdict: Verdict | undefined): boolean {
  return trustSource === "host" && decidedBy === "host" && verdict === "deny";
}

export function withheldWords(os: PlatformOs, activeDefenceInstalled: boolean, hostWithheld: boolean): string {
  if (hostWithheld) return HOST_WITHHELD_WORDS;
  if (os === "macos") return WITHHELD_WORDS.macos;
  return activeDefenceInstalled ? WITHHELD_WORDS.linuxWithActiveDefence : WITHHELD_WORDS.linux;
}

export function layerWords(layer: Layer, verdict: Verdict, agent: string): string | undefined {
  const base = (LAYER_WORDS as Record<string, string | undefined>)[`${layer}:${verdict}`];
  return base === undefined ? undefined : base.replace("{agent}", agent);
}

/** An allowance a per-agent layer gave where Active Defence on the host decided the rules. */
export const HOST_LAYER_WORDS: Record<"agent_type" | "instance", string> = {
  agent_type: "Allowed by the {agent} profile, decided by Active Defence on this host.",
  instance: "Allowed by an exception for this instance, decided by Active Defence on this host.",
};

/** One line in the Changes list (P6), by what was done. */
export const AGENT_DECISION_ACTIONS = ["approve", "profile", "allow", "revoke"] as const;
export type AgentDecisionAction = (typeof AGENT_DECISION_ACTIONS)[number];

export function asDecisionAction(value: unknown): AgentDecisionAction | undefined {
  return typeof value === "string" && (AGENT_DECISION_ACTIONS as readonly string[]).includes(value) ? (value as AgentDecisionAction) : undefined;
}

/** What the page says about the agent count: "3 agents on this machine." */
export type TrustCounts = { total: number; confined: number; observed: number; declared: number };

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/**
 * The Overview's one sentence about how far the agents are backed. Pure:
 * counts in, words out. Parts that are zero are left out.
 */
export function agentTrustSentence(counts: TrustCounts, place: string): string {
  const head = `${counts.total} ${plural(counts.total, "agent", "agents")} on ${place}.`;
  const parts: string[] = [];
  if (counts.confined > 0) parts.push(`${counts.confined} ${plural(counts.confined, "runs", "run")} confined`);
  if (counts.observed > 0) {
    parts.push(`${counts.observed} ${plural(counts.observed, "runs", "run")} in a jail nothing outside it has confirmed`);
  }
  if (counts.declared > 0) {
    const its = counts.declared === 1 ? "its" : "their";
    const it = counts.declared === 1 ? "it is" : "they are";
    parts.push(`${counts.declared} ${plural(counts.declared, "runs", "run")} as you, and only ${its} own word says what ${it}`);
  }
  return parts.length === 0 ? head : `${head} ${parts.join("; ")}.`;
}

export const CONFLICT_WORDS =
  "Its hook says the {agent} profile allowed this, but nothing outside its jail confirmed the jail, so this is not taken as an allowance.";

/**
 * The "Decided by" line of a case. A layer that allows only because an
 * instance runs confined is never worded as such for an instance that does
 * not: the label is untrusted, so the line says it could not be confirmed,
 * unless the hook recorded that Active Defence on its host decided the rules
 * (`hostDecided`), which the line says, neutrally, as what was recorded.
 */
export function layerLine(
  layer: Layer,
  verdict: Verdict,
  trust: Trust,
  agent: string,
  hostDecided = false,
): { text: string; conflict: boolean } | undefined {
  if ((layer === "agent_type" || layer === "instance") && verdict === "allow" && trust !== "host_verified") {
    if (hostDecided) return { text: HOST_LAYER_WORDS[layer].replace("{agent}", agent), conflict: false };
    return { text: CONFLICT_WORDS.replace("{agent}", agent), conflict: true };
  }
  const text = layerWords(layer, verdict, agent);
  return text === undefined ? undefined : { text, conflict: false };
}

const SHORT_DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });

/** "30 Jul", for the day the guard's log starts (a UTC date). */
export function shortDay(iso: string): string | undefined {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? SHORT_DAY.format(ms) : undefined;
}

/** "25 Sept, 17:34", in the reader's own clock; built per call, so it follows the zone the page runs in. */
export function dayAndTime(ms: number): string {
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
}

/** When something happened, for a sentence: "at 14:02" today, "on 28 Sept at 14:05" before. In the reader's own clock. */
export function atWords(ms: number, now: number): string {
  const day = (at: number) => new Intl.DateTimeFormat("en-GB", { year: "numeric", month: "2-digit", day: "2-digit" }).format(at);
  const clock = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(ms);
  if (day(ms) === day(now)) return `at ${clock}`;
  const date = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" }).format(ms);
  return `on ${date} at ${clock}`;
}
