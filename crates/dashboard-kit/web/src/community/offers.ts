import { formatCount } from "../presentation";
import type { Concern, FlaggedConcerns } from "./api";
import type { OfferSlot } from "./dismiss";
import type { DecisionOutcomeKey, MessageOutcomeKey, PlatformOs } from "./words";

/**
 * Where Community says what Active Defence would add, and in what words.
 *
 * The rules (spec M2), each pinned by a test:
 *  - an offer is tied to THIS situation (the reader's own count, a case whose
 *    command ran, a credential read) and says what the paid capability does
 *    in general, never that it "would have stopped" this command;
 *  - it is platform-honest: Active Defence runs on Linux, so on a Mac or a PC
 *    it says "On a Linux server" and never implies this machine can run it;
 *  - the paid features are named with the words already public, and Secret
 *    Read Guard is a NAME: no sentence here says how it works;
 *  - at most one link per screen, with no query string, and nothing is sent
 *    anywhere;
 *  - an offer under a case is at most `CASE_OFFER_MAX` characters: it sits
 *    under the reader's own step, and must never outweigh it.
 */

export const PRICING_URL = "https://innerwarden.com/pricing";
export const EDITIONS_URL = "https://innerwarden.com/docs/editions-and-guarantees";

/** The longest an offer under a case may be. */
export const CASE_OFFER_MAX = 160;

export type Offer = {
  slot: OfferSlot;
  /** A stable name for the situation, for `data-offer`. */
  key: string;
  body: string;
  action: string;
  href: string;
};

function lead(os: PlatformOs): string {
  return os === "linux" ? "On this Linux machine," : "On a Linux server,";
}

const GATE = "Active Defence's kernel Execution Gate refuses any program nobody authorized.";

/**
 * Flagged commands that RAN here in a way Community's own refusing mode does
 * not stop (the rules asked for a review, or a deny went through an MCP
 * connection that only warns), with the span they were counted over.
 */
export type RanHere = { count: number; span: string };

/**
 * The Overview's one offer, in the card for attacks on this machine, which
 * Community does not watch. It leads with the reader's own number, then the
 * one capability about their agent, then the server ones.
 */
export function serverOffer(os: PlatformOs, ran?: RanHere): Offer {
  const reliance = ran !== undefined && ran.count > 0
    ? `${formatCount(ran.count)} flagged ${ran.count === 1 ? "command" : "commands"} ran here ${ran.span}: Community relies on your agent asking first.`
    : "Community relies on your agent asking the guard first.";
  return {
    slot: "server",
    key: "server",
    body: `${reliance} ${lead(os)} Active Defence adds the kernel Execution Gate, and watches the server itself with the host sensor, an SSH decoy and automatic response.`,
    action: "See Active Defence",
    href: PRICING_URL,
  };
}

/**
 * The offer under a case, chosen by what happened and what the command
 * reached for, or none. First match wins: an outcome that needs no offer ends
 * the search before any concern is read.
 */
export function caseOffer(item: { outcomeKey: DecisionOutcomeKey; concern: Concern }, os: PlatformOs): Offer | undefined {
  if (item.outcomeKey === "refused_before_run" || item.outcomeKey === "checked_only") return undefined;
  const offer = (key: string, body: string): Offer => ({ slot: "case", key, body, action: "See Active Defence", href: PRICING_URL });
  if (item.concern === "credential_read") {
    return offer("credential_read", `This command reached for a credential file. ${lead(os)} Active Defence adds Secret Read Guard.`);
  }
  if (item.concern === "domain_fetch") {
    return offer(
      "domain_fetch",
      `This command fetched from the internet by name. ${lead(os)} Active Defence adds DNS Guard, which refuses domains you did not approve.`,
    );
  }
  if (item.outcomeKey === "would_have_refused" || item.outcomeKey === "flagged_ran" || item.outcomeKey === "unsafe_may_have_run") {
    return offer("execution_gate", `Community relies on your agent asking the guard first. ${lead(os)} ${GATE}`);
  }
  return undefined;
}

/**
 * The offer under a message someone sent the agent, or none where
 * InnerWarden already stopped it: the same rule a case follows for a
 * command refused before it ran.
 */
export function messageOffer(os: PlatformOs, outcomeKey: MessageOutcomeKey = "declined_by_agent"): Offer | undefined {
  if (outcomeKey === "stopped_by_innerwarden") return undefined;
  return {
    slot: "case",
    key: "message",
    body: `Observe records; it cannot stop what the agent then runs. ${lead(os)} ${GATE}`,
    action: "See Active Defence",
    href: PRICING_URL,
  };
}

/** The foot of Protection's "Not in Community". */
export function protectionOffer(): Offer {
  return {
    slot: "protection",
    key: "protection",
    body: "These are Active Defence, for Linux servers.",
    action: "Compare the editions",
    href: EDITIONS_URL,
  };
}

/**
 * Said in place of every offer on a machine where Active Defence is
 * installed. INSTALLED, never armed: this dashboard runs without privileges
 * and cannot read the host stack, so it claims nothing about what runs there.
 */
export const INSTALLED_LINE = {
  lead: "Active Defence is installed on this host.",
  body: "This dashboard runs without privileges and cannot read it, so it does not say what is running there. Ask the host:",
  command: "innerwarden get status",
} as const;

/** One paid capability, by the name the product is sold under. */
export type PaidCapability = { key: string; glyph: "gate" | "key" | "globe" | "eye" | "decoy" | "shield" | "person"; name: string; line: string };

/** Protection's "Not in Community", in the words already public on innerwarden.com. */
export const NOT_IN_COMMUNITY: readonly PaidCapability[] = [
  { key: "execution_gate", glyph: "gate", name: "Execution Gate", line: "A program nobody authorized does not start, even when the agent never asks the guard." },
  { key: "secret_read_guard", glyph: "key", name: "Secret Read Guard", line: "Part of Active Defence." },
  { key: "dns_guard", glyph: "globe", name: "DNS Guard", line: "Refuses domains you did not approve." },
  { key: "host_sensor", glyph: "eye", name: "Host sensor", line: "Watches programs and connections on the server, not only what the agent reports." },
  { key: "ssh_decoy", glyph: "decoy", name: "SSH decoy", line: "A decoy SSH login that records what attackers try." },
  { key: "automatic_response", glyph: "shield", name: "Automatic response", line: "Blocks an attacking address for a set time and checks the block held." },
  { key: "analyst_tools", glyph: "person", name: "Analyst tools", line: "Verdicts, blocking from a case, exclusions, and a second factor for changes." },
];

/**
 * What happened ON THIS MACHINE that a paid row answers, from the CLI's
 * counts (`guard/protection`'s `flagged`), or nothing: a row with no fact of
 * its own here stays as it is. A count, never a claim about what the paid
 * capability would have done with it.
 */
export function paidRowFact(key: string, flagged: FlaggedConcerns | undefined, sinceWords: string | undefined): string | undefined {
  if (flagged === undefined) return undefined;
  const since = sinceWords === undefined ? "" : ` since ${sinceWords}`;
  const n = (value: number, one: string, many: string) => `${formatCount(value)} ${value === 1 ? one : many}`;
  if (key === "execution_gate" && flagged.ran > 0) {
    return `${n(flagged.ran, "flagged command", "flagged commands")} ran on this machine${since}.`;
  }
  if (key === "secret_read_guard" && flagged.credentialRead > 0) {
    return `${n(flagged.credentialRead, "case", "cases")} here reached for a credential file${since}.`;
  }
  if (key === "dns_guard" && flagged.domainFetch > 0) {
    return `${n(flagged.domainFetch, "flagged command", "flagged commands")} here fetched from the internet by name${since}.`;
  }
  return undefined;
}
