import type { Concern } from "./api";
import type { OfferSlot } from "./dismiss";
import type { DecisionOutcomeKey, PlatformOs } from "./words";

/**
 * Where Community says what Active Defence would add, and in what words.
 *
 * The rules (spec M2), each pinned by a test:
 *  - an offer is tied to THIS situation (a card with no source, a case whose
 *    command ran, a credential read) and says what the paid capability does
 *    in general, never that it "would have stopped" this command;
 *  - it is platform-honest: Active Defence runs on Linux, so on a Mac or a PC
 *    it says "On a Linux server" and never implies this machine can run it;
 *  - the paid features are named with the words already public, and Secret
 *    Read Guard is a NAME: no sentence here says how it works;
 *  - there is at most one link per screen, with no query string, and nothing
 *    is sent anywhere.
 */

export const PRICING_URL = "https://innerwarden.com/pricing";
export const EDITIONS_URL = "https://innerwarden.com/docs/editions-and-guarantees";

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

const EXECUTION_GATE =
  "Active Defence adds the kernel Execution Gate: a program nobody authorized does not start, even if the agent never asks.";

/** The Overview's one offer, in the card for attacks on this machine, which Community does not watch. */
export function serverOffer(os: PlatformOs): Offer {
  const adds = "the host sensor, an SSH decoy, and automatic response that blocks an attacker and checks the block held.";
  return {
    slot: "server",
    key: "server",
    body: os === "linux"
      ? `On this Linux machine, Active Defence adds ${adds}`
      : `Active Defence runs on Linux servers, where it adds ${adds}`,
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
    return offer("execution_gate", `Community relies on your agent asking the guard first. ${lead(os)} ${EXECUTION_GATE}`);
  }
  return undefined;
}

/** The offer under a message someone sent the agent. */
export function messageOffer(os: PlatformOs): Offer {
  return {
    slot: "case",
    key: "message",
    body: `Observe records what reached your agent; it cannot stop what the agent then runs. ${lead(os)} ${EXECUTION_GATE}`,
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
  { key: "host_sensor", glyph: "eye", name: "Host sensor", line: "Sees every program and connection on the server, not only what the agent reports." },
  { key: "ssh_decoy", glyph: "decoy", name: "SSH decoy", line: "A decoy SSH login that records what attackers try." },
  { key: "automatic_response", glyph: "shield", name: "Automatic response", line: "Blocks an attacking address for a set time and checks the block held." },
  { key: "analyst_tools", glyph: "person", name: "Analyst tools", line: "Verdicts, blocking from a case, exclusions, and a second factor for changes." },
];
