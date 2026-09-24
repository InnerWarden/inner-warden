import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Overview } from "../api";
import { HostAttention, OverviewRecord } from "./Home";

/**
 * "8 addresses are waiting on you" was a dead end: a number, and no way to
 * the cases it counts. The way through is a button to the waiting queue, and
 * it is offered whenever there is a Cases screen to open: under the calm line
 * too, because that line counts today and the queue keeps every day.
 *
 * These RENDER the section.
 */
const waiting = { addresses_waiting: 8, counts: "distinct external addresses, today" };
const nothing = { addresses_waiting: 0, counts: "distinct external addresses, today" };

describe("the way through from what is waiting", () => {
  it("offers the queue when something is waiting and there is a Cases screen", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} onOpen={() => undefined} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).toContain("See all waiting cases, from any day");
    expect(html).toContain("<button");
  });

  /**
   * The button used to read "See what is waiting" directly under "8
   * addresses", and opened every waiting CASE of ALL time: a list that can be
   * hundreds of rows long. What the reader is promised is now what they get,
   * and the difference is said beside the button, not left to be discovered.
   */
  it("says what the link opens, and that it is not the number above it", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} onOpen={() => undefined} />);
    expect(html).not.toContain("See what is waiting");
    expect(html).toContain("cases rather than addresses");
    expect(html).toContain("cases as well as the host");
    expect(html).toContain("will not match this number");
  });

  /**
   * THE DEFECT THIS PINS
   *
   * Today's two counts read 0 and the calm line hid the link, while the queue
   * it opens keeps every day: an undecided privilege escalation that arrived
   * at 23:30 UTC and was parked for a person at 00:30 was in the queue under
   * "Nothing on the host is waiting for you" and no button.
   *
   * FAILS ON REVERT: hide the link under the calm line again
   * (`!quiet && onOpen !== undefined`) and there is no button here.
   */
  it("offers the queue under today's good news, calmly, because the queue keeps every day", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={nothing} onOpen={() => undefined} />);
    expect(html).toContain("Nothing new on the host today is waiting for you");
    expect(html).not.toContain("Nothing on the host is waiting for you");
    expect(html).toContain("<button");
    expect(html).toContain("See the waiting queue, from any day");
    expect(html).toContain("what earlier days left waiting");
    // Calm, not a warning: none of the waiting state's amber.
    expect(html).not.toContain("amber");
  });

  it("offers nothing when the shell has no Cases screen to open", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).not.toContain("<button");
    // The note explains the link; without the link it would explain nothing.
    expect(html).not.toContain("will not match this number");
    const calm = renderToStaticMarkup(<HostAttention waiting={nothing} />);
    expect(calm).not.toContain("<button");
    expect(calm).not.toContain("earlier days");
  });

  /**
   * THE DEFECT THIS PINS
   *
   * The producer's definitions were printed by default, word for word, as the
   * paragraphs under the title: long clauses in the producer's own terms, read
   * by a customer as internal notes rather than the plain answer. The title
   * and the link are the answer; the definition is behind "What this number
   * counts", one click away for whoever wants to check it.
   *
   * FAILS ON REVERT: print the definitions as body paragraphs again and there
   * is no disclosure, and the definition comes before the button.
   */
  it("keeps what the number counts behind a disclosure, after the answer", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} onOpen={() => undefined} />);
    const details = html.indexOf("<details");
    const summary = html.indexOf("What this number counts");
    const definition = html.indexOf("Distinct external addresses, today.");
    const button = html.indexOf("<button");
    expect(details).toBeGreaterThanOrEqual(0);
    expect(summary).toBeGreaterThan(details);
    expect(definition).toBeGreaterThan(summary);
    expect(button).toBeGreaterThanOrEqual(0);
    expect(definition).toBeGreaterThan(button);
    // Closed by default: the reader asks for it.
    expect(html).not.toMatch(/<details[^>]*\sopen/);
  });

  it("renders nothing at all for a build with no host layer", () => {
    expect(renderToStaticMarkup(<HostAttention waiting={undefined} onOpen={() => undefined} />)).toBe("");
  });
});

/**
 * THE DEFECT THESE PIN
 *
 * The way through was decided on the address count alone. A host whose only
 * waiting findings name no external address (an undecided privilege
 * escalation, a lateral movement to an internal address) read "Nothing on the
 * host is waiting for you" and offered no link, while the waiting queue held
 * them. The host now serves those findings beside the addresses, and the link
 * shows when either count is above zero.
 *
 * FAILS ON REVERT: read `addresses_waiting` alone again and the first test
 * renders the calm line with no button.
 */
const ADDRESS_COUNTS = "distinct outside addresses, today, with a finding nothing has decided on";
const FINDING_COUNTS = "host findings from today that wait in Cases and that a count of addresses cannot include";
/** The two definitions as they read on the screen, under their labels. */
const ADDRESS_SENTENCE = "Distinct outside addresses, today, with a finding nothing has decided on.";
const FINDING_SENTENCE = "Host findings from today that wait in Cases and that a count of addresses cannot include.";
const onlyFindings = {
  addresses_waiting: 0,
  counts: ADDRESS_COUNTS,
  findings_waiting_off_the_line: 3,
  findings_waiting_off_the_line_counts: FINDING_COUNTS,
};

describe("the way through when what waits has no address", () => {
  it("offers the queue when only findings are waiting", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={onlyFindings} onOpen={() => undefined} />);
    expect(html).toContain("3 findings are waiting on you");
    expect(html).not.toContain("Nothing new on the host today");
    expect(html).toContain("<button");
    expect(html).toContain("See all waiting cases, from any day");
    // What the title counts is said beside it; the address definition is not,
    // because the title names no address.
    expect(html).toContain("What this number counts");
    expect(html).toContain(FINDING_SENTENCE);
    expect(html).not.toContain(ADDRESS_SENTENCE);
  });

  it("says what each number counts when both addresses and findings wait", () => {
    const html = renderToStaticMarkup(
      <HostAttention waiting={{ ...onlyFindings, addresses_waiting: 8 }} onOpen={() => undefined} />,
    );
    expect(html).toContain("8 addresses, and 3 findings the address count leaves out, are waiting on you");
    expect(html).toContain("<button");
    expect(html).toContain("What these numbers count");
    const addresses = html.indexOf(ADDRESS_SENTENCE);
    const findings = html.indexOf(FINDING_SENTENCE);
    expect(addresses).toBeGreaterThanOrEqual(0);
    expect(findings).toBeGreaterThan(addresses);
  });

  it("still offers no link when the shell has no Cases screen", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={onlyFindings} />);
    expect(html).toContain("3 findings are waiting on you");
    expect(html).not.toContain("<button");
  });

  it("says nothing new today, and still offers the queue, when neither addresses nor findings wait", () => {
    const html = renderToStaticMarkup(
      <HostAttention waiting={{ ...onlyFindings, findings_waiting_off_the_line: 0 }} onOpen={() => undefined} />,
    );
    expect(html).toContain("Nothing new on the host today is waiting for you");
    expect(html).toContain("Nothing the host found today is asking for a person.");
    expect(html).toContain("See the waiting queue, from any day");
    // Nothing is counted, so there is nothing to define.
    expect(html).not.toContain("<details");
  });
});

/**
 * THE DEFECT THESE PIN
 *
 * The host line rendered only inside the branch for a guardrail that had
 * recorded decisions. A paid host whose agent guardrail had recorded none got
 * the onboarding panel and never "8 addresses are waiting on you", the first
 * thing a reader who does not know the product needs from this screen. The
 * line reads the HOST layer, not the guardrail, so the guardrail's count must
 * not decide whether it shows.
 *
 * These render the part of the Overview that makes that choice, with the host's
 * figures handed in.
 */
function overview(extra: Partial<Overview> = {}): Overview {
  return {
    sessions: 0,
    commands: 0,
    blocked: 0,
    review: 0,
    allowed: 0,
    top_categories: [],
    recent_blocks: [],
    ...extra,
  };
}

/** The onboarding heading, which names whose decisions it counts. */
const ONBOARDING = "No agent guardrail decisions recorded yet";

function record(value: Overview, edition: "community" | "enterprise", onOpenQueue?: () => void): string {
  return renderToStaticMarkup(
    <OverviewRecord overview={value} mode="unknown" edition={edition} onOpenActivity={() => undefined} onOpenQueue={onOpenQueue} />,
  );
}

describe("the host line does not depend on the guardrail's decisions", () => {
  it("says what the host has waiting on a paid host whose guardrail recorded nothing", () => {
    const html = record(overview({ host_attention: waiting }), "enterprise", () => undefined);
    // The precondition that used to hide it: no guardrail decisions at all.
    expect(html).toContain(ONBOARDING);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).toContain("See all waiting cases, from any day");
  });

  it("puts what is waiting above the steps for connecting an agent", () => {
    const html = record(overview({ host_attention: waiting }), "enterprise", () => undefined);
    const hostLine = html.indexOf("8 addresses are waiting on you");
    const onboarding = html.indexOf(ONBOARDING);
    expect(hostLine).toBeGreaterThanOrEqual(0);
    expect(onboarding).toBeGreaterThan(hostLine);
  });

  /**
   * The host line's definition ends "... whose latest decision is absent or
   * awaiting confirmation, today", and the onboarding heading comes after it.
   * A bare "No decisions recorded yet" there reads as a claim about the host's
   * decisions, the very ones the line above just counted as waiting. The
   * heading says whose decisions it means.
   */
  it("names the agent guardrail in the heading under the host line", () => {
    const html = record(overview({
      host_attention: {
        addresses_waiting: 8,
        counts: "distinct external addresses whose latest decision is absent or awaiting confirmation, today",
      },
    }), "enterprise", () => undefined);
    const hostLine = html.indexOf("awaiting confirmation, today");
    const heading = html.indexOf(ONBOARDING);
    expect(hostLine).toBeGreaterThanOrEqual(0);
    expect(heading).toBeGreaterThan(hostLine);
    expect(html).not.toContain("No decisions recorded yet");
  });

  it("says the good news once when nothing new on the host is waiting", () => {
    const html = record(overview({ host_attention: nothing }), "enterprise", () => undefined);
    expect(html).toContain(ONBOARDING);
    expect(html.split("Nothing new on the host today is waiting for you")).toHaveLength(2);
    expect(html).toContain("See the waiting queue, from any day");
  });

  /**
   * Community has no host layer and sends no `host_attention`. Absent is not
   * zero: the onboarding panel shows and no host line at all, neither the
   * warning nor the good news, which would be a claim about a host this build
   * cannot see.
   */
  it("shows no host line on a build with no host layer", () => {
    const html = record(overview(), "community", () => undefined);
    expect(html).toContain(ONBOARDING);
    expect(html).not.toContain("host-attention-title");
    expect(html).not.toContain("waiting on you");
    expect(html).not.toContain("Nothing new on the host today");
    expect(html).not.toContain("waiting queue");
  });

  /**
   * The same way through, on the Overview a paid host really renders when
   * its agent guardrail has recorded nothing: only findings wait on the host.
   */
  it("offers the queue from the Overview when only findings with no address are waiting", () => {
    const html = record(overview({ host_attention: onlyFindings }), "enterprise", () => undefined);
    expect(html).toContain(ONBOARDING);
    expect(html).toContain("3 findings are waiting on you");
    expect(html).toContain("See all waiting cases, from any day");
    expect(html).not.toContain("Nothing new on the host today");
  });

  it("keeps the host line under the decision record once the guardrail has decisions", () => {
    const html = record(overview({ commands: 5, sessions: 1, allowed: 5, host_attention: waiting }), "enterprise", () => undefined);
    // By the panel's id rather than its heading, so renaming the heading can
    // never make this pass without the panel being gone.
    expect(html).not.toContain("zero-state-title");
    const decisions = html.indexOf("decision-summary-title");
    const hostLine = html.indexOf("8 addresses are waiting on you");
    expect(decisions).toBeGreaterThanOrEqual(0);
    expect(hostLine).toBeGreaterThan(decisions);
  });
});
