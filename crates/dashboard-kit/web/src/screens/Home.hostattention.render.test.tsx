import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Overview } from "../api";
import { HostAttention, OverviewRecord } from "./Home";

/**
 * "8 addresses are waiting on you" was a dead end: a number, and no way to
 * the cases it counts. The way through is a button to the waiting queue, and
 * it is offered only when there is somewhere to go AND something to see.
 *
 * These RENDER the section. Reverting `through` to `onOpen !== undefined`
 * makes the second test fail: a link to an empty list under "nothing is
 * waiting".
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
    expect(html).toContain("longer than this number");
  });

  it("offers nothing under good news", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={nothing} onOpen={() => undefined} />);
    expect(html).toContain("Nothing on the host is waiting for you");
    expect(html).not.toContain("waiting cases");
    expect(html).not.toContain("<button");
  });

  it("offers nothing when the shell has no Cases screen to open", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).not.toContain("<button");
    // The note explains the link; without the link it would explain nothing.
    expect(html).not.toContain("longer than this number");
  });

  it("renders nothing at all for a build with no host layer", () => {
    expect(renderToStaticMarkup(<HostAttention waiting={undefined} onOpen={() => undefined} />)).toBe("");
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
   * The host line's body ends "... whose latest decision is absent or awaiting
   * confirmation, today", and the onboarding heading comes straight after it.
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

  it("says the good news once when nothing on the host is waiting", () => {
    const html = record(overview({ host_attention: nothing }), "enterprise", () => undefined);
    expect(html).toContain(ONBOARDING);
    expect(html).toContain("Nothing on the host is waiting for you");
    expect(html).not.toContain("<button");
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
    expect(html).not.toContain("Nothing on the host is waiting");
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
