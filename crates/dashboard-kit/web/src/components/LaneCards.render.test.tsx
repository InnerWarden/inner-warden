import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { overviewLaneCards, parseLaneCard, type LaneCard } from "../lanes";
import { LaneCards, laneLink } from "./LaneCards";
import lanesOverview from "../../tests/fixtures/enterprise/overview-lanes.json";

/**
 * The lane cards, RENDERED: one number, one sentence, the newest case and a
 * way into the cases behind it, for each lane the host answered.
 */

const cards = overviewLaneCards(lanesOverview.lanes) as LaneCard[];
const noop = () => undefined;

function card(html: string, lane: string): string {
  const start = html.indexOf(`data-lane="${lane}"`);
  if (start === -1) return "";
  const next = html.indexOf("data-lane=", start + 1);
  return html.slice(start, next === -1 ? undefined : next);
}

describe("a lane card on a paid host", () => {
  const html = renderToStaticMarkup(
    <LaneCards cards={cards} edition="enterprise" onOpenLane={noop} onOpenCase={noop} onOpenActivity={noop} />,
  );

  it("draws one card per lane, named the way the operator names them", () => {
    expect(html.match(/data-lane="/g)).toHaveLength(3);
    expect(card(html, "prompt")).toContain("Messages to your AI agent");
    expect(card(html, "agent")).toContain("What your AI agent did");
    expect(card(html, "host")).toContain("Attacks on this server");
  });

  it("gives each card its number, the span it covers and the host's sentence", () => {
    const agent = card(html, "agent");
    expect(agent).toMatch(/data-lane-count="[^"]*"[^>]*>8<\/span>/);
    expect(agent).toContain("in the last 24 hours");
    expect(agent).toContain("Your agent tried 8 commands. InnerWarden refused 5 before they ran");
    expect(card(html, "host")).toMatch(/data-lane-count="[^"]*"[^>]*>823<\/span>/);
  });

  it("names the newest case and makes it the way to that case", () => {
    const agent = card(html, "agent");
    expect(agent).toContain("Latest: ");
    expect(agent).toContain("AI agent session wren-visitor-28eb7f9c");
    expect(agent).toMatch(/<button[^>]*>AI agent session wren-visitor-28eb7f9c/);
    expect(agent).toContain('dateTime="2026-09-25T10:17:00Z"');
  });

  it("links each card into Cases with words that say where it goes", () => {
    expect(card(html, "prompt")).toContain("See the messages");
    expect(card(html, "agent")).toContain("See every command");
    expect(card(html, "host")).toContain("See the attacks");
  });

  /**
   * Something waiting on a person is never hidden: the host card says how
   * many, as a way to them, and a card with nothing waiting says nothing.
   */
  it("says what is waiting on a person, and only where something is", () => {
    expect(card(html, "host")).toContain("32 waiting on you");
    expect(card(html, "agent")).not.toContain("waiting on you");
    expect(card(html, "prompt")).not.toContain("waiting on you");
  });
});

describe("a lane with nothing to read", () => {
  const noSource = parseLaneCard("prompt", {
    availability: "no_source",
    sentence: "InnerWarden is not reading this agent's conversations yet.",
  }) as LaneCard;

  /**
   * THE RULE THIS PINS: a lane with no source shows no number at all, and no
   * link into an empty list. Its sentence says how to turn the source on.
   *
   * FAILS ON REVERT: render `count ?? 0` for every card and this one shows a
   * zero the host never claimed.
   */
  it("shows the host's sentence and no number, not a zero", () => {
    const html = renderToStaticMarkup(<LaneCards cards={[noSource]} edition="enterprise" onOpenLane={noop} />);
    expect(html).toContain("InnerWarden is not reading this agent&#x27;s conversations yet.");
    expect(html).not.toContain("data-lane-count");
    expect(html).not.toMatch(/>0</);
    // Nothing on the page leads anywhere, so the page does not promise it.
    expect(html).not.toContain("Each card opens");
    expect(html).not.toContain("See the messages");
    expect(html).toContain('data-lane-state="no_source"');
  });
});

describe("where a lane card leads", () => {
  it("opens Cases on the lane wherever there is a Cases screen", () => {
    for (const lane of ["prompt", "agent", "host"] as const) {
      expect(laneLink(lane, "enterprise", true)).toBe("cases");
      expect(laneLink(lane, "community", true)).toBe("cases");
    }
  });

  /**
   * Community has no Cases screen. Its Activity screen is its record of what
   * the agent did, so the agent's card opens that, and the other lanes link
   * nowhere rather than to an Overview that bounces back.
   */
  it("sends Community's agent card to Activity and draws the others as statements", () => {
    expect(laneLink("agent", "community", false)).toBe("activity");
    expect(laneLink("prompt", "community", false)).toBe("none");
    expect(laneLink("host", "community", false)).toBe("none");
    expect(laneLink("agent", "enterprise", false)).toBe("none");
  });

  it("renders a Community host that sends only the agent's lane as one card linking to Activity", () => {
    const agentOnly = overviewLaneCards({ agent: lanesOverview.lanes.agent }) as LaneCard[];
    const html = renderToStaticMarkup(<LaneCards cards={agentOnly} edition="community" onOpenActivity={noop} />);
    expect(html.match(/data-lane="/g)).toHaveLength(1);
    expect(html).toContain("See every command in Activity");
    // No Cases screen, so the newest case is text, not a button to nowhere.
    expect(html).not.toMatch(/<button[^>]*>AI agent session/);
  });

  it("keeps waiting visible as text when there is no Cases screen to open", () => {
    const host = overviewLaneCards({ host: lanesOverview.lanes.host }) as LaneCard[];
    const html = renderToStaticMarkup(<LaneCards cards={host} edition="community" />);
    expect(html).toContain("32 waiting on you");
    expect(html).not.toMatch(/<button[^>]*>32 waiting/);
  });
});

describe("the cards fill their row", () => {
  it("asks for no more columns than there are cards", () => {
    const one = renderToStaticMarkup(<LaneCards cards={cards.slice(0, 1)} edition="enterprise" />);
    expect(one).not.toContain("md:grid-cols-2");
    const two = renderToStaticMarkup(<LaneCards cards={cards.slice(0, 2)} edition="enterprise" />);
    expect(two).toContain("md:grid-cols-2");
    expect(two).not.toContain("lg:grid-cols-6");
    const three = renderToStaticMarkup(<LaneCards cards={cards} edition="enterprise" />);
    expect(three).toContain("lg:grid-cols-6");
  });
});
