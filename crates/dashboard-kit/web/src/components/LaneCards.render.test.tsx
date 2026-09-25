import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { overviewLaneCards, parseLaneCard, type LaneCard } from "../lanes";
import { LaneCards, laneLink, type LaneOpenOptions } from "./LaneCards";
// Both written by the paid server's own tests, not by hand.
import lanesOverview from "../../tests/fixtures/enterprise/overview-lanes.json";
import noSourceOverview from "../../tests/fixtures/enterprise/overview-lanes-no-source.json";

/**
 * The lane cards, RENDERED: one number and what it counts, one sentence, the
 * newest case and a way into the cases behind it, for each lane the host
 * answered.
 */

const cards = overviewLaneCards(lanesOverview.lanes) as LaneCard[];
const noop = () => undefined;

function card(html: string, lane: string): string {
  const start = html.indexOf(`data-lane="${lane}"`);
  if (start === -1) return "";
  const next = html.indexOf("data-lane=", start + 1);
  return html.slice(start, next === -1 ? undefined : next);
}

/** The React element tree, walked, so a test can press a button without a DOM. */
type Element = { type: unknown; props: Record<string, unknown> };

function buttons(node: unknown, found: Element[] = []): Element[] {
  if (Array.isArray(node)) {
    for (const child of node) buttons(child, found);
    return found;
  }
  if (typeof node !== "object" || node === null || !("props" in node)) return found;
  const element = node as Element;
  if (typeof element.type === "function") {
    return buttons((element.type as (props: Record<string, unknown>) => unknown)(element.props), found);
  }
  if (element.type === "button") found.push(element);
  buttons(element.props.children, found);
  return found;
}

function text(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  if (typeof node === "object" && node !== null && "props" in node) return text((node as Element).props.children);
  return "";
}

describe("a lane card on a paid host", () => {
  const html = renderToStaticMarkup(
    <LaneCards cards={cards} edition="enterprise" onOpenLane={noop} onOpenCase={noop} onOpenActivity={noop} />,
  );

  it("draws one card per lane, named the way the operator names them", () => {
    expect(html.match(/data-lane="/g)).toHaveLength(3);
    expect(card(html, "agent_messages")).toContain("Messages to your AI agent");
    expect(card(html, "agent_actions")).toContain("What your AI agent did");
    expect(card(html, "server_attacks")).toContain("Attacks on this server");
  });

  /**
   * THE RULE THIS PINS: the number says what it counts. The agent's card
   * counts COMMANDS and its link opens one case per session; a bare "2"
   * beside a tab counting cases reads as the same thing, and it is not.
   *
   * FAILS ON REVERT: print the number with the window alone and the unit is
   * gone from every card.
   */
  it("gives each card its number, what it counts, the span it covers and the host's sentence", () => {
    const agent = card(html, "agent_actions");
    expect(agent).toMatch(/data-lane-count="[^"]*"[^>]*>2<\/span>/);
    expect(agent).toContain(">commands in the last 7 days<");
    expect(agent).toContain("Your AI agent tried 2 commands in the last 7 days: InnerWarden refused 1 before they ran");
    expect(card(html, "agent_messages")).toContain(">messages in the last 7 days<");
    const server = card(html, "server_attacks");
    expect(server).toMatch(/data-lane-count="[^"]*"[^>]*>3<\/span>/);
    expect(server).toContain(">findings in the last 24 hours<");
  });

  it("prints one of a thing in the singular, and a number it was given no unit for on its own", () => {
    const one = parseLaneCard("agent_actions", { ...lanesOverview.lanes.agent_actions, count: 1 }) as LaneCard;
    expect(renderToStaticMarkup(<LaneCards cards={[one]} edition="enterprise" />)).toContain(">command in the last 7 days<");
    const bare = parseLaneCard("agent_actions", { ...lanesOverview.lanes.agent_actions, count_of: "rows" }) as LaneCard;
    const unitless = renderToStaticMarkup(<LaneCards cards={[bare]} edition="enterprise" />);
    expect(unitless).toContain(">in the last 7 days<");
    // The unit lives in the small print after the number; the host's own
    // sentence below it may say "commands" and is not the unit.
    expect(unitless).not.toContain(">commands in the last");
  });

  it("names the newest case and makes it the way to that case", () => {
    const agent = card(html, "agent_actions");
    expect(agent).toContain("Latest: ");
    expect(agent).toMatch(/<button[^>]*>Visitor 28eb7f9c asked your AI agent to run a command as root/);
    expect(agent).toContain(`dateTime="${lanesOverview.lanes.agent_actions.latest.at}"`);
  });

  it("links each card into Cases with words that say where it goes", () => {
    expect(card(html, "agent_messages")).toContain("See the messages");
    expect(card(html, "agent_actions")).toContain("See the sessions");
    expect(card(html, "server_attacks")).toContain("See the attacks");
    expect(html).toContain("Each card opens what is behind it.");
  });

  /**
   * Something waiting on a person is never hidden: an agent card says how
   * many, as a way to them, and a card with nothing waiting says nothing. The
   * server's own card counts no waiting (it sends `null`; its sentence says
   * what waits there today), so it draws no chip.
   */
  it("says what is waiting on a person, and only where something is", () => {
    expect(card(html, "agent_messages")).toContain("1 waiting on you");
    expect(card(html, "agent_actions")).not.toContain("waiting on you");
    expect(card(html, "server_attacks")).not.toContain("waiting on you");
  });

  /**
   * THE RULE THIS PINS: the host counts what is waiting inside the card's
   * own window, so the chip opens that window, and the number on the chip and
   * the list behind it describe the same span.
   *
   * FAILS ON REVERT: open the waiting list over all time and the list can
   * hold cases the chip never counted.
   */
  it("opens what is waiting in the window the host counted it in", () => {
    const opened: [string, LaneOpenOptions][] = [];
    const tree = LaneCards({
      cards,
      edition: "enterprise",
      onOpenLane: (lane, options) => void opened.push([lane, options]),
      onOpenCase: noop,
      onOpenActivity: noop,
    });
    const chip = buttons(tree).find((button) => text(button.props.children).includes("waiting on you"));
    if (chip === undefined) throw new Error("the messages card should offer its waiting cases");
    (chip.props.onClick as () => void)();
    expect(opened).toEqual([["agent_messages", { window: "7d", status: "waiting" }]]);
  });
});

describe("a lane with nothing to read", () => {
  const noSourceCards = overviewLaneCards(noSourceOverview.lanes) as LaneCard[];
  const noSource = noSourceCards.find((entry) => entry.lane === "agent_messages") as LaneCard;

  /**
   * THE RULE THIS PINS: a lane with no source shows no number at all, and no
   * link into an empty list. Its sentence says what is not being read.
   *
   * FAILS ON REVERT: render `count ?? 0` for every card and this one shows a
   * zero the host never claimed.
   */
  it("shows the host's sentence and no number, not a zero", () => {
    const html = renderToStaticMarkup(<LaneCards cards={[noSource]} edition="enterprise" onOpenLane={noop} />);
    expect(html).toContain("InnerWarden is not reading your AI agent&#x27;s messages yet");
    expect(html).not.toContain("data-lane-count");
    expect(html).not.toMatch(/>0</);
    expect(html).not.toContain("See the messages");
    expect(html).toContain('data-lane-state="no_source"');
  });

  /**
   * THE RULE THIS PINS: the line over the cards promises that each one opens
   * what is behind it, so it is said only when every card does. Beside a card
   * with no source, which has no link, it was a promise one card broke.
   *
   * FAILS ON REVERT: say it when any card links and this page, whose first
   * card has no link, says it.
   */
  it("promises a link on every card only when every card has one", () => {
    const html = renderToStaticMarkup(<LaneCards cards={noSourceCards} edition="enterprise" onOpenLane={noop} />);
    expect(html.match(/data-lane="/g)).toHaveLength(3);
    expect(card(html, "agent_actions")).toContain("See the sessions");
    expect(html).not.toContain("Each card opens");
    expect(html).toContain("Answered from this host&#x27;s own records.");
  });
});

describe("where a lane card leads", () => {
  it("opens Cases on the lane wherever there is a Cases screen", () => {
    for (const lane of ["agent_messages", "agent_actions", "server_attacks"] as const) {
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
    expect(laneLink("agent_actions", "community", false)).toBe("activity");
    expect(laneLink("agent_messages", "community", false)).toBe("none");
    expect(laneLink("server_attacks", "community", false)).toBe("none");
    expect(laneLink("agent_actions", "enterprise", false)).toBe("none");
  });

  it("renders a host that sends only the agent's lane, with no Cases screen, as one card linking to Activity", () => {
    const agentOnly = overviewLaneCards({ agent_actions: lanesOverview.lanes.agent_actions }) as LaneCard[];
    const html = renderToStaticMarkup(<LaneCards cards={agentOnly} edition="community" onOpenActivity={noop} />);
    expect(html.match(/data-lane="/g)).toHaveLength(1);
    expect(html).toContain("See every command in Activity");
    // No Cases screen, so the newest case is text, not a button to nowhere.
    expect(html).not.toMatch(/<button[^>]*>Visitor 28eb7f9c/);
  });

  it("keeps waiting visible as text when there is no Cases screen to open", () => {
    const messages = overviewLaneCards({ agent_messages: lanesOverview.lanes.agent_messages }) as LaneCard[];
    const html = renderToStaticMarkup(<LaneCards cards={messages} edition="community" />);
    expect(html).toContain("1 waiting on you");
    expect(html).not.toMatch(/<button[^>]*>1 waiting/);
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
