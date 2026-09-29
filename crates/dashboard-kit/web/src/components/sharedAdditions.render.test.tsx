import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import type { Overview } from "../api";
import { cardsWithWaitingFloor, OverviewScreen, waitingAcrossLanes, waitingCount, waitingLine } from "../screens/Home";
import { laneSince, overviewLaneCards, parseLaneCard, type LaneCard } from "../lanes";
import { CaseLaneTabs, EVERYTHING_MOVED_NOTE, laneAfterWaitingCleared, laneTabs } from "./CaseLaneTabs";
import { LaneCards, outcomeTone } from "./LaneCards";
import { GLYPHS } from "./icons";
import { setTechnicalDetail } from "./TechnicalDetail";
// Written by the paid server's own tests, not by hand.
import lanesOverview from "../../tests/fixtures/enterprise/overview-lanes.json";

/**
 * The shared pieces the Community pages needed, each an OPTIONAL addition:
 * absent, every one renders exactly what it rendered before, which is what
 * keeps the paid composition unchanged when it re-pins this kit.
 */
afterEach(() => setTechnicalDetail(false));

const noop = () => undefined;
const cards = overviewLaneCards(lanesOverview.lanes) as LaneCard[];

describe("LaneCards' three optional props", () => {
  it("render exactly today's markup when absent", () => {
    const before = renderToStaticMarkup(<LaneCards cards={cards} edition="enterprise" onOpenLane={noop} onOpenCase={noop} />);
    const explicit = renderToStaticMarkup(
      <LaneCards cards={cards} edition="enterprise" onOpenLane={noop} onOpenCase={noop} intro={undefined} linkLabel={() => undefined} footer={() => undefined} align={undefined} />,
    );
    expect(explicit).toBe(before);
    expect(before).toContain("Each card opens what is behind it.");
  });

  it("replace the intro, a card's link words, and add a foot above its link", () => {
    const html = renderToStaticMarkup(
      <LaneCards
        cards={cards}
        edition="community"
        onOpenLane={noop}
        intro="From this machine's own records."
        linkLabel={(lane) => (lane === "agent_actions" ? "See the flagged commands" : undefined)}
        footer={(card) => (card.lane === "server_attacks" ? <p data-foot="">a foot</p> : undefined)}
      />,
    );
    expect(html).toContain("From this machine&#x27;s own records.");
    expect(html).not.toContain("Each card opens what is behind it.");
    expect(html).toContain("See the flagged commands");
    expect(html).toContain("See the messages");
    const server = html.slice(html.indexOf('data-lane="server_attacks"'));
    expect(server.indexOf("data-foot")).toBeLessThan(server.indexOf("See the attacks"));
  });

  it("let a row of uneven cards keep their own heights, only when asked", () => {
    expect(renderToStaticMarkup(<LaneCards cards={cards} edition="community" align="start" />)).toContain("items-start");
    expect(renderToStaticMarkup(<LaneCards cards={cards} edition="community" />)).not.toContain("items-start");
  });

  it("give Community's two outcomes their jobs: flagged is grey, a check is light grey", () => {
    expect(outcomeTone("flagged_ran")).toEqual({ tone: "other" });
    expect(outcomeTone("checked_only")).toEqual({ tone: "watchLight" });
  });

  it("say 'since' a day when the host's record starts inside the window", () => {
    const since = parseLaneCard("agent_actions", { ...lanesOverview.lanes.agent_actions, since: "2026-09-25T17:33:40Z" }) as LaneCard;
    expect(since.state === "available" && since.since).toBe("2026-09-25T17:33:40Z");
    const html = renderToStaticMarkup(<LaneCards cards={[since]} edition="community" />);
    expect(html).toContain(">commands since 25 Sept 2026<");
    expect(html).not.toContain(">commands in the last 7 days<");
    expect(laneSince("25 Sept")).toBeUndefined();
    expect(laneSince(20260925)).toBeUndefined();
  });
});

describe("a waiting count read from a capped read: a floor, 'At least'", () => {
  const incomplete = { count: 202, window: "all", complete: false } as const;

  it("reads `complete` and keeps whole counts exactly as they were", () => {
    expect(waitingCount(incomplete)).toEqual(incomplete);
    expect(waitingCount({ count: 202, window: "all" })).toEqual({ count: 202, window: "all" });
    expect(waitingCount({ count: 202, window: "all", complete: "no" })).toEqual({ count: 202, window: "all" });
  });

  /** FAILS ON REVERT: drop the `complete` read and the title says "202 cases". */
  it("says 'At least', never splits a floor into today and earlier, and names no number on the link", () => {
    const line = waitingLine({ ...incomplete, today: 3 });
    expect(line.title).toBe("At least 202 cases are waiting on you");
    expect(line.body).toBe("InnerWarden read only its newest records, so older cases may be waiting too.");
    expect(line.body).not.toContain("today");
    expect(line.through?.label).toBe("See the waiting cases");
    expect(waitingLine({ count: 1, window: "all", complete: false }).title).toBe("At least 1 case is waiting on you");
  });

  it("does not subtract the chips from a floor", () => {
    expect(waitingAcrossLanes({ count: 5, window: "7d", complete: false }, cards)).toBeUndefined();
  });

  it("lets a lane chip counted over the same read say 'At least' too", () => {
    const floored = cardsWithWaitingFloor(cards, { count: 3, window: "7d", complete: false });
    const messages = floored.find((card) => card.lane === "agent_messages");
    expect(messages?.state === "available" && messages.waitingComplete).toBe(false);
    const html = renderToStaticMarkup(<LaneCards cards={floored} edition="enterprise" onOpenLane={noop} />);
    expect(html).toContain("At least 1 waiting on you");
    expect(cardsWithWaitingFloor(cards, { count: 3, window: "7d" })).toBe(cards);
  });

  it("renders the Overview line as a floor", () => {
    const overview = { ...lanesOverview, waiting: { count: 202, window: "all", complete: false } } as unknown as Overview;
    const html = renderToStaticMarkup(<OverviewScreen overview={overview} edition="enterprise" onOpenActivity={noop} onOpenCase={noop} onOpenQueue={noop} onOpenLane={noop} />);
    expect(html).toContain("At least 202 cases are waiting on you");
    expect(html).not.toContain("arrived today");
  });
});

describe("the lane tabs' two optional props", () => {
  it("offer only the lanes a screen names, in its order", () => {
    const tabs = laneTabs("agent_actions", { agent_messages: 3 }, true, { choices: ["agent_actions", "agent_messages"] });
    expect(tabs.map((tab) => tab.choice)).toEqual(["agent_actions", "agent_messages"]);
    expect(tabs[1].count).toBe(3);
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" choices={["agent_actions", "agent_messages"]} onChange={noop} />);
    expect(html).not.toContain('data-lane="server_attacks"');
  });

  it("keep Everything behind the switch once a plain viewer releases the waiting filter", () => {
    const offered = (value: "everything" | "agent_actions", technical: boolean, statusFilter?: string) =>
      laneTabs(value, undefined, technical, statusFilter === undefined ? {} : { statusFilter }).some((tab) => tab.choice === "everything");
    expect(offered("everything", false, "waiting")).toBe(true);
    expect(offered("everything", false, "all")).toBe(false);
    expect(offered("agent_actions", true, "all")).toBe(true);
    // Without the prop, today's rule: a shared link to Everything keeps its tab.
    expect(offered("everything", false)).toBe(true);
    expect(offered("agent_actions", false)).toBe(false);
  });

  it("move a plain viewer off Everything to their own lane, and say where the rest is", () => {
    expect(laneAfterWaitingCleared("everything", false, undefined, { agent_actions: 2 })).toBe("agent_actions");
    expect(laneAfterWaitingCleared("everything", false, "server_attacks", undefined)).toBe("server_attacks");
    expect(laneAfterWaitingCleared("everything", false, "everything", { agent_actions: 0 })).toBe("server_attacks");
    expect(laneAfterWaitingCleared("everything", true, undefined, undefined)).toBeUndefined();
    expect(laneAfterWaitingCleared("agent_actions", false, undefined, undefined)).toBeUndefined();
    expect(EVERYTHING_MOVED_NOTE).toContain("Show technical detail");
  });
});

describe("the two new glyphs", () => {
  it("are small, single paths on the 16 grid", () => {
    for (const name of ["plug", "cage"] as const) {
      expect(GLYPHS[name].length).toBeLessThan(200);
      expect(GLYPHS[name]).toMatch(/^M/);
    }
  });
});
