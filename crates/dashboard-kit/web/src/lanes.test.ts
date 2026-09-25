import { describe, expect, it } from "vitest";

import {
  CASE_LANE_STORAGE_KEY,
  LANE_COPY,
  LANE_WINDOW_PHRASE,
  defaultCaseLane,
  laneCountNoun,
  laneParameter,
  overviewLaneCards,
  parseLaneCard,
  rememberCaseLane,
  rememberedCaseLane,
} from "./lanes";
// Both written by the paid server's own tests (the Overview it serves for the
// demo, and for a host that records no messages), not by hand.
import lanesOverview from "../tests/fixtures/enterprise/overview-lanes.json";
import noSourceOverview from "../tests/fixtures/enterprise/overview-lanes-no-source.json";

/**
 * The host's answer to the three questions is read strictly, one lane at a
 * time, and what cannot be shown honestly is dropped rather than completed.
 * These hand the reader a payload and read what it keeps.
 */

// The server's agent card, as it sends it.
const agent = lanesOverview.lanes.agent_actions;

describe("which lanes an Overview shows", () => {
  /**
   * THE RULE THIS PINS: absent is not empty. A host that sends no `lanes`
   * (every Community host, every paid host older than the field) must get the
   * page it always had, so the reader returns undefined, never [].
   *
   * FAILS ON REVERT: return `[]` for a missing field and the Overview takes
   * the lanes layout with no cards on it.
   */
  it("reads a host that sends no lanes as sending none, not as sending zero", () => {
    expect(overviewLaneCards(undefined)).toBeUndefined();
    expect(overviewLaneCards(null)).toBeUndefined();
    expect(overviewLaneCards([])).toBeUndefined();
    expect(overviewLaneCards("lanes")).toBeUndefined();
    // Present, but nothing in it can be shown: the same as absent.
    expect(overviewLaneCards({})).toBeUndefined();
    expect(overviewLaneCards({ agent_actions: { availability: "available" } })).toBeUndefined();
  });

  it("keeps the reading order whatever order the host sent them in", () => {
    const { server_attacks, agent_actions, agent_messages } = lanesOverview.lanes;
    const cards = overviewLaneCards({ server_attacks, agent_actions, agent_messages });
    expect(cards?.map((card) => card.lane)).toEqual(["agent_messages", "agent_actions", "server_attacks"]);
  });

  /** A lane the host did not send, or sent broken, is not drawn; the others are. */
  it("shows only the lanes it can read", () => {
    expect(overviewLaneCards({ agent_actions: agent })?.map((card) => card.lane)).toEqual(["agent_actions"]);
    const { agent_messages: _dropped, ...twoLanes } = lanesOverview.lanes;
    expect(overviewLaneCards(twoLanes)?.map((card) => card.lane)).toEqual(["agent_actions", "server_attacks"]);
  });

  it("ignores a lane name it does not know rather than failing the others", () => {
    expect(overviewLaneCards({ agent_actions: agent, network: agent })?.map((card) => card.lane)).toEqual(["agent_actions"]);
  });

  /**
   * THE DEFECT THIS PINS: the kit named the lanes `prompt`, `agent` and
   * `host`, and the server sends `agent_messages`, `agent_actions` and
   * `server_attacks`. Every lane card on a real host was dropped as unknown,
   * and the Overview never showed one. This reads the server's own answer.
   *
   * FAILS ON REVERT: rename a lane back and its card is gone from this list.
   */
  it("reads every card the server sends, under the server's own names", () => {
    const cards = overviewLaneCards(lanesOverview.lanes);
    expect(cards?.map((card) => [card.lane, card.state])).toEqual([
      ["agent_messages", "available"],
      ["agent_actions", "available"],
      ["server_attacks", "available"],
    ]);
    const actions = cards?.find((card) => card.lane === "agent_actions");
    if (actions?.state !== "available") throw new Error("the agent's lane should be available");
    expect(actions.count).toBe(2);
    expect(actions.countOf).toBe("commands");
    expect(actions.window).toBe("7d");
    expect(actions.waiting).toBe(0);
    expect(actions.latest?.caseId).toMatch(/^case:community-session:/);
    expect(actions.latest?.title).toMatch(/^Visitor 28eb7f9c asked your AI agent to /);
    // The server's lane counts nothing as waiting; it sends null, which is
    // not a zero the card may print.
    const attacks = cards?.find((card) => card.lane === "server_attacks");
    if (attacks?.state !== "available") throw new Error("the server's lane should be available");
    expect(attacks.window).toBe("24h");
    expect(attacks.countOf).toBe("findings");
    expect("waiting" in attacks).toBe(false);
  });

  it("reads a host that records no messages as a lane with no source, beside two with numbers", () => {
    const cards = overviewLaneCards(noSourceOverview.lanes);
    expect(cards?.map((card) => [card.lane, card.state])).toEqual([
      ["agent_messages", "no_source"],
      ["agent_actions", "available"],
      ["server_attacks", "available"],
    ]);
  });
});

describe("one lane card", () => {
  it("needs its number, its window and its sentence", () => {
    const bare = { availability: "available", window: "7d", count: 8, sentence: agent.sentence };
    expect(parseLaneCard("agent_actions", bare)).toEqual({ lane: "agent_actions", state: "available", count: 8, window: "7d", sentence: agent.sentence });
    for (const broken of [
      { ...agent, count: undefined },
      { ...agent, count: -1 },
      { ...agent, count: 1.5 },
      { ...agent, count: "8" },
      { ...agent, count: Number.NaN },
      { ...agent, window: undefined },
      { ...agent, window: "2h" },
      { ...agent, sentence: "" },
      { ...agent, sentence: "   " },
      { ...agent, sentence: "x".repeat(601) },
      { ...agent, sentence: 7 },
    ]) {
      expect(parseLaneCard("agent_actions", broken), JSON.stringify(broken)).toBeUndefined();
    }
  });

  /**
   * THE RULE THIS PINS: the number says what it counts. The agent's card
   * counts COMMANDS, and the Cases lane it opens lists one case per session,
   * so a bare number beside it reads as a count of those cases.
   *
   * FAILS ON REVERT: drop `count_of` from the reader and the card has no
   * unit to print.
   */
  it("keeps what the number counts, and prints no unit it was not told", () => {
    const card = parseLaneCard("agent_actions", agent);
    expect(card?.state === "available" ? card.countOf : undefined).toBe("commands");
    for (const countOf of [undefined, null, "cases", "Commands", 3]) {
      const unknown = parseLaneCard("agent_actions", { ...agent, count_of: countOf });
      if (unknown?.state !== "available") throw new Error("an unknown unit must not cost the card");
      expect("countOf" in unknown, String(countOf)).toBe(false);
    }
    expect(laneCountNoun("commands", 8)).toBe("commands");
    expect(laneCountNoun("commands", 1)).toBe("command");
    expect(laneCountNoun("messages", 0)).toBe("messages");
    expect(laneCountNoun("findings", 1)).toBe("finding");
    expect(laneCountNoun(undefined, 8)).toBeUndefined();
  });

  /** A card that names another lane than the key it came under is contradictory. */
  it("drops a card whose own lane disagrees with where it was sent", () => {
    expect(parseLaneCard("agent_messages", agent)).toBeUndefined();
    const { lane: _lane, ...unnamed } = agent;
    expect(parseLaneCard("agent_messages", unnamed)?.lane).toBe("agent_messages");
  });

  /**
   * THE RULE THIS PINS: a lane with no source has no number. A zero there
   * would say the lane was watched and found empty, which is exactly what
   * the host just said it cannot know.
   *
   * FAILS ON REVERT: carry `count` onto a `no_source` card and it has one.
   */
  it("gives a lane with no source no number, even when the host sent one", () => {
    const card = parseLaneCard("agent_messages", { ...noSourceOverview.lanes.agent_messages, count: 0, waiting: 0 });
    expect(card).toEqual({ lane: "agent_messages", state: "no_source", sentence: noSourceOverview.lanes.agent_messages.sentence });
    expect(card && "count" in card).toBe(false);
  });

  it("drops an availability it does not know rather than guessing what it meant", () => {
    for (const availability of ["unavailable", "degraded", "", undefined, "AVAILABLE"]) {
      expect(parseLaneCard("agent_actions", { ...agent, availability })).toBeUndefined();
    }
  });

  /** The extras cost only their own line when they are malformed. */
  it("drops a malformed extra and keeps the card", () => {
    const withBadExtras = parseLaneCard("agent_actions", {
      ...agent,
      waiting: -3,
      latest: { title: "Visitor 28eb7f9c asked your AI agent to run a command as root", at: "yesterday" },
    });
    expect(withBadExtras).toEqual({ lane: "agent_actions", state: "available", count: 2, countOf: "commands", window: "7d", sentence: agent.sentence });
    for (const latest of [null, { at: "2026-09-25T10:00:00Z" }, { title: "", at: "2026-09-25T10:00:00Z" }, { title: "t", at: "2026-13-45T99:00:00Z" }]) {
      const card = parseLaneCard("agent_actions", { ...agent, latest });
      expect(card && card.state === "available" ? card.latest : "no card").toBeUndefined();
    }
  });

  it("keeps a latest case without an id as text, and one with an id as a link target", () => {
    const at = "2026-09-25T10:17:00Z";
    const plain = parseLaneCard("agent_actions", { ...agent, latest: { title: "A session", at } });
    expect(plain && plain.state === "available" ? plain.latest : undefined).toEqual({ title: "A session", at });
    const linked = parseLaneCard("agent_actions", { ...agent, latest: { title: "A session", at, case_id: "case:1" } });
    expect(linked && linked.state === "available" ? linked.latest : undefined).toEqual({ title: "A session", at, caseId: "case:1" });
    const oversized = parseLaneCard("agent_actions", { ...agent, latest: { title: "A session", at, case_id: "c".repeat(257) } });
    expect(oversized && oversized.state === "available" ? oversized.latest : undefined).toEqual({ title: "A session", at });
  });
});

describe("the words about each lane", () => {
  it("names the three lanes the way the operator does", () => {
    expect(LANE_COPY.agent_messages.name).toBe("Messages to your AI agent");
    expect(LANE_COPY.agent_actions.name).toBe("What your AI agent did");
    expect(LANE_COPY.server_attacks.name).toBe("Attacks on this server");
  });

  /**
   * The agent's lane lists one case per SESSION while its card counts
   * commands, so its link and intro must not promise a row per command.
   */
  it("does not promise the agent's lane lists one row per command", () => {
    expect(LANE_COPY.agent_actions.link).toBe("See the sessions");
    expect(LANE_COPY.agent_actions.intro).toMatch(/^One case for each session of your AI agent/);
  });

  /** Plain words only: no wire token, no dash the writing rule bans. */
  it("carries no internal token or banned dash in anything a reader sees", () => {
    // Built from code points so this file cannot trip the em dash gate.
    const bannedDash = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);
    const shown = [
      ...Object.values(LANE_COPY).flatMap((copy) => [copy.name, copy.blurb, copy.link, copy.intro]),
      ...Object.values(LANE_WINDOW_PHRASE),
    ];
    for (const text of shown) {
      expect(text, text).not.toMatch(/_/);
      expect(text, text).not.toMatch(bannedDash);
      // The wire names carry an underscore, so the check above catches them.
      expect(text, text).not.toMatch(/\b(prompt|host)\b lane/);
    }
  });
});

describe("the lane Cases opens on", () => {
  it("opens the lane this viewer last used", () => {
    expect(defaultCaseLane("server_attacks", { agent_actions: 12 })).toBe("server_attacks");
    expect(defaultCaseLane("everything", undefined)).toBe("everything");
  });

  /**
   * THE OPERATOR'S RULE: with nothing remembered, the agent's lane when the
   * host has agent records, otherwise the server's, so a host with no agent
   * never opens on an empty tab.
   *
   * FAILS ON REVERT: always answer the agent's lane and a host with no agent
   * records opens on an empty lane.
   */
  it("opens the agent's lane where there are agent records, and the server's where there are none", () => {
    expect(defaultCaseLane(undefined, { agent_messages: 1, agent_actions: 1, server_attacks: 3, other: 2 })).toBe("agent_actions");
    expect(defaultCaseLane(undefined, { agent_actions: 0, server_attacks: 900 })).toBe("server_attacks");
    expect(defaultCaseLane(undefined, { server_attacks: 900 })).toBe("server_attacks");
    // Counts not known yet: the agent's lane, corrected by the first answer.
    expect(defaultCaseLane(undefined, undefined)).toBe("agent_actions");
  });

  it("asks the host for no lane at all when every case is the choice", () => {
    expect(laneParameter("everything")).toBe("");
    for (const lane of ["agent_messages", "agent_actions", "server_attacks"] as const) expect(laneParameter(lane)).toBe(lane);
  });

  it("remembers the lane in this browser, and forgets nothing it cannot read", () => {
    const store = new Map<string, string>();
    const storage = { getItem: (key: string) => store.get(key) ?? null, setItem: (key: string, value: string) => void store.set(key, value) };
    expect(rememberedCaseLane(storage)).toBeUndefined();
    rememberCaseLane("agent_messages", storage);
    expect(store.get(CASE_LANE_STORAGE_KEY)).toBe("agent_messages");
    expect(rememberedCaseLane(storage)).toBe("agent_messages");
    // A value this bundle does not know is nothing remembered.
    for (const unknown of ["network", "agent", "prompt", "host"]) {
      store.set(CASE_LANE_STORAGE_KEY, unknown);
      expect(rememberedCaseLane(storage), unknown).toBeUndefined();
    }
  });

  /** A private window or blocked storage throws; the screen must not. */
  it("treats storage that throws as nothing remembered", () => {
    const throwing = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
    };
    expect(rememberedCaseLane(throwing)).toBeUndefined();
    expect(() => rememberCaseLane("agent_actions", throwing)).not.toThrow();
    expect(rememberedCaseLane(undefined)).toBeUndefined();
  });
});
