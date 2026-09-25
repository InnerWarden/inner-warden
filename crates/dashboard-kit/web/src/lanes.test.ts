import { describe, expect, it } from "vitest";

import {
  CASE_LANE_STORAGE_KEY,
  LANE_COPY,
  LANE_WINDOW_PHRASE,
  defaultCaseLane,
  laneParameter,
  overviewLaneCards,
  parseLaneCard,
  rememberCaseLane,
  rememberedCaseLane,
} from "./lanes";
import lanesOverview from "../tests/fixtures/enterprise/overview-lanes.json";

/**
 * The host's answer to the three questions is read strictly, one lane at a
 * time, and what cannot be shown honestly is dropped rather than completed.
 * These hand the reader a payload and read what it keeps.
 */

const agent = {
  availability: "available",
  window: "24h",
  count: 8,
  sentence: "Your agent tried 8 commands. InnerWarden refused 5 before they ran.",
};

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
    expect(overviewLaneCards({ agent: { availability: "available" } })).toBeUndefined();
  });

  it("keeps the reading order whatever order the host sent them in", () => {
    const cards = overviewLaneCards({ host: { ...agent }, agent: { ...agent }, prompt: { ...agent } });
    expect(cards?.map((card) => card.lane)).toEqual(["prompt", "agent", "host"]);
  });

  /**
   * Community has agent records and nothing else. It shows the lanes it has
   * data for, and a lane the host did not send is not drawn at all.
   */
  it("shows only the lanes the host sent", () => {
    expect(overviewLaneCards({ agent })?.map((card) => card.lane)).toEqual(["agent"]);
  });

  it("ignores a lane name it does not know rather than failing the others", () => {
    expect(overviewLaneCards({ agent, network: agent })?.map((card) => card.lane)).toEqual(["agent"]);
  });

  it("reads the fixture a lanes host sends", () => {
    const cards = overviewLaneCards(lanesOverview.lanes);
    expect(cards).toHaveLength(3);
    const host = cards?.find((card) => card.lane === "host");
    if (host?.state !== "available") throw new Error("the host lane should be available");
    expect(host.count).toBe(823);
    expect(host.waiting).toBe(32);
    expect(host.latest?.caseId).toBe("case:incident:lane-host-1");
  });
});

describe("one lane card", () => {
  it("needs its number, its window and its sentence", () => {
    expect(parseLaneCard("agent", agent)).toEqual({ lane: "agent", state: "available", count: 8, window: "24h", sentence: agent.sentence });
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
      expect(parseLaneCard("agent", broken), JSON.stringify(broken)).toBeUndefined();
    }
  });

  /**
   * THE RULE THIS PINS: a lane with no source has no number. A zero there
   * would say the lane was watched and found empty, which is exactly what
   * the host just said it cannot know.
   *
   * FAILS ON REVERT: carry `count` onto a `no_source` card and it has one.
   */
  it("gives a lane with no source no number, even when the host sent one", () => {
    const card = parseLaneCard("prompt", { availability: "no_source", count: 0, window: "24h", sentence: "Not reading conversations yet." });
    expect(card).toEqual({ lane: "prompt", state: "no_source", sentence: "Not reading conversations yet." });
    expect(card && "count" in card).toBe(false);
  });

  it("drops an availability it does not know rather than guessing what it meant", () => {
    for (const availability of ["unavailable", "degraded", "", undefined, "AVAILABLE"]) {
      expect(parseLaneCard("agent", { ...agent, availability })).toBeUndefined();
    }
  });

  /** The extras cost only their own line when they are malformed. */
  it("drops a malformed extra and keeps the card", () => {
    const withBadExtras = parseLaneCard("host", {
      ...agent,
      waiting: -3,
      latest: { title: "SSH password guessing", at: "yesterday" },
    });
    expect(withBadExtras).toEqual({ lane: "host", state: "available", count: 8, window: "24h", sentence: agent.sentence });
    for (const latest of [null, { at: "2026-09-25T10:00:00Z" }, { title: "", at: "2026-09-25T10:00:00Z" }, { title: "t", at: "2026-13-45T99:00:00Z" }]) {
      const card = parseLaneCard("host", { ...agent, latest });
      expect(card && card.state === "available" ? card.latest : "no card").toBeUndefined();
    }
  });

  it("keeps a latest case without an id as text, and one with an id as a link target", () => {
    const at = "2026-09-25T10:17:00Z";
    const plain = parseLaneCard("agent", { ...agent, latest: { title: "A session", at } });
    expect(plain && plain.state === "available" ? plain.latest : undefined).toEqual({ title: "A session", at });
    const linked = parseLaneCard("agent", { ...agent, latest: { title: "A session", at, case_id: "case:1" } });
    expect(linked && linked.state === "available" ? linked.latest : undefined).toEqual({ title: "A session", at, caseId: "case:1" });
    const oversized = parseLaneCard("agent", { ...agent, latest: { title: "A session", at, case_id: "c".repeat(257) } });
    expect(oversized && oversized.state === "available" ? oversized.latest : undefined).toEqual({ title: "A session", at });
  });
});

describe("the words about each lane", () => {
  it("names the three lanes the way the operator does", () => {
    expect(LANE_COPY.prompt.name).toBe("Messages to your AI agent");
    expect(LANE_COPY.agent.name).toBe("What your AI agent did");
    expect(LANE_COPY.host.name).toBe("Attacks on this server");
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
      expect(text, text).not.toMatch(/\b(prompt|host)\b lane/);
    }
  });
});

describe("the lane Cases opens on", () => {
  it("opens the lane this viewer last used", () => {
    expect(defaultCaseLane("host", { agent: 12 })).toBe("host");
    expect(defaultCaseLane("everything", undefined)).toBe("everything");
  });

  /**
   * THE OPERATOR'S RULE: with nothing remembered, the agent's lane when the
   * host has agent records, otherwise the server's, so a host with no agent
   * never opens on an empty tab.
   *
   * FAILS ON REVERT: always answer `agent` and a host with no agent records
   * opens on an empty lane.
   */
  it("opens the agent's lane where there are agent records, and the server's where there are none", () => {
    expect(defaultCaseLane(undefined, { agent: 3, host: 900 })).toBe("agent");
    expect(defaultCaseLane(undefined, { agent: 0, host: 900 })).toBe("host");
    expect(defaultCaseLane(undefined, { host: 900 })).toBe("host");
    // Counts not known yet: the agent's lane, corrected by the first answer.
    expect(defaultCaseLane(undefined, undefined)).toBe("agent");
  });

  it("asks the host for no lane at all when every case is the choice", () => {
    expect(laneParameter("everything")).toBe("");
    for (const lane of ["prompt", "agent", "host"] as const) expect(laneParameter(lane)).toBe(lane);
  });

  it("remembers the lane in this browser, and forgets nothing it cannot read", () => {
    const store = new Map<string, string>();
    const storage = { getItem: (key: string) => store.get(key) ?? null, setItem: (key: string, value: string) => void store.set(key, value) };
    expect(rememberedCaseLane(storage)).toBeUndefined();
    rememberCaseLane("prompt", storage);
    expect(store.get(CASE_LANE_STORAGE_KEY)).toBe("prompt");
    expect(rememberedCaseLane(storage)).toBe("prompt");
    // A value this bundle does not know is nothing remembered.
    store.set(CASE_LANE_STORAGE_KEY, "network");
    expect(rememberedCaseLane(storage)).toBeUndefined();
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
    expect(() => rememberCaseLane("agent", throwing)).not.toThrow();
    expect(rememberedCaseLane(undefined)).toBeUndefined();
  });
});
