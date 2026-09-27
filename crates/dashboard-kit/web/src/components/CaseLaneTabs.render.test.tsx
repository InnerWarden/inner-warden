import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { CaseLaneTabs, laneIntro, laneTabCount, laneTabs, nextLaneTab } from "./CaseLaneTabs";
import { caseViewUrl, EMPTY_CASE_VIEW, readCaseViewState } from "./CaseFilters";
import { setTechnicalDetail } from "./TechnicalDetail";

/**
 * The lane tabs a Cases screen draws once the host has said it files cases
 * into lanes (the list answer's `lane_filter` says the lane was served).
 * RENDERED, and the keyboard rule is a pure function the handler calls.
 */

afterEach(() => setTechnicalDetail(false));

const noop = () => undefined;

// The counts the server sent beside its own page.
const serverCounts = { agent_messages: 1, agent_actions: 1, server_attacks: 3, other: 2 };

describe("the tab row", () => {
  it("offers the three lanes, named the way the operator names them, with the host's counts", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" counts={{ ...serverCounts, server_attacks: 823 }} onChange={noop} panelId="case-list" />);
    expect(html).toContain('role="tablist"');
    expect(html.match(/role="tab"/g)).toHaveLength(3);
    expect(html).toContain("Messages to your AI agent");
    expect(html).toContain("What your AI agent did");
    expect(html).toContain("Attacks on this server");
    expect(html).toContain(">823</span>");
    expect(html).toContain('aria-label="Attacks on this server, 823 cases"');
    // One case per session in the agent's lane, so the count is sessions.
    expect(html).toContain('aria-label="What your AI agent did, 1 session"');
    expect(html).toContain('aria-label="Messages to your AI agent, 1 message"');
    expect(html).toContain('aria-controls="case-list"');
  });

  it("marks the open lane selected and says what it lists", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" onChange={noop} />);
    expect(html).toMatch(/aria-selected="true"[^>]*data-lane="agent_actions"/);
    expect(html.match(/aria-selected="true"/g)).toHaveLength(1);
    expect(html).toContain("One case for each session of your AI agent");
    // One tab stop for the whole row, on the open tab.
    expect(html.match(/tabindex="0"/gi)).toHaveLength(1);
  });

  /**
   * THE RULE THIS PINS: a count the host did not send is no badge, not a
   * zero. A lane it counted at zero says zero.
   *
   * FAILS ON REVERT: render `counts?.[lane] ?? 0` and the messages tab below
   * claims zero messages on a host that never counted them.
   */
  it("draws no badge for a lane the host did not count, and a zero for one it counted at zero", () => {
    const tabs = laneTabs("agent_actions", { agent_actions: 0 }, false);
    expect(tabs.find((tab) => tab.choice === "agent_messages")?.count).toBeUndefined();
    expect(tabs.find((tab) => tab.choice === "agent_actions")?.count).toBe(0);
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" counts={{ agent_actions: 0 }} onChange={noop} />);
    expect(html.match(/tabular-nums/g)).toHaveLength(1);
    expect(renderToStaticMarkup(<CaseLaneTabs value="agent_actions" onChange={noop} />)).not.toContain("tabular-nums");
  });

  /**
   * Every case is the three lanes and the cases in none, so its badge is the
   * four added up, and only when the host counted all four.
   *
   * FAILS ON REVERT: leave the everything tab without a count and its badge
   * is gone; add up what is there and a missing part reads as the whole.
   */
  it("counts every case on the everything tab as the four added up, and only when all four came", () => {
    const every = laneTabs("everything", serverCounts, true).find((tab) => tab.choice === "everything");
    expect(every?.count).toBe(7);
    const partial = laneTabs("everything", { agent_messages: 1, agent_actions: 1, server_attacks: 3 }, true);
    expect(partial.find((tab) => tab.choice === "everything")?.count).toBeUndefined();
  });

  /**
   * "Everything" lists raw telemetry and bookkeeping beside the lanes: a
   * technical question, offered in the technical view, or when a shared link
   * already opened it, so the open tab is always on screen.
   */
  it("offers every case only in the technical view, or when it is the open tab", () => {
    expect(renderToStaticMarkup(<CaseLaneTabs value="server_attacks" onChange={noop} />)).not.toContain(">Everything<");
    setTechnicalDetail(true);
    expect(renderToStaticMarkup(<CaseLaneTabs value="server_attacks" onChange={noop} />)).toContain(">Everything<");
    setTechnicalDetail(false);
    const opened = renderToStaticMarkup(<CaseLaneTabs value="everything" onChange={noop} />);
    expect(opened).toMatch(/aria-selected="true"[^>]*data-lane="everything"/);
    expect(opened).toContain("belong to none of the three lanes");
    expect(laneIntro("everything")).toContain("raw telemetry");
  });
});

describe("the keyboard", () => {
  const tabs = laneTabs("agent_actions", undefined, true);

  it("moves with the arrows, wrapping at the ends, and jumps with Home and End", () => {
    expect(nextLaneTab(tabs, "agent_actions", "ArrowRight")).toBe("server_attacks");
    expect(nextLaneTab(tabs, "agent_actions", "ArrowLeft")).toBe("agent_messages");
    expect(nextLaneTab(tabs, "agent_messages", "ArrowLeft")).toBe("everything");
    expect(nextLaneTab(tabs, "everything", "ArrowRight")).toBe("agent_messages");
    expect(nextLaneTab(tabs, "server_attacks", "Home")).toBe("agent_messages");
    expect(nextLaneTab(tabs, "agent_messages", "End")).toBe("everything");
  });

  it("moves nothing for any other key", () => {
    for (const key of ["Enter", " ", "Tab", "ArrowDown", "a"]) expect(nextLaneTab(tabs, "agent_actions", key)).toBeUndefined();
    expect(nextLaneTab([], "agent_actions", "ArrowRight")).toBeUndefined();
  });
});

describe("the lane in the address bar", () => {
  it("reads each lane, and every case, and drops anything else", () => {
    for (const lane of ["agent_messages", "agent_actions", "server_attacks", "everything"]) {
      expect(readCaseViewState(`?view=cases&lane=${lane}`).lane).toBe(lane);
    }
    for (const junk of ["network", "AGENT_ACTIONS", "", "all", "agent", "prompt", "host"]) {
      expect(readCaseViewState(`?view=cases&lane=${encodeURIComponent(junk)}`).lane).toBe("");
    }
    expect(readCaseViewState("?view=cases").lane).toBe("");
  });

  /**
   * THE DEFECT THIS PINS: the Overview's own link from the server reads
   * `?view=cases&lane=agent_actions&window=7d`, and the screen read that
   * lane as none and opened its default instead.
   *
   * FAILS ON REVERT: read only the old spellings and this address opens no
   * lane.
   */
  it("reads the address the server's Overview links to", () => {
    const state = readCaseViewState("?view=cases&lane=agent_actions&window=7d");
    expect(state.lane).toBe("agent_actions");
    expect(state.window).toBe("7d");
  });

  /**
   * No lane in the address is not "every case": the screen then picks the
   * default lane. So an empty lane writes nothing, and every case is written
   * as its own word.
   */
  it("writes the lane when chosen and nothing when the screen is to pick", () => {
    const base = "https://dashboard.test/?view=overview";
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "agent_messages" }, base).searchParams.get("lane")).toBe("agent_messages");
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "everything" }, base).searchParams.get("lane")).toBe("everything");
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "" }, `${base}&lane=server_attacks`).searchParams.has("lane")).toBe(false);
    const back = readCaseViewState(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "server_attacks", status: "waiting" }, base).search);
    expect(back.lane).toBe("server_attacks");
    expect(back.status).toBe("waiting");
  });
});

/**
 * A count with no span was how a reader compared 4 on the Overview (7 days)
 * with 2 here (24 hours) and read it as lost data. With the list's window
 * handed in, every count carries it, on screen and aloud, and the window can
 * be changed from beside the counts it changes.
 */
describe("the span beside each count", () => {
  it("prints the window next to every tab count, and names it aloud", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" counts={serverCounts} onChange={noop} window="7d" />);
    expect(html.match(/ · 7 days<\/span>/g)).toHaveLength(3);
    expect(html).toContain('aria-label="Attacks on this server, 3 cases in the last 7 days"');
    expect(html).toContain('aria-label="What your AI agent did, 1 session in the last 7 days"');
  });

  /**
   * The agent's Overview card counts commands, and its tab lists one case per
   * session. With the unit said only aloud, the badge read "4 · 7 days" under
   * a card reading 7, and a reader took the two for one count that had lost
   * three. Each badge names what it counts.
   *
   * FAILS ON REVERT: print the number alone and "1 · 7 days" is back.
   */
  it("names each count's unit in the badge, the lane's own", () => {
    const html = renderToStaticMarkup(
      <CaseLaneTabs value="agent_actions" counts={{ agent_messages: 1, agent_actions: 4, server_attacks: 2_435, other: 2 }} onChange={noop} window="all" />,
    );
    expect(html).toContain(">1 message<span");
    expect(html).toContain(">4 sessions<span");
    expect(html).toContain(">2,435 cases<span");
    expect(html.match(/ · all time<\/span>/g)).toHaveLength(3);
    expect(laneTabCount("everything", 1)).toBe("1 case");
    expect(laneTabCount("agent_actions", 1)).toBe("1 session");
  });

  it("offers a visible window control only with a window and a way to change it", () => {
    const picked: string[] = [];
    const withControl = renderToStaticMarkup(
      <CaseLaneTabs value="agent_actions" counts={serverCounts} onChange={noop} window="24h" onWindowChange={(next) => picked.push(next)} />,
    );
    expect(withControl).toContain("Time window");
    expect(withControl).toMatch(/<option value="24h" selected="">Last 24 hours<\/option>/);
    expect(withControl.match(/<option /g)).toHaveLength(5);
    expect(renderToStaticMarkup(<CaseLaneTabs value="agent_actions" counts={serverCounts} onChange={noop} window="24h" />)).not.toContain("Time window");
  });

  /**
   * An older Cases screen passes no window, and its tabs read as they did:
   * the counts alone, and no control.
   */
  it("draws the counts alone when the screen passes no window", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent_actions" counts={serverCounts} onChange={noop} />);
    expect(html).not.toContain(" · ");
    expect(html).not.toContain("Time window");
    expect(html).toContain('aria-label="Attacks on this server, 3 cases"');
  });
});
