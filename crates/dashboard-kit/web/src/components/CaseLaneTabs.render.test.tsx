import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { CaseLaneTabs, laneIntro, laneTabs, nextLaneTab } from "./CaseLaneTabs";
import { caseViewUrl, EMPTY_CASE_VIEW, readCaseViewState } from "./CaseFilters";
import { setTechnicalDetail } from "./TechnicalDetail";

/**
 * The lane tabs a Cases screen draws once the host has said it files cases
 * into lanes (its list answer carried `lane_counts`). RENDERED, and the
 * keyboard rule is a pure function the handler calls.
 */

afterEach(() => setTechnicalDetail(false));

const noop = () => undefined;

describe("the tab row", () => {
  it("offers the three lanes, named the way the operator names them, with the host's counts", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent" counts={{ prompt: 3, agent: 1, host: 823 }} onChange={noop} panelId="case-list" />);
    expect(html).toContain('role="tablist"');
    expect(html.match(/role="tab"/g)).toHaveLength(3);
    expect(html).toContain("Messages to your AI agent");
    expect(html).toContain("What your AI agent did");
    expect(html).toContain("Attacks on this server");
    expect(html).toContain(">823</span>");
    expect(html).toContain('aria-label="Attacks on this server, 823 cases"');
    expect(html).toContain('aria-label="What your AI agent did, 1 case"');
    expect(html).toContain('aria-controls="case-list"');
  });

  it("marks the open lane selected and says what it lists", () => {
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent" onChange={noop} />);
    expect(html).toMatch(/aria-selected="true"[^>]*data-lane="agent"/);
    expect(html.match(/aria-selected="true"/g)).toHaveLength(1);
    expect(html).toContain("Every command your AI agent tried to run");
    // One tab stop for the whole row, on the open tab.
    expect(html.match(/tabindex="0"/gi)).toHaveLength(1);
  });

  /**
   * THE RULE THIS PINS: a count the host did not send is no badge, not a
   * zero. A lane it counted at zero says zero.
   *
   * FAILS ON REVERT: render `counts?.[lane] ?? 0` and the prompt tab below
   * claims zero messages on a host that never counted them.
   */
  it("draws no badge for a lane the host did not count, and a zero for one it counted at zero", () => {
    const tabs = laneTabs("agent", { agent: 0 }, false);
    expect(tabs.find((tab) => tab.choice === "prompt")?.count).toBeUndefined();
    expect(tabs.find((tab) => tab.choice === "agent")?.count).toBe(0);
    const html = renderToStaticMarkup(<CaseLaneTabs value="agent" counts={{ agent: 0 }} onChange={noop} />);
    expect(html.match(/tabular-nums/g)).toHaveLength(1);
    expect(renderToStaticMarkup(<CaseLaneTabs value="agent" onChange={noop} />)).not.toContain("tabular-nums");
  });

  /**
   * "Everything" lists raw telemetry and bookkeeping beside the lanes: a
   * technical question, offered in the technical view, or when a shared link
   * already opened it, so the open tab is always on screen.
   */
  it("offers every case only in the technical view, or when it is the open tab", () => {
    expect(renderToStaticMarkup(<CaseLaneTabs value="host" onChange={noop} />)).not.toContain(">Everything<");
    setTechnicalDetail(true);
    expect(renderToStaticMarkup(<CaseLaneTabs value="host" onChange={noop} />)).toContain(">Everything<");
    setTechnicalDetail(false);
    const opened = renderToStaticMarkup(<CaseLaneTabs value="everything" onChange={noop} />);
    expect(opened).toMatch(/aria-selected="true"[^>]*data-lane="everything"/);
    expect(opened).toContain("belong to none of the three lanes");
    expect(laneIntro("everything")).toContain("raw telemetry");
  });
});

describe("the keyboard", () => {
  const tabs = laneTabs("agent", undefined, true);

  it("moves with the arrows, wrapping at the ends, and jumps with Home and End", () => {
    expect(nextLaneTab(tabs, "agent", "ArrowRight")).toBe("host");
    expect(nextLaneTab(tabs, "agent", "ArrowLeft")).toBe("prompt");
    expect(nextLaneTab(tabs, "prompt", "ArrowLeft")).toBe("everything");
    expect(nextLaneTab(tabs, "everything", "ArrowRight")).toBe("prompt");
    expect(nextLaneTab(tabs, "host", "Home")).toBe("prompt");
    expect(nextLaneTab(tabs, "prompt", "End")).toBe("everything");
  });

  it("moves nothing for any other key", () => {
    for (const key of ["Enter", " ", "Tab", "ArrowDown", "a"]) expect(nextLaneTab(tabs, "agent", key)).toBeUndefined();
    expect(nextLaneTab([], "agent", "ArrowRight")).toBeUndefined();
  });
});

describe("the lane in the address bar", () => {
  it("reads each lane, and every case, and drops anything else", () => {
    for (const lane of ["prompt", "agent", "host", "everything"]) {
      expect(readCaseViewState(`?view=cases&lane=${lane}`).lane).toBe(lane);
    }
    for (const junk of ["network", "AGENT", "", "all"]) {
      expect(readCaseViewState(`?view=cases&lane=${encodeURIComponent(junk)}`).lane).toBe("");
    }
    expect(readCaseViewState("?view=cases").lane).toBe("");
  });

  /**
   * No lane in the address is not "every case": the screen then picks the
   * default lane. So an empty lane writes nothing, and every case is written
   * as its own word.
   */
  it("writes the lane when chosen and nothing when the screen is to pick", () => {
    const base = "https://dashboard.test/?view=overview";
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "prompt" }, base).searchParams.get("lane")).toBe("prompt");
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "everything" }, base).searchParams.get("lane")).toBe("everything");
    expect(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "" }, `${base}&lane=host`).searchParams.has("lane")).toBe(false);
    const back = readCaseViewState(caseViewUrl({ ...EMPTY_CASE_VIEW, lane: "host", status: "waiting" }, base).search);
    expect(back.lane).toBe("host");
    expect(back.status).toBe("waiting");
  });
});
