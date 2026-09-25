import { describe, expect, it } from "vitest";

import { DashboardCasesClient, everythingCount, parseCaseListPage, parseLaneCounts } from "./cases";
// Every page and refusal below was written by the paid server's own tests
// (a store holding one message to the agent, one agent denial and three host
// findings), not by hand: these are the shapes a real host answers with.
import agentActionsPage from "../../tests/fixtures/enterprise/cases-lanes-agent-actions.json";
import agentMessagesPage from "../../tests/fixtures/enterprise/cases-lanes-agent-messages.json";
import everythingPage from "../../tests/fixtures/enterprise/cases-lanes-everything.json";
import refusals from "../../tests/fixtures/enterprise/cases-lanes-refusals.json";
import serverAttacksPage from "../../tests/fixtures/enterprise/cases-lanes-server-attacks.json";

/**
 * Lanes on the case list: the `lane` filter, the `lane_counts` beside a page,
 * whether the answer is a lane at all, and what the client does with a server
 * that has never heard of either.
 *
 * The server is a fake `fetch` that answers by what the request carries; no
 * test here reaches a network.
 */

type Answer = { status: number; body: unknown };

const PAGE = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: "2026-09-25T10:20:00Z",
  items: [],
  next_cursor: null,
};
/** The server's answer to a query parameter or `include` name it does not know. */
const UNKNOWN_PARAMETER: Answer = { status: 400, body: refusals.refused_include_name.body };
/** The server's answer to a `lane` value that is not one of its three. */
const UNKNOWN_LANE: Answer = { status: 400, body: refusals.refused_lane_value.body };

function server(answer: (url: URL) => Answer) {
  const seen: URL[] = [];
  const fetchImplementation = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "https://dashboard.test/");
    seen.push(url);
    const { status, body } = answer(url);
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { seen, client: new DashboardCasesClient(fetchImplementation) };
}

const includes = (url: URL) => (url.searchParams.get("include") ?? "").split(",").filter((name) => name.length > 0);

const PAGES: Record<string, Record<string, unknown>> = {
  "": everythingPage,
  agent_messages: agentMessagesPage,
  agent_actions: agentActionsPage,
  server_attacks: serverAttacksPage,
};

/**
 * A server that files cases into lanes, answering the way the real one does:
 * its own page for each lane, the counts and the row total only when named,
 * any other lane refused as a filter and any other `include` name refused.
 */
const lanesServer = (url: URL): Answer => {
  const lane = url.searchParams.get("lane") ?? "";
  const page = PAGES[lane];
  if (page === undefined) return UNKNOWN_LANE;
  const names = includes(url);
  if (names.some((name) => !["rows_in_window", "lane_counts", "item_lane"].includes(name))) return UNKNOWN_PARAMETER;
  const { lane_counts: counts, rows_in_window: rows, ...rest } = page;
  return {
    status: 200,
    body: {
      ...rest,
      ...(names.includes("rows_in_window") ? { rows_in_window: rows } : {}),
      ...(names.includes("lane_counts") ? { lane_counts: counts } : {}),
    },
  };
};

/**
 * A paid server from before lanes, as the one live today answers: `lane` is
 * an unknown parameter, and `rows_in_window` is the only `include` it serves.
 */
const beforeLanes = (url: URL): Answer =>
  url.searchParams.has("lane") || includes(url).some((name) => name !== "rows_in_window")
    ? UNKNOWN_PARAMETER
    : { status: 200, body: { ...PAGE, ...(includes(url).includes("rows_in_window") ? { rows_in_window: 0 } : {}) } };

describe("the lane counts beside a page", () => {
  /**
   * THE DEFECT THIS PINS: the kit read `prompt`, `agent` and `host`, and the
   * server counts `agent_messages`, `agent_actions`, `server_attacks` and
   * `other`. Every real page parsed to empty counts, so every tab lost its
   * badge.
   *
   * FAILS ON REVERT: read the old names and these counts are gone.
   */
  it("are read from the page the server sends, under its own names", () => {
    const page = parseCaseListPage(agentActionsPage, 20);
    expect(page.lane_counts).toEqual({ agent_messages: 1, agent_actions: 1, server_attacks: 3, other: 2 });
  });

  /** The four add up to every case the same request holds without a lane. */
  it("add up to the list without a lane, which is the everything badge", () => {
    const counts = parseCaseListPage(everythingPage, 20).lane_counts;
    expect(everythingCount(counts)).toBe(everythingPage.total_in_window);
    // A part missing is no total: a smaller number presented as the whole.
    const { other: _other, ...three } = counts ?? {};
    expect(everythingCount(three)).toBeUndefined();
    expect(everythingCount(undefined)).toBeUndefined();
  });

  /**
   * THE RULE THIS PINS: the list envelope is parsed with an exact key list,
   * and a key it does not know blanks the whole Cases screen. `lane_counts`
   * is on the list, so a server that sends it does not, and the client's own
   * `lane_filter` is NOT, so no server can claim a lane was applied.
   *
   * FAILS ON REVERT: drop `lane_counts` from the envelope's key list and this
   * page is refused outright.
   */
  it("do not trip the exact envelope, and the client's own mark cannot come from the wire", () => {
    expect(() => parseCaseListPage({ ...PAGE, lane_counts: { agent_actions: 1 } }, 20)).not.toThrow();
    expect(() => parseCaseListPage({ ...PAGE, lanes: {} }, 20)).toThrow(/unexpected field lanes/);
    expect(() => parseCaseListPage({ ...PAGE, lane_filter: { served: true, lane: "agent_actions" } }, 20)).toThrow(/unexpected field lane_filter/);
  });

  /** A bad number costs its tab a badge, never the reader the list. */
  it("are read one key at a time, and a bad one is not sent", () => {
    expect(parseLaneCounts({ agent_messages: 3, agent_actions: -1, server_attacks: 2.5, other: 4 })).toEqual({ agent_messages: 3, other: 4 });
    expect(parseLaneCounts({ agent_actions: 4, network: 9 })).toEqual({ agent_actions: 4 });
    expect(parseLaneCounts({ agent_actions: -0 })).toEqual({ agent_actions: 0 });
    expect(Object.is(parseLaneCounts({ agent_actions: -0 })?.agent_actions, -0)).toBe(false);
    for (const junk of [undefined, null, 7, "counts", [1, 2, 3]]) {
      expect(parseLaneCounts(junk)).toBeUndefined();
    }
    expect(parseCaseListPage({ ...PAGE, lane_counts: [1, 2] }, 20).lane_counts).toBeUndefined();
  });

  /**
   * THE RULE THIS PINS: counts with nothing readable in them are not sent.
   * An empty object counted as PRESENT, so a screen drew tabs with no badges
   * and chose its opening lane from counts that said nothing.
   *
   * FAILS ON REVERT: return `{}` for an object with no known key and these
   * read as counts.
   */
  it("are not sent when nothing in them names a lane this bundle knows", () => {
    expect(parseLaneCounts({})).toBeUndefined();
    expect(parseLaneCounts({ prompt: 1, agent: 2, host: 3 })).toBeUndefined();
    expect(parseLaneCounts({ agent_actions: "2", server_attacks: null })).toBeUndefined();
    expect("lane_counts" in parseCaseListPage({ ...PAGE, lane_counts: { prompt: 1 } }, 20)).toBe(false);
  });

  it("are absent from a page that did not carry them, never zero", () => {
    expect("lane_counts" in parseCaseListPage(PAGE, 20)).toBe(false);
  });
});

describe("the lane a request asks for", () => {
  it("is sent with the counts, beside the row total, as one include value", async () => {
    const { seen, client } = server(lanesServer);
    const result = await client.list({ lane: "agent_actions", lane_counts: true, window: "7d" });
    if (result.state !== "ready") throw new Error(`a lane request failed: ${JSON.stringify(result)}`);
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.get("lane")).toBe("agent_actions");
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window,lane_counts");
    expect(seen[0].searchParams.get("window")).toBe("7d");
    expect(result.data.lane_counts).toEqual({ agent_messages: 1, agent_actions: 1, server_attacks: 3, other: 2 });
    expect(result.data.items.map((item) => item.title)).toEqual([agentActionsPage.items[0].title]);
    expect(result.data.lane_filter).toEqual({ served: true, lane: "agent_actions" });
  });

  /**
   * THE DEFECT THIS PINS: the kit sent `lane=agent`, which the server
   * refuses as a filter and the client does not retry, so the Cases list
   * failed on every lane tab. Each lane goes as the server spells it, and is
   * answered.
   *
   * FAILS ON REVERT: send any other spelling and the server refuses it.
   */
  it("goes as the server spells it, and every lane is answered", async () => {
    for (const lane of ["agent_messages", "agent_actions", "server_attacks"] as const) {
      const { seen, client } = server(lanesServer);
      const result = await client.list({ lane, lane_counts: true, window: "7d" });
      expect(result.state, lane).toBe("ready");
      expect(seen).toHaveLength(1);
      expect(seen[0].searchParams.get("lane")).toBe(lane);
    }
  });

  it("asks for the counts alone on the everything tab, and says the rows are every case", async () => {
    const { seen, client } = server(lanesServer);
    const result = await client.list({ lane: "", lane_counts: true });
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window,lane_counts");
    if (result.state !== "ready") throw new Error("unreachable");
    expect(result.data.lane_filter).toEqual({ served: true, lane: null });
  });

  /**
   * The counts force the host's full read, so a screen polls a lane without
   * them. That answer is still the lane, and says so.
   */
  it("marks a lane polled without its counts as that lane", async () => {
    const { seen, client } = server(lanesServer);
    const result = await client.list({ lane: "agent_actions", window: "7d" });
    expect(seen[0].searchParams.get("lane")).toBe("agent_actions");
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
    if (result.state !== "ready") throw new Error("unreachable");
    expect("lane_counts" in result.data).toBe(false);
    expect(result.data.lane_filter).toEqual({ served: true, lane: "agent_actions" });
  });

  /**
   * A request that asks for no lane is the request it was before lanes: the
   * row total and nothing else, so an older server sees nothing new, and the
   * answer claims nothing about lanes either way.
   */
  it("changes nothing for a screen that asks for no lane", async () => {
    const { seen, client } = server(lanesServer);
    const result = await client.list({ status: "waiting" });
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.getAll("include")).toEqual(["rows_in_window"]);
    if (result.state !== "ready") throw new Error("unreachable");
    expect("lane_filter" in result.data).toBe(false);
  });

  it("never sends a lane this bundle does not know", async () => {
    for (const unknown of ["network", "agent", "prompt", "host"]) {
      const { seen, client } = server(lanesServer);
      const result = await client.list({ lane: unknown as never });
      expect(seen[0].searchParams.has("lane"), unknown).toBe(false);
      expect(result.state, unknown).toBe("ready");
    }
  });
});

describe("a paid server older than lanes", () => {
  /**
   * THE RULE THIS PINS: an older server refuses `lane` as an unknown
   * parameter. The client asks again without the lane and without the
   * counts, and the answer it hands back says the lane was NOT served: it is
   * the unfiltered list, and never presented as a lane.
   *
   * FAILS ON REVERT: return the refusal instead of asking again and the
   * whole Cases screen fails on every older server.
   */
  it("still gets the list, asked again without the lane, and says the lane was not served", async () => {
    const { seen, client } = server(beforeLanes);
    const result = await client.list({ lane: "agent_actions", lane_counts: true, status: "waiting" });
    if (result.state !== "ready") throw new Error("an older server's list was lost");
    expect("lane_counts" in result.data).toBe(false);
    expect(result.data.lane_filter).toEqual({ served: false });
    expect(result.data.rows_in_window).toBe(0);
    expect(seen).toHaveLength(2);
    expect(seen[0].searchParams.get("lane")).toBe("agent_actions");
    expect(seen[1].searchParams.has("lane")).toBe(false);
    expect(seen[1].searchParams.get("include")).toBe("rows_in_window");
    // The same question otherwise.
    expect(seen[1].searchParams.get("status")).toBe("waiting");
  });

  /**
   * THE DEFECT THIS PINS: the only sign a lane was applied was the presence
   * of `lane_counts`. A lane polled WITHOUT the counts, against a server that
   * refuses lanes, came back as the unfiltered list looking exactly like a
   * lane's answer, so a screen showed every case under a lane's tab.
   *
   * FAILS ON REVERT: drop the mark and this answer is indistinguishable from
   * the lane.
   */
  it("marks the unfiltered list as not the lane even when no counts were asked for", async () => {
    const { client } = server(beforeLanes);
    const result = await client.list({ lane: "agent_actions", window: "7d" });
    if (result.state !== "ready") throw new Error("an older server's list was lost");
    expect(result.data.lane_filter).toEqual({ served: false });
    // And on every later poll, once the client has stopped asking.
    const again = await client.list({ lane: "agent_actions", window: "7d" });
    if (again.state !== "ready") throw new Error("unreachable");
    expect(again.data.lane_filter).toEqual({ served: false });
  });

  it("stops asking for lanes once the narrower request has been answered", async () => {
    const { seen, client } = server(beforeLanes);
    await client.list({ lane: "agent_actions", lane_counts: true });
    seen.length = 0;
    await client.list({ lane: "server_attacks", lane_counts: true });
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
  });

  /** Older still: neither lanes nor the row total. Three asks, then one. */
  it("walks down to the plain request on a server that knows neither", async () => {
    const { seen, client } = server((url) => (url.searchParams.has("lane") || url.searchParams.has("include") ? UNKNOWN_PARAMETER : { status: 200, body: PAGE }));
    const first = await client.list({ lane: "agent_actions", lane_counts: true });
    if (first.state !== "ready") throw new Error("unreachable");
    expect(first.data.lane_filter).toEqual({ served: false });
    expect(seen).toHaveLength(3);
    expect(seen[2].searchParams.has("include")).toBe(false);
    seen.length = 0;
    await client.list({ lane: "agent_actions", lane_counts: true });
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.toString()).toBe("limit=20");
  });

  it("learns nothing from refusals all the way down", async () => {
    const { seen, client } = server(() => UNKNOWN_PARAMETER);
    const result = await client.list({ lane: "agent_actions", lane_counts: true });
    if (result.state === "ready") throw new Error("a refused request was answered");
    expect(seen).toHaveLength(3);
    seen.length = 0;
    await client.list({ lane: "agent_actions", lane_counts: true });
    expect(seen[0].searchParams.get("lane")).toBe("agent_actions");
  });

  /** A refusal with another code is about the request, and is not retried. */
  it("does not retry a refused lane value", async () => {
    const { seen, client } = server(() => UNKNOWN_LANE);
    const result = await client.list({ lane: "agent_actions", lane_counts: true });
    if (result.state === "ready") throw new Error("a refused request was answered");
    expect(result.problem.code).toBe("enterprise_cases_filter_invalid");
    expect(seen).toHaveLength(1);
  });
});
