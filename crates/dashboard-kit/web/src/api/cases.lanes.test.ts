import { describe, expect, it } from "vitest";

import { DashboardCasesClient, parseCaseListPage, parseLaneCounts } from "./cases";
import lanesPage from "../../tests/fixtures/enterprise/cases-page-lanes.json";

/**
 * Lanes on the case list: the `lane` filter, the `lane_counts` beside a page,
 * and what the client does with a server that has never heard of either.
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
const UNKNOWN_PARAMETER: Answer = {
  status: 400,
  body: { code: "enterprise_cases_query_invalid", message: "The cases query contains an unknown or malformed parameter.", retryable: false },
};

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

/** A server that files cases into lanes and knows every `include` name. */
const lanesServer = (url: URL): Answer => ({
  status: 200,
  body: {
    ...PAGE,
    ...(includes(url).includes("rows_in_window") ? { rows_in_window: 0 } : {}),
    ...(includes(url).includes("lane_counts") ? { lane_counts: { prompt: 1, agent: 2, host: 3 } } : {}),
  },
});

/** A server from before lanes: `lane` and `lane_counts` are unknown to it. */
const beforeLanes = (url: URL): Answer =>
  url.searchParams.has("lane") || includes(url).some((name) => name !== "rows_in_window")
    ? UNKNOWN_PARAMETER
    : { status: 200, body: { ...PAGE, ...(includes(url).includes("rows_in_window") ? { rows_in_window: 0 } : {}) } };

describe("the lane counts beside a page", () => {
  it("are read from a page that carries them", () => {
    const page = parseCaseListPage(lanesPage, 20);
    expect(page.lane_counts).toEqual({ prompt: 3, agent: 1, host: 823 });
  });

  /**
   * THE RULE THIS PINS: the list envelope is parsed with an exact key list,
   * and a key it does not know blanks the whole Cases screen. `lane_counts`
   * is on the list, so a server that sends it does not.
   *
   * FAILS ON REVERT: drop `lane_counts` from the envelope's key list and this
   * page is refused outright.
   */
  it("do not trip the exact envelope", () => {
    expect(() => parseCaseListPage({ ...PAGE, lane_counts: { agent: 1 } }, 20)).not.toThrow();
    // The rule itself still holds for everything else.
    expect(() => parseCaseListPage({ ...PAGE, lanes: {} }, 20)).toThrow(/unexpected field lanes/);
  });

  /**
   * A bad number costs its tab a badge, never the reader the list.
   */
  it("are read one lane at a time, and a bad one is not sent", () => {
    expect(parseLaneCounts({ prompt: 3, agent: -1, host: 2.5 })).toEqual({ prompt: 3 });
    expect(parseLaneCounts({ prompt: "3", agent: null, host: Number.POSITIVE_INFINITY })).toEqual({});
    expect(parseLaneCounts({ agent: 4, network: 9 })).toEqual({ agent: 4 });
    expect(parseLaneCounts({ agent: -0 })).toEqual({ agent: 0 });
    expect(Object.is(parseLaneCounts({ agent: -0 })?.agent, -0)).toBe(false);
    for (const junk of [undefined, null, 7, "counts", [1, 2, 3]]) {
      expect(parseLaneCounts(junk)).toBeUndefined();
    }
    expect(parseCaseListPage({ ...PAGE, lane_counts: [1, 2] }, 20).lane_counts).toBeUndefined();
  });

  it("are absent from a page that did not carry them, never zero", () => {
    expect("lane_counts" in parseCaseListPage(PAGE, 20)).toBe(false);
  });
});

describe("the lane a request asks for", () => {
  it("is sent with the counts, beside the row total, as one include value", async () => {
    const { seen, client } = server(lanesServer);
    const result = await client.list({ lane: "agent", lane_counts: true, window: "24h" });
    if (result.state !== "ready") throw new Error("unreachable");
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.get("lane")).toBe("agent");
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window,lane_counts");
    expect(seen[0].searchParams.get("window")).toBe("24h");
    expect(result.data.lane_counts).toEqual({ prompt: 1, agent: 2, host: 3 });
  });

  it("asks for the counts alone on the everything tab", async () => {
    const { seen, client } = server(lanesServer);
    await client.list({ lane: "", lane_counts: true });
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window,lane_counts");
  });

  /**
   * A request that asks for no lane is the request it was before lanes: the
   * row total and nothing else, so an older server sees nothing new.
   */
  it("changes nothing for a screen that asks for no lane", async () => {
    const { seen, client } = server(lanesServer);
    await client.list({ status: "waiting" });
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.getAll("include")).toEqual(["rows_in_window"]);
  });

  it("never sends a lane this bundle does not know", async () => {
    const { seen, client } = server(lanesServer);
    await client.list({ lane: "network" as never });
    expect(seen[0].searchParams.has("lane")).toBe(false);
  });
});

describe("a paid server older than lanes", () => {
  /**
   * THE RULE THIS PINS: an older server refuses `lane` as an unknown
   * parameter. The client asks again without the lane and without the
   * counts, and the answer it hands back carries no `lane_counts`, which is
   * how the screen knows to stop offering lanes. It is the unfiltered list,
   * and never presented as a lane.
   *
   * FAILS ON REVERT: return the refusal instead of asking again and the
   * whole Cases screen fails on every older server.
   */
  it("still gets the list, asked again without the lane, and says no lanes came back", async () => {
    const { seen, client } = server(beforeLanes);
    const result = await client.list({ lane: "agent", lane_counts: true, status: "waiting" });
    if (result.state !== "ready") throw new Error("an older server's list was lost");
    expect("lane_counts" in result.data).toBe(false);
    expect(result.data.rows_in_window).toBe(0);
    expect(seen).toHaveLength(2);
    expect(seen[0].searchParams.get("lane")).toBe("agent");
    expect(seen[1].searchParams.has("lane")).toBe(false);
    expect(seen[1].searchParams.get("include")).toBe("rows_in_window");
    // The same question otherwise.
    expect(seen[1].searchParams.get("status")).toBe("waiting");
  });

  it("stops asking for lanes once the narrower request has been answered", async () => {
    const { seen, client } = server(beforeLanes);
    await client.list({ lane: "agent", lane_counts: true });
    seen.length = 0;
    await client.list({ lane: "host", lane_counts: true });
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.has("lane")).toBe(false);
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
  });

  /** Older still: neither lanes nor the row total. Three asks, then one. */
  it("walks down to the plain request on a server that knows neither", async () => {
    const { seen, client } = server((url) => (url.searchParams.has("lane") || url.searchParams.has("include") ? UNKNOWN_PARAMETER : { status: 200, body: PAGE }));
    const first = await client.list({ lane: "agent", lane_counts: true });
    expect(first.state).toBe("ready");
    expect(seen).toHaveLength(3);
    expect(seen[2].searchParams.has("include")).toBe(false);
    seen.length = 0;
    await client.list({ lane: "agent", lane_counts: true });
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.toString()).toBe("limit=20");
  });

  it("learns nothing from refusals all the way down", async () => {
    const { seen, client } = server(() => UNKNOWN_PARAMETER);
    const result = await client.list({ lane: "agent", lane_counts: true });
    if (result.state === "ready") throw new Error("a refused request was answered");
    expect(seen).toHaveLength(3);
    seen.length = 0;
    await client.list({ lane: "agent", lane_counts: true });
    expect(seen[0].searchParams.get("lane")).toBe("agent");
  });

  /** A refusal with another code is about the request, and is not retried. */
  it("does not retry a refused lane value", async () => {
    const { seen, client } = server(() => ({ status: 400, body: { code: "enterprise_cases_filter_invalid", message: "bad lane", retryable: false } }));
    const result = await client.list({ lane: "agent", lane_counts: true });
    if (result.state === "ready") throw new Error("a refused request was answered");
    expect(result.problem.code).toBe("enterprise_cases_filter_invalid");
    expect(seen).toHaveLength(1);
  });
});
