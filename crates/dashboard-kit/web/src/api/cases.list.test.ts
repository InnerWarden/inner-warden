import { describe, expect, it } from "vitest";
import { DashboardCasesClient } from "./cases";

/**
 * The status filter reaches the host as `?status=`, bounded like the others,
 * and is absent from the request when it is clear, as it was before the
 * filter existed.
 */
async function requestedUrl(query: Parameters<DashboardCasesClient["list"]>[0]): Promise<URL> {
  let seen: string | undefined;
  const fetchImplementation = (async (input: RequestInfo | URL) => {
    seen = String(input);
    return new Response("{}", { status: 503, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  await new DashboardCasesClient(fetchImplementation).list(query);
  if (seen === undefined) throw new Error("the client never called fetch");
  return new URL(seen, "https://dashboard.test/");
}

describe("the case list request carries the status filter", () => {
  it("sends the queue the Overview link asks for", async () => {
    const url = await requestedUrl({ status: "waiting", window: "all" });
    expect(url.searchParams.get("status")).toBe("waiting");
    expect(url.searchParams.get("window")).toBe("all");
  });

  it("sends nothing for a clear status", async () => {
    for (const status of ["", undefined]) {
      const url = await requestedUrl({ status });
      expect(url.searchParams.has("status")).toBe(false);
    }
  });

  it("drops a status longer than the host would accept rather than sending it", async () => {
    const url = await requestedUrl({ status: "x".repeat(33) });
    expect(url.searchParams.has("status")).toBe(false);
  });
});

/**
 * The case total counts cases before the recurrence fold and the pages walk
 * rows after it, so the only honest "of M" for a page is the row total. The
 * paid server sends it only when asked, so every list request asks, whatever
 * else it carries.
 */
describe("the case list request asks for the row total", () => {
  it("asks on a bare request and on a filtered, windowed, paged one", async () => {
    for (const query of [undefined, {}, { status: "waiting", window: "all" as const, cursor: "opaque-page-2", limit: 50 }]) {
      const url = await requestedUrl(query);
      expect(url.pathname).toBe("/api/dashboard/v1/cases");
      expect(url.searchParams.getAll("include")).toEqual(["rows_in_window"]);
    }
  });

  it("keeps the filters beside it rather than replacing them", async () => {
    const url = await requestedUrl({ severity: "high", window: "7d" });
    expect(url.searchParams.get("severity")).toBe("high");
    expect(url.searchParams.get("window")).toBe("7d");
    expect(url.searchParams.get("limit")).toBe("20");
  });
});

/**
 * A paid server older than `rows_in_window` refuses `include` as an unknown
 * parameter: 400 `enterprise_cases_query_invalid`, not retryable. Sent on
 * every list request, that refusal failed the whole Cases screen. On exactly
 * that refusal the client asks once more without it, and once the plain
 * request is answered it stops asking.
 *
 * The server is a fake `fetch` that answers by what the request carries.
 */
type Answer = { status: number; body: unknown };

const PAGE = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: "2026-09-24T08:00:00Z",
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

/** A server that predates `include`: it refuses the name, and serves the rest. */
const olderServer = (url: URL): Answer =>
  url.searchParams.has("include") ? UNKNOWN_PARAMETER : { status: 200, body: PAGE };

describe("a paid server older than the row total", () => {
  it("still gets a page, asked again without the parameter it refused", async () => {
    const { seen, client } = server(olderServer);
    const result = await client.list({ status: "waiting", window: "7d", limit: 50 });
    expect(result.state).toBe("ready");
    if (result.state !== "ready") throw new Error("unreachable");
    // No row total came back, so the page says none, never zero.
    expect("rows_in_window" in result.data).toBe(false);
    expect(seen).toHaveLength(2);
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
    expect(seen[1].searchParams.has("include")).toBe(false);
    // The second request is the same question, less the one parameter.
    const rest = new URLSearchParams(seen[0].searchParams);
    rest.delete("include");
    expect(seen[1].searchParams.toString()).toBe(rest.toString());
  });

  it("stops asking once the plain request has been answered", async () => {
    const { seen, client } = server(olderServer);
    await client.list();
    seen.length = 0;
    const next = await client.list({ cursor: "opaque-page-2" });
    expect(next.state).toBe("ready");
    expect(seen).toHaveLength(1);
    expect(seen[0].searchParams.has("include")).toBe(false);
    expect(seen[0].searchParams.get("cursor")).toBe("opaque-page-2");
  });

  /**
   * Two refusals in a row mean the parameter was not what the server refused,
   * so nothing is learned: the refusal is reported and the next call asks for
   * the row total again.
   */
  it("reports a refusal the plain request gets too, and learns nothing from it", async () => {
    const { seen, client } = server(() => UNKNOWN_PARAMETER);
    const result = await client.list();
    if (result.state === "ready") throw new Error("a refused request was answered");
    expect(result.problem.httpStatus).toBe(400);
    expect(result.problem.code).toBe("enterprise_cases_query_invalid");
    expect(seen).toHaveLength(2);
    seen.length = 0;
    await client.list();
    expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
  });

  /**
   * Only the unknown-parameter refusal is retried. Every other refusal has its
   * own code, and sending the same filter again would get the same answer.
   */
  it("does not retry any other refusal", async () => {
    const answers: Answer[] = [
      { status: 400, body: { code: "enterprise_cases_filter_invalid", message: "bad filter", retryable: false } },
      { status: 400, body: { code: "enterprise_cases_window_invalid", message: "bad window", retryable: false } },
      // The same code on another status is not the refusal of a parameter.
      // 500 reads as the same "error" state a 400 does, so only the status
      // tells them apart.
      { status: 500, body: { code: "enterprise_cases_query_invalid", message: "same code, not a 400", retryable: false } },
      { status: 503, body: { code: "enterprise_cases_query_invalid", message: "same code, not a 400", retryable: true } },
      { status: 404, body: {} },
    ];
    for (const answer of answers) {
      const { seen, client } = server(() => answer);
      const result = await client.list();
      if (result.state === "ready") throw new Error("a refused request was answered");
      expect(result.problem.httpStatus).toBe(answer.status);
      expect(seen).toHaveLength(1);
      expect(seen[0].searchParams.get("include")).toBe("rows_in_window");
    }
  });

  it("asks once and keeps asking against a server that knows the field", async () => {
    const { seen, client } = server(() => ({ status: 200, body: { ...PAGE, rows_in_window: 0 } }));
    const first = await client.list();
    const second = await client.list();
    if (first.state !== "ready" || second.state !== "ready") throw new Error("unreachable");
    expect(first.data.rows_in_window).toBe(0);
    expect(seen).toHaveLength(2);
    for (const url of seen) expect(url.searchParams.get("include")).toBe("rows_in_window");
  });
});
