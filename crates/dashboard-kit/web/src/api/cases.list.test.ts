import { describe, expect, it } from "vitest";
import { DashboardCasesClient } from "./cases";

/**
 * The status filter reaches the host as `?status=`, bounded like the others,
 * and is absent from the request when it is clear, so a request with no
 * status is byte-identical to the one an older shell sent.
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
