import { describe, expect, it, vi } from "vitest";
import { DashboardV1Client, retainDashboardResource, type DashboardResource } from "./client";
import { DashboardCasesClient } from "./cases";

const bootstrap = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: "2026-07-18T12:00:00Z",
  edition: "community",
  product_version: "0.16.4",
  community_contract: {
    id: "CJC-090",
    version: "CJC-090-v1",
    canonicalization: "RAW-UTF8-BYTES-SHA256",
    digest: `sha256:${"a".repeat(64)}`,
  },
  assurance_matrix: null,
  authorization_matrix: null,
  platform: { os: "linux", architecture: "x86_64", enterprise_candidate: true, reason_code: null },
  session: { authenticated: false, actor_id: null, role: null, scopes: [] },
  capabilities: [],
  highest_priority_gap: null,
  privacy: { storage: [], redactions: [], egress: [] },
};

function jsonResponse(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

describe("DashboardV1Client", () => {
  it("uses only the typed same-origin v1 path and browser credentials", async () => {
    const fetcher = vi.fn(async () => jsonResponse(bootstrap));
    const client = new DashboardV1Client(fetcher as typeof fetch);

    await expect(client.getBootstrap()).resolves.toMatchObject({ state: "ready", data: { edition: "community" } });
    expect(fetcher).toHaveBeenCalledWith("/api/dashboard/v1/bootstrap", expect.objectContaining({
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    }));
  });

  it.each([
    [401, "authentication_required"],
    [403, "forbidden"],
    [404, "unavailable"],
    [409, "conflict"],
    [503, "unavailable"],
    [501, "unsupported"],
    [429, "rate_limited"],
    [500, "error"],
  ] as const)("maps HTTP %s to an explicit %s state", async (status, state) => {
    const client = new DashboardV1Client(vi.fn(async () => jsonResponse({
      schema_version: "innerwarden.dashboard.v1",
      code: "fixture_problem",
      message: "Fixture adapter state",
      retryable: status >= 500 || status === 429,
    }, status, status === 429 ? { "retry-after": "7" } : undefined)) as typeof fetch);

    await expect(client.getPosture()).resolves.toMatchObject({
      state,
      problem: {
        endpoint: "posture",
        httpStatus: status,
        code: "fixture_problem",
        retryAfterSeconds: status === 429 ? 7 : null,
      },
    });
  });

  it("separates an unreachable adapter from a malformed successful contract", async () => {
    const offline = new DashboardV1Client(vi.fn(async () => { throw new TypeError("offline detail"); }) as typeof fetch);
    await expect(offline.getAgents()).resolves.toMatchObject({
      state: "unavailable",
      problem: { code: "network_unavailable", httpStatus: null },
    });

    const malformed = new DashboardV1Client(vi.fn(async () => jsonResponse({ edition: "enterprise" })) as typeof fetch);
    await expect(malformed.getBootstrap()).resolves.toMatchObject({
      state: "error",
      problem: { code: "contract_validation_failed", httpStatus: 200 },
    });
  });

  it("loads token intelligence only from the typed same-origin v1 route", async () => {
    const payload = {
      schema_version: "innerwarden.dashboard.v1",
      generated_at: "2026-07-18T12:00:00Z",
      availability: "unsupported",
      scope: "no_supported_history",
      totals: null,
      providers: [],
    };
    const fetcher = vi.fn(async () => jsonResponse(payload));
    const client = new DashboardV1Client(fetcher as typeof fetch);

    await expect(client.getTokenIntelligence()).resolves.toMatchObject({
      state: "ready",
      data: { availability: "unsupported", totals: null },
    });
    expect(fetcher).toHaveBeenCalledWith("/api/dashboard/v1/token-intelligence", expect.objectContaining({
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    }));
  });

  it("retains only validated data and marks it stale after refresh failure", () => {
    const previous: DashboardResource<typeof bootstrap> = { state: "ready", data: bootstrap };
    expect(retainDashboardResource(previous, {
      state: "unavailable",
      problem: {
        endpoint: "bootstrap",
        httpStatus: 503,
        code: "adapter_unavailable",
        message: "Unavailable",
        retryable: true,
        retryAfterSeconds: null,
      },
    })).toMatchObject({ state: "stale", data: bootstrap, problem: { code: "adapter_unavailable" } });
  });
});


/**
 * A request that never answers is a failure, not a wait. The screens poll
 * with an in-flight guard, so one hung request held every later poll back,
 * and Protection went on holding a verification made on a read it could no
 * longer renew.
 *
 * FAILS ON REVERT: fetch without a deadline and these never settle.
 */
describe("a dashboard request that never answers", () => {
  /** A fetch that answers only by rejecting when its signal aborts. */
  function hanging(): typeof fetch {
    return ((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    })) as unknown as typeof fetch;
  }

  it("is reported as unavailable when it runs past the deadline, so the page turns stale", async () => {
    const result = await new DashboardV1Client(hanging(), 20).getPosture();
    expect(result).toMatchObject({ state: "unavailable", problem: { code: "request_timed_out", endpoint: "posture", retryable: true } });
    const previous: DashboardResource<{ n: number }> = { state: "ready", data: { n: 1 } };
    expect(retainDashboardResource(previous, result as never).state).toBe("stale");
    await expect(new DashboardCasesClient(hanging(), 20).get("case:1")).resolves.toMatchObject({ problem: { code: "request_timed_out" } });
  });

  it("still hands the caller's own abort back to the caller", async () => {
    const controller = new AbortController();
    const pending = new DashboardV1Client(hanging(), 10_000).getBootstrap(controller.signal);
    controller.abort("dashboard-unmount");
    await expect(pending).rejects.toBeDefined();
  });

  it("does not time out an answer that arrived in time", async () => {
    const client = new DashboardV1Client((async () => jsonResponse(bootstrap)) as unknown as typeof fetch, 20);
    await expect(client.getBootstrap()).resolves.toMatchObject({ state: "ready" });
  });
});
