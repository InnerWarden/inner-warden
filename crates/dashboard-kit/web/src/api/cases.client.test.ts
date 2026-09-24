import { describe, expect, it, vi } from "vitest";

import { DashboardCasesClient, parseCaseListPage } from "./cases";
import caseAgentHost from "../../tests/fixtures/enterprise/case-agent-host-001.json";
import casesPageOne from "../../tests/fixtures/enterprise/cases-page-1.json";

/**
 * What the Cases client does with each way a request can end: refused before
 * it is sent, unreachable, cancelled, answered with the contract, or answered
 * with something else. The host's answer is handed in as a fake `fetch`; no
 * test here reaches a network.
 */

function answering(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}

function failing(error: unknown) {
  return vi.fn(async () => {
    throw error;
  });
}

function client(fetchImplementation: ReturnType<typeof vi.fn>): DashboardCasesClient {
  return new DashboardCasesClient(fetchImplementation as unknown as typeof fetch);
}

describe("requests the client refuses to send", () => {
  it("refuses a page size outside 1..100 and never asks the host", async () => {
    for (const limit of [0, 101, 1.5]) {
      const fetchImplementation = answering(casesPageOne);
      const result = await client(fetchImplementation).list({ limit });
      expect(result.state).toBe("error");
      if (result.state === "ready") throw new Error("unreachable");
      expect(result.problem.code).toBe("invalid_limit");
      expect(result.problem.retryable).toBe(false);
      expect(fetchImplementation).not.toHaveBeenCalled();
    }
  });

  it("refuses a case id the host could not hold and never asks the host", async () => {
    for (const caseId of ["", "x".repeat(257)]) {
      const fetchImplementation = answering(caseAgentHost);
      const result = await client(fetchImplementation).get(caseId);
      if (result.state === "ready") throw new Error("an invalid id was answered");
      expect(result.problem.code).toBe("invalid_case_id");
      expect(result.problem.endpoint).toBe("case_detail");
      expect(fetchImplementation).not.toHaveBeenCalled();
    }
  });

  /**
   * An id is data from the host, and it lands in a path. Encoded, it stays one
   * path segment and cannot walk to another endpoint.
   */
  it("keeps a case id inside one path segment", async () => {
    const fetchImplementation = answering(caseAgentHost);
    await client(fetchImplementation).get("case/../posture?x=1");
    const [url] = fetchImplementation.mock.calls[0] as unknown as [string];
    expect(url).toBe("/api/dashboard/v1/cases/case%2F..%2Fposture%3Fx%3D1");
  });
});

describe("how an answer comes back", () => {
  it("hands back a page that matches the contract", async () => {
    const result = await client(answering(casesPageOne)).list();
    expect(result.state).toBe("ready");
    if (result.state !== "ready") throw new Error("unreachable");
    expect(result.data).toEqual(parseCaseListPage(casesPageOne, 20));
  });

  it("hands back a case that matches the contract", async () => {
    const result = await client(answering(caseAgentHost)).get("case-agent-host-001");
    expect(result.state).toBe("ready");
    if (result.state !== "ready") throw new Error("unreachable");
    expect(result.data.id).toBe("case-agent-host-001");
  });

  /**
   * A body outside the contract is not rendered with whatever fields happen
   * to parse. It is reported as the contract failure it is, and not retried,
   * because the same host will send the same body again.
   */
  it("refuses a body outside the contract rather than rendering part of it", async () => {
    const result = await client(answering({ ...casesPageOne, total: 3 })).list();
    if (result.state === "ready") throw new Error("a body outside the contract was accepted");
    expect(result.state).toBe("error");
    expect(result.problem.code).toBe("contract_validation_failed");
    expect(result.problem.retryable).toBe(false);
  });

  it("reports a host it could not reach as unavailable, and worth retrying", async () => {
    const result = await client(failing(new TypeError("Failed to fetch"))).list();
    if (result.state === "ready") throw new Error("an unreachable host was answered");
    expect(result.state).toBe("unavailable");
    expect(result.problem.code).toBe("network_unavailable");
    expect(result.problem.retryable).toBe(true);
  });

  /**
   * A request the screen cancelled (the operator changed a filter) must stay
   * cancelled. Turned into "unavailable" it would paint an outage banner over
   * a screen that is working.
   */
  it("lets a cancelled request stay cancelled instead of reporting an outage", async () => {
    const abort = new DOMException("The operation was aborted.", "AbortError");
    await expect(client(failing(abort)).list()).rejects.toBe(abort);

    const controller = new AbortController();
    controller.abort();
    const other = new TypeError("Failed to fetch");
    await expect(client(failing(other)).list({}, controller.signal)).rejects.toBe(other);
  });

  it("reads a refusal from the host as the state it names", async () => {
    const result = await client(answering({ code: "no_session", message: "Sign in again." }, 401)).list();
    if (result.state === "ready") throw new Error("a refusal was answered");
    expect(result.state).toBe("authentication_required");
    expect(result.problem.code).toBe("no_session");
  });
});
