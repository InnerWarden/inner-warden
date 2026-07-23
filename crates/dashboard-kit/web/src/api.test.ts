import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchAgents, fetchTokenIntelligence } from "./api";

function respond(payload: unknown) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    json: async () => payload,
  }));
}

afterEach(() => vi.unstubAllGlobals());

describe("dashboard API validation", () => {
  it("accepts explicit unknown auto-connect state instead of coercing it to disabled", async () => {
    respond({
      schema_version: 2,
      generated_at_ms: 1,
      availability: "available",
      discovery_limited: false,
      auto_connect: {
        status: "unavailable",
        enabled: null,
        mode: null,
        refresh_interval_secs: 60,
      },
      agents: [],
    });

    const payload = await fetchAgents();
    expect(payload.auto_connect.enabled).toBeNull();
    expect(payload.auto_connect.mode).toBeNull();
  });

  it("accepts lossless decimal token strings and rejects rounded JS numbers", async () => {
    const row = {
      agent_id: "codex",
      display_name: "Codex",
      availability: "available",
      total_tokens: "18446744073709551615",
      input_tokens: "9007199254740993",
      output_tokens: "1",
      cache_read_input_tokens: null,
      cached_input_tokens: null,
      cache_creation_input_tokens: null,
      reasoning_output_tokens: null,
      sessions: 1,
      last_observed_at_ms: 1,
      provenance: { source: "local_session_log", quality: "partial", note: "local" },
    };
    const payload = {
      schema_version: 1,
      generated_at_ms: 1,
      scope: "available_local_history",
      availability: "partial",
      agents: [row],
    };
    respond(payload);
    expect((await fetchTokenIntelligence()).agents[0].total_tokens).toBe(row.total_tokens);

    respond({
      ...payload,
      agents: [{ ...row, total_tokens: 9_007_199_254_740_993 }],
    });
    await expect(fetchTokenIntelligence()).rejects.toThrow("invalid response shape");
  });
});
