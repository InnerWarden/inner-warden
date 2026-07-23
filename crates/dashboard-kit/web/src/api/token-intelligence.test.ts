import { describe, expect, it } from "vitest";
import { parseTokenIntelligence } from "./validate";

const counters = {
  total: "900719925474099312345",
  input: "900719925474099300000",
  output: "12345",
  cache_read_input: null,
  cached_input: null,
  cache_creation_input: null,
  reasoning_output: null,
};

const source = {
  id: "codex-local-history",
  kind: "local_history",
  authority: "canonical",
  version: "v1",
  completeness: "partial",
  limitations: ["retained history only"],
};

function available() {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-07-18T12:00:00Z",
    availability: "available",
    scope: "available_local_history",
    totals: { ...counters },
    providers: [{
      agent_id: "codex",
      display_name: "Codex",
      availability: "available",
      counters: { ...counters },
      sessions: "900719925474099312345",
      last_observed_at: "2026-07-18T11:59:00Z",
      provenance: source,
      note: "Local retained history; not billing data.",
    }],
  };
}

describe("token intelligence v1 validation", () => {
  it("preserves arbitrary-precision counters as canonical decimal strings", () => {
    const parsed = parseTokenIntelligence(available());
    expect(parsed.totals?.total).toBe("900719925474099312345");
    expect(parsed.providers[0]?.sessions).toBe("900719925474099312345");
  });

  it("rejects estimates, unsafe JSON numbers and non-canonical decimals", () => {
    for (const value of [42, "01", "-1", "1.5", "estimated"] as const) {
      const payload = available();
      payload.providers[0]!.counters.total = value as never;
      expect(() => parseTokenIntelligence(payload)).toThrow();
    }
  });

  it("does not allow an unavailable source or aggregate to leak counters", () => {
    const payload = available();
    payload.availability = "unavailable";
    payload.scope = "unknown";
    expect(() => parseTokenIntelligence(payload)).toThrow(/must not claim available history or totals/);

    const providerPayload = available();
    providerPayload.providers[0]!.availability = "unsupported";
    expect(() => parseTokenIntelligence(providerPayload)).toThrow(/must not expose inferred counters/);
  });
});
