import { describe, expect, it } from "vitest";
import { parseDashboardBootstrap } from "./validate";

function bootstrapWithSourceKind(kind: unknown): unknown {
  const stage = { state: "unknown", evidence: [], reason_code: "not_observed" };
  return {
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
    capabilities: [{
      id: "community.visibility",
      tier: "community",
      availability: "unknown",
      entitlement: "not_required",
      support: "supported",
      desired_mode: "disabled",
      effective_mode: "unknown",
      convergence: {
        configured: stage,
        loaded: stage,
        running: stage,
        enforcing: stage,
        verified_effective: stage,
      },
      rollout_state: "unknown",
      health: "unknown",
      scope: [],
      covered_action_classes: [],
      bypass_classes: [],
      known_uncovered_paths: [],
      freshness: {
        observed_at: null,
        budget_seconds: 30,
        state: "missing",
        age_seconds: null,
      },
      last_evidence: null,
      sources: [{
        id: "visibility-source",
        kind,
        authority: "canonical",
        version: "1",
        completeness: "partial",
        limitations: [],
      }],
      claims: [],
      reason_code: "not_observed",
      summary: "visibility not observed",
    }],
    highest_priority_gap: null,
    privacy: { storage: [], redactions: [], egress: [] },
  };
}

describe("dashboard v1 source validation", () => {
  it("accepts a declared SourceKind", () => {
    expect(parseDashboardBootstrap(bootstrapWithSourceKind("runtime_probe"))
      .capabilities[0].sources[0].kind).toBe("runtime_probe");
  });

  it("rejects an unknown free-form SourceKind", () => {
    expect(() => parseDashboardBootstrap(bootstrapWithSourceKind("shell_guess")))
      .toThrow(/unsupported value shell_guess/);
  });
});
