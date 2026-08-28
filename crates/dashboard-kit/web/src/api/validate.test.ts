import { describe, expect, it } from "vitest";
import { parseDashboardBootstrap, parseDashboardPosture } from "./validate";

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

// A layer payload with the shape the enterprise agent actually publishes.
function postureWithLayer(extra: Record<string, unknown>): unknown {
  const stage = { state: "unknown", evidence: [], reason_code: null };
  const freshness = { observed_at: null, budget_seconds: 30, state: "unknown", age_seconds: null };
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-08-20T20:12:00Z",
    layers: [
      {
        id: "dns_resolution_control-layer",
        label: "DNS resolution control",
        capability_ids: ["dns_resolution_control"],
        claim_state: "not_covered",
        effective_mode: "unknown",
        desired_mode: "enforce",
        effective_scope: [],
        covered_action_classes: [],
        known_gaps: [],
        freshness,
        convergence: { configured: stage, loaded: stage, running: stage, enforcing: stage, verified_effective: stage },
        evidence: [],
        ...extra,
      },
    ],
    gaps: [],
  };
}

describe("the disposition survives validation", () => {
  it("keeps the host's disposition instead of dropping it", () => {
    // This validator REBUILDS each layer field by field, so a field it does not
    // name is silently discarded. Measured on a pilot box 2026-08-20: the agent
    // published `disposition: "not_enabled"` for the DNS guard and the page
    // rendered "Can't confirm", because the screen fell back to deriving the
    // state from effective_mode after this function ate the field.
    const parsed = parseDashboardPosture(
      postureWithLayer({ disposition: "not_enabled", disposition_reason: "It is switched on but has nothing to act on yet." }),
    );

    expect(parsed.layers[0].disposition).toBe("not_enabled");
    expect(parsed.layers[0].disposition_reason).toContain("nothing to act on");
  });

  it("parses an older agent that sends neither field", () => {
    const parsed = parseDashboardPosture(postureWithLayer({}));

    expect(parsed.layers[0].disposition).toBeUndefined();
    expect(parsed.layers[0].disposition_reason).toBeUndefined();
  });

  it("rejects a disposition outside the closed set", () => {
    // A typo or a newer agent's unknown value must fail loudly here rather than
    // silently colouring a control with whatever the fallback happens to pick.
    expect(() => parseDashboardPosture(postureWithLayer({ disposition: "probably_fine" })))
      .toThrow(/unsupported value probably_fine/);
  });

  /**
   * The same defect, one level up. The host computes the page's one-line
   * verdict, including whether any control still prints a command, and this
   * function used not to name `summary`, so it ate it and the screen wrote its
   * own line from the counts alone. That line ended "Nothing needs you."
   * unconditionally.
   */
  it("carries the host's summary instead of eating it", () => {
    const payload = postureWithLayer({}) as Record<string, unknown>;
    payload.summary = "2 of 5 host controls are off and protect nothing";
    expect(parseDashboardPosture(payload).summary).toBe("2 of 5 host controls are off and protect nothing");
  });

  it("parses a producer that sends no summary at all", () => {
    expect(parseDashboardPosture(postureWithLayer({})).summary).toBeUndefined();
  });

  it("rejects a summary that is present but not a string", () => {
    // Falling back quietly would hide a producer bug behind a page that still
    // looks right.
    const payload = postureWithLayer({}) as Record<string, unknown>;
    payload.summary = 5;
    expect(() => parseDashboardPosture(payload)).toThrow();
  });
});
