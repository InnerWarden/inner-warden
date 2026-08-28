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

// ─────────── the two sections the paid host sends and nobody rendered ────────
//
// Measured on the shipped Enterprise bundle before this change: it contained
// ZERO occurrences of `enforcing_count`, `control_count`, `local_model` and
// `agent_layer`, on a host that sends all four. The same field-by-field rebuild
// that ate `disposition` ate these, so the on-device model and the guardrail's
// own figures never reached the screen at all.
//
// The payloads below are the shapes the producer builds, copied from
// `agent/src/dashboard/v1/local_model.rs` and `.../agent_layer.rs`.

const EVIDENCE_BASIS =
  "Counted from the guardrail's own decision record on this host. It is what the guardrail "
  + "reports it did, not something the host proved, so nothing in this section changes a host "
  + "control above.";

const COVERS = "everything in the guardrail's decision record on this host; the record is "
  + "capped and drops its oldest entries";

function localModelPayload(): Record<string, unknown> {
  return {
    state: "loaded",
    display_name: "Local Warden Model",
    provider: "local_classifier",
    model_id: "warden-student-v3",
    roles: ["decides what to do about an incident", "labels an incident"],
    measured: [
      {
        id: "ai_decision_count",
        label: "Decisions returned",
        value: "602",
        covers: "today, on this host: every decision the agent made went to this model",
      },
      {
        id: "avg_decision_latency_ms",
        label: "Average decision latency",
        value: "12 ms",
        covers: "today, on this host: every decision the agent made went to this model",
      },
    ],
    not_measured: [
      "how often the model agreed with the deterministic rules",
      "the model's accuracy on this host: scoring it needs outcomes labelled as right or wrong, "
      + "which this host does not have",
    ],
    summary: "The Local Warden Model is loaded and decides on this host. It scores, it does not "
      + "write, so a written explanation needs a language model connected as well.",
  };
}

function agentLayerPayload(): Record<string, unknown> {
  return {
    state: "screening",
    reason: "agent_layer_screening",
    display_name: "Command and prompt screening, and MCP tool calls",
    evidence_basis: EVIDENCE_BASIS,
    evidence_source: "/var/lib/innerwarden/graph.json",
    sessions: ["openclaw", "release-check"],
    measured: [
      { id: "commands_screened", label: "Commands screened", value: "601", covers: COVERS },
      { id: "commands_refused", label: "Commands the guardrail refused", value: "4", covers: COVERS },
      { id: "mcp_calls_screened", label: "MCP tool calls screened", value: "1", covers: COVERS },
      { id: "agent_sessions", label: "AI agent sessions in the record", value: "2", covers: COVERS },
    ],
    not_measured: [
      "prompts screened inside an agent conversation: the guardrail writes those to its event "
      + "log, and this section counts only its decision record",
    ],
    summary: "The guardrail screened 601 commands and 1 MCP tool call on this host, across 2 "
      + "agent sessions. It refused 4, and recorded 9 more it would have refused had it been "
      + "enforcing.",
  };
}

function postureWithSections(extra: Record<string, unknown>): Record<string, unknown> {
  return { ...(postureWithLayer({}) as Record<string, unknown>), ...extra };
}

describe("the host's own control count survives validation", () => {
  it("keeps both numbers instead of eating them", () => {
    const parsed = parseDashboardPosture(postureWithSections({ enforcing_count: 1, control_count: 5 }));

    expect(parsed.enforcing_count).toBe(1);
    expect(parsed.control_count).toBe(5);
  });

  it("rejects a count that is present but not a count", () => {
    // Silently dropping it would leave the screen with no number and no clue
    // that the host sent one.
    expect(() => parseDashboardPosture(postureWithSections({ enforcing_count: "one", control_count: 5 })))
      .toThrow(/posture\.enforcing_count/);
    expect(() => parseDashboardPosture(postureWithSections({ enforcing_count: 1, control_count: -5 })))
      .toThrow(/posture\.control_count/);
  });
});

describe("the local model section survives validation", () => {
  it("keeps every field the host measured, and the gaps it named", () => {
    const parsed = parseDashboardPosture(postureWithSections({ local_model: localModelPayload() }));
    const model = parsed.local_model;

    expect(model?.state).toBe("loaded");
    expect(model?.display_name).toBe("Local Warden Model");
    expect(model?.provider).toBe("local_classifier");
    expect(model?.model_id).toBe("warden-student-v3");
    expect(model?.roles).toContain("decides what to do about an incident");
    expect(model?.measured.map((entry) => entry.id)).toEqual(["ai_decision_count", "avg_decision_latency_ms"]);
    // The population travels with the number or the number means nothing.
    expect(model?.measured[0].covers).toContain("every decision the agent made went to this model");
    expect(model?.not_measured).toHaveLength(2);
    expect(model?.summary).toContain("It scores, it does not write");
  });

  it("keeps a host that has no model at all", () => {
    const parsed = parseDashboardPosture(postureWithSections({
      local_model: {
        ...localModelPayload(),
        state: "not_configured",
        provider: null,
        model_id: null,
        roles: [],
        measured: [],
      },
    }));

    expect(parsed.local_model?.state).toBe("not_configured");
    expect(parsed.local_model?.provider).toBeNull();
    // The name is present in every state, so a host with no model still names
    // the thing the buyer paid for.
    expect(parsed.local_model?.display_name).toBe("Local Warden Model");
  });

  it("rejects a state outside the closed set", () => {
    expect(() => parseDashboardPosture(postureWithSections({
      local_model: { ...localModelPayload(), state: "probably_loaded" },
    }))).toThrow(/unsupported value probably_loaded/);
  });

  it("rejects a measured value with no stated population", () => {
    // A count with no `covers` is the exact defect these sections exist to
    // avoid, so a producer that ships one fails here rather than on the page.
    expect(() => parseDashboardPosture(postureWithSections({
      local_model: {
        ...localModelPayload(),
        measured: [{ id: "ai_decision_count", label: "Decisions returned", value: "602" }],
      },
    }))).toThrow(/posture\.local_model\.measured\[0\]\.covers/);
  });
});

describe("the agent layer section survives validation", () => {
  it("keeps the figures, the sessions and the basis the host sent", () => {
    const parsed = parseDashboardPosture(postureWithSections({ agent_layer: agentLayerPayload() }));
    const layer = parsed.agent_layer;

    expect(layer?.state).toBe("screening");
    expect(layer?.reason).toBe("agent_layer_screening");
    expect(layer?.display_name).toContain("MCP tool calls");
    // The sentence that stops these figures reading as host-proved evidence.
    expect(layer?.evidence_basis).toBe(EVIDENCE_BASIS);
    expect(layer?.evidence_source).toBe("/var/lib/innerwarden/graph.json");
    expect(layer?.sessions).toEqual(["openclaw", "release-check"]);
    expect(layer?.measured.map((entry) => entry.value)).toEqual(["601", "4", "1", "2"]);
    expect(layer?.not_measured[0]).toContain("prompts screened inside an agent conversation");
  });

  it("keeps a record that could not be read distinct from a quiet one", () => {
    const unreadable = parseDashboardPosture(postureWithSections({
      agent_layer: {
        ...agentLayerPayload(),
        state: "record_unreadable",
        reason: "guard_record_permission_denied",
        sessions: [],
        measured: [],
        not_measured: [
          "anything the guardrail screened: its decision record could not be read, so this is "
          + "not a quiet host",
        ],
        summary: "The guardrail's decision record exists and this agent may not open it.",
      },
    }));

    expect(unreadable.agent_layer?.state).toBe("record_unreadable");
    // The CAUSE, not the state. Two causes under one code send the operator to
    // check the wrong thing.
    expect(unreadable.agent_layer?.reason).toBe("guard_record_permission_denied");
    expect(unreadable.agent_layer?.measured).toEqual([]);
  });

  it("rejects a section that drops the basis line", () => {
    // The basis is what keeps an agent-reported figure from being read as a
    // host-proved one. A section that could render without it is the one thing
    // this must never be.
    const withoutBasis = agentLayerPayload();
    delete withoutBasis.evidence_basis;
    expect(() => parseDashboardPosture(postureWithSections({ agent_layer: withoutBasis })))
      .toThrow(/posture\.agent_layer\.evidence_basis/);
  });

  it("rejects a state outside the closed set", () => {
    expect(() => parseDashboardPosture(postureWithSections({
      agent_layer: { ...agentLayerPayload(), state: "quiet" },
    }))).toThrow(/unsupported value quiet/);
  });
});

describe("an older host that sends neither section still parses", () => {
  it("parses a producer that predates all four fields", () => {
    // Additive means additive. A host on an older build sends none of these,
    // and losing its whole posture over an absent section would be a far worse
    // failure than the one this change fixes.
    const parsed = parseDashboardPosture(postureWithLayer({}));

    expect(parsed.enforcing_count).toBeUndefined();
    expect(parsed.control_count).toBeUndefined();
    expect(parsed.local_model).toBeUndefined();
    expect(parsed.agent_layer).toBeUndefined();
    // And everything it DID send is still there.
    expect(parsed.layers).toHaveLength(1);
  });
});
