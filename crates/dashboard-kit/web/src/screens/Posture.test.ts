import { describe, expect, it } from "vitest";
import type {
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  EvidenceRef,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
  SourceRef,
  StageAnswer,
} from "../api/v1";
import {
  checkedAt,
  controlPill,
  emptyGapsLine,
  gapAudience,
  plainMode,
  postureHeadline,
  scopeDisplay,
} from "./Posture";

// A realistic enterprise posture payload: the five host controls the paid
// adapter actually publishes (execution gate, host visibility, DNS guard,
// secret guard, response controls), all tier enterprise_core, with the gap mix
// observed on a healthy production host.

const generatedAt = "2026-08-07T12:00:02Z";
const observedAt = "2026-08-07T12:00:00Z";
const evaluatedAt = "2026-08-07T12:00:02Z";

const source: SourceRef = {
  id: "posture-runtime",
  kind: "kernel_state",
  authority: "canonical",
  version: "1",
  completeness: "complete",
  limitations: [],
};

const fresh: EvidenceFreshness = { observed_at: observedAt, budget_seconds: 30, state: "fresh", age_seconds: 2 };

const evidence: EvidenceRef = {
  id: "posture-evidence",
  kind: "runtime_verification",
  source,
  observed_at: observedAt,
  integrity: "verified",
  redaction: [],
  freshness: fresh,
};

const hostScope: ScopeRef = {
  id: "host:prod-01",
  kind: "host",
  display_name: "prod-01",
  verification: "host_verified",
  evidence: [evidence],
};

const agentScope: ScopeRef = {
  id: "cgroup:openclaw",
  kind: "cgroup",
  display_name: "OpenClaw workload",
  verification: "host_verified",
  evidence: [evidence],
};

function stage(state: StageAnswer, reason: string | null = null): RuntimeConvergence["configured"] {
  return { state, evidence: state === "yes" ? [evidence] : [], reason_code: reason };
}

const converged: RuntimeConvergence = {
  configured: stage("yes"),
  loaded: stage("yes"),
  running: stage("yes"),
  enforcing: stage("yes"),
  verified_effective: stage("yes"),
};

function capability(id: string, mode: CapabilityStatus["effective_mode"], scope: ScopeRef, claims: CapabilityStatus["claims"] = []): CapabilityStatus {
  return {
    id,
    tier: "enterprise_core",
    availability: "available",
    entitlement: "valid",
    support: "supported",
    desired_mode: mode,
    effective_mode: mode,
    convergence: converged,
    rollout_state: mode === "enforce" ? "enforcing" : "observing",
    health: "healthy",
    scope: [scope],
    covered_action_classes: ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: fresh,
    last_evidence: evidence,
    sources: [source],
    claims,
    reason_code: null,
    summary: `${id} fixture`,
  };
}

function layer(id: string, label: string, capabilityId: string, mode: ProtectionLayer["effective_mode"], scope: ScopeRef, gaps: CoverageGap[] = []): ProtectionLayer {
  return {
    id,
    label,
    capability_ids: [capabilityId],
    claim_state: mode === "enforce" ? "active" : "visibility_only",
    effective_mode: mode,
    desired_mode: mode,
    effective_scope: [scope],
    covered_action_classes: ["process_execution"],
    known_gaps: gaps,
    freshness: fresh,
    convergence: converged,
    evidence: [evidence],
  };
}

function gap(id: string, state: CoverageGap["state"], nextStep: string): CoverageGap {
  return {
    id,
    capability_id: "kernel_execution_control",
    affected_scope: [agentScope],
    action_classes: ["process_execution"],
    state,
    evidence: [evidence],
    next_step: nextStep,
  };
}

// The self-audit gaps a healthy enterprise host publishes permanently.
const assuranceGap = gap("kernel-execution-assurance-gap", "unknown", "publish and pin the reviewed Assurance Matrix before presenting a protection claim");
const membershipGap = gap("kernel-execution-scope-membership-gap", "unknown", "publish cgroup identity and membership evidence; an armed flag and member count are not scope proof");
const temporalGap = gap("kernel-execution-temporal-gap", "unknown", "obtain a producer timestamp at or before response generation before relying on this state");
const scopeStateGap = gap("kernel-execution-scope-state-gap", "unknown", "read the live scope state and bind an attributable workload identity before presenting scope coverage");
// The gaps that mean a control the user turned on is not working.
const runtimeGap = gap("kernel-execution-runtime-gap", "degraded", "restore the active BPF-LSM runtime before enabling enforcement");
const effectivenessGap = gap("kernel-execution-effectiveness-gap", "unknown", "compare signed and live rule content or digests and verify the expected BPF program attachment and provenance");
const visibilityGap = { ...gap("host-visibility-gap", "not_covered", "start the sensor and publish a collector-health snapshot"), capability_id: "host_visibility" };

const FIVE_LAYERS: ProtectionLayer[] = [
  layer("host_execution_layer", "Independent host execution", "kernel_execution_control", "enforce", agentScope),
  layer("host_visibility_layer", "Host visibility", "host_visibility", "observe", hostScope),
  layer("dns_guard_layer", "DNS guard", "dns_guard", "observe", hostScope),
  layer("secret_guard_layer", "Secret guard", "secret_read_guard", "observe", hostScope),
  layer("response_layer", "Response controls", "response_controls", "enforce", hostScope),
];

function bootstrap(): DashboardBootstrap {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: generatedAt,
    edition: "enterprise",
    product_version: "0.16.4",
    community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"d".repeat(64)}` },
    assurance_matrix: { id: "AM-090", version: "AM-090-v1", canonicalization: "RFC8785-JCS", digest: `sha256:${"a".repeat(64)}` },
    authorization_matrix: null,
    platform: { os: "linux", architecture: "aarch64", enterprise_candidate: true, reason_code: null },
    session: { authenticated: true, actor_id: "operator", role: "security_operator", scopes: [] },
    capabilities: FIVE_LAYERS.map((entry) => capability(entry.capability_ids[0], entry.effective_mode, entry.effective_scope[0])),
    highest_priority_gap: null,
    privacy: { storage: [], redactions: [], egress: [] },
  };
}

function posture(layers: ProtectionLayer[] = FIVE_LAYERS, gaps: CoverageGap[] = []): DashboardPosture {
  return { schema_version: "innerwarden.dashboard.v1", generated_at: generatedAt, layers, gaps };
}

describe("the verdict hero leads with what the user asked", () => {
  it("counts verified controls out of the five the enterprise adapter publishes", () => {
    const pills = posture().layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    expect(pills).toHaveLength(5);
    // This fixture has TWO controls enforcing, and the old headline read
    // "0 of 5 host controls verified active" over exactly this data: it counted
    // a narrower notion of verified than the rows displayed and never said so.
    // Production showed the same shortfall, "1 of 5", with three rows reading
    // Enforcing and the kernel measured as enforcing on two of them.
    expect(postureHeadline(pills)).toBe("2 of 5 host controls enforcing");
  });

  it("never claims verified active without the assurance rule agreeing", () => {
    // No claims records exist in this fixture, so layerAssuranceLabel says
    // verifiedActive=false for every control; the hero must not say otherwise.
    const pills = posture().layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    expect(pills.every((pill) => !pill.verified)).toBe(true);
    expect(pills.every((pill) => pill.tone !== "positive")).toBe(true);
  });

  it("shows each control in plain words with its scope name and check time", () => {
    const pill = controlPill(posture().layers[0], bootstrap(), generatedAt, true, evaluatedAt);
    expect(pill.name).toBe("Independent host execution");
    expect(pill.mode).toBe("Enforcing");
    expect(pill.scope).toBe("OpenClaw workload");
    expect(pill.freshness).toMatch(/^as of \d{2}:\d{2}$/);
    // The producer freshness budget is contract bookkeeping; the summary never
    // mentions it.
    expect(pill.freshness).not.toContain("budget");
  });

  it("reads as refreshing, not as failure, while the snapshot is stale", () => {
    const pill = controlPill(posture().layers[0], bootstrap(), generatedAt, false, evaluatedAt);
    expect(pill.mode).toBe("Refreshing");
    expect(pill.verified).toBe(false);
  });
});

describe("mode words are user words", () => {
  it("maps modes to Enforcing, Watching, Rehearsing and Off", () => {
    expect(plainMode({ effective_mode: "enforce", desired_mode: "enforce" })).toBe("Enforcing");
    expect(plainMode({ effective_mode: "observe", desired_mode: "observe" })).toBe("Watching");
    expect(plainMode({ effective_mode: "rehearse", desired_mode: "rehearse" })).toBe("Rehearsing");
    expect(plainMode({ effective_mode: "disabled", desired_mode: "disabled" })).toBe("Off");
  });

  it("never borrows armed intent as a claim of enforcement", () => {
    // Returned "Enforcing, verifying", which a production host rendered
    // directly above a subtitle reading "not checked yet" and a coverage gap
    // reading "Degraded", all about the same control. Armed-but-unconfirmed is
    // a check that did not run, not a shade of working.
    expect(plainMode({ effective_mode: "unknown", desired_mode: "enforce" })).toBe("Not confirmed");
    expect(plainMode({ effective_mode: "unknown", desired_mode: "unknown" })).toBe("Not confirmed");
    expect(plainMode({ effective_mode: "unknown", desired_mode: "disabled" })).toBe("Off");
  });
});

describe("freshness is a wall clock, not a counter that resets as you watch", () => {
  it("stamps the observation time instead of counting seconds", () => {
    // Was relative, and with the screen refreshing every few seconds it read
    // "checked 0s ago" almost permanently, resetting as you looked at it. A
    // number that never settles reads as a system that never settles.
    const at = new Date("2026-08-17T14:32:05Z");
    const hh = String(at.getHours()).padStart(2, "0");
    expect(checkedAt({ ...fresh, observed_at: at.toISOString() })).toBe(`as of ${hh}:32`);
  });

  it("says never checked rather than inventing a time", () => {
    expect(checkedAt({ ...fresh, observed_at: null })).toBe("never checked");
  });
});

describe("scope summaries drop the verification parenthetical", () => {
  it("uses the display name only", () => {
    expect(scopeDisplay([agentScope])).toBe("OpenClaw workload");
    expect(scopeDisplay([])).toBe("No scope reported");
  });
});

describe("gap routing: amber is reserved for what the user must act on", () => {
  it("routes the permanent self-audit gaps to the quiet verification lane", () => {
    // These fire on EVERY healthy enterprise host. As amber cards they made a
    // working deployment look broken; nothing the operator clicks resolves
    // them.
    for (const entry of [assuranceGap, membershipGap, temporalGap, scopeStateGap]) {
      expect(gapAudience(entry)).toBe("verification");
    }
  });

  it("keeps a control that is on but not working amber", () => {
    expect(gapAudience(runtimeGap)).toBe("operator");
    expect(gapAudience(effectivenessGap)).toBe("operator");
    expect(gapAudience(visibilityGap)).toBe("operator");
  });

  it("keeps degraded, stale and not-covered states amber regardless of id", () => {
    expect(gapAudience(gap("some-new-gap", "degraded", "restore it"))).toBe("operator");
    expect(gapAudience(gap("some-new-gap", "stale", "refresh it"))).toBe("operator");
    expect(gapAudience(gap("some-new-gap", "not_covered", "cover it"))).toBe("operator");
  });
});

describe("the empty gaps state is one quiet line", () => {
  it("says the positive thing and stops", () => {
    expect(emptyGapsLine(0)).toBe("No coverage gaps in this snapshot.");
  });

  it("stays honest when only verification-lane gaps exist", () => {
    expect(emptyGapsLine(3)).toBe("No coverage gaps need attention in this snapshot.");
  });
});


describe("the poll cadence matches the evidence it renders", () => {
  it("refreshes slower than a second but faster than the proof goes stale", async () => {
    const { POSTURE_REFRESH_MS } = await import("../App");
    // The evidence behind this screen is the effect canary, which re-runs every
    // 1200s. Polling every 5s meant 239 of every 240 requests returned the same
    // proof, and the freshness line read "checked 0s ago" resetting as you
    // watched it: a number that never settles reads as a system that never
    // settles.
    const CANARY_INTERVAL_MS = 1_200_000;
    expect(POSTURE_REFRESH_MS).toBeGreaterThan(60_000);
    expect(POSTURE_REFRESH_MS).toBeLessThanOrEqual(CANARY_INTERVAL_MS);
  });
});
