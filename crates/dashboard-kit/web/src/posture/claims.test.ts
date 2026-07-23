import { describe, expect, it } from "vitest";
import type { CapabilityStatus, EvidenceRef, ScopeRef } from "../api/v1";
import { capabilityMayClaimActiveContainment } from "./claims";

const matrix = {
  id: "innerwarden.assurance-matrix",
  version: "AM-090-v1",
  canonicalization: "YAML-TO-RFC8785-JCS" as const,
  digest: `sha256:${"a".repeat(64)}`,
};

const evidence: EvidenceRef = {
  id: "ev-1",
  kind: "runtime_verification",
  source: {
    id: "kernel_state",
    kind: "kernel_state",
    authority: "canonical",
    version: "1",
    completeness: "complete",
    limitations: [],
  },
  observed_at: "2026-07-18T12:00:00Z",
  integrity: "verified",
  redaction: [],
  freshness: {
    observed_at: "2026-07-18T12:00:00Z",
    budget_seconds: 30,
    state: "fresh",
    age_seconds: 1,
  },
};

const scope: ScopeRef = {
  id: "host-1",
  kind: "host",
  display_name: "pilot host",
  verification: "host_verified",
  evidence: [{ ...evidence }],
};

function stage(state: "yes" | "no" | "unknown" | "not_applicable") {
  return { state, evidence: state === "yes" ? [{ ...evidence }] : [], reason_code: null };
}

function activeCapability(): CapabilityStatus {
  return {
    id: "kernel_execution_control",
    tier: "enterprise_core",
    availability: "available",
    entitlement: "valid",
    support: "supported",
    desired_mode: "enforce",
    effective_mode: "enforce",
    convergence: {
      configured: stage("yes"), loaded: stage("yes"), running: stage("yes"),
      enforcing: stage("yes"), verified_effective: stage("yes"),
    },
    rollout_state: "enforcing",
    health: "healthy",
    scope: [{ ...scope }],
    covered_action_classes: ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: {
      observed_at: evidence.observed_at,
      budget_seconds: 30, state: "fresh", age_seconds: 1,
    },
    last_evidence: { ...evidence },
    sources: [],
    claims: [{
      id: "claim-1", statement: "covered executions are blocked", semantic_key: null, status: "verified",
      versions: [{ ...matrix }],
      population: "host-1", environment: "linux",
      observed_at: evidence.observed_at, reviewed_at: evidence.observed_at, expires_at: "2026-07-18T12:01:00Z",
      scope: [{ ...scope }], action_classes: ["process_execution"],
      evidence: [{ ...evidence }], limitations: [],
    }],
    reason_code: null,
    summary: "fresh verified enforcement",
  };
}

const context = {
  matrix,
  claim_id: "claim-1",
  scope_id: "host-1",
  scope_kind: "host" as const,
  action_class: "process_execution",
  population: "host-1",
  environment: "linux",
  generated_at: "2026-07-18T12:00:01Z",
  evaluated_at: "2026-07-18T12:00:01Z",
};

describe("active-containment claim guard", () => {
  it("accepts only the fully evidenced Enterprise host state", () => {
    expect(capabilityMayClaimActiveContainment(activeCapability(), context)).toBe(true);
  });

  it.each([
    ["observe", (capability: CapabilityStatus) => { capability.effective_mode = "observe"; }],
    ["stale", (capability: CapabilityStatus) => { capability.freshness.state = "stale"; }],
    ["unsupported", (capability: CapabilityStatus) => { capability.support = "unsupported"; }],
    ["declared scope", (capability: CapabilityStatus) => { capability.scope[0].verification = "declared"; }],
    ["unverified evidence", (capability: CapabilityStatus) => { capability.last_evidence!.integrity = "unverified"; }],
    ["unverified runtime", (capability: CapabilityStatus) => { capability.convergence.verified_effective.state = "unknown"; }],
    ["rollout not enforcing", (capability: CapabilityStatus) => { capability.rollout_state = "canary"; }],
    ["scope outside capability", (capability: CapabilityStatus) => { capability.claims[0].scope[0].id = "host-elsewhere"; }],
    ["action outside capability", (capability: CapabilityStatus) => { capability.claims[0].action_classes = ["secret_read"]; }],
    ["contradictory timestamp", (capability: CapabilityStatus) => { capability.freshness.observed_at = "2026-07-18T11:00:00Z"; }],
  ])("rejects %s", (_name, mutate) => {
    const capability = activeCapability();
    mutate(capability);
    expect(capabilityMayClaimActiveContainment(capability, context)).toBe(false);
  });

  it.each([
    ["unpinned matrix", (capability: CapabilityStatus) => capability, { ...context, matrix: { ...context.matrix, digest: "" } }],
    ["reported age mismatch", (capability: CapabilityStatus) => { capability.freshness.age_seconds = 0; return capability; }, context],
    ["unverified configured stage", (capability: CapabilityStatus) => { capability.convergence.configured.evidence = []; return capability; }, context],
    ["known bypass", (capability: CapabilityStatus) => { capability.bypass_classes = ["unmapped_bypass"]; return capability; }, context],
    ["known uncovered path", (capability: CapabilityStatus) => { capability.known_uncovered_paths = ["unmapped_path"]; return capability; }, context],
    ["wrong matrix digest", (capability: CapabilityStatus) => { capability.claims[0].versions[0].digest = `sha256:${"b".repeat(64)}`; return capability; }, context],
    ["wrong population", (capability: CapabilityStatus) => { capability.claims[0].population = "other-host"; return capability; }, context],
    ["wrong environment", (capability: CapabilityStatus) => { capability.claims[0].environment = "staging"; return capability; }, context],
    ["claim limitations", (capability: CapabilityStatus) => { capability.claims[0].limitations = ["one path excluded"]; return capability; }, context],
    ["future producer timestamp", (capability: CapabilityStatus) => capability, { ...context, evaluated_at: "2026-07-18T11:59:59Z" }],
    ["frozen snapshot", (capability: CapabilityStatus) => capability, { ...context, evaluated_at: "2026-07-18T12:00:31Z" }],
  ])("rejects %s", (_name, mutate, claimContext) => {
    expect(capabilityMayClaimActiveContainment(mutate(activeCapability()), claimContext)).toBe(false);
  });
});
