import type { CapabilityStatus, ProtectionLayer, ScopeRef, VersionRef } from "../api/v1";

export type ContainmentClaimContext = {
  matrix: VersionRef;
  claim_id: string;
  scope_id: string;
  scope_kind: ScopeRef["kind"];
  action_class: string;
  population: string;
  environment: string;
  /** Producer snapshot generation time. */
  generated_at: string;
  /** Consumer-controlled clock used to expire frozen snapshots. */
  evaluated_at: string;
};

const verifiedEvidence = (evidence: { integrity: string }[]) =>
  evidence.length > 0 && evidence.every((item) => item.integrity === "verified");

const hasHostVerifiedScope = (scope: ScopeRef[], context: ContainmentClaimContext) =>
  scope.some((item) => item.id === context.scope_id
    && item.kind === context.scope_kind
    && item.verification === "host_verified"
    && verifiedEvidence(item.evidence));

const matrixIsPinned = (matrix: VersionRef) => matrix.id.trim() !== ""
  && matrix.version.trim() !== ""
  && /^sha256:[a-f0-9]{64}$/.test(matrix.digest);

const sameMatrix = (left: VersionRef, right: VersionRef) => left.id === right.id
  && left.version === right.version
  && left.canonicalization === right.canonicalization
  && left.digest === right.digest;

const freshnessIsCurrent = (
  freshness: CapabilityStatus["freshness"],
  context: ContainmentClaimContext,
) => {
  if (freshness.state !== "fresh" || freshness.budget_seconds <= 0
    || freshness.observed_at === null || freshness.age_seconds === null) return false;
  const generatedMs = Date.parse(context.generated_at);
  const evaluatedMs = Date.parse(context.evaluated_at);
  const observedMs = Date.parse(freshness.observed_at);
  if (![generatedMs, evaluatedMs, observedMs].every(Number.isFinite)) return false;
  if (observedMs > generatedMs || generatedMs > evaluatedMs) return false;
  const producerAge = Math.floor((generatedMs - observedMs) / 1_000);
  const consumerAge = Math.floor((evaluatedMs - observedMs) / 1_000);
  return producerAge >= 0
    && consumerAge >= 0
    && freshness.age_seconds === producerAge
    && consumerAge <= freshness.budget_seconds;
};

const evidenceMatchesFreshness = (
  evidence: CapabilityStatus["claims"][number]["evidence"],
  freshness: CapabilityStatus["freshness"],
) => verifiedEvidence(evidence)
  && evidence.some((item) => item.observed_at === freshness.observed_at
    && item.freshness.observed_at === freshness.observed_at
    && item.freshness.budget_seconds === freshness.budget_seconds
    && item.freshness.state === freshness.state
    && item.freshness.age_seconds === freshness.age_seconds);

const verifiedStage = (
  stage: CapabilityStatus["convergence"]["configured"],
  freshness: CapabilityStatus["freshness"],
) => stage.state === "yes" && evidenceMatchesFreshness(stage.evidence, freshness);

const contextIsBound = (context: ContainmentClaimContext) => matrixIsPinned(context.matrix)
  && context.claim_id.trim() !== ""
  && context.scope_id.trim() !== ""
  && context.action_class.trim() !== ""
  && context.population.trim() !== ""
  && context.environment.trim() !== "";

const claimSupportsContext = (
  claim: CapabilityStatus["claims"][number],
  context: ContainmentClaimContext,
  freshness: CapabilityStatus["freshness"],
) => claim.id === context.claim_id
  && claim.status === "verified"
  && claim.versions.some((version) => sameMatrix(version, context.matrix))
  && ((claim.statement?.trim().length ?? 0) > 0 || (claim.semantic_key?.trim().length ?? 0) > 0)
  && claim.population === context.population
  && claim.environment === context.environment
  && claim.limitations.length === 0
  && claim.observed_at === freshness.observed_at
  && claim.reviewed_at !== null
  && claim.expires_at !== null
  && Number.isFinite(Date.parse(claim.reviewed_at))
  && Number.isFinite(Date.parse(claim.expires_at))
  && Date.parse(claim.reviewed_at) <= Date.parse(claim.expires_at)
  && Date.parse(context.evaluated_at) <= Date.parse(claim.expires_at)
  && hasHostVerifiedScope(claim.scope, context)
  && claim.action_classes.includes(context.action_class)
  && evidenceMatchesFreshness(claim.evidence, freshness);

/**
 * Presentation guardrail only: the backend remains the evidence authority. This
 * makes the browser fail closed if unsupported, declared, stale or weakly
 * evidenced data is accidentally labelled as active host containment.
 */
export function capabilityMayClaimActiveContainment(
  capability: CapabilityStatus,
  context: ContainmentClaimContext,
): boolean {
  return capability.tier === "enterprise_core"
    && capability.availability === "available"
    && capability.support === "supported"
    && capability.effective_mode === "enforce"
    && capability.rollout_state === "enforcing"
    && capability.health === "healthy"
    && contextIsBound(context)
    && freshnessIsCurrent(capability.freshness, context)
    && verifiedStage(capability.convergence.configured, capability.freshness)
    && verifiedStage(capability.convergence.loaded, capability.freshness)
    && verifiedStage(capability.convergence.running, capability.freshness)
    && verifiedStage(capability.convergence.enforcing, capability.freshness)
    && verifiedStage(capability.convergence.verified_effective, capability.freshness)
    && hasHostVerifiedScope(capability.scope, context)
    && capability.covered_action_classes.includes(context.action_class)
    && capability.bypass_classes.length === 0
    && capability.known_uncovered_paths.length === 0
    && capability.last_evidence?.integrity === "verified"
    && evidenceMatchesFreshness([capability.last_evidence], capability.freshness)
    && capability.claims.some((claim) => claimSupportsContext(
      claim,
      context,
      capability.freshness,
    ));
}

export function layerMayClaimActiveContainment(
  layer: ProtectionLayer,
  capability: CapabilityStatus,
  layerContext: ContainmentClaimContext,
  capabilityContext: ContainmentClaimContext,
): boolean {
  return layer.capability_ids.includes(capability.id)
    && sameClaimTarget(layerContext, capabilityContext)
    && capabilityMayClaimActiveContainment(capability, capabilityContext)
    && layer.claim_state === "active"
    && layer.effective_mode === "enforce"
    && contextIsBound(layerContext)
    && freshnessIsCurrent(layer.freshness, layerContext)
    && layer.known_gaps.length === 0
    && hasHostVerifiedScope(layer.effective_scope, layerContext)
    && layer.covered_action_classes.includes(layerContext.action_class)
    && evidenceMatchesFreshness(layer.evidence, layer.freshness)
    && verifiedStage(layer.convergence.configured, layer.freshness)
    && verifiedStage(layer.convergence.loaded, layer.freshness)
    && verifiedStage(layer.convergence.running, layer.freshness)
    && verifiedStage(layer.convergence.enforcing, layer.freshness)
    && verifiedStage(layer.convergence.verified_effective, layer.freshness);
}

const sameClaimTarget = (
  left: ContainmentClaimContext,
  right: ContainmentClaimContext,
) => sameMatrix(left.matrix, right.matrix)
  && left.claim_id === right.claim_id
  && left.scope_id === right.scope_id
  && left.scope_kind === right.scope_kind
  && left.action_class === right.action_class
  && left.population === right.population
  && left.environment === right.environment
  && left.evaluated_at === right.evaluated_at;
