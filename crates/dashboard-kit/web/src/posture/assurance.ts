import type { CapabilityStatus, ProtectionLayer, VersionRef } from "../api/v1";
import { layerMayClaimActiveContainment } from "./claims";

export type LayerAssuranceLabel = {
  label: string;
  status: string;
  verifiedActive: boolean;
};

export function layerAssuranceLabel(
  layer: ProtectionLayer,
  capabilities: CapabilityStatus[],
  matrix: VersionRef | null,
  layerGeneratedAt: string,
  capabilityGeneratedAt: string,
  evaluatedAt: string,
  environment: string,
  claimsCurrent = true,
): LayerAssuranceLabel {
  const claimTargets = layer.effective_scope.flatMap((scope) =>
    layer.covered_action_classes.map((actionClass) => ({ scope, actionClass })));
  const verifiedActive = claimsCurrent
    && matrix !== null
    && claimTargets.length > 0
    && claimTargets.every(({ scope, actionClass }) => capabilities.some((capability) =>
      capability.claims.some((claim) => layerMayClaimActiveContainment(
        layer,
        capability,
        {
          matrix,
          claim_id: claim.id,
          scope_id: scope.id,
          scope_kind: scope.kind,
          action_class: actionClass,
          population: claim.population,
          environment,
          generated_at: layerGeneratedAt,
          evaluated_at: evaluatedAt,
        },
        {
          matrix,
          claim_id: claim.id,
          scope_id: scope.id,
          scope_kind: scope.kind,
          action_class: actionClass,
          population: claim.population,
          environment,
          generated_at: capabilityGeneratedAt,
          evaluated_at: evaluatedAt,
        },
      ))));

  if (verifiedActive) return { label: "Verified active enforcement", status: "active", verifiedActive: true };

  switch (layer.claim_state) {
    case "visibility_only":
      return { label: "Visibility only", status: "visibility_only", verifiedActive: false };
    case "readiness_only":
      return { label: "Readiness only", status: "readiness_only", verifiedActive: false };
    case "degraded":
      return { label: "Evidence degraded", status: "degraded", verifiedActive: false };
    case "not_covered":
      return { label: "Not covered", status: "not_covered", verifiedActive: false };
    case "unavailable":
      return { label: "Unavailable", status: "unavailable", verifiedActive: false };
    case "active":
      return { label: "Active claim withheld", status: "degraded", verifiedActive: false };
    default:
      return { label: "Status unknown", status: "unknown", verifiedActive: false };
  }
}
