//! Presentation-side safety rails for protection and containment wording.
//!
//! These helpers cannot prove a control effective; only the producer can emit
//! runtime evidence. They fail closed when that evidence is missing, stale,
//! unhealthy, out of scope, or not converged.

use crate::contract::{
    Availability, CapabilityStatus, CapabilityTier, ClaimState, ClaimStatus, EffectiveMode,
    EvidenceFreshness, EvidenceRef, FreshnessState, HealthState, IntegrityState, ProtectionLayer,
    ScopeKind, ScopeRef, ScopeVerification, StageAnswer, StageState, SupportLevel, VersionRef,
};

/// The exact claim the UI intends to render. A global "protected" boolean is
/// deliberately not supported: every affirmative statement must be bound to a
/// reviewed matrix revision, host-verified scope, action class and response
/// generation time.
pub struct ContainmentClaimContext<'a> {
    pub matrix: &'a VersionRef,
    pub claim_id: &'a str,
    pub scope_id: &'a str,
    pub scope_kind: ScopeKind,
    pub action_class: &'a str,
    pub population: &'a str,
    pub environment: &'a str,
    /// Time at which the producer assembled the response. This is checked for
    /// internal age coherence, but is never treated as the current clock.
    pub generated_at: &'a str,
    /// Consumer-controlled evaluation time. Injecting this makes expiry
    /// deterministic in tests and prevents a frozen producer snapshot from
    /// refreshing its own freshness forever.
    pub evaluated_at: &'a str,
}

pub fn capability_may_claim_active_containment(
    capability: &CapabilityStatus,
    context: &ContainmentClaimContext<'_>,
) -> bool {
    capability.availability == Availability::Available
        && capability.tier == CapabilityTier::EnterpriseCore
        && capability.support == SupportLevel::Supported
        && capability.effective_mode == EffectiveMode::Enforce
        && capability.rollout_state == crate::contract::RolloutState::Enforcing
        && capability.health == HealthState::Healthy
        && matrix_is_pinned(context.matrix)
        && freshness_is_current(&capability.freshness, context)
        && stage_is_verified(&capability.convergence.configured, &capability.freshness)
        && stage_is_verified(&capability.convergence.loaded, &capability.freshness)
        && stage_is_verified(&capability.convergence.running, &capability.freshness)
        && stage_is_verified(&capability.convergence.enforcing, &capability.freshness)
        && stage_is_verified(
            &capability.convergence.verified_effective,
            &capability.freshness,
        )
        && scope_is_host_verified(
            &capability.scope,
            context.scope_id,
            context.scope_kind,
        )
        && capability
            .covered_action_classes
            .iter()
            .any(|action| action == context.action_class)
        // The foundation DTO cannot yet bind these free-form gaps to a precise
        // scope/action pair. Fail closed until the Assurance Matrix adapter has
        // proven they do not apply to this requested statement.
        && capability.bypass_classes.is_empty()
        && capability.known_uncovered_paths.is_empty()
        && capability.last_evidence.as_ref().is_some_and(|evidence| {
            evidence_matches_freshness(evidence, &capability.freshness)
        })
        && capability.claims.iter().any(|claim| {
            claim_supports_context(claim, context, &capability.freshness)
        })
}

pub fn layer_may_claim_active_containment(
    layer: &ProtectionLayer,
    capability: &CapabilityStatus,
    layer_context: &ContainmentClaimContext<'_>,
    capability_context: &ContainmentClaimContext<'_>,
) -> bool {
    layer.capability_ids.iter().any(|id| id == &capability.id)
        && same_claim_target(layer_context, capability_context)
        && capability_may_claim_active_containment(capability, capability_context)
        && layer.claim_state == ClaimState::Active
        && layer.effective_mode == EffectiveMode::Enforce
        && matrix_is_pinned(layer_context.matrix)
        && freshness_is_current(&layer.freshness, layer_context)
        && layer.known_gaps.is_empty()
        && layer
            .covered_action_classes
            .iter()
            .any(|action| action == layer_context.action_class)
        && scope_is_host_verified(
            &layer.effective_scope,
            layer_context.scope_id,
            layer_context.scope_kind,
        )
        && evidence_set_is_verified(&layer.evidence, &layer.freshness)
        && stage_is_verified(&layer.convergence.configured, &layer.freshness)
        && stage_is_verified(&layer.convergence.loaded, &layer.freshness)
        && stage_is_verified(&layer.convergence.running, &layer.freshness)
        && stage_is_verified(&layer.convergence.enforcing, &layer.freshness)
        && stage_is_verified(&layer.convergence.verified_effective, &layer.freshness)
}

fn same_claim_target(
    left: &ContainmentClaimContext<'_>,
    right: &ContainmentClaimContext<'_>,
) -> bool {
    left.matrix == right.matrix
        && left.claim_id == right.claim_id
        && left.scope_id == right.scope_id
        && left.scope_kind == right.scope_kind
        && left.action_class == right.action_class
        && left.population == right.population
        && left.environment == right.environment
        && left.evaluated_at == right.evaluated_at
}

fn matrix_is_pinned(matrix: &VersionRef) -> bool {
    !matrix.id.trim().is_empty()
        && !matrix.version.trim().is_empty()
        && matrix.digest.len() == 71
        && matrix.digest.starts_with("sha256:")
        && matrix.digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn scope_is_host_verified(scopes: &[ScopeRef], id: &str, kind: ScopeKind) -> bool {
    scopes.iter().any(|scope| {
        scope.id == id
            && scope.kind == kind
            && scope.verification == ScopeVerification::HostVerified
            && !scope.evidence.is_empty()
            && scope
                .evidence
                .iter()
                .all(|evidence| evidence.integrity == IntegrityState::Verified)
    })
}

fn freshness_is_current(
    freshness: &EvidenceFreshness,
    context: &ContainmentClaimContext<'_>,
) -> bool {
    if freshness.state != FreshnessState::Fresh || freshness.budget_seconds == 0 {
        return false;
    }
    let (Some(observed_at), Some(reported_age)) =
        (freshness.observed_at.as_deref(), freshness.age_seconds)
    else {
        return false;
    };
    let Ok(generated_at) = chrono::DateTime::parse_from_rfc3339(context.generated_at) else {
        return false;
    };
    let Ok(evaluated_at) = chrono::DateTime::parse_from_rfc3339(context.evaluated_at) else {
        return false;
    };
    let Ok(observed_at) = chrono::DateTime::parse_from_rfc3339(observed_at) else {
        return false;
    };
    let producer_age = generated_at
        .signed_duration_since(observed_at)
        .num_seconds();
    let consumer_age = evaluated_at
        .signed_duration_since(observed_at)
        .num_seconds();
    observed_at <= generated_at
        && generated_at <= evaluated_at
        && producer_age >= 0
        && consumer_age >= 0
        && u64::try_from(producer_age).ok() == Some(reported_age)
        && u64::try_from(consumer_age)
            .ok()
            .is_some_and(|age| age <= freshness.budget_seconds)
}

fn claim_supports_context(
    claim: &crate::contract::ClaimRecord,
    context: &ContainmentClaimContext<'_>,
    freshness: &EvidenceFreshness,
) -> bool {
    let (Some(reviewed_at), Some(expires_at)) =
        (claim.reviewed_at.as_deref(), claim.expires_at.as_deref())
    else {
        return false;
    };
    let Ok(reviewed_at) = chrono::DateTime::parse_from_rfc3339(reviewed_at) else {
        return false;
    };
    let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return false;
    };
    let Ok(evaluated_at) = chrono::DateTime::parse_from_rfc3339(context.evaluated_at) else {
        return false;
    };

    claim.id == context.claim_id
        && claim.status == ClaimStatus::Verified
        && claim
            .versions
            .iter()
            .any(|version| version == context.matrix)
        && claim
            .statement
            .as_deref()
            .is_some_and(|statement| !statement.trim().is_empty())
        && claim.population == context.population
        && claim.environment == context.environment
        && claim.limitations.is_empty()
        && claim.observed_at.as_deref() == freshness.observed_at.as_deref()
        && reviewed_at <= expires_at
        && evaluated_at <= expires_at
        && scope_is_host_verified(&claim.scope, context.scope_id, context.scope_kind)
        && claim
            .action_classes
            .iter()
            .any(|action| action == context.action_class)
        && evidence_set_is_verified(&claim.evidence, freshness)
}

fn stage_is_verified(stage: &StageState, freshness: &EvidenceFreshness) -> bool {
    stage.state == StageAnswer::Yes && evidence_set_is_verified(&stage.evidence, freshness)
}

fn evidence_set_is_verified(evidence: &[EvidenceRef], freshness: &EvidenceFreshness) -> bool {
    !evidence.is_empty()
        && evidence
            .iter()
            .all(|item| item.integrity == IntegrityState::Verified)
        && evidence
            .iter()
            .any(|item| evidence_matches_freshness(item, freshness))
}

fn evidence_matches_freshness(evidence: &EvidenceRef, freshness: &EvidenceFreshness) -> bool {
    evidence.integrity == IntegrityState::Verified
        && evidence.freshness == *freshness
        && freshness.observed_at.as_deref() == Some(evidence.observed_at.as_str())
}
