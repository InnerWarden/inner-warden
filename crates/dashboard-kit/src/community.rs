//! Pure Community projections for the shared dashboard foundation contract.
//!
//! The caller supplies already-bounded observations. This module neither scans
//! the machine nor writes configuration, so it can be reused without turning
//! the Community HTTP server into an Enterprise control plane.

use chrono::{SecondsFormat, Utc};

use crate::contract::{
    Availability, CapabilityStatus, CapabilityTier, ClaimState, Completeness, DashboardBootstrap,
    DashboardEdition, DashboardPosture, DashboardSession, EffectiveMode, Entitlement,
    EvidenceFreshness, EvidenceRef, FreshnessState, HealthState, IntegrityState, PlatformStatus,
    PrivacyBoundary, ProtectionLayer, RolloutState, RuntimeConvergence, ScopeKind, ScopeRef,
    ScopeVerification, SourceAuthority, SourceKind, SourceRef, StageAnswer, StageState,
    SupportLevel,
};
use crate::versions;

#[derive(Debug, Clone)]
pub struct CommunityProjectionInput {
    pub generated_at: String,
    pub generated_at_ms: u64,
    pub product_version: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub exposed: bool,
    /// Desired/configured agent-side mode. It is never promoted to an effective
    /// runtime mode without separate evidence.
    pub configured_guardrail_mode: EffectiveMode,
    pub guarded_agents: usize,
    pub discovery_availability: Availability,
    pub discovery_observed_at_ms: Option<u64>,
    pub discovery_freshness_budget_seconds: u64,
    pub token_availability: Availability,
    pub token_observed_at_ms: Option<u64>,
    pub token_freshness_budget_seconds: u64,
    pub local_record_availability: Availability,
    pub local_record_observed_at_ms: Option<u64>,
    pub local_record_freshness_budget_seconds: u64,
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn build_bootstrap(input: &CommunityProjectionInput) -> DashboardBootstrap {
    DashboardBootstrap {
        schema_version: versions::SCHEMA_VERSION.into(),
        generated_at: input.generated_at.clone(),
        edition: DashboardEdition::Community,
        product_version: input.product_version.clone(),
        community_contract: versions::community_journey_contract(),
        assurance_matrix: None,
        authorization_matrix: None,
        platform: PlatformStatus {
            os: input.platform_os.clone(),
            architecture: input.platform_architecture.clone(),
            enterprise_candidate: input.platform_os == "linux",
            reason_code: (input.platform_os != "linux")
                .then(|| "independent_host_enforcement_requires_supported_linux".into()),
        },
        session: DashboardSession {
            authenticated: false,
            actor_id: None,
            role: None,
            scopes: Vec::new(),
        },
        capabilities: build_capabilities(input),
        // Community absence alone is not a sales gap. A CTA may be derived only
        // after the user declares or evidence identifies a scoped assurance gap.
        highest_priority_gap: None,
        privacy: PrivacyBoundary {
            storage: vec!["local_configuration_and_history".into()],
            redactions: vec![
                "prompts_responses_and_tool_content_not_returned_by_token_intelligence".into(),
                "common_secret_patterns_redacted_from_local_decision_record".into(),
            ],
            // Socket exposure is reported separately. An empty list means no
            // structured egress path was observed; it does not infer local-only.
            egress: Vec::new(),
        },
    }
}

pub fn build_posture(input: &CommunityProjectionInput) -> DashboardPosture {
    let capabilities = build_capabilities(input);
    let guardrail = capabilities
        .iter()
        .find(|capability| capability.id == "community.agent_guardrails")
        .expect("Community projection always contains agent guardrails");
    DashboardPosture {
        schema_version: versions::SCHEMA_VERSION.into(),
        generated_at: input.generated_at.clone(),
        layers: vec![
            ProtectionLayer {
                id: "agent_layer".into(),
                label: "Agent layer".into(),
                capability_ids: vec![guardrail.id.clone()],
                // Configuration is useful posture, but not fresh proof that an
                // agent has restarted or every current action is intercepted.
                claim_state: if input.guarded_agents == 0 {
                    ClaimState::Unavailable
                } else {
                    ClaimState::Unknown
                },
                effective_mode: EffectiveMode::Unknown,
                // Configured integration scope is retained on the capability,
                // but no scope is called effective without runtime evidence.
                effective_scope: Vec::new(),
                covered_action_classes: Vec::new(),
                known_gaps: Vec::new(),
                freshness: guardrail.freshness.clone(),
                convergence: guardrail.convergence.clone(),
                evidence: guardrail.last_evidence.clone().into_iter().collect(),
            },
            ProtectionLayer {
                id: "independent_host_layer".into(),
                label: "Independent host layer".into(),
                capability_ids: Vec::new(),
                claim_state: ClaimState::Unavailable,
                effective_mode: EffectiveMode::Disabled,
                effective_scope: Vec::new(),
                covered_action_classes: Vec::new(),
                known_gaps: Vec::new(),
                freshness: missing_freshness(),
                convergence: unknown_convergence("independent_host_runtime_not_available"),
                evidence: Vec::new(),
            },
        ],
        gaps: Vec::new(),
    }
}

fn build_capabilities(input: &CommunityProjectionInput) -> Vec<CapabilityStatus> {
    vec![
        agent_guardrail_capability(input),
        visibility_capability(
            input,
            "community.agent_discovery",
            input.discovery_availability,
            input.discovery_observed_at_ms,
            input.discovery_freshness_budget_seconds,
            SourceKind::RuntimeProbe,
            "Bounded local agent discovery; identity and integration remain independent.",
        ),
        visibility_capability(
            input,
            "community.token_intelligence",
            input.token_availability,
            input.token_observed_at_ms,
            input.token_freshness_budget_seconds,
            SourceKind::LocalHistory,
            "Numeric retained-history counters only; partial and not a billing statement.",
        ),
        visibility_capability(
            input,
            "community.local_decision_record",
            input.local_record_availability,
            input.local_record_observed_at_ms,
            input.local_record_freshness_budget_seconds,
            SourceKind::LocalGraph,
            "Local decisions and execution evidence where recorded; deny is not inferred as blocked.",
        ),
        static_capability(
            input,
            "community.ai_jail",
            // Platform support is not installation/runtime evidence. Until a
            // dedicated adapter verifies the actual jail implementation on
            // this machine, availability must remain unknown.
            Availability::Unknown,
            if matches!(input.platform_os.as_str(), "linux" | "macos") {
                SupportLevel::Supported
            } else {
                SupportLevel::Unsupported
            },
            "AI Jail support is known by platform; local availability remains unknown until a runtime adapter verifies it.",
        ),
        static_capability(
            input,
            "community.notifications",
            // The Community dashboard intentionally does not read the shared
            // notification config or attempt delivery probes. This is an
            // explicit absence of dashboard evidence, not proof that channels
            // are disabled, failed, healthy, or configured.
            Availability::Unavailable,
            SupportLevel::Supported,
            "Notification configuration and delivery status are unavailable to the read-only dashboard; use the local CLI.",
        ),
    ]
}

fn agent_guardrail_capability(input: &CommunityProjectionInput) -> CapabilityStatus {
    let configured = input.guarded_agents > 0;
    let evidence = configured
        .then(|| {
            observation_evidence(
                input,
                "agent_guardrail_configuration",
                input.discovery_observed_at_ms,
                input.discovery_freshness_budget_seconds,
                SourceKind::Configuration,
            )
        })
        .flatten();
    let scope = configured
        .then(|| ScopeRef {
            id: "configured-agent-integrations".into(),
            kind: ScopeKind::Resource,
            display_name: Some(format!(
                "{} configured agent integration(s)",
                input.guarded_agents
            )),
            verification: ScopeVerification::Configured,
            evidence: evidence.clone().into_iter().collect(),
        })
        .into_iter()
        .collect();
    CapabilityStatus {
        id: "community.agent_guardrails".into(),
        tier: CapabilityTier::Community,
        availability: if configured {
            Availability::Available
        } else {
            Availability::NotConfigured
        },
        entitlement: Entitlement::NotRequired,
        support: SupportLevel::Supported,
        desired_mode: input.configured_guardrail_mode,
        effective_mode: EffectiveMode::Unknown,
        convergence: RuntimeConvergence {
            configured: stage(
                if configured {
                    StageAnswer::Yes
                } else {
                    StageAnswer::No
                },
                evidence.clone(),
                None,
            ),
            loaded: stage(
                StageAnswer::Unknown,
                None,
                Some("agent_restart_not_verified"),
            ),
            running: stage(StageAnswer::Unknown, None, Some("runtime_not_verified")),
            enforcing: stage(StageAnswer::Unknown, None, Some("runtime_not_verified")),
            verified_effective: stage(
                StageAnswer::Unknown,
                None,
                Some("no_independent_runtime_outcome_for_aggregate_scope"),
            ),
        },
        rollout_state: if configured {
            RolloutState::Installed
        } else {
            RolloutState::Eligible
        },
        health: HealthState::Unknown,
        scope,
        covered_action_classes: Vec::new(),
        bypass_classes: vec![
            "unmediated_agent_action".into(),
            "disabled_agent_surface".into(),
        ],
        known_uncovered_paths: vec![
            "actions_outside_confirmed_hook_or_mcp_mediation".into(),
            "agent_layer_tamper_or_bypass".into(),
        ],
        freshness: observation_freshness(
            input,
            configured
                .then_some(input.discovery_observed_at_ms)
                .flatten(),
            input.discovery_freshness_budget_seconds,
        ),
        last_evidence: evidence,
        sources: vec![SourceRef {
            id: "community_agent_configuration".into(),
            kind: SourceKind::Configuration,
            authority: SourceAuthority::Canonical,
            version: Some(input.product_version.clone()),
            completeness: Completeness::Partial,
            limitations: vec!["configuration_does_not_prove_runtime_effectiveness".into()],
        }],
        claims: Vec::new(),
        reason_code: (!configured).then(|| "no_effective_reviewed_wiring_detected".into()),
        summary: if configured {
            format!(
                "{} agent integration(s) are configured; current runtime interception is not independently verified.",
                input.guarded_agents
            )
        } else {
            "No effective reviewed agent wiring is currently detected.".into()
        },
    }
}

fn visibility_capability(
    input: &CommunityProjectionInput,
    id: &str,
    availability: Availability,
    observed_at_ms: Option<u64>,
    freshness_budget_seconds: u64,
    source_kind: SourceKind,
    summary: &str,
) -> CapabilityStatus {
    let freshness = observation_freshness(input, observed_at_ms, freshness_budget_seconds);
    let availability = match freshness.state {
        FreshnessState::Stale
            if matches!(
                availability,
                Availability::Available | Availability::Degraded
            ) =>
        {
            Availability::Stale
        }
        FreshnessState::Missing | FreshnessState::Unknown
            if matches!(
                availability,
                Availability::Available | Availability::Degraded
            ) =>
        {
            Availability::Unknown
        }
        _ => availability,
    };
    let observed = matches!(
        availability,
        Availability::Available | Availability::Degraded
    ) && observed_at_ms.is_some();
    let evidence = observation_evidence(
        input,
        id,
        observed_at_ms,
        freshness_budget_seconds,
        source_kind,
    );
    CapabilityStatus {
        id: id.into(),
        tier: CapabilityTier::Community,
        availability,
        entitlement: Entitlement::NotRequired,
        support: SupportLevel::Supported,
        desired_mode: EffectiveMode::Disabled,
        effective_mode: EffectiveMode::Disabled,
        convergence: RuntimeConvergence {
            configured: stage(StageAnswer::NotApplicable, None, None),
            loaded: stage(StageAnswer::NotApplicable, None, None),
            running: stage(
                if observed {
                    StageAnswer::Yes
                } else {
                    StageAnswer::Unknown
                },
                evidence.clone(),
                (!observed).then_some("producer_not_currently_available"),
            ),
            enforcing: stage(StageAnswer::NotApplicable, None, None),
            verified_effective: stage(StageAnswer::NotApplicable, None, None),
        },
        rollout_state: RolloutState::Installed,
        health: if observed {
            HealthState::Healthy
        } else {
            HealthState::Unknown
        },
        scope: Vec::new(),
        covered_action_classes: Vec::new(),
        bypass_classes: Vec::new(),
        known_uncovered_paths: Vec::new(),
        freshness,
        last_evidence: evidence,
        sources: vec![SourceRef {
            id: id.into(),
            kind: source_kind,
            authority: SourceAuthority::Canonical,
            version: Some(input.product_version.clone()),
            completeness: Completeness::Partial,
            limitations: Vec::new(),
        }],
        claims: Vec::new(),
        reason_code: (!observed).then(|| "producer_unavailable_or_loading".into()),
        summary: summary.into(),
    }
}

fn static_capability(
    input: &CommunityProjectionInput,
    id: &str,
    availability: Availability,
    support: SupportLevel,
    summary: &str,
) -> CapabilityStatus {
    CapabilityStatus {
        id: id.into(),
        tier: CapabilityTier::Community,
        availability,
        entitlement: Entitlement::NotRequired,
        support,
        desired_mode: EffectiveMode::Disabled,
        effective_mode: EffectiveMode::Unknown,
        convergence: RuntimeConvergence {
            configured: stage(StageAnswer::Unknown, None, Some("not_projected")),
            loaded: stage(StageAnswer::Unknown, None, Some("not_projected")),
            running: stage(StageAnswer::Unknown, None, Some("not_projected")),
            enforcing: stage(StageAnswer::NotApplicable, None, None),
            verified_effective: stage(StageAnswer::NotApplicable, None, None),
        },
        rollout_state: match availability {
            Availability::Unsupported => RolloutState::Ineligible,
            Availability::Available => RolloutState::Eligible,
            _ => RolloutState::Unknown,
        },
        health: HealthState::Unknown,
        scope: Vec::new(),
        covered_action_classes: Vec::new(),
        bypass_classes: Vec::new(),
        known_uncovered_paths: Vec::new(),
        freshness: missing_freshness(),
        last_evidence: None,
        sources: vec![SourceRef {
            id: "compiled_community_capability".into(),
            kind: SourceKind::Configuration,
            authority: SourceAuthority::Canonical,
            version: Some(input.product_version.clone()),
            completeness: Completeness::Partial,
            limitations: vec!["availability_does_not_mean_active".into()],
        }],
        claims: Vec::new(),
        reason_code: match availability {
            Availability::Unknown => Some("not_projected".into()),
            Availability::Unavailable => Some("unavailable_to_read_only_dashboard".into()),
            _ => None,
        },
        summary: summary.into(),
    }
}

fn stage(state: StageAnswer, evidence: Option<EvidenceRef>, reason: Option<&str>) -> StageState {
    StageState {
        state,
        evidence: evidence.into_iter().collect(),
        reason_code: reason.map(str::to_owned),
    }
}

fn unknown_convergence(reason: &str) -> RuntimeConvergence {
    RuntimeConvergence {
        configured: stage(StageAnswer::Unknown, None, Some(reason)),
        loaded: stage(StageAnswer::Unknown, None, Some(reason)),
        running: stage(StageAnswer::Unknown, None, Some(reason)),
        enforcing: stage(StageAnswer::Unknown, None, Some(reason)),
        verified_effective: stage(StageAnswer::Unknown, None, Some(reason)),
    }
}

fn observation_evidence(
    input: &CommunityProjectionInput,
    kind: &str,
    observed_at_ms: Option<u64>,
    budget_seconds: u64,
    source_kind: SourceKind,
) -> Option<EvidenceRef> {
    let observed_at = observed_at_ms.and_then(rfc3339_from_epoch_ms)?;
    Some(EvidenceRef {
        id: format!("{kind}:{observed_at}"),
        kind: kind.into(),
        source: SourceRef {
            id: "community_dashboard_projection".into(),
            kind: source_kind,
            authority: SourceAuthority::Canonical,
            version: Some(input.product_version.clone()),
            completeness: Completeness::Partial,
            limitations: vec!["projection_does_not_prove_runtime_effectiveness".into()],
        },
        observed_at: observed_at.clone(),
        integrity: IntegrityState::Unverified,
        redaction: Vec::new(),
        freshness: observation_freshness(input, observed_at_ms, budget_seconds),
    })
}

fn observation_freshness(
    input: &CommunityProjectionInput,
    observed_at_ms: Option<u64>,
    budget_seconds: u64,
) -> EvidenceFreshness {
    let budget_seconds = budget_seconds.clamp(1, 9_007_199_254_740_991);
    let Some(observed_at_ms) = observed_at_ms else {
        return missing_freshness_with_budget(budget_seconds);
    };
    let Some(observed_at) = rfc3339_from_epoch_ms(observed_at_ms) else {
        return missing_freshness_with_budget(budget_seconds);
    };
    if observed_at_ms > input.generated_at_ms {
        return EvidenceFreshness {
            observed_at: Some(observed_at),
            budget_seconds,
            state: FreshnessState::Unknown,
            age_seconds: None,
        };
    }
    let age_seconds = (input.generated_at_ms - observed_at_ms) / 1_000;
    EvidenceFreshness {
        observed_at: Some(observed_at),
        budget_seconds,
        state: if age_seconds <= budget_seconds {
            FreshnessState::Fresh
        } else {
            FreshnessState::Stale
        },
        age_seconds: Some(age_seconds),
    }
}

fn missing_freshness() -> EvidenceFreshness {
    missing_freshness_with_budget(30)
}

fn missing_freshness_with_budget(budget_seconds: u64) -> EvidenceFreshness {
    EvidenceFreshness {
        observed_at: None,
        budget_seconds: budget_seconds.clamp(1, 9_007_199_254_740_991),
        state: FreshnessState::Missing,
        age_seconds: None,
    }
}

fn rfc3339_from_epoch_ms(epoch_ms: u64) -> Option<String> {
    let epoch_ms = i64::try_from(epoch_ms).ok()?;
    chrono::DateTime::<Utc>::from_timestamp_millis(epoch_ms)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix() -> crate::contract::VersionRef {
        crate::contract::VersionRef {
            id: "innerwarden.assurance-matrix".into(),
            version: "AM-090-v1".into(),
            canonicalization: crate::contract::Canonicalization::YamlToRfc8785Jcs,
            digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn input(os: &str, mode: EffectiveMode, guarded_agents: usize) -> CommunityProjectionInput {
        CommunityProjectionInput {
            generated_at: "2026-07-18T12:00:00.000Z".into(),
            generated_at_ms: 1_768_564_800_000,
            product_version: "0.16.4-rc.1".into(),
            platform_os: os.into(),
            platform_architecture: "aarch64".into(),
            exposed: false,
            configured_guardrail_mode: mode,
            guarded_agents,
            discovery_availability: Availability::Available,
            discovery_observed_at_ms: Some(1_768_564_790_000),
            discovery_freshness_budget_seconds: 65,
            token_availability: Availability::Available,
            token_observed_at_ms: Some(1_768_564_500_000),
            token_freshness_budget_seconds: 660,
            local_record_availability: Availability::Available,
            local_record_observed_at_ms: Some(1_768_564_790_000),
            local_record_freshness_budget_seconds: 65,
        }
    }

    #[test]
    fn configured_enforce_is_not_promoted_to_effective_or_verified() {
        let bootstrap = build_bootstrap(&input("macos", EffectiveMode::Enforce, 2));
        let guardrail = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.agent_guardrails")
            .unwrap();
        assert_eq!(guardrail.desired_mode, EffectiveMode::Enforce);
        assert_eq!(guardrail.effective_mode, EffectiveMode::Unknown);
        assert_eq!(
            guardrail.convergence.verified_effective.state,
            StageAnswer::Unknown
        );
        let matrix = matrix();
        let context = crate::claims::ContainmentClaimContext {
            matrix: &matrix,
            claim_id: "community-agent-guardrail",
            scope_id: "configured-agent-integrations",
            scope_kind: ScopeKind::Resource,
            action_class: "process_execution",
            population: "configured-agent-integrations",
            environment: "macos",
            generated_at: bootstrap.generated_at.as_str(),
            evaluated_at: bootstrap.generated_at.as_str(),
        };
        assert!(!guardrail.may_claim_active_containment(&context));
        assert!(bootstrap.assurance_matrix.is_none());
        assert!(bootstrap.authorization_matrix.is_none());
        assert!(bootstrap.highest_priority_gap.is_none());
    }

    #[test]
    fn unsupported_host_keeps_community_healthy_without_linux_claims() {
        let bootstrap = build_bootstrap(&input("macos", EffectiveMode::Observe, 1));
        assert_eq!(bootstrap.edition, DashboardEdition::Community);
        assert!(!bootstrap.platform.enterprise_candidate);
        let posture = build_posture(&input("macos", EffectiveMode::Observe, 1));
        let host = posture
            .layers
            .iter()
            .find(|layer| layer.id == "independent_host_layer")
            .unwrap();
        assert_eq!(host.claim_state, ClaimState::Unavailable);
        let matrix = matrix();
        let context = crate::claims::ContainmentClaimContext {
            matrix: &matrix,
            claim_id: "independent-host-layer",
            scope_id: "host-1",
            scope_kind: ScopeKind::Host,
            action_class: "process_execution",
            population: "host-1",
            environment: "macos",
            generated_at: posture.generated_at.as_str(),
            evaluated_at: posture.generated_at.as_str(),
        };
        assert!(!host.may_claim_active_containment(&bootstrap.capabilities[0], &context, &context));
        assert!(
            posture.gaps.is_empty(),
            "Enterprise absence alone is not a sales incident"
        );
        let agent = posture
            .layers
            .iter()
            .find(|layer| layer.id == "agent_layer")
            .unwrap();
        assert!(agent.effective_scope.is_empty());
    }

    #[test]
    fn a_stalled_snapshot_cannot_refresh_its_own_freshness() {
        let mut stalled = input("linux", EffectiveMode::Enforce, 1);
        stalled.generated_at_ms = 1_768_565_800_000;
        stalled.generated_at = "2026-01-16T00:16:40.000Z".into();
        let bootstrap = build_bootstrap(&stalled);
        let discovery = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.agent_discovery")
            .unwrap();
        assert_eq!(discovery.availability, Availability::Stale);
        assert_eq!(discovery.freshness.state, FreshnessState::Stale);
        assert!(discovery.freshness.age_seconds.unwrap() > 65);
        assert_ne!(
            discovery.freshness.observed_at.as_deref(),
            Some(stalled.generated_at.as_str())
        );
    }

    #[test]
    fn a_future_observation_never_becomes_fresh_or_available() {
        let mut future = input("linux", EffectiveMode::Observe, 0);
        future.discovery_observed_at_ms = Some(future.generated_at_ms + 1);
        let bootstrap = build_bootstrap(&future);
        let discovery = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.agent_discovery")
            .unwrap();
        assert_eq!(discovery.freshness.state, FreshnessState::Unknown);
        assert_eq!(discovery.freshness.age_seconds, None);
        assert_eq!(discovery.availability, Availability::Unknown);
        assert_eq!(discovery.convergence.running.state, StageAnswer::Unknown);
        assert_eq!(discovery.health, HealthState::Unknown);
    }

    #[test]
    fn ai_jail_availability_is_unknown_without_adapter_evidence() {
        for os in ["linux", "macos", "windows"] {
            let bootstrap = build_bootstrap(&input(os, EffectiveMode::Observe, 0));
            let jail = bootstrap
                .capabilities
                .iter()
                .find(|capability| capability.id == "community.ai_jail")
                .unwrap();
            assert_eq!(jail.availability, Availability::Unknown);
            assert_eq!(jail.effective_mode, EffectiveMode::Unknown);
            assert!(jail.claims.is_empty());
        }
    }
}
