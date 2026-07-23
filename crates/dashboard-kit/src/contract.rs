//! Stable Rust DTOs for `innerwarden.dashboard.v1`.
//!
//! The OpenAPI source of truth lives with feature 090. These DTOs deliberately
//! keep availability, configuration, runtime convergence, scope, freshness and
//! verified evidence separate so installation or licensing can never be
//! rendered as effective protection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
    Unsupported,
    NotConfigured,
    Loading,
    Degraded,
    Failed,
    Stale,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveMode {
    Disabled,
    Learning,
    Observe,
    Rehearse,
    Enforce,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entitlement {
    NotRequired,
    Valid,
    Grace,
    Expired,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    Supported,
    Partial,
    Experimental,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageAnswer {
    Yes,
    No,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutState {
    Ineligible,
    Eligible,
    Installed,
    Observing,
    Rehearsing,
    Ready,
    Canary,
    Enforcing,
    Degraded,
    Disarmed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Fresh,
    Stale,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    Verified,
    LocalChain,
    Unverified,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    RuntimeProbe,
    Sqlite,
    ResponseLifecycle,
    KernelState,
    LocalHistory,
    LocalGraph,
    Configuration,
    Licence,
    Telemetry,
    KnowledgeGraph,
    Operator,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthority {
    Canonical,
    Corroborating,
    Inferred,
    Fallback,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial,
    Lossy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Canonicalization {
    #[serde(rename = "RFC8785-JCS")]
    Rfc8785Jcs,
    #[serde(rename = "YAML-TO-RFC8785-JCS")]
    YamlToRfc8785Jcs,
    #[serde(rename = "RAW-UTF8-BYTES-SHA256")]
    RawUtf8BytesSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Agent,
    Session,
    ProcessTree,
    Workload,
    Cgroup,
    Container,
    Pod,
    Host,
    Tenant,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeVerification {
    HostVerified,
    Configured,
    Declared,
    Conflicting,
    Unattributed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTier {
    Community,
    EnterpriseCore,
    ComplianceExtension,
    FleetExtension,
    AdvancedIntelligenceExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Verified,
    Stale,
    Contradicted,
    Unverified,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardEdition {
    Community,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapState {
    NotCovered,
    Degraded,
    Stale,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    Active,
    VisibilityOnly,
    ReadinessOnly,
    Degraded,
    NotCovered,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRef {
    pub id: String,
    pub version: String,
    pub canonicalization: Canonicalization,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFreshness {
    pub observed_at: Option<String>,
    pub budget_seconds: u64,
    pub state: FreshnessState,
    pub age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub id: String,
    pub kind: String,
    pub source: SourceRef,
    pub observed_at: String,
    pub integrity: IntegrityState,
    pub redaction: Vec<String>,
    pub freshness: EvidenceFreshness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub id: String,
    pub kind: SourceKind,
    pub authority: SourceAuthority,
    pub version: Option<String>,
    pub completeness: Completeness,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRef {
    pub id: String,
    pub kind: ScopeKind,
    pub display_name: Option<String>,
    pub verification: ScopeVerification,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageState {
    pub state: StageAnswer,
    pub evidence: Vec<EvidenceRef>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConvergence {
    pub configured: StageState,
    pub loaded: StageState,
    pub running: StageState,
    pub enforcing: StageState,
    pub verified_effective: StageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub id: String,
    pub statement: Option<String>,
    pub semantic_key: Option<String>,
    pub status: ClaimStatus,
    /// Immutable references used to evaluate this claim. At least one must
    /// match the reviewed matrix selected by the consumer.
    pub versions: Vec<VersionRef>,
    pub population: String,
    pub environment: String,
    pub observed_at: Option<String>,
    pub reviewed_at: Option<String>,
    pub expires_at: Option<String>,
    pub scope: Vec<ScopeRef>,
    pub action_classes: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub id: String,
    pub tier: CapabilityTier,
    pub availability: Availability,
    pub entitlement: Entitlement,
    pub support: SupportLevel,
    pub desired_mode: EffectiveMode,
    pub effective_mode: EffectiveMode,
    pub convergence: RuntimeConvergence,
    pub rollout_state: RolloutState,
    pub health: HealthState,
    pub scope: Vec<ScopeRef>,
    pub covered_action_classes: Vec<String>,
    pub bypass_classes: Vec<String>,
    pub known_uncovered_paths: Vec<String>,
    pub freshness: EvidenceFreshness,
    pub last_evidence: Option<EvidenceRef>,
    pub sources: Vec<SourceRef>,
    pub claims: Vec<ClaimRecord>,
    pub reason_code: Option<String>,
    pub summary: String,
}

impl CapabilityStatus {
    /// Strict UI guardrail for one matrix-versioned scope and action class.
    /// This does not decide policy; it prevents the presentation layer from
    /// promoting configured, stale, partial or unverified state into a claim.
    pub fn may_claim_active_containment(
        &self,
        context: &crate::claims::ContainmentClaimContext<'_>,
    ) -> bool {
        crate::claims::capability_may_claim_active_containment(self, context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformStatus {
    pub os: String,
    pub architecture: String,
    /// An OS-level lead for readiness evaluation, not proof that kernel,
    /// privilege, sensor or enforcement prerequisites are satisfied.
    pub enterprise_candidate: bool,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSession {
    pub authenticated: bool,
    pub actor_id: Option<String>,
    pub role: Option<String>,
    pub scopes: Vec<ScopeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBoundary {
    pub storage: Vec<String>,
    pub redactions: Vec<String>,
    pub egress: Vec<EgressPath>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationClass {
    None,
    LocalProcess,
    CustomerManaged,
    VendorManaged,
    ThirdParty,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressState {
    Disabled,
    Configured,
    Active,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    NotRequired,
    Explicit,
    ConfiguredByAdmin,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    None,
    RequestLifetime,
    CustomerPolicy,
    VendorPolicy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub mode: RetentionMode,
    pub maximum_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalFallback {
    NotRequired,
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPath {
    pub id: String,
    pub destination_class: DestinationClass,
    pub purpose: String,
    pub data_classes: Vec<String>,
    pub state: EgressState,
    pub consent: ConsentState,
    pub retention: RetentionPolicy,
    pub redaction: Vec<String>,
    pub local_fallback: LocalFallback,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub id: String,
    pub capability_id: String,
    pub affected_scope: Vec<ScopeRef>,
    pub action_classes: Vec<String>,
    pub state: GapState,
    pub evidence: Vec<EvidenceRef>,
    pub next_step: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardBootstrap {
    pub schema_version: String,
    pub generated_at: String,
    pub edition: DashboardEdition,
    pub product_version: String,
    pub community_contract: VersionRef,
    pub assurance_matrix: Option<VersionRef>,
    pub authorization_matrix: Option<VersionRef>,
    pub platform: PlatformStatus,
    pub session: DashboardSession,
    pub capabilities: Vec<CapabilityStatus>,
    pub highest_priority_gap: Option<CoverageGap>,
    pub privacy: PrivacyBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionLayer {
    pub id: String,
    pub label: String,
    pub capability_ids: Vec<String>,
    pub claim_state: ClaimState,
    pub effective_mode: EffectiveMode,
    pub effective_scope: Vec<ScopeRef>,
    pub covered_action_classes: Vec<String>,
    pub known_gaps: Vec<CoverageGap>,
    pub freshness: EvidenceFreshness,
    pub convergence: RuntimeConvergence,
    pub evidence: Vec<EvidenceRef>,
}

impl ProtectionLayer {
    pub fn may_claim_active_containment(
        &self,
        capability: &CapabilityStatus,
        layer_context: &crate::claims::ContainmentClaimContext<'_>,
        capability_context: &crate::claims::ContainmentClaimContext<'_>,
    ) -> bool {
        crate::claims::layer_may_claim_active_containment(
            self,
            capability,
            layer_context,
            capability_context,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardPosture {
    pub schema_version: String,
    pub generated_at: String,
    pub layers: Vec<ProtectionLayer>,
    pub gaps: Vec<CoverageGap>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(state: StageAnswer, evidence: Option<EvidenceRef>) -> StageState {
        StageState {
            state,
            evidence: evidence.into_iter().collect(),
            reason_code: None,
        }
    }

    fn evidence() -> EvidenceRef {
        let freshness = EvidenceFreshness {
            observed_at: Some("2026-07-18T12:00:00Z".into()),
            budget_seconds: 30,
            state: FreshnessState::Fresh,
            age_seconds: Some(1),
        };
        EvidenceRef {
            id: "ev-1".into(),
            kind: "runtime_verification".into(),
            source: SourceRef {
                id: "kernel_state".into(),
                kind: SourceKind::KernelState,
                authority: SourceAuthority::Canonical,
                version: Some("1".into()),
                completeness: Completeness::Complete,
                limitations: Vec::new(),
            },
            observed_at: "2026-07-18T12:00:00Z".into(),
            integrity: IntegrityState::Verified,
            redaction: Vec::new(),
            freshness,
        }
    }

    fn enforcing_capability() -> CapabilityStatus {
        let ev = evidence();
        let scope = ScopeRef {
            id: "host-1".into(),
            kind: ScopeKind::Host,
            display_name: Some("pilot host".into()),
            verification: ScopeVerification::HostVerified,
            evidence: vec![ev.clone()],
        };
        CapabilityStatus {
            id: "kernel_execution_control".into(),
            tier: CapabilityTier::EnterpriseCore,
            availability: Availability::Available,
            entitlement: Entitlement::Valid,
            support: SupportLevel::Supported,
            desired_mode: EffectiveMode::Enforce,
            effective_mode: EffectiveMode::Enforce,
            convergence: RuntimeConvergence {
                configured: stage(StageAnswer::Yes, Some(ev.clone())),
                loaded: stage(StageAnswer::Yes, Some(ev.clone())),
                running: stage(StageAnswer::Yes, Some(ev.clone())),
                enforcing: stage(StageAnswer::Yes, Some(ev.clone())),
                verified_effective: stage(StageAnswer::Yes, Some(ev.clone())),
            },
            rollout_state: RolloutState::Enforcing,
            health: HealthState::Healthy,
            scope: vec![scope.clone()],
            covered_action_classes: vec!["process_execution".into()],
            bypass_classes: Vec::new(),
            known_uncovered_paths: Vec::new(),
            freshness: EvidenceFreshness {
                observed_at: Some(ev.observed_at.clone()),
                budget_seconds: 30,
                state: FreshnessState::Fresh,
                age_seconds: Some(1),
            },
            last_evidence: Some(ev.clone()),
            sources: Vec::new(),
            claims: vec![ClaimRecord {
                id: "claim-1".into(),
                statement: Some("execution attempts in the declared host scope are blocked".into()),
                semantic_key: None,
                status: ClaimStatus::Verified,
                versions: vec![assurance_matrix()],
                population: "host-1".into(),
                environment: "linux".into(),
                observed_at: Some(ev.observed_at.clone()),
                reviewed_at: Some("2026-07-18T12:00:00Z".into()),
                expires_at: Some("2026-07-18T12:01:00Z".into()),
                scope: vec![scope],
                action_classes: vec!["process_execution".into()],
                evidence: vec![ev],
                limitations: Vec::new(),
            }],
            reason_code: None,
            summary: "verified runtime enforcement".into(),
        }
    }

    fn claim_context<'a>(matrix: &'a VersionRef) -> crate::claims::ContainmentClaimContext<'a> {
        crate::claims::ContainmentClaimContext {
            matrix,
            claim_id: "claim-1",
            scope_id: "host-1",
            scope_kind: ScopeKind::Host,
            action_class: "process_execution",
            population: "host-1",
            environment: "linux",
            generated_at: "2026-07-18T12:00:01Z",
            evaluated_at: "2026-07-18T12:00:01Z",
        }
    }

    fn assurance_matrix() -> VersionRef {
        VersionRef {
            id: "innerwarden.assurance-matrix".into(),
            version: "AM-090-v1".into(),
            canonicalization: Canonicalization::YamlToRfc8785Jcs,
            digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn enforcing_layer(capability: &CapabilityStatus) -> ProtectionLayer {
        ProtectionLayer {
            id: "independent_host_layer".into(),
            label: "Independent host layer".into(),
            capability_ids: vec![capability.id.clone()],
            claim_state: ClaimState::Active,
            effective_mode: EffectiveMode::Enforce,
            effective_scope: capability.scope.clone(),
            covered_action_classes: capability.covered_action_classes.clone(),
            known_gaps: Vec::new(),
            freshness: capability.freshness.clone(),
            convergence: capability.convergence.clone(),
            evidence: capability.last_evidence.clone().into_iter().collect(),
        }
    }

    #[test]
    fn only_fresh_verified_enforce_can_back_containment_wording() {
        let current = enforcing_capability();
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);
        assert!(current.may_claim_active_containment(&context));

        let mut observe = current.clone();
        observe.effective_mode = EffectiveMode::Observe;
        assert!(!observe.may_claim_active_containment(&context));

        let mut stale = current.clone();
        stale.freshness.state = FreshnessState::Stale;
        assert!(!stale.may_claim_active_containment(&context));

        let mut unverified = current;
        unverified.convergence.verified_effective.state = StageAnswer::Unknown;
        assert!(!unverified.may_claim_active_containment(&context));
    }

    #[test]
    fn unsupported_declared_or_unverified_host_state_never_backs_containment() {
        let current = enforcing_capability();
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);

        let mut unsupported = current.clone();
        unsupported.support = SupportLevel::Unsupported;
        assert!(!unsupported.may_claim_active_containment(&context));

        let mut declared = current.clone();
        declared.scope[0].verification = ScopeVerification::Declared;
        assert!(!declared.may_claim_active_containment(&context));

        let mut weak_integrity = current;
        weak_integrity.last_evidence.as_mut().unwrap().integrity = IntegrityState::Unverified;
        assert!(!weak_integrity.may_claim_active_containment(&context));
    }

    #[test]
    fn mismatched_scope_action_or_timestamp_never_backs_containment() {
        let current = enforcing_capability();
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);

        let mut wrong_scope = current.clone();
        wrong_scope.claims[0].scope[0].id = "host-elsewhere".into();
        assert!(!wrong_scope.may_claim_active_containment(&context));

        let mut wrong_action = current.clone();
        wrong_action.claims[0].action_classes = vec!["secret_read".into()];
        assert!(!wrong_action.may_claim_active_containment(&context));

        let mut contradictory_time = current;
        contradictory_time.freshness.observed_at = Some("2026-07-18T11:00:00Z".into());
        assert!(!contradictory_time.may_claim_active_containment(&context));
    }

    #[test]
    fn exact_matrix_rollout_population_environment_and_limitations_are_required() {
        let current = enforcing_capability();
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);

        let mut wrong_matrix = current.clone();
        wrong_matrix.claims[0].versions[0].digest = format!("sha256:{}", "b".repeat(64));
        assert!(!wrong_matrix.may_claim_active_containment(&context));

        let mut not_enforcing = current.clone();
        not_enforcing.rollout_state = RolloutState::Canary;
        assert!(!not_enforcing.may_claim_active_containment(&context));

        let mut wrong_population = current.clone();
        wrong_population.claims[0].population = "other-host".into();
        assert!(!wrong_population.may_claim_active_containment(&context));

        let mut wrong_environment = current.clone();
        wrong_environment.claims[0].environment = "staging".into();
        assert!(!wrong_environment.may_claim_active_containment(&context));

        let mut limited = current;
        limited.claims[0]
            .limitations
            .push("one execution path is excluded".into());
        assert!(!limited.may_claim_active_containment(&context));
    }

    #[test]
    fn consumer_clock_rejects_future_and_frozen_snapshots() {
        let current = enforcing_capability();
        let matrix = assurance_matrix();

        let mut future = claim_context(&matrix);
        future.evaluated_at = "2026-07-18T11:59:59Z";
        assert!(!current.may_claim_active_containment(&future));

        let mut frozen = claim_context(&matrix);
        frozen.evaluated_at = "2026-07-18T12:00:31Z";
        assert!(!current.may_claim_active_containment(&frozen));
    }

    #[test]
    fn layer_requires_a_corresponding_fully_converged_capability() {
        let capability = enforcing_capability();
        let layer = enforcing_layer(&capability);
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);
        assert!(layer.may_claim_active_containment(&capability, &context, &context));

        let later_capability = capability.clone();
        let mut layer_context = claim_context(&matrix);
        layer_context.evaluated_at = "2026-07-18T12:00:02Z";
        let mut capability_context = claim_context(&matrix);
        capability_context.evaluated_at = "2026-07-18T12:00:02Z";
        assert!(layer.may_claim_active_containment(
            &later_capability,
            &layer_context,
            &capability_context
        ));

        let mut not_verified = capability.clone();
        not_verified.convergence.verified_effective.state = StageAnswer::No;
        assert!(!layer.may_claim_active_containment(&not_verified, &context, &context));

        let mut unrelated = capability;
        unrelated.id = "unrelated_visibility".into();
        assert!(!layer.may_claim_active_containment(&unrelated, &context, &context));
    }

    #[test]
    fn unavailable_values_round_trip_without_becoming_zero_or_false_claims() {
        let mut capability = enforcing_capability();
        let matrix = assurance_matrix();
        let context = claim_context(&matrix);
        capability.availability = Availability::Unknown;
        capability.last_evidence = None;
        capability.freshness.age_seconds = None;
        let encoded = serde_json::to_string(&capability).unwrap();
        assert!(encoded.contains("\"availability\":\"unknown\""));
        assert!(encoded.contains("\"age_seconds\":null"));
        assert!(!capability.may_claim_active_containment(&context));
    }
}
