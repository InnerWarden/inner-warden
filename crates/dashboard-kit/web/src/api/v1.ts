export const DASHBOARD_SCHEMA_VERSION = "innerwarden.dashboard.v1" as const;

export type Availability =
  | "available"
  | "unavailable"
  | "unsupported"
  | "not_configured"
  | "loading"
  | "degraded"
  | "failed"
  | "stale"
  | "unknown";

export type EffectiveMode = "disabled" | "learning" | "observe" | "rehearse" | "enforce" | "mixed" | "unknown";
export type StageAnswer = "yes" | "no" | "unknown" | "not_applicable";
export type FreshnessState = "fresh" | "stale" | "missing" | "unknown";
export type ClaimState = "active" | "visibility_only" | "readiness_only" | "degraded" | "not_covered" | "unavailable" | "unknown";
export type SecurityOutcome =
  | "observed_only"
  | "allowed"
  | "blocked_before_execution"
  | "would_block"
  | "contained"
  | "failed"
  | "reverted"
  | "not_observed"
  | "unknown";
export type IdentityConfidence = "host_verified" | "configured" | "declared" | "conflicting" | "unattributed";
export type SourceKind =
  | "runtime_probe"
  | "sqlite"
  | "response_lifecycle"
  | "kernel_state"
  | "local_history"
  | "local_graph"
  | "configuration"
  | "licence"
  | "telemetry"
  | "knowledge_graph"
  | "operator"
  | "unknown";

export type Canonicalization = "RFC8785-JCS" | "YAML-TO-RFC8785-JCS" | "RAW-UTF8-BYTES-SHA256";
export type VersionRef = { id: string; version: string; canonicalization: Canonicalization; digest: string };
export type EvidenceFreshness = {
  observed_at: string | null;
  budget_seconds: number;
  state: FreshnessState;
  age_seconds: number | null;
};
export type EvidenceRef = {
  id: string;
  kind: string;
  source: SourceRef;
  observed_at: string;
  integrity: "verified" | "local_chain" | "unverified" | "unknown";
  redaction: string[];
  freshness: EvidenceFreshness;
};
export type SourceRef = {
  id: string;
  kind: SourceKind;
  authority: "canonical" | "corroborating" | "inferred" | "fallback" | "unknown";
  version: string | null;
  completeness: "complete" | "partial" | "lossy" | "unknown";
  limitations: string[];
};
export type ScopeRef = {
  id: string;
  kind: "agent" | "session" | "process_tree" | "workload" | "cgroup" | "container" | "pod" | "host" | "tenant" | "resource";
  display_name: string | null;
  verification: IdentityConfidence;
  evidence: EvidenceRef[];
};
export type StageState = { state: StageAnswer; evidence: EvidenceRef[]; reason_code: string | null };
export type RuntimeConvergence = {
  configured: StageState;
  loaded: StageState;
  running: StageState;
  enforcing: StageState;
  verified_effective: StageState;
};
export type ClaimRecord = {
  id: string;
  statement: string | null;
  semantic_key: string | null;
  status: "verified" | "stale" | "contradicted" | "unverified" | "not_applicable";
  versions: VersionRef[];
  population: string;
  environment: string;
  observed_at: string | null;
  reviewed_at: string | null;
  expires_at: string | null;
  scope: ScopeRef[];
  action_classes: string[];
  evidence: EvidenceRef[];
  limitations: string[];
};
export type CapabilityStatus = {
  id: string;
  tier: "community" | "enterprise_core" | "compliance_extension" | "fleet_extension" | "advanced_intelligence_extension";
  availability: Availability;
  entitlement: "not_required" | "valid" | "grace" | "expired" | "invalid" | "unknown";
  support: "supported" | "partial" | "experimental" | "unsupported" | "unknown";
  desired_mode: EffectiveMode;
  effective_mode: EffectiveMode;
  convergence: RuntimeConvergence;
  rollout_state: "ineligible" | "eligible" | "installed" | "observing" | "rehearsing" | "ready" | "canary" | "enforcing" | "degraded" | "disarmed" | "unknown";
  health: "healthy" | "degraded" | "failed" | "unknown";
  scope: ScopeRef[];
  covered_action_classes: string[];
  bypass_classes: string[];
  known_uncovered_paths: string[];
  freshness: EvidenceFreshness;
  last_evidence: EvidenceRef | null;
  sources: SourceRef[];
  claims: ClaimRecord[];
  reason_code: string | null;
  summary: string;
};
export type CoverageGap = {
  id: string;
  capability_id: string;
  affected_scope: ScopeRef[];
  action_classes: string[];
  state: "not_covered" | "degraded" | "stale" | "unknown" | "unsupported";
  evidence: EvidenceRef[];
  next_step: string;
};
export type DashboardBootstrap = {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  generated_at: string;
  edition: "community" | "enterprise";
  product_version: string;
  community_contract: VersionRef;
  assurance_matrix: VersionRef | null;
  authorization_matrix: VersionRef | null;
  platform: { os: string; architecture: string; enterprise_candidate: boolean; reason_code: string | null };
  session: { authenticated: boolean; actor_id: string | null; role: string | null; scopes: ScopeRef[] };
  capabilities: CapabilityStatus[];
  highest_priority_gap: CoverageGap | null;
  privacy: PrivacyBoundary;
};
export type EgressPath = {
  id: string;
  destination_class: "none" | "local_process" | "customer_managed" | "vendor_managed" | "third_party" | "unknown";
  purpose: string;
  data_classes: string[];
  state: "disabled" | "configured" | "active" | "unavailable" | "unknown";
  consent: "not_required" | "explicit" | "configured_by_admin" | "denied" | "unknown";
  retention: {
    mode: "none" | "request_lifetime" | "customer_policy" | "vendor_policy" | "unknown";
    maximum_seconds: number | null;
  };
  redaction: string[];
  local_fallback: "not_required" | "available" | "unavailable" | "unknown";
  evidence: EvidenceRef[];
};
export type PrivacyBoundary = { storage: string[]; redactions: string[]; egress: EgressPath[] };
export type ProtectionLayer = {
  id: string;
  label: string;
  capability_ids: string[];
  claim_state: ClaimState;
  effective_mode: EffectiveMode;
  // The configured/armed intent, independent of runtime verification. When
  // effective_mode is "unknown" because active containment is not fully
  // verified, this still carries the known armed mode (e.g. "enforce") so the
  // surface never shows a bare Unknown for a control that is demonstrably armed.
  desired_mode: EffectiveMode;
  effective_scope: ScopeRef[];
  covered_action_classes: string[];
  known_gaps: CoverageGap[];
  freshness: EvidenceFreshness;
  convergence: RuntimeConvergence;
  evidence: EvidenceRef[];
};
export type DashboardPosture = {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  generated_at: string;
  layers: ProtectionLayer[];
  gaps: CoverageGap[];
};

export type Metric = {
  metric_id: string;
  definition: string;
  source: SourceRef | null;
  scope: ScopeRef[];
  window: { started_at: string | null; ended_at: string | null };
  generated_at: string;
  freshness: EvidenceFreshness;
  availability: Availability;
  value: string | number | boolean | null;
  unit: string | null;
  denominator: string | null;
  reconciliation: "reconciled" | "explained" | "unreconciled" | "not_applicable" | "unknown";
  evidence: EvidenceRef[];
  claim_ref: string | null;
};

export type AgentCapabilityName =
  | "discovery"
  | "identity"
  | "action_interception"
  | "mcp_protection"
  | "automatic_setup"
  | "token_intelligence"
  | "session_attribution"
  | "community_enforcement"
  | "host_correlation"
  | "enterprise_scope_coverage";

export type AgentCapabilityState = {
  capability: AgentCapabilityName;
  availability: Availability;
  support: "supported" | "partial" | "experimental" | "unsupported" | "unknown";
  evidence: EvidenceRef[];
  limitations: string[];
  observed_at: string | null;
};

export type AgentSessionRef = {
  session_id: string;
  started_at?: string | null;
  ended_at?: string | null;
  identity_confidence: IdentityConfidence;
  evidence: EvidenceRef[];
};

export type AgentSubject = {
  agent_id: string;
  principal: string | null;
  product: string | null;
  provider: string | null;
  agent_class: "coding" | "autonomous" | "mcp_based" | "custom" | "unknown";
  runtime: string | null;
  model: string | null;
  identity_confidence: IdentityConfidence;
  identity_evidence: EvidenceRef[];
  sessions: AgentSessionRef[];
  capabilities: AgentCapabilityState[];
};

export type AgentInventory = {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  generated_at: string;
  availability: Availability;
  discovery_limited: boolean;
  subjects: AgentSubject[];
};

export type TokenCounterSet = {
  total: string | null;
  input: string | null;
  output: string | null;
  cache_read_input: string | null;
  cached_input: string | null;
  cache_creation_input: string | null;
  reasoning_output: string | null;
};

export type TokenProviderUsage = {
  agent_id: string;
  display_name: string;
  availability: Availability;
  counters: TokenCounterSet;
  sessions: string | null;
  last_observed_at: string | null;
  provenance: SourceRef;
  note: string;
};

export type TokenIntelligence = {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  generated_at: string;
  availability: Availability;
  scope: "available_local_history" | "no_supported_history" | "unknown";
  totals: TokenCounterSet | null;
  providers: TokenProviderUsage[];
};
