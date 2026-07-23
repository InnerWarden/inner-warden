import {
  DASHBOARD_SCHEMA_VERSION,
  type AgentCapabilityState,
  type AgentInventory,
  type AgentSessionRef,
  type AgentSubject,
  type CapabilityStatus,
  type ClaimRecord,
  type CoverageGap,
  type DashboardBootstrap,
  type DashboardPosture,
  type EgressPath,
  type EvidenceFreshness,
  type EvidenceRef,
  type Metric,
  type ProtectionLayer,
  type ScopeRef,
  type SourceRef,
  type StageState,
  type TokenCounterSet,
  type TokenIntelligence,
  type TokenProviderUsage,
  type VersionRef,
} from "./v1";

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${path}: expected object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string") throw new Error(`${path}: expected string`);
  return value;
}

function nullableText(value: unknown, path: string): string | null {
  return value === null ? null : text(value, path);
}

function bool(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path}: expected boolean`);
  return value;
}

function finiteNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    throw new Error(`${path}: expected finite I-JSON number`);
  }
  return value;
}

function integer(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(`${path}: expected non-negative safe integer`);
  return Number(value);
}

function positiveInteger(value: unknown, path: string): number {
  const parsed = integer(value, path);
  if (parsed === 0) throw new Error(`${path}: expected positive safe integer`);
  return parsed;
}

function nullableInteger(value: unknown, path: string): number | null {
  return value === null ? null : integer(value, path);
}

function oneOf<const T extends readonly string[]>(value: unknown, options: T, path: string): T[number] {
  const candidate = text(value, path);
  if (!options.includes(candidate)) throw new Error(`${path}: unsupported value ${candidate}`);
  return candidate as T[number];
}

function array<T>(value: unknown, path: string, parse: (item: unknown, path: string) => T): T[] {
  if (!Array.isArray(value)) throw new Error(`${path}: expected array`);
  return value.map((item, index) => parse(item, `${path}[${index}]`));
}

const stringArray = (value: unknown, path: string) => array(value, path, text);

function versionRef(value: unknown, path: string): VersionRef {
  const item = record(value, path);
  const digest = text(item.digest, `${path}.digest`);
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error(`${path}.digest: invalid sha256 digest`);
  return {
    id: text(item.id, `${path}.id`),
    version: text(item.version, `${path}.version`),
    canonicalization: oneOf(item.canonicalization, ["RFC8785-JCS", "YAML-TO-RFC8785-JCS", "RAW-UTF8-BYTES-SHA256"] as const, `${path}.canonicalization`),
    digest,
  };
}

export function parseVersionRef(value: unknown, path = "version_ref"): VersionRef {
  return versionRef(value, path);
}

function evidence(value: unknown, path: string): EvidenceRef {
  const item = record(value, path);
  return {
    id: text(item.id, `${path}.id`),
    kind: text(item.kind, `${path}.kind`),
    source: source(item.source, `${path}.source`),
    observed_at: text(item.observed_at, `${path}.observed_at`),
    integrity: oneOf(item.integrity, ["verified", "local_chain", "unverified", "unknown"] as const, `${path}.integrity`),
    redaction: stringArray(item.redaction, `${path}.redaction`),
    freshness: freshness(item.freshness, `${path}.freshness`),
  };
}

export function parseEvidenceRef(value: unknown, path = "evidence"): EvidenceRef {
  return evidence(value, path);
}

function freshness(value: unknown, path: string): EvidenceFreshness {
  const item = record(value, path);
  return {
    observed_at: nullableText(item.observed_at, `${path}.observed_at`),
    budget_seconds: positiveInteger(item.budget_seconds, `${path}.budget_seconds`),
    state: oneOf(item.state, ["fresh", "stale", "missing", "unknown"] as const, `${path}.state`),
    age_seconds: nullableInteger(item.age_seconds, `${path}.age_seconds`),
  };
}

function scope(value: unknown, path: string): ScopeRef {
  const item = record(value, path);
  return {
    id: text(item.id, `${path}.id`),
    kind: oneOf(item.kind, ["agent", "session", "process_tree", "workload", "cgroup", "container", "pod", "host", "tenant", "resource"] as const, `${path}.kind`),
    display_name: nullableText(item.display_name, `${path}.display_name`),
    verification: oneOf(item.verification, ["host_verified", "configured", "declared", "conflicting", "unattributed"] as const, `${path}.verification`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
  };
}

export function parseScopeRef(value: unknown, path = "scope"): ScopeRef {
  return scope(value, path);
}

function source(value: unknown, path: string): SourceRef {
  const item = record(value, path);
  return {
    id: text(item.id, `${path}.id`),
    kind: oneOf(item.kind, [
      "runtime_probe", "sqlite", "response_lifecycle", "kernel_state",
      "local_history", "local_graph", "configuration", "licence",
      "telemetry", "knowledge_graph", "operator", "unknown",
    ] as const, `${path}.kind`),
    authority: oneOf(item.authority, ["canonical", "corroborating", "inferred", "fallback", "unknown"] as const, `${path}.authority`),
    version: nullableText(item.version, `${path}.version`),
    completeness: oneOf(item.completeness, ["complete", "partial", "lossy", "unknown"] as const, `${path}.completeness`),
    limitations: stringArray(item.limitations, `${path}.limitations`),
  };
}

function claimRecord(value: unknown, path: string): ClaimRecord {
  const claim = record(value, path);
  return {
    id: text(claim.id, `${path}.id`),
    statement: nullableText(claim.statement, `${path}.statement`),
    semantic_key: nullableText(claim.semantic_key, `${path}.semantic_key`),
    status: oneOf(claim.status, ["verified", "stale", "contradicted", "unverified", "not_applicable"] as const, `${path}.status`),
    versions: array(claim.versions, `${path}.versions`, versionRef),
    population: text(claim.population, `${path}.population`),
    environment: text(claim.environment, `${path}.environment`),
    observed_at: nullableText(claim.observed_at, `${path}.observed_at`),
    reviewed_at: nullableText(claim.reviewed_at, `${path}.reviewed_at`),
    expires_at: nullableText(claim.expires_at, `${path}.expires_at`),
    scope: array(claim.scope, `${path}.scope`, scope),
    action_classes: stringArray(claim.action_classes, `${path}.action_classes`),
    evidence: array(claim.evidence, `${path}.evidence`, evidence),
    limitations: stringArray(claim.limitations, `${path}.limitations`),
  };
}

function stage(value: unknown, path: string): StageState {
  const item = record(value, path);
  return {
    state: oneOf(item.state, ["yes", "no", "unknown", "not_applicable"] as const, `${path}.state`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
    reason_code: nullableText(item.reason_code, `${path}.reason_code`),
  };
}

function gap(value: unknown, path: string): CoverageGap {
  const item = record(value, path);
  return {
    id: text(item.id, `${path}.id`),
    capability_id: text(item.capability_id, `${path}.capability_id`),
    affected_scope: array(item.affected_scope, `${path}.affected_scope`, scope),
    action_classes: stringArray(item.action_classes, `${path}.action_classes`),
    state: oneOf(item.state, ["not_covered", "degraded", "stale", "unknown", "unsupported"] as const, `${path}.state`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
    next_step: text(item.next_step, `${path}.next_step`),
  };
}

function capability(value: unknown, path: string): CapabilityStatus {
  const item = record(value, path);
  const convergence = record(item.convergence, `${path}.convergence`);
  const lastEvidence = item.last_evidence;
  return {
    id: text(item.id, `${path}.id`),
    tier: oneOf(item.tier, ["community", "enterprise_core", "compliance_extension", "fleet_extension", "advanced_intelligence_extension"] as const, `${path}.tier`),
    availability: oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, `${path}.availability`),
    entitlement: oneOf(item.entitlement, ["not_required", "valid", "grace", "expired", "invalid", "unknown"] as const, `${path}.entitlement`),
    support: oneOf(item.support, ["supported", "partial", "experimental", "unsupported", "unknown"] as const, `${path}.support`),
    desired_mode: oneOf(item.desired_mode, ["disabled", "learning", "observe", "rehearse", "enforce", "mixed", "unknown"] as const, `${path}.desired_mode`),
    effective_mode: oneOf(item.effective_mode, ["disabled", "learning", "observe", "rehearse", "enforce", "mixed", "unknown"] as const, `${path}.effective_mode`),
    convergence: {
      configured: stage(convergence.configured, `${path}.convergence.configured`),
      loaded: stage(convergence.loaded, `${path}.convergence.loaded`),
      running: stage(convergence.running, `${path}.convergence.running`),
      enforcing: stage(convergence.enforcing, `${path}.convergence.enforcing`),
      verified_effective: stage(convergence.verified_effective, `${path}.convergence.verified_effective`),
    },
    rollout_state: oneOf(item.rollout_state, ["ineligible", "eligible", "installed", "observing", "rehearsing", "ready", "canary", "enforcing", "degraded", "disarmed", "unknown"] as const, `${path}.rollout_state`),
    health: oneOf(item.health, ["healthy", "degraded", "failed", "unknown"] as const, `${path}.health`),
    scope: array(item.scope, `${path}.scope`, scope),
    covered_action_classes: stringArray(item.covered_action_classes, `${path}.covered_action_classes`),
    bypass_classes: stringArray(item.bypass_classes, `${path}.bypass_classes`),
    known_uncovered_paths: stringArray(item.known_uncovered_paths, `${path}.known_uncovered_paths`),
    freshness: freshness(item.freshness, `${path}.freshness`),
    last_evidence: lastEvidence === null ? null : evidence(lastEvidence, `${path}.last_evidence`),
    sources: array(item.sources, `${path}.sources`, source),
    claims: array(item.claims, `${path}.claims`, claimRecord),
    reason_code: nullableText(item.reason_code, `${path}.reason_code`),
    summary: text(item.summary, `${path}.summary`),
  };
}

function layer(value: unknown, path: string): ProtectionLayer {
  const item = record(value, path);
  const convergence = record(item.convergence, `${path}.convergence`);
  return {
    id: text(item.id, `${path}.id`), label: text(item.label, `${path}.label`), capability_ids: stringArray(item.capability_ids, `${path}.capability_ids`),
    claim_state: oneOf(item.claim_state, ["active", "visibility_only", "readiness_only", "degraded", "not_covered", "unavailable", "unknown"] as const, `${path}.claim_state`),
    effective_mode: oneOf(item.effective_mode, ["disabled", "learning", "observe", "rehearse", "enforce", "mixed", "unknown"] as const, `${path}.effective_mode`),
    // Tolerate an older agent that predates the layer-level desired_mode: default
    // to "unknown" so a mixed-version fleet still parses (the UI then shows the
    // same bare Unknown as before; a current agent supplies the armed intent).
    desired_mode: item.desired_mode === undefined
      ? "unknown"
      : oneOf(item.desired_mode, ["disabled", "learning", "observe", "rehearse", "enforce", "mixed", "unknown"] as const, `${path}.desired_mode`),
    effective_scope: array(item.effective_scope, `${path}.effective_scope`, scope), covered_action_classes: stringArray(item.covered_action_classes, `${path}.covered_action_classes`),
    known_gaps: array(item.known_gaps, `${path}.known_gaps`, gap),
    freshness: freshness(item.freshness, `${path}.freshness`),
    convergence: {
      configured: stage(convergence.configured, `${path}.convergence.configured`),
      loaded: stage(convergence.loaded, `${path}.convergence.loaded`),
      running: stage(convergence.running, `${path}.convergence.running`),
      enforcing: stage(convergence.enforcing, `${path}.convergence.enforcing`),
      verified_effective: stage(convergence.verified_effective, `${path}.convergence.verified_effective`),
    },
    evidence: array(item.evidence, `${path}.evidence`, evidence),
  };
}

function egressPath(value: unknown, path: string): EgressPath {
  const item = record(value, path);
  const retention = record(item.retention, `${path}.retention`);
  return {
    id: text(item.id, `${path}.id`),
    destination_class: oneOf(item.destination_class, ["none", "local_process", "customer_managed", "vendor_managed", "third_party", "unknown"] as const, `${path}.destination_class`),
    purpose: text(item.purpose, `${path}.purpose`),
    data_classes: stringArray(item.data_classes, `${path}.data_classes`),
    state: oneOf(item.state, ["disabled", "configured", "active", "unavailable", "unknown"] as const, `${path}.state`),
    consent: oneOf(item.consent, ["not_required", "explicit", "configured_by_admin", "denied", "unknown"] as const, `${path}.consent`),
    retention: {
      mode: oneOf(retention.mode, ["none", "request_lifetime", "customer_policy", "vendor_policy", "unknown"] as const, `${path}.retention.mode`),
      maximum_seconds: nullableInteger(retention.maximum_seconds, `${path}.retention.maximum_seconds`),
    },
    redaction: stringArray(item.redaction, `${path}.redaction`),
    local_fallback: oneOf(item.local_fallback, ["not_required", "available", "unavailable", "unknown"] as const, `${path}.local_fallback`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
  };
}

export function parseDashboardBootstrap(value: unknown): DashboardBootstrap {
  const item = record(value, "bootstrap");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("bootstrap.schema_version: unsupported contract version");
  const platform = record(item.platform, "bootstrap.platform");
  const session = record(item.session, "bootstrap.session");
  const privacy = record(item.privacy, "bootstrap.privacy");
  return {
    schema_version: DASHBOARD_SCHEMA_VERSION, generated_at: text(item.generated_at, "bootstrap.generated_at"),
    edition: oneOf(item.edition, ["community", "enterprise"] as const, "bootstrap.edition"), product_version: text(item.product_version, "bootstrap.product_version"),
    community_contract: versionRef(item.community_contract, "bootstrap.community_contract"),
    assurance_matrix: item.assurance_matrix === null ? null : versionRef(item.assurance_matrix, "bootstrap.assurance_matrix"),
    authorization_matrix: item.authorization_matrix === null ? null : versionRef(item.authorization_matrix, "bootstrap.authorization_matrix"),
    platform: { os: text(platform.os, "bootstrap.platform.os"), architecture: text(platform.architecture, "bootstrap.platform.architecture"), enterprise_candidate: bool(platform.enterprise_candidate, "bootstrap.platform.enterprise_candidate"), reason_code: nullableText(platform.reason_code, "bootstrap.platform.reason_code") },
    session: { authenticated: bool(session.authenticated, "bootstrap.session.authenticated"), actor_id: nullableText(session.actor_id, "bootstrap.session.actor_id"), role: nullableText(session.role, "bootstrap.session.role"), scopes: array(session.scopes, "bootstrap.session.scopes", scope) },
    capabilities: array(item.capabilities, "bootstrap.capabilities", capability),
    highest_priority_gap: item.highest_priority_gap === null ? null : gap(item.highest_priority_gap, "bootstrap.highest_priority_gap"),
    privacy: {
      storage: stringArray(privacy.storage, "bootstrap.privacy.storage"),
      redactions: stringArray(privacy.redactions, "bootstrap.privacy.redactions"),
      egress: array(privacy.egress, "bootstrap.privacy.egress", egressPath),
    },
  };
}

export function parseDashboardPosture(value: unknown): DashboardPosture {
  const item = record(value, "posture");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("posture.schema_version: unsupported contract version");
  return {
    schema_version: DASHBOARD_SCHEMA_VERSION,
    generated_at: text(item.generated_at, "posture.generated_at"),
    layers: array(item.layers, "posture.layers", layer),
    gaps: array(item.gaps, "posture.gaps", gap),
  };
}

function metricValue(value: unknown, path: string): Metric["value"] {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  return finiteNumber(value, path);
}

export function parseMetric(value: unknown, path = "metric"): Metric {
  const item = record(value, path);
  const window = record(item.window, `${path}.window`);
  const parsed: Metric = {
    metric_id: text(item.metric_id, `${path}.metric_id`),
    definition: text(item.definition, `${path}.definition`),
    source: item.source === null ? null : source(item.source, `${path}.source`),
    scope: array(item.scope, `${path}.scope`, scope),
    window: {
      started_at: nullableText(window.started_at, `${path}.window.started_at`),
      ended_at: nullableText(window.ended_at, `${path}.window.ended_at`),
    },
    generated_at: text(item.generated_at, `${path}.generated_at`),
    freshness: freshness(item.freshness, `${path}.freshness`),
    availability: oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, `${path}.availability`),
    value: metricValue(item.value, `${path}.value`),
    unit: nullableText(item.unit, `${path}.unit`),
    denominator: nullableText(item.denominator, `${path}.denominator`),
    reconciliation: oneOf(item.reconciliation, ["reconciled", "explained", "unreconciled", "not_applicable", "unknown"] as const, `${path}.reconciliation`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
    claim_ref: nullableText(item.claim_ref, `${path}.claim_ref`),
  };

  if (parsed.availability === "available") {
    if (parsed.source === null) throw new Error(`${path}.source: required when available`);
    if (parsed.freshness.state !== "fresh") throw new Error(`${path}.freshness: available metric must be fresh`);
    if (parsed.value === null) throw new Error(`${path}.value: required when available`);
    if (parsed.unit === null || parsed.unit.length === 0) throw new Error(`${path}.unit: required when available`);
    if (parsed.evidence.length === 0) throw new Error(`${path}.evidence: required when available`);
  }
  if (["unavailable", "unsupported", "not_configured", "loading", "failed", "unknown"].includes(parsed.availability) && parsed.value !== null) {
    throw new Error(`${path}.value: must be null when unavailable`);
  }
  return parsed;
}

function agentSession(value: unknown, path: string): AgentSessionRef {
  const item = record(value, path);
  return {
    session_id: text(item.session_id, `${path}.session_id`),
    started_at: item.started_at === undefined ? undefined : nullableText(item.started_at, `${path}.started_at`),
    ended_at: item.ended_at === undefined ? undefined : nullableText(item.ended_at, `${path}.ended_at`),
    identity_confidence: oneOf(item.identity_confidence, ["host_verified", "configured", "declared", "conflicting", "unattributed"] as const, `${path}.identity_confidence`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
  };
}

function agentCapability(value: unknown, path: string): AgentCapabilityState {
  const item = record(value, path);
  const parsed: AgentCapabilityState = {
    capability: oneOf(item.capability, [
      "discovery", "identity", "action_interception", "mcp_protection", "automatic_setup",
      "token_intelligence", "session_attribution", "community_enforcement", "host_correlation",
      "enterprise_scope_coverage",
    ] as const, `${path}.capability`),
    availability: oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, `${path}.availability`),
    support: oneOf(item.support, ["supported", "partial", "experimental", "unsupported", "unknown"] as const, `${path}.support`),
    evidence: array(item.evidence, `${path}.evidence`, evidence),
    limitations: stringArray(item.limitations, `${path}.limitations`),
    observed_at: nullableText(item.observed_at, `${path}.observed_at`),
  };
  if ((parsed.availability === "available" || ["supported", "partial"].includes(parsed.support))
    && (parsed.evidence.length === 0 || parsed.observed_at === null)) {
    throw new Error(`${path}: available or supported capability requires evidence and observation time`);
  }
  return parsed;
}

function agentSubject(value: unknown, path: string): AgentSubject {
  const item = record(value, path);
  const parsed: AgentSubject = {
    agent_id: text(item.agent_id, `${path}.agent_id`),
    principal: nullableText(item.principal, `${path}.principal`),
    product: nullableText(item.product, `${path}.product`),
    provider: nullableText(item.provider, `${path}.provider`),
    agent_class: oneOf(item.agent_class, ["coding", "autonomous", "mcp_based", "custom", "unknown"] as const, `${path}.agent_class`),
    runtime: nullableText(item.runtime, `${path}.runtime`),
    model: nullableText(item.model, `${path}.model`),
    identity_confidence: oneOf(item.identity_confidence, ["host_verified", "configured", "declared", "conflicting", "unattributed"] as const, `${path}.identity_confidence`),
    identity_evidence: array(item.identity_evidence, `${path}.identity_evidence`, evidence),
    sessions: array(item.sessions, `${path}.sessions`, agentSession),
    capabilities: array(item.capabilities, `${path}.capabilities`, agentCapability),
  };
  if (parsed.identity_confidence === "host_verified"
    && !parsed.identity_evidence.some((entry) => entry.integrity === "verified")) {
    throw new Error(`${path}.identity_evidence: host-verified identity requires verified evidence`);
  }
  return parsed;
}

export function parseAgentInventory(value: unknown): AgentInventory {
  const item = record(value, "agents");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("agents.schema_version: unsupported contract version");
  return {
    schema_version: DASHBOARD_SCHEMA_VERSION,
    generated_at: text(item.generated_at, "agents.generated_at"),
    availability: oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, "agents.availability"),
    discovery_limited: bool(item.discovery_limited, "agents.discovery_limited"),
    subjects: array(item.subjects, "agents.subjects", agentSubject),
  };
}

function nullableDecimal(value: unknown, path: string): string | null {
  if (value === null) return null;
  const parsed = text(value, path);
  if (!/^(0|[1-9][0-9]*)$/.test(parsed)) throw new Error(`${path}: expected canonical non-negative decimal string`);
  return parsed;
}

function tokenCounters(value: unknown, path: string): TokenCounterSet {
  const item = record(value, path);
  return {
    total: nullableDecimal(item.total, `${path}.total`),
    input: nullableDecimal(item.input, `${path}.input`),
    output: nullableDecimal(item.output, `${path}.output`),
    cache_read_input: nullableDecimal(item.cache_read_input, `${path}.cache_read_input`),
    cached_input: nullableDecimal(item.cached_input, `${path}.cached_input`),
    cache_creation_input: nullableDecimal(item.cache_creation_input, `${path}.cache_creation_input`),
    reasoning_output: nullableDecimal(item.reasoning_output, `${path}.reasoning_output`),
  };
}

function hasTokenCounter(counters: TokenCounterSet): boolean {
  return Object.values(counters).some((counter) => counter !== null);
}

function tokenProvider(value: unknown, path: string): TokenProviderUsage {
  const item = record(value, path);
  const parsed: TokenProviderUsage = {
    agent_id: text(item.agent_id, `${path}.agent_id`),
    display_name: text(item.display_name, `${path}.display_name`),
    availability: oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, `${path}.availability`),
    counters: tokenCounters(item.counters, `${path}.counters`),
    sessions: nullableDecimal(item.sessions, `${path}.sessions`),
    last_observed_at: nullableText(item.last_observed_at, `${path}.last_observed_at`),
    provenance: source(item.provenance, `${path}.provenance`),
    note: text(item.note, `${path}.note`),
  };
  if (parsed.availability === "available") {
    if (parsed.last_observed_at === null || !hasTokenCounter(parsed.counters)) {
      throw new Error(`${path}: available token source requires an observation time and at least one counter`);
    }
  } else if (["unavailable", "unsupported", "not_configured", "loading", "failed", "unknown"].includes(parsed.availability)) {
    if (parsed.sessions !== null || parsed.last_observed_at !== null || hasTokenCounter(parsed.counters)) {
      throw new Error(`${path}: unavailable token source must not expose inferred counters or observations`);
    }
  }
  return parsed;
}

export function parseTokenIntelligence(value: unknown): TokenIntelligence {
  const item = record(value, "token_intelligence");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("token_intelligence.schema_version: unsupported contract version");
  const availability = oneOf(item.availability, ["available", "unavailable", "unsupported", "not_configured", "loading", "degraded", "failed", "stale", "unknown"] as const, "token_intelligence.availability");
  const scopeValue = oneOf(item.scope, ["available_local_history", "no_supported_history", "unknown"] as const, "token_intelligence.scope");
  const totals = item.totals === null ? null : tokenCounters(item.totals, "token_intelligence.totals");
  const providers = array(item.providers, "token_intelligence.providers", tokenProvider);
  if (availability === "available") {
    if (scopeValue !== "available_local_history" || totals === null || !hasTokenCounter(totals)
      || !providers.some((provider) => provider.availability === "available")) {
      throw new Error("token_intelligence: available state requires local history, totals and an available provider");
    }
  } else if (scopeValue === "available_local_history" || totals !== null) {
    throw new Error("token_intelligence: unavailable state must not claim available history or totals");
  }
  return {
    schema_version: DASHBOARD_SCHEMA_VERSION,
    generated_at: text(item.generated_at, "token_intelligence.generated_at"),
    availability,
    scope: scopeValue,
    totals,
    providers,
  };
}
