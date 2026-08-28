import {
  DASHBOARD_API_ROOT,
  contractProblem,
  failureForStatus,
  networkProblem,
  responseProblem,
  type DashboardApiProblem,
  type DashboardClientFailure,
  type DashboardClientResult,
} from "./client";
import {
  DASHBOARD_SCHEMA_VERSION,
  type EffectiveMode,
  type EvidenceRef,
  type IdentityConfidence,
  type ScopeRef,
  type SecurityOutcome,
} from "./v1";
import { parseEvidenceRef, parseScopeRef } from "./validate";

export type CaseSeverity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type CaseStatus = "open" | "needs_review" | "observing" | "contained" | "dismissed" | "closed" | "unknown";
export type CaseEventType =
  | "agent_intent"
  | "host_observation"
  | "signal"
  | "incident"
  | "recommendation"
  | "policy_decision"
  | "enforcement_attempt"
  | "verification"
  | "operator_action"
  | "feedback"
  | "evidence_gap";
export type RelationshipConfidence = "causal" | "strongly_supported" | "contextual" | "unknown";

export type CaseSummary = {
  id: string;
  title: string;
  severity: CaseSeverity;
  status: CaseStatus;
  scope: ScopeRef[];
  latest_event_at: string;
  outcome: SecurityOutcome;
};

export type CaseListPage = {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  generated_at: string;
  items: CaseSummary[];
  next_cursor: string | null;
  /**
   * Echo of the requested window, present only when the request named one and
   * the server honours it. The free server sends none of these three fields;
   * every consumer must treat them as absent-safe.
   */
  window?: CaseListWindow;
  /** Cases in the whole window, not just this page: the "5 of 312" number. */
  total_in_window?: number;
  /**
   * False when a bounded source read hit its row cap, making total_in_window a
   * LOWER bound. Render "at least N", never bare N, when this is false.
   */
  window_complete?: boolean;
};

export type AuthorityRef = { kind: string; id: string; version?: string | null; inferred?: boolean | null };
export type DecisionProvenance = {
  rule?: AuthorityRef | null;
  model?: AuthorityRef | null;
  policy?: AuthorityRef | null;
  kernel?: AuthorityRef | null;
  operator?: AuthorityRef | null;
  fallback?: AuthorityRef | null;
};
export type CaseEvent = {
  id: string;
  event_type: CaseEventType;
  observed_at: string;
  recorded_at: string;
  authority: string | null;
  mode: EffectiveMode | null;
  summary: string;
  relationship: RelationshipConfidence;
  source_refs: EvidenceRef[];
  action_lifecycle?: string | null;
  decision_provenance?: DecisionProvenance | null;
};

export type FeedbackRecord = {
  id: string;
  finding_type: "true_positive" | "false_positive" | "false_deny" | "override" | "mute" | "needs_review" | "expected" | "uncertain";
  status: "open" | "resolved" | "accepted_risk";
  actor_id: string;
  recorded_at: string;
  reason: string;
  scope: ScopeRef[];
  evidence: EvidenceRef[];
};

export type VerifiedOutcome = {
  outcome: SecurityOutcome;
  mode: EffectiveMode;
  actual_denial_or_containment_occurred: boolean;
  verification_status: "verified" | "unverified" | "not_applicable" | "unknown";
  verifier: string | null;
  verified_at: string | null;
  effective_scope: ScopeRef[];
  evidence: EvidenceRef[];
  enforcement_attempt_id: string | null;
  // How well the record supports the outcome it reports, DECIDED BY THE
  // BACKEND. The kit renders this; it does not recompute it. Recomputing it is
  // the defect: this component used to run its own predicate, which disagreed
  // with the header's for every in-path guard refusal and printed "Outcome
  // claim withheld" directly under "Blocked Before Execution".
  //
  //   proven    something independent of the actor observed it
  //   recorded  the component in the path reported it, nothing else watched
  //   unproven  the record does not hold together
  trust: OutcomeTrust;
  trust_explanation: string;
};

export const OUTCOME_TRUSTS = ["proven", "recorded", "unproven"] as const;
export type OutcomeTrust = (typeof OUTCOME_TRUSTS)[number];

// --- Enrichment: signals wired together from the underlying incident / decision /
// mitre mapping. Everything is producer-REPORTED (not verified). Every field is
// optional so an orphan observation serialises an all-empty enrichment and the UI
// renders honest "not reported" states instead of inventing data.
export type DetectionContext = { detector: string; kind?: string | null; layer?: string | null; reason?: string | null; recommended_checks: string[] };
export type AiVerdict = { provider: string; model_kind: string; verdict?: string | null; risk_score?: number | null; reason?: string | null };
export type AgentActivity = { agent_name: string; command?: string | null; atr_rule_ids: string[]; risk_score?: number | null; recommendation?: string | null; explanation?: string | null };
export type RuleHit = { kind: string; id: string; name?: string | null };
export type MitreRef = { technique_id: string; technique_name?: string | null; tactic?: string | null };
export type GeoInfo = { country?: string | null; city?: string | null; lat?: number | null; lon?: number | null; asn?: string | null; isp?: string | null };
export type ThreatIntel = { ip?: string | null; geo?: GeoInfo | null; abuseipdb_score?: number | null; dshield?: boolean | null; dna_fingerprint?: string | null; campaign_ids: string[] };
export type HoneypotContext = { session_id?: string | null; protocol?: string | null; commands: string[]; credentials_seen?: number | null };
export type DnsLookup = { domain: string; action?: string | null; reason?: string | null };
export type CaseEnrichment = {
  detection?: DetectionContext | null;
  ai?: AiVerdict | null;
  agent_activity?: AgentActivity | null;
  rules: RuleHit[];
  mitre: MitreRef[];
  threat_intel?: ThreatIntel | null;
  honeypot?: HoneypotContext | null;
  dns: DnsLookup[];
  reason_code?: string | null;
};

export type UnifiedCase = CaseSummary & {
  schema_version: typeof DASHBOARD_SCHEMA_VERSION;
  identity: { subject_ids: string[]; confidence: IdentityConfidence; evidence: EvidenceRef[] };
  recurrence: {
    first_seen_at: string;
    last_seen_at: string;
    occurrences: string;
    state: "single" | "recurring" | "persistent" | "unknown";
  };
  timeline: CaseEvent[];
  evidence: EvidenceRef[];
  feedback: FeedbackRecord[];
  verified_outcomes: VerifiedOutcome[];
  enrichment?: CaseEnrichment | null;
};

/** The server-side time windows the paid Cases API accepts. */
export type CaseListWindow = "1h" | "24h" | "7d" | "30d" | "all";

export type CaseListQuery = {
  cursor?: string | null;
  limit?: number;
  /**
   * Server-side time window. Optional and additive: the free product's server
   * ignores unknown params it was never sent, and when this is omitted the
   * request and response are byte-identical to the legacy exchange.
   */
  window?: CaseListWindow | "";
  outcome?: SecurityOutcome | "";
  mode?: EffectiveMode | "";
  authority?: string;
  capability?: string;
  agent?: string;
  host?: string;
  severity?: CaseSeverity | "";
  q?: string;
  /**
   * List order. "recent" is pure chronology (latest event first); "findings"
   * (the server default when omitted) leads with incident-tier cases, then
   * severity. Additive like `window`: an older server ignores it.
   */
  sort?: "recent" | "findings" | "";
};

type Fetch = typeof globalThis.fetch;

const SEVERITIES = ["critical", "high", "medium", "low", "informational", "unknown"] as const;
const STATUSES = ["open", "needs_review", "observing", "contained", "dismissed", "closed", "unknown"] as const;
const OUTCOMES = ["observed_only", "allowed", "blocked_before_execution", "would_block", "contained", "failed", "reverted", "not_observed", "unknown"] as const;
const MODES = ["disabled", "learning", "observe", "rehearse", "enforce", "mixed", "unknown"] as const;
const EVENT_TYPES = ["agent_intent", "host_observation", "signal", "incident", "recommendation", "policy_decision", "enforcement_attempt", "verification", "operator_action", "feedback", "evidence_gap"] as const;
const RELATIONSHIPS = ["causal", "strongly_supported", "contextual", "unknown"] as const;
const IDENTITY_CONFIDENCE = ["host_verified", "configured", "declared", "conflicting", "unattributed"] as const;

function object(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${path}: expected object`);
  return value as Record<string, unknown>;
}

function exact(item: Record<string, unknown>, allowed: readonly string[], path: string): void {
  const extras = Object.keys(item).filter((key) => !allowed.includes(key));
  if (extras.length > 0) throw new Error(`${path}: unexpected field ${extras[0]}`);
}

function string(value: unknown, path: string, minimum = 0, maximum = 4_096): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum) {
    throw new Error(`${path}: expected bounded string`);
  }
  return value;
}

function nullableString(value: unknown, path: string, maximum = 4_096): string | null {
  return value === null ? null : string(value, path, 0, maximum);
}

function dateTime(value: unknown, path: string): string {
  const parsed = string(value, path, 1, 128);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(parsed) || Number.isNaN(Date.parse(parsed))) {
    throw new Error(`${path}: expected RFC 3339 date-time`);
  }
  return parsed;
}

function oneOf<const T extends readonly string[]>(value: unknown, allowed: T, path: string): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) throw new Error(`${path}: unexpected enum value`);
  return value as T[number];
}

function array<T>(value: unknown, path: string, parser: (entry: unknown, path: string) => T, maximum = 1_000): T[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`${path}: expected bounded array`);
  return value.map((entry, index) => parser(entry, `${path}[${index}]`));
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path}: expected boolean`);
  return value;
}

function caseSummary(value: unknown, path: string): CaseSummary {
  const item = object(value, path);
  exact(item, ["id", "title", "severity", "status", "scope", "latest_event_at", "outcome"], path);
  return {
    id: string(item.id, `${path}.id`, 1, 256),
    title: string(item.title, `${path}.title`, 1, 1_024),
    severity: oneOf(item.severity, SEVERITIES, `${path}.severity`),
    status: oneOf(item.status, STATUSES, `${path}.status`),
    scope: array(item.scope, `${path}.scope`, parseScopeRef, 100),
    latest_event_at: dateTime(item.latest_event_at, `${path}.latest_event_at`),
    outcome: oneOf(item.outcome, OUTCOMES, `${path}.outcome`),
  };
}

function caseEvent(value: unknown, path: string): CaseEvent {
  const item = object(value, path);
  exact(
    item,
    ["id", "event_type", "observed_at", "recorded_at", "authority", "mode", "summary", "relationship", "source_refs", "action_lifecycle", "decision_provenance"],
    path,
  );
  return {
    id: string(item.id, `${path}.id`, 1, 256),
    event_type: oneOf(item.event_type, EVENT_TYPES, `${path}.event_type`),
    observed_at: dateTime(item.observed_at, `${path}.observed_at`),
    recorded_at: dateTime(item.recorded_at, `${path}.recorded_at`),
    authority: nullableString(item.authority, `${path}.authority`, 256),
    mode: item.mode === null ? null : oneOf(item.mode, MODES, `${path}.mode`),
    summary: string(item.summary, `${path}.summary`, 1, 4_096),
    relationship: oneOf(item.relationship, RELATIONSHIPS, `${path}.relationship`),
    source_refs: array(item.source_refs, `${path}.source_refs`, parseEvidenceRef, 100),
    action_lifecycle:
      typeof item.action_lifecycle === "string" ? item.action_lifecycle.slice(0, 256) : null,
    decision_provenance: parseDecisionProvenance(item.decision_provenance),
  };
}

// Lenient: decision provenance is descriptive context; a missing/partial/malformed
// block must never fail the whole case (the UI derives provenance from authority +
// source_refs and does not require this field).
function parseDecisionProvenance(value: unknown): DecisionProvenance | null {
  if (value === null || value === undefined || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  const ref = (x: unknown): AuthorityRef | null => {
    if (x === null || typeof x !== "object") return null;
    const r = x as Record<string, unknown>;
    if (typeof r.kind !== "string" || typeof r.id !== "string") return null;
    return {
      kind: r.kind.slice(0, 128),
      id: r.id.slice(0, 256),
      version: typeof r.version === "string" ? r.version.slice(0, 128) : null,
      inferred: typeof r.inferred === "boolean" ? r.inferred : null,
    };
  };
  const out: DecisionProvenance = {
    rule: ref(v.rule),
    model: ref(v.model),
    policy: ref(v.policy),
    kernel: ref(v.kernel),
    operator: ref(v.operator),
    fallback: ref(v.fallback),
  };
  return Object.values(out).some(Boolean) ? out : null;
}

function feedback(value: unknown, path: string): FeedbackRecord {
  const item = object(value, path);
  exact(item, ["id", "finding_type", "status", "actor_id", "recorded_at", "reason", "scope", "evidence"], path);
  return {
    id: string(item.id, `${path}.id`, 1, 256),
    finding_type: oneOf(item.finding_type, ["true_positive", "false_positive", "false_deny", "override", "mute", "needs_review", "expected", "uncertain"] as const, `${path}.finding_type`),
    status: oneOf(item.status, ["open", "resolved", "accepted_risk"] as const, `${path}.status`),
    actor_id: string(item.actor_id, `${path}.actor_id`, 1, 256),
    recorded_at: dateTime(item.recorded_at, `${path}.recorded_at`),
    reason: string(item.reason, `${path}.reason`, 0, 4_096),
    scope: array(item.scope, `${path}.scope`, parseScopeRef, 100),
    evidence: array(item.evidence, `${path}.evidence`, parseEvidenceRef, 100),
  };
}

function verifiedOutcome(value: unknown, path: string): VerifiedOutcome {
  const item = object(value, path);
  exact(item, ["outcome", "mode", "actual_denial_or_containment_occurred", "verification_status", "verifier", "verified_at", "effective_scope", "evidence", "enforcement_attempt_id", "trust", "trust_explanation"], path);
  return {
    outcome: oneOf(item.outcome, OUTCOMES, `${path}.outcome`),
    mode: oneOf(item.mode, MODES, `${path}.mode`),
    actual_denial_or_containment_occurred: boolean(item.actual_denial_or_containment_occurred, `${path}.actual_denial_or_containment_occurred`),
    verification_status: oneOf(item.verification_status, ["verified", "unverified", "not_applicable", "unknown"] as const, `${path}.verification_status`),
    verifier: nullableString(item.verifier, `${path}.verifier`, 256),
    verified_at: item.verified_at === null ? null : dateTime(item.verified_at, `${path}.verified_at`),
    effective_scope: array(item.effective_scope, `${path}.effective_scope`, parseScopeRef, 100),
    evidence: array(item.evidence, `${path}.evidence`, parseEvidenceRef, 100),
    enforcement_attempt_id: nullableString(item.enforcement_attempt_id, `${path}.enforcement_attempt_id`, 256),
    trust: oneOf(item.trust, OUTCOME_TRUSTS, `${path}.trust`),
    trust_explanation: string(item.trust_explanation, `${path}.trust_explanation`, 0, 1024),
  };
}

export function parseCaseListPage(value: unknown, requestedLimit = 20): CaseListPage {
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 100) throw new Error("cases.limit: outside 1..100");
  const item = object(value, "cases");
  exact(item, ["schema_version", "generated_at", "items", "next_cursor", "window", "total_in_window", "window_complete"], "cases");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("cases.schema_version: unsupported contract version");
  const items = array(item.items, "cases.items", caseSummary, requestedLimit);
  if (new Set(items.map((entry) => entry.id)).size !== items.length) throw new Error("cases.items: duplicate case id");
  const page: CaseListPage = {
    schema_version: DASHBOARD_SCHEMA_VERSION,
    generated_at: dateTime(item.generated_at, "cases.generated_at"),
    items,
    next_cursor: nullableString(item.next_cursor, "cases.next_cursor", 2_048),
  };
  // The windowed trio is all-or-nothing from the paid server; each field is
  // still validated independently so a half-shaped payload fails loudly
  // instead of rendering a number that means nothing.
  if (item.window !== undefined) {
    const windows: readonly string[] = ["1h", "24h", "7d", "30d", "all"];
    if (typeof item.window !== "string" || !windows.includes(item.window)) throw new Error("cases.window: unknown window");
    page.window = item.window as CaseListWindow;
  }
  if (item.total_in_window !== undefined) {
    if (typeof item.total_in_window !== "number" || !Number.isInteger(item.total_in_window) || item.total_in_window < 0) {
      throw new Error("cases.total_in_window: not a non-negative integer");
    }
    page.total_in_window = item.total_in_window;
  }
  if (item.window_complete !== undefined) {
    if (typeof item.window_complete !== "boolean") throw new Error("cases.window_complete: not a boolean");
    page.window_complete = item.window_complete;
  }
  return page;
}

export function parseUnifiedCase(value: unknown): UnifiedCase {
  const item = object(value, "case");
  exact(item, ["id", "title", "severity", "status", "scope", "latest_event_at", "outcome", "schema_version", "identity", "recurrence", "timeline", "evidence", "feedback", "verified_outcomes", "enrichment"], "case");
  if (item.schema_version !== DASHBOARD_SCHEMA_VERSION) throw new Error("case.schema_version: unsupported contract version");
  const identity = object(item.identity, "case.identity");
  exact(identity, ["subject_ids", "confidence", "evidence"], "case.identity");
  const recurrence = object(item.recurrence, "case.recurrence");
  exact(recurrence, ["first_seen_at", "last_seen_at", "occurrences", "state"], "case.recurrence");
  const summary = caseSummary({
    id: item.id,
    title: item.title,
    severity: item.severity,
    status: item.status,
    scope: item.scope,
    latest_event_at: item.latest_event_at,
    outcome: item.outcome,
  }, "case");
  const occurrences = string(recurrence.occurrences, "case.recurrence.occurrences", 1, 128);
  if (!/^[1-9][0-9]*$/.test(occurrences)) throw new Error("case.recurrence.occurrences: expected positive decimal string");
  const timeline = array(item.timeline, "case.timeline", caseEvent, 1_000);
  if (new Set(timeline.map((entry) => entry.id)).size !== timeline.length) throw new Error("case.timeline: duplicate event id");
  return {
    ...summary,
    schema_version: DASHBOARD_SCHEMA_VERSION,
    identity: {
      subject_ids: array(identity.subject_ids, "case.identity.subject_ids", (entry, path) => string(entry, path, 1, 256), 100),
      confidence: oneOf(identity.confidence, IDENTITY_CONFIDENCE, "case.identity.confidence"),
      evidence: array(identity.evidence, "case.identity.evidence", parseEvidenceRef, 100),
    },
    recurrence: {
      first_seen_at: dateTime(recurrence.first_seen_at, "case.recurrence.first_seen_at"),
      last_seen_at: dateTime(recurrence.last_seen_at, "case.recurrence.last_seen_at"),
      occurrences,
      state: oneOf(recurrence.state, ["single", "recurring", "persistent", "unknown"] as const, "case.recurrence.state"),
    },
    timeline,
    evidence: array(item.evidence, "case.evidence", parseEvidenceRef, 1_000),
    feedback: array(item.feedback, "case.feedback", feedback, 1_000),
    verified_outcomes: array(item.verified_outcomes, "case.verified_outcomes", verifiedOutcome, 1_000),
    enrichment: parseEnrichment(item.enrichment),
  };
}

// Lenient: enrichment is best-effort context. A missing/partial/malformed block
// must NEVER fail the whole case: it degrades to `undefined` and the UI renders
// honest "not reported" states.
function parseEnrichment(value: unknown): CaseEnrichment | undefined {
  if (value === null || value === undefined || typeof value !== "object") return undefined;
  const v = value as Record<string, unknown>;
  const str = (x: unknown, max = 4_096): string | undefined =>
    typeof x === "string" && x.length > 0 ? x.slice(0, max) : undefined;
  const num = (x: unknown): number | undefined =>
    typeof x === "number" && Number.isFinite(x) ? x : undefined;
  const bool = (x: unknown): boolean | undefined => (typeof x === "boolean" ? x : undefined);
  const strArr = (x: unknown, max = 64): string[] =>
    Array.isArray(x) ? x.filter((e): e is string => typeof e === "string" && e.length > 0).slice(0, max) : [];
  const obj = (x: unknown): Record<string, unknown> | undefined =>
    x !== null && typeof x === "object" && !Array.isArray(x) ? (x as Record<string, unknown>) : undefined;

  const det = obj(v.detection);
  const ai = obj(v.ai);
  const act = obj(v.agent_activity);
  const ti = obj(v.threat_intel);
  const geo = obj(ti?.geo);
  const hp = obj(v.honeypot);

  return {
    detection: det && str(det.detector)
      ? { detector: str(det.detector)!, kind: str(det.kind) ?? null, layer: str(det.layer) ?? null, reason: str(det.reason) ?? null, recommended_checks: strArr(det.recommended_checks) }
      : null,
    ai: ai && str(ai.provider)
      ? { provider: str(ai.provider)!, model_kind: str(ai.model_kind) ?? "unknown", verdict: str(ai.verdict) ?? null, risk_score: num(ai.risk_score) ?? null, reason: str(ai.reason) ?? null }
      : null,
    agent_activity: act && str(act.agent_name)
      ? { agent_name: str(act.agent_name)!, command: str(act.command) ?? null, atr_rule_ids: strArr(act.atr_rule_ids), risk_score: num(act.risk_score) ?? null, recommendation: str(act.recommendation) ?? null, explanation: str(act.explanation) ?? null }
      : null,
    rules: Array.isArray(v.rules)
      ? v.rules.map(obj).filter((r): r is Record<string, unknown> => !!r && !!str(r.id)).map((r) => ({ kind: str(r.kind) ?? "rule", id: str(r.id)!, name: str(r.name) ?? null })).slice(0, 64)
      : [],
    mitre: Array.isArray(v.mitre)
      ? v.mitre.map(obj).filter((m): m is Record<string, unknown> => !!m && !!str(m.technique_id)).map((m) => ({ technique_id: str(m.technique_id)!, technique_name: str(m.technique_name) ?? null, tactic: str(m.tactic) ?? null })).slice(0, 32)
      : [],
    threat_intel: ti && (str(ti.ip) || geo || num(ti.abuseipdb_score) !== undefined || strArr(ti.campaign_ids).length)
      ? {
          ip: str(ti.ip) ?? null,
          geo: geo ? { country: str(geo.country) ?? null, city: str(geo.city) ?? null, lat: num(geo.lat) ?? null, lon: num(geo.lon) ?? null, asn: str(geo.asn) ?? null, isp: str(geo.isp) ?? null } : null,
          abuseipdb_score: num(ti.abuseipdb_score) ?? null,
          dshield: bool(ti.dshield) ?? null,
          dna_fingerprint: str(ti.dna_fingerprint) ?? null,
          campaign_ids: strArr(ti.campaign_ids),
        }
      : null,
    honeypot: hp && (strArr(hp.commands).length || str(hp.session_id))
      ? { session_id: str(hp.session_id) ?? null, protocol: str(hp.protocol) ?? null, commands: strArr(hp.commands, 200), credentials_seen: num(hp.credentials_seen) ?? null }
      : null,
    dns: Array.isArray(v.dns)
      ? v.dns.map(obj).filter((d): d is Record<string, unknown> => !!d && !!str(d.domain)).map((d) => ({ domain: str(d.domain)!, action: str(d.action) ?? null, reason: str(d.reason) ?? null })).slice(0, 64)
      : [],
    reason_code: str(v.reason_code) ?? null,
  };
}

function invalidRequest(endpoint: "cases" | "case_detail", code: string, message: string): DashboardClientFailure {
  const problem: DashboardApiProblem = {
    endpoint,
    httpStatus: null,
    code,
    message,
    retryable: false,
    retryAfterSeconds: null,
  };
  return { state: "error", problem };
}

export class DashboardCasesClient {
  readonly #fetch: Fetch;

  constructor(fetchImplementation: Fetch = globalThis.fetch) {
    this.#fetch = fetchImplementation.bind(globalThis);
  }

  list(query: CaseListQuery = {}, signal?: AbortSignal): Promise<DashboardClientResult<CaseListPage>> {
    const limit = query.limit ?? 20;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      return Promise.resolve(invalidRequest("cases", "invalid_limit", "Case page size must be between 1 and 100."));
    }
    const parameters = new URLSearchParams({ limit: String(limit) });
    for (const [name, value, maximum] of [
      ["cursor", query.cursor, 2_048], ["outcome", query.outcome, 64], ["mode", query.mode, 64],
      ["authority", query.authority, 256], ["capability", query.capability, 256], ["agent", query.agent, 256],
      ["host", query.host, 256], ["severity", query.severity, 64], ["q", query.q, 256],
      ["window", query.window, 8], ["sort", query.sort, 8],
    ] as const) {
      if (value && value.length <= maximum) parameters.set(name, value);
    }
    return this.#get("cases", `${DASHBOARD_API_ROOT}/cases?${parameters}`, (payload) => parseCaseListPage(payload, limit), signal);
  }

  get(caseId: string, signal?: AbortSignal): Promise<DashboardClientResult<UnifiedCase>> {
    if (caseId.length < 1 || caseId.length > 256) {
      return Promise.resolve(invalidRequest("case_detail", "invalid_case_id", "The selected case identifier is invalid."));
    }
    return this.#get("case_detail", `${DASHBOARD_API_ROOT}/cases/${encodeURIComponent(caseId)}`, parseUnifiedCase, signal);
  }

  async #get<T>(endpoint: "cases" | "case_detail", url: string, parser: (value: unknown) => T, signal?: AbortSignal): Promise<DashboardClientResult<T>> {
    let response: Response;
    try {
      response = await this.#fetch(url, {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        headers: { accept: "application/json" },
        signal,
      });
    } catch (error) {
      if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) throw error;
      return networkProblem(endpoint);
    }
    if (!response.ok) return failureForStatus(await responseProblem(response, endpoint));
    try {
      return { state: "ready", data: parser(await response.json()) };
    } catch {
      return contractProblem(endpoint);
    }
  }
}

export const dashboardCasesClient = new DashboardCasesClient();
