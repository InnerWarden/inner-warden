// The shape the thin Rust API (`innerwarden dashboard`) serves. Newer binaries
// add posture and outcome evidence; every addition stays optional so the UI also
// works with the original graph-only contract.
export type GuardrailMode = "not_configured" | "monitor" | "enforce" | "mixed" | "partial" | "unknown";
export type DecisionOutcome = "allowed" | "blocked" | "would_block" | "screened" | "unknown";
export type DecisionMode = "monitor" | "enforce" | "check" | "unknown";

export type DashboardMeta = {
  version?: string;
  exposed?: boolean;
  edition?: string;
  guardrail?: {
    mode?: GuardrailMode | string;
    guarded_agents?: number;
  };
};

export type CategoryCount = { name: string; count: number };
export type DecisionSummary = {
  id?: string;
  session: string;
  command: string;
  recommendation?: string;
  outcome?: DecisionOutcome | string;
  mode_at_decision?: DecisionMode | string;
  recorded_at_ms?: number;
  categories: string[];
  decided_by: string;
};
export type BlockSummary = DecisionSummary;
export type Overview = {
  sessions: number;
  commands: number;
  blocked: number; // Legacy name: this counts deny verdicts, not proven blocks.
  review: number;
  allowed: number;
  top_categories: CategoryCount[];
  recent_blocks: BlockSummary[];
  deny_verdicts?: number;
  review_verdicts?: number;
  allow_verdicts?: number;
  unknown_verdicts?: number;
  actual_blocks?: number;
  would_block?: number;
  screened?: number;
  outcomes_unknown?: number;
  recent_decisions?: DecisionSummary[];
};
export type Node = { id: string; kind: string; label: string; attrs?: Record<string, string> };
export type Edge = { from: string; to: string; kind: string };
export type Graph = { nodes: Node[]; edges: Edge[] };

export type LocalAgent = {
  id: string;
  display_name: string;
  installed: boolean;
  running: boolean | null;
  detected_by: string[];
  guardrail: {
    mode: string;
    mechanism: string | null;
    setup_support: string;
  };
  auto_connect_eligible: boolean | null;
};

export type AgentsResponse = {
  schema_version: 2;
  generated_at_ms: number;
  // "unavailable" is a real answer, not a failure: the endpoint looked and
  // could not enumerate. The paid side reports it whenever the agent registry
  // is absent or unreadable. Leaving it out of the union made a valid payload
  // fail validation, so the panel rendered "did not respond" about an endpoint
  // that had answered.
  availability: "loading" | "available" | "error" | "unavailable";
  discovery_limited: boolean;
  auto_connect: {
    status?: "available" | "unavailable";
    enabled: boolean | null;
    mode: string | null;
    refresh_interval_secs: number;
  };
  agents: LocalAgent[];
};

export type TokenAgent = {
  agent_id: string;
  display_name: string;
  availability: string;
  total_tokens: string | null;
  input_tokens: string | null;
  output_tokens: string | null;
  cache_read_input_tokens: string | null;
  cached_input_tokens: string | null;
  cache_creation_input_tokens: string | null;
  reasoning_output_tokens: string | null;
  sessions: number | null;
  last_observed_at_ms: number | null;
  provenance: {
    source: string;
    quality: string;
    note: string;
  };
};

export type TokenIntelligenceResponse = {
  schema_version: number;
  generated_at_ms: number;
  scope: "available_local_history";
  availability: string;
  agents: TokenAgent[];
};

// The Activity screen: server-side filtered + paginated, so the browser never loads
// the whole graph. Mirrors crates/graph's CasesPage / SessionView / CmdView.
export type ActionView = {
  id?: string;
  seq: number;
  command: string;
  recommendation?: string;
  risk: number | null;
  decided_by: string;
  categories: string[];
  asi: string[];
  explanation: string;
  outcome?: DecisionOutcome | string;
  mode_at_decision?: DecisionMode | string;
  recorded_at_ms?: number;
};
// Backwards-compatible source name for code that still mirrors Rust's `CmdView`.
export type CmdView = ActionView;
export type SessionView = {
  id: string;
  label: string;
  commands: number;
  blocked: number; // Legacy alias for deny_verdicts.
  review: number;
  allowed: number;
  items: ActionView[];
  truncated: boolean;
  deny_verdicts?: number;
  review_verdicts?: number;
  allow_verdicts?: number;
  unknown_verdicts?: number;
  actual_blocks?: number;
  would_block?: number;
  screened?: number;
  outcomes_unknown?: number;
};
export type CasesPage = {
  sessions: SessionView[]; total_sessions: number; total_commands: number;
  offset: number; limit: number;
};
export type CasesQuery = {
  verdict?: string; q?: string; session?: string; offset?: number; limit?: number;
};

async function get<T>(path: string): Promise<T> {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) {
    const payload = await r.json().catch(() => undefined) as { error?: string } | undefined;
    throw new Error(payload?.error ?? `${path}: ${r.status}`);
  }
  return r.json();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isNullableDecimalString(value: unknown): boolean {
  return value === null || (typeof value === "string" && /^(0|[1-9]\d*)$/.test(value));
}

function isAgentsResponse(value: unknown): value is AgentsResponse {
  if (!isRecord(value) || !Array.isArray(value.agents) || !isRecord(value.auto_connect)) return false;
  return value.schema_version === 2
    && typeof value.generated_at_ms === "number"
    && ["loading", "available", "error", "unavailable"].includes(String(value.availability))
    && typeof value.discovery_limited === "boolean"
    && (typeof value.auto_connect.enabled === "boolean" || value.auto_connect.enabled === null)
    && (typeof value.auto_connect.mode === "string" || value.auto_connect.mode === null)
    && (value.auto_connect.status == null || value.auto_connect.status === "available" || value.auto_connect.status === "unavailable")
    && typeof value.auto_connect.refresh_interval_secs === "number"
    && value.agents.every((agent) => isRecord(agent)
      && typeof agent.id === "string"
      && typeof agent.display_name === "string"
      && typeof agent.installed === "boolean"
      && (typeof agent.running === "boolean" || agent.running === null)
      && Array.isArray(agent.detected_by)
      && agent.detected_by.every((method) => typeof method === "string")
      && isRecord(agent.guardrail)
      && typeof agent.guardrail.mode === "string"
      && typeof agent.guardrail.setup_support === "string"
      && (typeof agent.guardrail.mechanism === "string" || agent.guardrail.mechanism === null)
      && (typeof agent.auto_connect_eligible === "boolean" || agent.auto_connect_eligible === null));
}

function isTokenIntelligenceResponse(value: unknown): value is TokenIntelligenceResponse {
  if (!isRecord(value) || !Array.isArray(value.agents)) return false;
  return typeof value.schema_version === "number"
    && typeof value.generated_at_ms === "number"
    && value.scope === "available_local_history"
    && typeof value.availability === "string"
    && value.agents.every((agent) => isRecord(agent)
      && typeof agent.agent_id === "string"
      && typeof agent.display_name === "string"
      && typeof agent.availability === "string"
      && isNullableDecimalString(agent.total_tokens)
      && isNullableDecimalString(agent.input_tokens)
      && isNullableDecimalString(agent.output_tokens)
      && isNullableDecimalString(agent.cache_read_input_tokens)
      && isNullableDecimalString(agent.cached_input_tokens)
      && isNullableDecimalString(agent.cache_creation_input_tokens)
      && isNullableDecimalString(agent.reasoning_output_tokens)
      && (typeof agent.sessions === "number" || agent.sessions === null)
      && (typeof agent.last_observed_at_ms === "number" || agent.last_observed_at_ms === null)
      && isRecord(agent.provenance)
      && typeof agent.provenance.source === "string"
      && typeof agent.provenance.quality === "string"
      && typeof agent.provenance.note === "string");
}

async function getValidated<T>(path: string, validate: (value: unknown) => value is T): Promise<T> {
  const value: unknown = await get(path);
  if (!validate(value)) throw new Error(`${path}: invalid response shape`);
  return value;
}

// The guard-decision contract has its own path because ONE bundle is served by
// two products, and `api/overview` already meant something else on the paid side:
// there it is the host overview (events, incidents, AI), with no `top_categories`.
// The Overview screen asked for guard decisions, got a host report, sliced a field
// that was not there, and the whole dashboard rendered WHITE in production.
//
// `api/guard/*` is served by both. The free CLI aliases it onto the handlers
// below; the paid agent answers from the same shared `Graph::overview`.
export const fetchMeta = () => get<DashboardMeta>("api/guard/meta");
export const fetchOverview = () => get<Overview>("api/guard/overview");
export const fetchGraph = () => get<Graph>("api/graph");
// Same reason as `guard/meta` and `guard/overview` above, found the same way:
// these two still asked for the FREE CLI's paths, so on the paid side they 404ed
// and the Overview screen showed "unavailable" panels that retried forever.
// `api/guard/*` is the path both products answer.
export const fetchAgents = () => getValidated("api/guard/agents", isAgentsResponse);
export const fetchTokenIntelligence = () => getValidated("api/guard/token-intelligence", isTokenIntelligenceResponse);
export function fetchCases(p: CasesQuery): Promise<CasesPage> {
  const qs = new URLSearchParams();
  if (p.verdict) qs.set("verdict", p.verdict);
  if (p.q) qs.set("q", p.q);
  if (p.session) qs.set("session", p.session);
  if (p.offset) qs.set("offset", String(p.offset));
  qs.set("limit", String(p.limit ?? 20));
  return get<CasesPage>(`api/cases?${qs.toString()}`);
}
