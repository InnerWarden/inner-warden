import type { AgentInventory, DashboardBootstrap, DashboardPosture, TokenIntelligence } from "./v1";
import { parseAgentInventory, parseDashboardBootstrap, parseDashboardPosture, parseTokenIntelligence } from "./validate";

export const DASHBOARD_API_ROOT = "/api/dashboard/v1";

export type DashboardEndpoint =
  | "bootstrap"
  | "posture"
  | "agents"
  | "token-intelligence"
  | "cases"
  | "case_detail"
  | "evaluation"
  | "evaluation_draft"
  | "action_preview"
  | "privileged_action"
  | "proof_report";

export type DashboardApiProblem = {
  endpoint: DashboardEndpoint;
  httpStatus: number | null;
  code: string;
  message: string;
  retryable: boolean;
  retryAfterSeconds: number | null;
};

export type DashboardClientFailure =
  | { state: "authentication_required"; problem: DashboardApiProblem }
  | { state: "forbidden"; problem: DashboardApiProblem }
  | { state: "unavailable"; problem: DashboardApiProblem }
  | { state: "unsupported"; problem: DashboardApiProblem }
  | { state: "conflict"; problem: DashboardApiProblem }
  | { state: "rate_limited"; problem: DashboardApiProblem }
  | { state: "error"; problem: DashboardApiProblem };

export type DashboardClientResult<T> = { state: "ready"; data: T } | DashboardClientFailure;

export type DashboardResource<T> =
  | { state: "idle" | "loading" }
  | { state: "ready"; data: T }
  | { state: "stale"; data: T; problem: DashboardApiProblem }
  | DashboardClientFailure;

type Parser<T> = (value: unknown) => T;
type Fetch = typeof globalThis.fetch;

function boundedText(value: unknown, fallback: string, maximum: number): string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum ? value : fallback;
}

function parseRetryAfter(response: Response): number | null {
  const raw = response.headers.get("retry-after");
  if (raw === null || !/^[1-9][0-9]{0,4}$/.test(raw)) return null;
  const value = Number(raw);
  return value <= 86_400 ? value : null;
}

export async function responseProblem(response: Response, endpoint: DashboardEndpoint): Promise<DashboardApiProblem> {
  const payload = await response.json().catch(() => undefined) as Record<string, unknown> | undefined;
  return {
    endpoint,
    httpStatus: response.status,
    code: boundedText(payload?.code, `http_${response.status}`, 128),
    message: boundedText(payload?.message, "The dashboard adapter did not return a usable response.", 2_048),
    retryable: typeof payload?.retryable === "boolean" ? payload.retryable : response.status >= 500 || response.status === 429,
    retryAfterSeconds: parseRetryAfter(response),
  };
}

export function failureForStatus(problem: DashboardApiProblem): DashboardClientFailure {
  switch (problem.httpStatus) {
    case 401:
      return { state: "authentication_required", problem };
    case 403:
      return { state: "forbidden", problem };
    case 409:
      return { state: "conflict", problem };
    case 404:
    case 503:
      return { state: "unavailable", problem };
    case 501:
      return { state: "unsupported", problem };
    case 429:
      return { state: "rate_limited", problem };
    default:
      return { state: "error", problem };
  }
}

export function networkProblem(endpoint: DashboardEndpoint): DashboardClientFailure {
  return {
    state: "unavailable",
    problem: {
      endpoint,
      httpStatus: null,
      code: "network_unavailable",
      message: "The same-origin dashboard adapter could not be reached.",
      retryable: true,
      retryAfterSeconds: null,
    },
  };
}

export function contractProblem(endpoint: DashboardEndpoint): DashboardClientFailure {
  return {
    state: "error",
    problem: {
      endpoint,
      httpStatus: 200,
      code: "contract_validation_failed",
      message: "The adapter response did not match the dashboard v1 contract.",
      retryable: false,
      retryAfterSeconds: null,
    },
  };
}

export class DashboardV1Client {
  readonly #fetch: Fetch;

  constructor(fetchImplementation: Fetch = globalThis.fetch) {
    // Native browser fetch is a host method. Keep its global receiver when it
    // is stored behind the typed client instead of invoking it with the client
    // instance as `this` (which some runtimes reject before issuing a request).
    this.#fetch = fetchImplementation.bind(globalThis);
  }

  getBootstrap(signal?: AbortSignal): Promise<DashboardClientResult<DashboardBootstrap>> {
    return this.#get("bootstrap", parseDashboardBootstrap, signal);
  }

  getPosture(signal?: AbortSignal): Promise<DashboardClientResult<DashboardPosture>> {
    return this.#get("posture", parseDashboardPosture, signal);
  }

  getAgents(signal?: AbortSignal): Promise<DashboardClientResult<AgentInventory>> {
    return this.#get("agents", parseAgentInventory, signal);
  }

  getTokenIntelligence(signal?: AbortSignal): Promise<DashboardClientResult<TokenIntelligence>> {
    return this.#get("token-intelligence", parseTokenIntelligence, signal);
  }

  async #get<T>(endpoint: DashboardEndpoint, parser: Parser<T>, signal?: AbortSignal): Promise<DashboardClientResult<T>> {
    let response: Response;
    try {
      response = await this.#fetch(`${DASHBOARD_API_ROOT}/${endpoint}`, {
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

    let payload: unknown;
    try {
      payload = await response.json();
      return { state: "ready", data: parser(payload) };
    } catch {
      return contractProblem(endpoint);
    }
  }
}

export const dashboardV1Client = new DashboardV1Client();

/** Retain only previously validated data and label it stale after a failed refresh. */
export function retainDashboardResource<T>(
  previous: DashboardResource<T>,
  result: DashboardClientResult<T>,
): DashboardResource<T> {
  if (result.state === "ready") return result;
  if (previous.state === "ready" || previous.state === "stale") {
    return { state: "stale", data: previous.data, problem: result.problem };
  }
  return result;
}
