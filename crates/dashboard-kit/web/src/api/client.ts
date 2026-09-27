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

/**
 * How long one dashboard request may take before it is given up.
 *
 * The screens poll with an in-flight guard, so a request that never answered
 * held every later poll back for good, and the page went on showing the last
 * answer as current: Protection held a control at "Protecting" on a read it
 * could no longer renew. A request past this is a failure like a dropped
 * connection, so the page marks what it shows as stale and the next poll
 * asks again.
 */
export const DASHBOARD_FETCH_TIMEOUT_MS = 30_000;

export function timeoutProblem(endpoint: DashboardEndpoint): DashboardClientFailure {
  return {
    state: "unavailable",
    problem: {
      endpoint,
      httpStatus: null,
      code: "request_timed_out",
      message: "The same-origin dashboard adapter did not answer in time.",
      retryable: true,
      retryAfterSeconds: null,
    },
  };
}

/**
 * A signal for one request that aborts when the caller's does, or when the
 * request has run for `timeoutMs`. `timedOut()` tells the two apart: the
 * caller's abort is theirs to handle, a timeout is a failure to report.
 * `done()` must be called when the request settles.
 */
export function requestDeadline(signal: AbortSignal | undefined, timeoutMs: number): {
  signal: AbortSignal;
  timedOut: () => boolean;
  done: () => void;
} {
  const controller = new AbortController();
  let expired = false;
  const forward = () => controller.abort(signal?.reason);
  if (signal?.aborted) controller.abort(signal.reason);
  else signal?.addEventListener("abort", forward, { once: true });
  const timer = setTimeout(() => {
    expired = true;
    controller.abort("request-timed-out");
  }, timeoutMs);
  return {
    signal: controller.signal,
    timedOut: () => expired,
    done: () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", forward);
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
  readonly #timeoutMs: number;

  constructor(fetchImplementation: Fetch = globalThis.fetch, timeoutMs: number = DASHBOARD_FETCH_TIMEOUT_MS) {
    // Native browser fetch is a host method. Keep its global receiver when it
    // is stored behind the typed client instead of invoking it with the client
    // instance as `this` (which some runtimes reject before issuing a request).
    this.#fetch = fetchImplementation.bind(globalThis);
    this.#timeoutMs = timeoutMs;
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
    const deadline = requestDeadline(signal, this.#timeoutMs);
    try {
      let response: Response;
      try {
        response = await this.#fetch(`${DASHBOARD_API_ROOT}/${endpoint}`, {
          method: "GET",
          cache: "no-store",
          credentials: "same-origin",
          redirect: "error",
          headers: { accept: "application/json" },
          signal: deadline.signal,
        });
      } catch (error) {
        if (deadline.timedOut()) return timeoutProblem(endpoint);
        if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) throw error;
        return networkProblem(endpoint);
      }

      if (!response.ok) return failureForStatus(await responseProblem(response, endpoint));

      let payload: unknown;
      try {
        payload = await response.json();
        return { state: "ready", data: parser(payload) };
      } catch {
        // A body that stopped arriving is a timeout, not a malformed reply.
        if (deadline.timedOut()) return timeoutProblem(endpoint);
        return contractProblem(endpoint);
      }
    } finally {
      deadline.done();
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
