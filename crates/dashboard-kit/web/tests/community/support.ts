import type { Page, Route } from "@playwright/test";

export const EMPTY_OVERVIEW = {
  sessions: 0,
  commands: 0,
  blocked: 0,
  review: 0,
  allowed: 0,
  deny_verdicts: 0,
  review_verdicts: 0,
  allow_verdicts: 0,
  unknown_verdicts: 0,
  actual_blocks: 0,
  would_block: 0,
  screened: 0,
  outcomes_unknown: 0,
  top_categories: [],
  recent_blocks: [],
  recent_decisions: [],
};

export const EMPTY_AGENTS = {
  schema_version: 2,
  generated_at_ms: Date.UTC(2026, 6, 18, 12, 0, 0),
  availability: "available",
  discovery_limited: false,
  auto_connect: {
    status: "available",
    enabled: false,
    mode: "disabled",
    refresh_interval_secs: 30,
  },
  agents: [],
};

export const NO_TOKEN_HISTORY = {
  schema_version: 1,
  generated_at_ms: Date.UTC(2026, 6, 18, 12, 0, 0),
  scope: "available_local_history",
  availability: "no_data",
  agents: [],
};

export const action = (overrides: Record<string, unknown> = {}) => ({
  id: "decision-1",
  seq: 1,
  command: "printf safe",
  recommendation: "allow",
  risk: 0,
  decided_by: "rules",
  categories: [],
  asi: [],
  explanation: "A deterministic fixture decision.",
  outcome: "allowed",
  mode_at_decision: "check",
  recorded_at_ms: Date.UTC(2026, 6, 18, 12, 0, 0),
  ...overrides,
});

export const session = (overrides: Record<string, unknown> = {}) => ({
  id: "session-1",
  label: "fixture-session",
  commands: 1,
  blocked: 0,
  review: 0,
  allowed: 1,
  deny_verdicts: 0,
  review_verdicts: 0,
  allow_verdicts: 1,
  unknown_verdicts: 0,
  actual_blocks: 0,
  would_block: 0,
  screened: 1,
  outcomes_unknown: 0,
  items: [action()],
  truncated: false,
  ...overrides,
});

export const casesPage = (overrides: Record<string, unknown> = {}) => ({
  sessions: [session()],
  total_sessions: 1,
  total_commands: 1,
  offset: 0,
  limit: 12,
  ...overrides,
});

export async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(body),
  });
}

export async function installOverview(page: Page, body: unknown = EMPTY_OVERVIEW) {
  await page.route("**/api/guard/overview", (route) => fulfillJson(route, body));
}

export async function installMachineDefaults(page: Page) {
  await page.route("**/api/guard/agents", (route) => fulfillJson(route, EMPTY_AGENTS));
  await page.route("**/api/guard/token-intelligence", (route) => fulfillJson(route, NO_TOKEN_HISTORY));
}
