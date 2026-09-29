import { readFileSync } from "node:fs";
import { expect, type Page, type Route } from "@playwright/test";

/**
 * What the Community journeys share: the fixtures the CLI's own test writes
 * (`tests/fixtures/community`, never edited by hand), the answers a fresh
 * install gives, and the checks every page must pass.
 */

export function fixture<T = any>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../fixtures/community/${name}`, import.meta.url), "utf8")) as T;
}

/** The fixture record's clock: 2026-09-29 14:05 UTC. */
export const FIXTURE_NOW_MS = Date.UTC(2026, 8, 29, 14, 5, 0);

/** The two synthetic sessions the fixture record holds. */
export const S_APP = "4b1d9c2e-demo-4000-8000-000000000001";
export const S_INFRA = "7e0a55f1-demo-4000-8000-000000000002";

/** Fixture cases, by what happened to them. */
export const CASE = {
  /** `cat ~/.ssh/config` in monitor mode: a deny, recorded, and it ran. */
  wouldRefuse: `cmd:${S_APP}:63`,
  /** `bash /tmp/build-cache/run.sh --clean`: a review, and it ran. */
  flaggedRan: `cmd:${S_APP}:62`,
  /** `curl ... | sh` in monitor mode: a fetch from the internet by name. */
  domainFetch: `cmd:${S_APP}:56`,
  /** `sudo rm -rf / --no-preserve-root` in enforce mode: refused. */
  refused: `cmd:${S_INFRA}:20`,
  /** An MCP call judged unsafe that carried nothing to refuse. */
  unsafeRan: "cmd:mcp:cursor:1",
  /** `innerwarden check` by hand. */
  checked: "cmd:local:0",
} as const;

export const META = {
  version: "1.5.0-fixture",
  exposed: false,
  edition: "community",
  guardrail: { mode: "monitor", guarded_agents: 1 },
};

export async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(body),
  });
}

/** Matches one `guard/*` route by its path, whatever its query string. */
export function guardRoute(name: string) {
  return (url: URL) => url.pathname === `/api/guard/${name}`;
}

export const EMPTY_AGENTS = {
  schema_version: 2,
  generated_at_ms: FIXTURE_NOW_MS,
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
  generated_at_ms: FIXTURE_NOW_MS,
  scope: "available_local_history",
  availability: "no_data",
  agents: [],
};

/**
 * The overview a fresh install answers, as the CLI builds it: nothing
 * recorded, no agent connected, observe not installed.
 */
export const ZERO_OVERVIEW = {
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
  lanes: {
    agent_actions: {
      lane: "agent_actions",
      availability: "no_source",
      sentence: "No agent is connected to the guard yet.",
      next_step: {
        command: "innerwarden agents connect --all --monitor",
        line: "Connects every agent it finds, in monitor mode: it records and refuses nothing.",
      },
    },
    agent_messages: {
      lane: "agent_messages",
      availability: "no_source",
      sentence: "Nothing records what people ask your agent yet.",
      next_step: {
        command: "innerwarden observe install",
        line: "Records the risky messages people send your agent. It does not block them.",
      },
    },
    server_attacks: {
      lane: "server_attacks",
      availability: "no_source",
      sentence: "Community watches what your AI agents try to run. It does not watch this machine itself.",
    },
  },
  record: { decisions: 0, flagged: 0 },
};

export const EMPTY_DECISIONS = {
  schema_version: 1,
  generated_at_ms: FIXTURE_NOW_MS,
  items: [],
  total: 0,
  flagged_total: 0,
  by_outcome: {},
  reasons: [],
  reasons_distinct: 0,
  sessions: {},
  suppress: { allow: 0, mute_rules: 0, mute_categories: 0 },
  record: { decisions: 0, flagged: 0 },
};

export const EMPTY_HISTORY = {
  schema_version: 1,
  generated_at_ms: FIXTURE_NOW_MS,
  readable: true,
  unparsable_lines: 0,
  refusals: { blocked: 0, would_block: 0, weeks: [] },
  messages: { recorded: 0, last_7d: 0 },
  suppression_changes: 0,
};

export const EMPTY_ATTEMPTS = { schema_version: 1, items: [], total: 0 };

/** Routes every source a fresh install reads, answering as it would. */
export async function installZero(page: Page) {
  await page.route(guardRoute("overview"), (route) => fulfillJson(route, ZERO_OVERVIEW));
  await page.route(guardRoute("decisions"), (route) => fulfillJson(route, EMPTY_DECISIONS));
  await page.route(guardRoute("history"), (route) => {
    const attempts = new URL(route.request().url()).searchParams.get("kind") === "attempt";
    return fulfillJson(route, attempts ? EMPTY_ATTEMPTS : EMPTY_HISTORY);
  });
  await page.route(guardRoute("agents"), (route) => fulfillJson(route, EMPTY_AGENTS));
  await page.route(guardRoute("token-intelligence"), (route) => fulfillJson(route, NO_TOKEN_HISTORY));
}

export async function pageWidth(page: Page) {
  return page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
}

/**
 * The upgrade path's two hard rules, on whatever page is open: at most one
 * link to innerwarden.com, and nothing drawn blurred (no locked screen, no
 * teaser behind frosted glass).
 */
export async function expectHonestUpsell(page: Page) {
  expect(await page.locator('a[href^="https://innerwarden.com"]').count()).toBeLessThanOrEqual(1);
  const blurred = await page.evaluate(() =>
    Array.from(document.querySelectorAll("*")).filter((element) => {
      const style = getComputedStyle(element);
      return style.filter.includes("blur") || style.backdropFilter.includes("blur");
    }).length,
  );
  expect(blurred).toBe(0);
}

/** The five Community tabs, in the nav's order, with the route each opens. */
export const COMMUNITY_TABS = [
  ["Overview", "/"],
  ["Protection", "/?view=posture"],
  ["Cases", "/?view=activity"],
  ["Agents", "/?view=agents"],
  ["Tokens", "/?view=tokens"],
] as const;

/** What each page draws once it has an answer, to wait on before measuring. */
export const PAGE_READY: Record<(typeof COMMUNITY_TABS)[number][0], string> = {
  Overview: "#on-machine-title",
  Protection: "#protection-title",
  Cases: "#cases-title",
  Agents: "#agents-title",
  Tokens: "#tokens-title",
};
