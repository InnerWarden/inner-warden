import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const baseBootstrap = JSON.parse(readFileSync(new URL("../fixtures/enterprise/bootstrap.json", import.meta.url), "utf8"));

const observedAt = "2026-07-18T12:00:00Z";
const source = {
  id: "fixture-runtime-probe",
  kind: "runtime_probe",
  authority: "canonical",
  version: "1",
  completeness: "complete",
  limitations: [],
};
const fresh = { observed_at: observedAt, budget_seconds: 30, state: "fresh", age_seconds: 0 };
const evidence = {
  id: "fixture-evidence",
  kind: "runtime_probe",
  source,
  observed_at: observedAt,
  integrity: "verified",
  redaction: [],
  freshness: fresh,
};
const scope = {
  id: "host:fixture",
  kind: "host",
  display_name: "fixture host",
  verification: "host_verified",
  evidence: [evidence],
};

function stage(state: "yes" | "no" | "unknown" | "not_applicable", reasonCode: string | null = null) {
  return { state, evidence: state === "yes" ? [evidence] : [], reason_code: reasonCode };
}

function hostCapability(state: "healthy" | "partial" | "stale" | "unsupported") {
  const available = state === "healthy";
  const unsupported = state === "unsupported";
  const stale = state === "stale";
  return {
    id: "host_visibility",
    tier: "enterprise_core",
    availability: unsupported ? "unsupported" : stale ? "stale" : available ? "available" : "degraded",
    entitlement: "not_required",
    support: unsupported ? "unsupported" : state === "partial" ? "partial" : "supported",
    desired_mode: "observe",
    effective_mode: unsupported ? "disabled" : "observe",
    convergence: {
      configured: unsupported ? stage("not_applicable") : stage("yes"),
      loaded: unsupported ? stage("not_applicable") : stage("yes"),
      running: unsupported ? stage("unknown", "unsupported_host") : stage("yes"),
      enforcing: stage("not_applicable"),
      verified_effective: stage("not_applicable"),
    },
    rollout_state: unsupported ? "ineligible" : state === "partial" ? "degraded" : "observing",
    health: available ? "healthy" : state === "partial" ? "degraded" : "unknown",
    scope: unsupported ? [] : [scope],
    covered_action_classes: [],
    bypass_classes: [],
    known_uncovered_paths: state === "partial" ? ["collector_without_runtime_confirmation"] : [],
    freshness: unsupported
      ? { observed_at: null, budget_seconds: 30, state: "missing", age_seconds: null }
      : stale
        ? { observed_at: observedAt, budget_seconds: 30, state: "stale", age_seconds: 90 }
        : fresh,
    last_evidence: unsupported ? null : evidence,
    sources: unsupported ? [] : [source],
    claims: [],
    reason_code: unsupported ? "platform_unsupported" : state === "partial" ? "collector_partial" : stale ? "producer_stale" : null,
    summary: `${state} host visibility fixture`,
  };
}

function gap(state: "degraded" | "stale" | "unsupported") {
  return {
    id: `${state}-host-gap`,
    capability_id: "host_visibility",
    affected_scope: state === "unsupported" ? [] : [scope],
    action_classes: ["host_observation"],
    state,
    evidence: state === "unsupported" ? [] : [evidence],
    next_step: state === "unsupported" ? "Use a supported Linux host" : "Restore current collector evidence",
  };
}

function hostPosture(state: "healthy" | "partial" | "stale" | "unsupported") {
  const capability = hostCapability(state);
  const gaps = state === "healthy" ? [] : [gap(state === "partial" ? "degraded" : state)];
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: observedAt,
    layers: [{
      id: "host_visibility_layer",
      label: "Host visibility",
      capability_ids: [capability.id],
      claim_state: state === "healthy" ? "visibility_only" : state === "unsupported" ? "unavailable" : "degraded",
      effective_mode: capability.effective_mode,
      effective_scope: capability.scope,
      covered_action_classes: [],
      known_gaps: gaps,
      freshness: capability.freshness,
      convergence: capability.convergence,
      evidence: capability.last_evidence ? [capability.last_evidence] : [],
    }],
    gaps,
  };
}

async function installEnterpriseState(page: Page, state: "healthy" | "partial" | "stale" | "unsupported", includeAgents = false, includeTokens = false) {
  const capabilities = [hostCapability(state)];
  if (includeAgents) {
    capabilities.push({
      ...hostCapability("partial"),
      id: "community.agent_discovery",
      tier: "community",
      entitlement: "not_required",
      availability: "available",
      support: "supported",
      summary: "bounded provider-neutral discovery",
    });
  }
  if (includeTokens) {
    capabilities.push({
      ...hostCapability("partial"),
      id: "community.token_intelligence",
      tier: "community",
      entitlement: "not_required",
      availability: "available",
      support: "supported",
      summary: "numeric retained-history counters only",
    });
  }
  const bootstrap = structuredClone(baseBootstrap);
  bootstrap.capabilities = capabilities;
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: bootstrap }));
  await page.route("**/api/dashboard/v1/posture", (route) => route.fulfill({ json: hostPosture(state) }));
}

test("Community keeps its current white shell and logo returns to home", async ({ page }) => {
  await page.goto("http://127.0.0.1:4173/");
  await expect(page.getByText("Community", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connect an agent to start screening its actions." })).toBeVisible();

  await page.getByRole("button", { name: "Activity" }).click();
  await expect(page.getByRole("heading", { name: "Activity" })).toBeVisible();
  await page.getByRole("button", { name: "Go to overview" }).click();
  await expect(page.getByRole("heading", { name: "Connect an agent to start screening its actions." })).toBeVisible();
});

test("healthy Enterprise mounts capability-derived Posture without Community upsell content", async ({ page }) => {
  await installEnterpriseState(page, "healthy");
  await page.goto("/");

  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Posture" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Runtime assurance foundation" })).toBeVisible();
  await expect(page.getByText("Explore Active Defence", { exact: false })).toHaveCount(0);

  await page.getByRole("button", { name: "Posture" }).click();
  await expect(page.getByRole("heading", { name: "Agent-boundary controls" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Independent host controls" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Host visibility" })).toBeVisible();
  await expect(page.getByText("Visibility only", { exact: true })).toBeVisible();
});

test("partial Enterprise keeps the scoped gap and degraded semantics visible", async ({ page }) => {
  await installEnterpriseState(page, "partial");
  await page.goto("/");
  await page.getByRole("button", { name: "Posture" }).click();

  await expect(page.getByText("Evidence degraded", { exact: true })).toBeVisible();
  await expect(page.getByText("Degraded", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Restore current collector evidence", { exact: false }).first()).toBeVisible();
});

test("stale Enterprise never presents last-known host posture as current", async ({ page }) => {
  await installEnterpriseState(page, "stale");
  await page.goto("/");
  await page.getByRole("button", { name: "Posture" }).click();

  await expect(page.getByText(/Stale; 90s old; 30s budget/)).toBeVisible();
  await expect(page.getByText("Verified active enforcement", { exact: true })).toHaveCount(0);
});

test("unsupported Enterprise capability stays visible without equivalent-protection wording", async ({ page }) => {
  await installEnterpriseState(page, "unsupported");
  await page.goto("/");
  await page.getByRole("button", { name: "Posture" }).click();

  await expect(page.getByText("Unavailable", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Unsupported", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Use a supported Linux host", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("Verified active enforcement", { exact: true })).toHaveCount(0);
});

test("adapter-absent Enterprise shell does not fall back to legacy or Community content", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Enterprise posture adapter not declared" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Posture" })).toHaveCount(0);
  await expect(page.getByText("Community Edition", { exact: true })).toHaveCount(0);
  await expect(page.getByText("No layers reported", { exact: true })).toHaveCount(0);
});

test("declared but unavailable adapter is explicit and does not reuse legacy payloads", async ({ page }) => {
  await installEnterpriseState(page, "healthy");
  await page.unroute("**/api/dashboard/v1/posture");
  await page.route("**/api/dashboard/v1/posture", (route) => route.fulfill({
    status: 503,
    json: {
      schema_version: "innerwarden.dashboard.v1",
      code: "posture_adapter_unavailable",
      message: "Fixture adapter unavailable",
      retryable: true,
    },
  }));
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Enterprise posture is unavailable" })).toBeVisible();
  await expect(page.getByText("Runtime assurance foundation", { exact: true })).toHaveCount(0);
});

test("renamed or spoofed vendor metadata remains conflicting rather than trusted", async ({ page }) => {
  await installEnterpriseState(page, "healthy", true);
  await page.route("**/api/dashboard/v1/agents", (route) => route.fulfill({ json: {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: observedAt,
    availability: "available",
    discovery_limited: false,
    subjects: [{
      agent_id: "spoofed-claude-wrapper",
      principal: null,
      product: "Claude Code",
      provider: "Anthropic",
      agent_class: "custom",
      runtime: "renamed-wrapper",
      model: null,
      identity_confidence: "conflicting",
      identity_evidence: [{ ...evidence, integrity: "unverified" }],
      sessions: [],
      capabilities: [
        { capability: "discovery", availability: "available", support: "supported", evidence: [{ ...evidence, integrity: "unverified" }], limitations: ["process label conflicts with executable provenance"], observed_at: observedAt },
        { capability: "automatic_setup", availability: "unsupported", support: "unsupported", evidence: [], limitations: ["unreviewed integration"], observed_at: null },
      ],
    }],
  } }));
  await page.goto("/");
  await page.getByRole("button", { name: "Agents" }).click();

  await expect(page.getByRole("heading", { name: "Observed agent spoofed-claude-wrapper" })).toBeVisible();
  await expect(page.getByText("Conflicting identity", { exact: true })).toBeVisible();
  await expect(page.getByText("Claude Code", { exact: true })).toBeVisible();
  await expect(page.getByText("This identity is not host verified.", { exact: false })).toBeVisible();
  await expect(page.getByText("Host verified", { exact: true })).toHaveCount(0);
});

test("Enterprise keeps Community token intelligence visible without losing precision or inventing unavailable values", async ({ page }) => {
  await installEnterpriseState(page, "healthy", false, true);
  await page.route("**/api/dashboard/v1/token-intelligence", (route) => route.fulfill({ json: {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: observedAt,
    availability: "available",
    scope: "available_local_history",
    totals: {
      total: "900719925474099312345",
      input: "900719925474099300000",
      output: "12345",
      cache_read_input: null,
      cached_input: null,
      cache_creation_input: null,
      reasoning_output: null,
    },
    providers: [{
      agent_id: "codex",
      display_name: "Codex",
      availability: "available",
      counters: {
        total: "900719925474099312345",
        input: "900719925474099300000",
        output: "12345",
        cache_read_input: null,
        cached_input: null,
        cache_creation_input: null,
        reasoning_output: null,
      },
      sessions: "17",
      last_observed_at: observedAt,
      provenance: { ...evidence.source, id: "codex-local-history", kind: "local_history", completeness: "partial" },
      note: "Retained local history; not billing data.",
    }, {
      agent_id: "unknown-agent",
      display_name: "Unknown agent",
      availability: "unsupported",
      counters: { total: null, input: null, output: null, cache_read_input: null, cached_input: null, cache_creation_input: null, reasoning_output: null },
      sessions: null,
      last_observed_at: null,
      provenance: { ...evidence.source, id: "no-supported-history", kind: "local_history", completeness: "unknown" },
      note: "No supported source; no estimate inferred.",
    }],
  } }));

  await page.goto("/");
  await page.getByRole("button", { name: "Tokens" }).click();

  await expect(page.getByRole("heading", { name: "Token intelligence" })).toBeVisible();
  await expect(page.getByText("900,719,925,474,099,312,345", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("No supported local counter is available for this source")).toBeVisible();
  await expect(page.getByText("not billing data or a security score", { exact: false })).toBeVisible();
});
