import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page } from "@playwright/test";
import type {
  CapabilityStatus,
  ClaimState,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EffectiveMode,
  EvidenceFreshness,
  EvidenceRef,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
  StageAnswer,
  VersionRef,
} from "../../src/api/v1";

const communityUrl = "http://127.0.0.1:4173/";
const enterpriseUrl = "http://127.0.0.1:4174/";
const generatedAt = "2026-07-18T12:00:01Z";
const observedAt = "2026-07-18T12:00:00Z";
const evaluatedAt = "2026-07-18T12:00:01Z";

const baseEnterpriseBootstrap = JSON.parse(readFileSync(
  new URL("../fixtures/enterprise/bootstrap.json", import.meta.url),
  "utf8",
)) as DashboardBootstrap;
const claimLanguageSnapshots = JSON.parse(readFileSync(
  new URL("../fixtures/acceptance/claim-language.snapshots.json", import.meta.url),
  "utf8",
)) as Record<string, unknown>;

const assuranceMatrix: VersionRef = {
  id: "innerwarden.assurance-matrix",
  version: "AM-090-v1",
  canonicalization: "YAML-TO-RFC8785-JCS",
  digest: `sha256:${"a".repeat(64)}`,
};

const source = {
  id: "claim-language-runtime",
  kind: "kernel_state" as const,
  authority: "canonical" as const,
  version: "1",
  completeness: "complete" as const,
  limitations: [],
};

const fresh: EvidenceFreshness = {
  observed_at: observedAt,
  budget_seconds: 30,
  state: "fresh",
  age_seconds: 1,
};

const unknownFreshness: EvidenceFreshness = {
  observed_at: null,
  budget_seconds: 30,
  state: "unknown",
  age_seconds: null,
};

const evidence: EvidenceRef = {
  id: "claim-language-evidence",
  kind: "runtime_verification",
  source,
  observed_at: observedAt,
  integrity: "verified",
  redaction: [],
  freshness: fresh,
};

const scope: ScopeRef = {
  id: "host:claim-language",
  kind: "host",
  display_name: "claim-language host",
  verification: "host_verified",
  evidence: [evidence],
};

type EnterpriseClaimState = "observe" | "rehearse" | "enforce" | "degraded" | "unknown";

function stage(state: StageAnswer): RuntimeConvergence["configured"] {
  return {
    state,
    evidence: state === "yes" ? [evidence] : [],
    reason_code: state === "unknown" ? "runtime_state_unknown" : null,
  };
}

function convergence(state: EnterpriseClaimState): RuntimeConvergence {
  if (state === "unknown") {
    return {
      configured: stage("unknown"),
      loaded: stage("unknown"),
      running: stage("unknown"),
      enforcing: stage("unknown"),
      verified_effective: stage("unknown"),
    };
  }
  const enforcing = state === "enforce" ? stage("yes") : stage("not_applicable");
  return {
    configured: stage("yes"),
    loaded: stage("yes"),
    running: stage("yes"),
    enforcing,
    verified_effective: enforcing,
  };
}

function modeFor(state: EnterpriseClaimState): EffectiveMode {
  if (state === "degraded") return "observe";
  return state;
}

function claimStateFor(state: EnterpriseClaimState): ClaimState {
  if (state === "observe") return "visibility_only";
  if (state === "rehearse") return "readiness_only";
  if (state === "enforce") return "active";
  return state;
}

function gapFor(state: EnterpriseClaimState): CoverageGap[] {
  if (state !== "degraded") return [];
  return [{
    id: "claim-language-gap",
    capability_id: "kernel_execution_control",
    affected_scope: [scope],
    action_classes: ["process_execution"],
    state: "degraded",
    evidence: [evidence],
    next_step: "Restore verified runtime convergence before making an enforcement claim",
  }];
}

function capabilityFor(state: EnterpriseClaimState): CapabilityStatus {
  const mode = modeFor(state);
  const isUnknown = state === "unknown";
  const gaps = gapFor(state);
  return {
    id: "kernel_execution_control",
    tier: "enterprise_core",
    availability: isUnknown ? "unknown" : state === "degraded" ? "degraded" : "available",
    entitlement: isUnknown ? "unknown" : "valid",
    support: isUnknown ? "unknown" : "supported",
    desired_mode: mode,
    effective_mode: mode,
    convergence: convergence(state),
    rollout_state: state === "observe"
      ? "observing"
      : state === "rehearse"
        ? "rehearsing"
        : state === "enforce"
          ? "enforcing"
          : state,
    health: isUnknown ? "unknown" : state === "degraded" ? "degraded" : "healthy",
    scope: isUnknown ? [] : [scope],
    covered_action_classes: isUnknown ? [] : ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: gaps.length ? ["runtime_convergence_unverified"] : [],
    freshness: isUnknown ? unknownFreshness : fresh,
    last_evidence: isUnknown ? null : evidence,
    sources: isUnknown ? [] : [source],
    claims: state === "enforce" ? [{
      id: "claim-language-active-enforcement",
      statement: "Covered process executions are blocked before execution",
      semantic_key: null,
      status: "verified",
      versions: [assuranceMatrix],
      population: scope.id,
      environment: "linux",
      observed_at: observedAt,
      reviewed_at: observedAt,
      expires_at: "2026-07-18T12:00:30Z",
      scope: [scope],
      action_classes: ["process_execution"],
      evidence: [evidence],
      limitations: [],
    }] : [],
    reason_code: isUnknown ? "runtime_state_unknown" : state === "degraded" ? "runtime_convergence_unverified" : null,
    summary: `${state} claim-language fixture`,
  };
}

function postureFor(state: EnterpriseClaimState): DashboardPosture {
  const isUnknown = state === "unknown";
  const mode = modeFor(state);
  const gaps = gapFor(state);
  const layer: ProtectionLayer = {
    id: "host_execution_layer",
    label: "Independent host execution control",
    capability_ids: ["kernel_execution_control"],
    claim_state: claimStateFor(state),
    effective_mode: mode,
    effective_scope: isUnknown ? [] : [scope],
    covered_action_classes: isUnknown ? [] : ["process_execution"],
    known_gaps: gaps,
    freshness: isUnknown ? unknownFreshness : fresh,
    convergence: convergence(state),
    evidence: isUnknown ? [] : [evidence],
  };
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: generatedAt,
    layers: [layer],
    gaps,
  };
}

async function installEnterpriseClaimState(page: Page, state: EnterpriseClaimState) {
  await page.clock.install({ time: new Date(evaluatedAt) });
  const capability = capabilityFor(state);
  const bootstrap: DashboardBootstrap = {
    ...structuredClone(baseEnterpriseBootstrap),
    generated_at: generatedAt,
    assurance_matrix: assuranceMatrix,
    platform: {
      ...baseEnterpriseBootstrap.platform,
      os: "linux",
    },
    capabilities: [capability],
    highest_priority_gap: gapFor(state)[0] ?? null,
  };
  await page.route("**/api/dashboard/v1/bootstrap", (route) => route.fulfill({ json: bootstrap }));
  await page.route("**/api/dashboard/v1/posture", (route) => route.fulfill({ json: postureFor(state) }));
}

function normalizedText(locator: Locator) {
  return locator.innerText().then((value) => value.replace(/\s+/g, " ").trim());
}

function datum(layer: Locator, label: string) {
  return normalizedText(layer.locator("dt", { hasText: label }).locator("xpath=following-sibling::dd"));
}

async function enterpriseClaimLanguage(page: Page) {
  const layer = page.getByRole("article").filter({
    has: page.getByRole("heading", { name: "Independent host execution control" }),
  });
  return {
    edition: await normalizedText(page.getByText("Enterprise", { exact: true }).first()),
    boundary: await normalizedText(layer.getByRole("heading", { name: "Independent host execution control" })),
    assurance: await normalizedText(layer.locator("[data-status]").first()),
    effectiveMode: await datum(layer, "Effective mode"),
    freshness: await datum(layer, "Freshness"),
    effectiveScopes: await datum(layer, "Effective scopes"),
    evidenceRecords: await datum(layer, "Evidence records"),
  };
}

async function expectNoUnsupportedProtectionClaim(page: Page) {
  await expect(page.getByText("Verified active enforcement", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Protected", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Contained", { exact: true })).toHaveCount(0);
}

test("Community language states its useful agent boundary without implying host protection", async ({ page }) => {
  await page.goto(communityUrl);

  const communityHero = page.locator("section[aria-labelledby='posture-title']");
  const hostBoundary = page.locator("aside[aria-labelledby='active-defence-title']");
  const language = {
    edition: await normalizedText(page.getByText("Community", { exact: true }).first()),
    boundary: await normalizedText(communityHero.getByText("InnerWarden Community", { exact: true })),
    title: await normalizedText(communityHero.locator("#posture-title")),
    description: await normalizedText(communityHero.locator("#posture-title + p")),
    hostBoundaryTitle: await normalizedText(hostBoundary.locator("#active-defence-title")),
    hostBoundaryDescription: await normalizedText(hostBoundary.locator("#active-defence-title + p")),
  };

  expect(language).toEqual(claimLanguageSnapshots.community);
  await expect(page.getByText("Verified active enforcement", { exact: true })).toHaveCount(0);
});

test("Observe language is visibility-only", async ({ page }) => {
  await installEnterpriseClaimState(page, "observe");
  await page.goto(enterpriseUrl);

  expect(await enterpriseClaimLanguage(page)).toEqual(claimLanguageSnapshots.observe);
  await expectNoUnsupportedProtectionClaim(page);
});

test("Rehearse language is readiness-only", async ({ page }) => {
  await installEnterpriseClaimState(page, "rehearse");
  await page.goto(enterpriseUrl);

  expect(await enterpriseClaimLanguage(page)).toEqual(claimLanguageSnapshots.rehearse);
  await expectNoUnsupportedProtectionClaim(page);
});

test("Enforce language appears only for a fresh matrix-bound verified scope", async ({ page }) => {
  await installEnterpriseClaimState(page, "enforce");
  await page.goto(enterpriseUrl);

  expect(await enterpriseClaimLanguage(page)).toEqual(claimLanguageSnapshots.enforce);
  await expect(page.getByText("Verified active enforcement", { exact: true })).toBeVisible();
  await expect(page.getByText("Protected", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Contained", { exact: true })).toHaveCount(0);
});

test("degraded language withdraws the active claim and keeps the scoped recovery action", async ({ page }) => {
  await installEnterpriseClaimState(page, "degraded");
  await page.goto(enterpriseUrl);

  const recovery = page.locator("p").filter({ hasText: "Recorded next step:" });
  expect({
    ...await enterpriseClaimLanguage(page),
    recovery: await normalizedText(recovery),
  }).toEqual(claimLanguageSnapshots.degraded);
  await expect(recovery).toBeVisible();
  await expectNoUnsupportedProtectionClaim(page);
});

test("unknown language keeps missing scope and evidence unknown instead of converting them to protection", async ({ page }) => {
  await installEnterpriseClaimState(page, "unknown");
  await page.goto(enterpriseUrl);

  expect(await enterpriseClaimLanguage(page)).toEqual(claimLanguageSnapshots.unknown);
  await expectNoUnsupportedProtectionClaim(page);
});
