import { describe, expect, it } from "vitest";
// The screen's own source, for the structural guard at the bottom of this file.
import postureSource from "./Posture.tsx?raw";
import type {
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  EvidenceRef,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
  SourceRef,
  StageAnswer,
} from "../api/v1";
import {
  checkedAt,
  controlPill,
  dispositionLabel,
  dispositionOf,
  dispositionReason,
  dispositionTone,
  emptyGapsLine,
  gapAudience,
  effectiveDisposition,
  needsOperator,
  plainMode,
  postureHeadline,
  scopeDisplay,
} from "./Posture";

// A realistic enterprise posture payload: the five host controls the paid
// adapter actually publishes (execution gate, host visibility, DNS guard,
// secret guard, response controls), all tier enterprise_core, with the gap mix
// observed on a healthy production host.

const generatedAt = "2026-08-07T12:00:02Z";
const observedAt = "2026-08-07T12:00:00Z";
const evaluatedAt = "2026-08-07T12:00:02Z";

const source: SourceRef = {
  id: "posture-runtime",
  kind: "kernel_state",
  authority: "canonical",
  version: "1",
  completeness: "complete",
  limitations: [],
};

const fresh: EvidenceFreshness = { observed_at: observedAt, budget_seconds: 30, state: "fresh", age_seconds: 2 };

const evidence: EvidenceRef = {
  id: "posture-evidence",
  kind: "runtime_verification",
  source,
  observed_at: observedAt,
  integrity: "verified",
  redaction: [],
  freshness: fresh,
};

const hostScope: ScopeRef = {
  id: "host:prod-01",
  kind: "host",
  display_name: "prod-01",
  verification: "host_verified",
  evidence: [evidence],
};

const agentScope: ScopeRef = {
  id: "cgroup:openclaw",
  kind: "cgroup",
  display_name: "OpenClaw workload",
  verification: "host_verified",
  evidence: [evidence],
};

function stage(state: StageAnswer, reason: string | null = null): RuntimeConvergence["configured"] {
  return { state, evidence: state === "yes" ? [evidence] : [], reason_code: reason };
}

const converged: RuntimeConvergence = {
  configured: stage("yes"),
  loaded: stage("yes"),
  running: stage("yes"),
  enforcing: stage("yes"),
  verified_effective: stage("yes"),
};

function capability(id: string, mode: CapabilityStatus["effective_mode"], scope: ScopeRef, claims: CapabilityStatus["claims"] = []): CapabilityStatus {
  return {
    id,
    tier: "enterprise_core",
    availability: "available",
    entitlement: "valid",
    support: "supported",
    desired_mode: mode,
    effective_mode: mode,
    convergence: converged,
    rollout_state: mode === "enforce" ? "enforcing" : "observing",
    health: "healthy",
    scope: [scope],
    covered_action_classes: ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: fresh,
    last_evidence: evidence,
    sources: [source],
    claims,
    reason_code: null,
    summary: `${id} fixture`,
  };
}

function layer(id: string, label: string, capabilityId: string, mode: ProtectionLayer["effective_mode"], scope: ScopeRef, gaps: CoverageGap[] = []): ProtectionLayer {
  return {
    id,
    label,
    capability_ids: [capabilityId],
    claim_state: mode === "enforce" ? "active" : "visibility_only",
    effective_mode: mode,
    desired_mode: mode,
    effective_scope: [scope],
    covered_action_classes: ["process_execution"],
    known_gaps: gaps,
    freshness: fresh,
    convergence: converged,
    evidence: [evidence],
  };
}

function gap(id: string, state: CoverageGap["state"], nextStep: string): CoverageGap {
  return {
    id,
    capability_id: "kernel_execution_control",
    affected_scope: [agentScope],
    action_classes: ["process_execution"],
    state,
    evidence: [evidence],
    next_step: nextStep,
  };
}

// The self-audit gaps a healthy enterprise host publishes permanently.
const assuranceGap = gap("kernel-execution-assurance-gap", "unknown", "publish and pin the reviewed Assurance Matrix before presenting a protection claim");
const membershipGap = gap("kernel-execution-scope-membership-gap", "unknown", "publish cgroup identity and membership evidence; an armed flag and member count are not scope proof");
const temporalGap = gap("kernel-execution-temporal-gap", "unknown", "obtain a producer timestamp at or before response generation before relying on this state");
const scopeStateGap = gap("kernel-execution-scope-state-gap", "unknown", "read the live scope state and bind an attributable workload identity before presenting scope coverage");
// The gaps that mean a control the user turned on is not working.
const runtimeGap = gap("kernel-execution-runtime-gap", "degraded", "restore the active BPF-LSM runtime before enabling enforcement");
const effectivenessGap = gap("kernel-execution-effectiveness-gap", "unknown", "compare signed and live rule content or digests and verify the expected BPF program attachment and provenance");
const visibilityGap = { ...gap("host-visibility-gap", "not_covered", "start the sensor and publish a collector-health snapshot"), capability_id: "host_visibility" };

const FIVE_LAYERS: ProtectionLayer[] = [
  layer("host_execution_layer", "Independent host execution", "kernel_execution_control", "enforce", agentScope),
  layer("host_visibility_layer", "Host visibility", "host_visibility", "observe", hostScope),
  layer("dns_guard_layer", "DNS guard", "dns_guard", "observe", hostScope),
  layer("secret_guard_layer", "Secret guard", "secret_read_guard", "observe", hostScope),
  layer("response_layer", "Response controls", "response_controls", "enforce", hostScope),
];

function bootstrap(): DashboardBootstrap {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: generatedAt,
    edition: "enterprise",
    product_version: "0.16.4",
    community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"d".repeat(64)}` },
    assurance_matrix: { id: "AM-090", version: "AM-090-v1", canonicalization: "RFC8785-JCS", digest: `sha256:${"a".repeat(64)}` },
    authorization_matrix: null,
    platform: { os: "linux", architecture: "aarch64", enterprise_candidate: true, reason_code: null },
    session: { authenticated: true, actor_id: "operator", role: "security_operator", scopes: [] },
    capabilities: FIVE_LAYERS.map((entry) => capability(entry.capability_ids[0], entry.effective_mode, entry.effective_scope[0])),
    highest_priority_gap: null,
    privacy: { storage: [], redactions: [], egress: [] },
  };
}

function posture(layers: ProtectionLayer[] = FIVE_LAYERS, gaps: CoverageGap[] = []): DashboardPosture {
  return { schema_version: "innerwarden.dashboard.v1", generated_at: generatedAt, layers, gaps };
}

describe("the verdict hero leads with what the user asked", () => {
  it("counts verified controls out of the five the enterprise adapter publishes", () => {
    const pills = posture().layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    expect(pills).toHaveLength(5);
    // This fixture has TWO controls enforcing, and the old headline read
    // "0 of 5 host controls verified active" over exactly this data: it counted
    // a narrower notion of verified than the rows displayed and never said so.
    // Production showed the same shortfall, "1 of 5", with three rows reading
    // Enforcing and the kernel measured as enforcing on two of them.
    //
    // The headline now leads with whether anything needs the reader, because
    // that is the question they arrived with. The undercount this test was
    // written to catch is still caught: nothing in this fixture is broken, so
    // nothing may be reported as needing attention, and no control may go
    // missing from the count.
    expect(postureHeadline(pills)).toBe("5 host controls: 5 working. Nothing needs you.");
  });

  it("leads with what needs the reader, not with what is fine", () => {
    // One control short of what it was asked for; four healthy.
    const layers = FIVE_LAYERS.map((layer, index) =>
      index === 0 ? { ...layer, disposition: "needs_operator" as const } : layer,
    );
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );
    expect(postureHeadline(pills)).toBe("1 of 5 host controls needs your attention");
  });

  it("does not shout at a correct fresh install", () => {
    // An install deliberately arms nothing. Every control is therefore
    // unconfigured, which the old model reported as `not_covered`: a state the
    // badge rendered amber: so a perfectly installed product opened with a
    // full page of warnings and taught the reader that amber means nothing.
    const layers = FIVE_LAYERS.map((layer) => ({ ...layer, disposition: "not_enabled" as const }));
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );

    expect(postureHeadline(pills)).toBe("Nothing is turned on yet: 5 controls ready to enable");
    expect(pills.every((pill) => pill.tone === "neutral")).toBe(true);
    expect(pills.some((pill) => pill.tone === "attention")).toBe(false);
  });

  it("reads an older host's payload without inventing a claim", () => {
    // A host on a build that predates `disposition` sends none. The fallback
    // has to reconstruct it from what that build DID send, and it must never
    // manufacture the one state that means "we proved this protects you".
    const base = { ...FIVE_LAYERS[0] };
    delete (base as { disposition?: unknown }).disposition;

    // Doing what it was told, with no host verdict: working, not proven.
    expect(
      dispositionOf({ ...base, claim_state: "readiness_only", effective_mode: "observe", desired_mode: "observe" }),
    ).toBe("working_as_configured");

    // Unreadable is ours, whatever else the payload says.
    expect(
      dispositionOf({ ...base, claim_state: "degraded", effective_mode: "unknown", desired_mode: "enforce" }),
    ).toBe("cannot_verify");

    // Never armed: calm, not an alarm.
    expect(
      dispositionOf({ ...base, claim_state: "not_covered", effective_mode: "disabled", desired_mode: "enforce" }),
    ).toBe("not_enabled");

    // Short of what it was asked for: this one IS the reader's.
    expect(
      dispositionOf({ ...base, claim_state: "degraded", effective_mode: "observe", desired_mode: "enforce" }),
    ).toBe("needs_operator");
  });

  it("gives every state a sentence, even with none supplied", () => {
    // A state with no explanation is what made people stop reading this page.
    const base = { ...FIVE_LAYERS[0], label: "DNS resolution control" };
    delete (base as { disposition_reason?: unknown }).disposition_reason;
    for (const disposition of ["proven", "working_as_configured", "not_enabled", "cannot_verify", "needs_operator"] as const) {
      const why = dispositionReason({ ...base, disposition });
      expect(why.length).toBeGreaterThan(20);
      expect(why).toContain("DNS resolution control");
      expect(dispositionLabel(disposition).length).toBeGreaterThan(0);
    }
  });

  it("lets exactly one state ask the reader for something", () => {
    const asking = (["proven", "working_as_configured", "not_enabled", "cannot_verify", "needs_operator"] as const)
      .filter(needsOperator);
    expect(asking).toEqual(["needs_operator"]);
  });

  it("keeps amber scarce enough to mean something", () => {
    // Exactly one disposition may colour a control amber. If a second starts
    // doing it the page drifts back to permanent warnings and this work undoes
    // itself.
    const amber = (["proven", "working_as_configured", "not_enabled", "cannot_verify", "needs_operator"] as const)
      .filter((disposition) => dispositionTone(disposition) === "attention");
    expect(amber).toEqual(["needs_operator"]);
  });

  it("blames the product, not the reader, when a probe did not run", () => {
    // Measured on a pilot box 2026-08-20: the Secret Read Guard was armed and
    // ENFORCING, and the page said "Not confirmed / never checked", because the
    // program's kernel instruction-tag was not in a hardcoded two-entry
    // allowlist and CO-RE relocations make that tag per-kernel. Nothing the
    // reader could click would have changed it, so it must not read as theirs.
    const layer = { ...FIVE_LAYERS[0], disposition: "cannot_verify" as const };
    const pill = controlPill(layer, bootstrap(), generatedAt, true, evaluatedAt);

    expect(pill.tone).toBe("neutral");
    expect(pill.mode).toBe("Can't confirm");
    expect(pill.reason).toMatch(/ours to fix, not yours/);
  });

  it("never claims verified active without the assurance rule agreeing", () => {
    // No claims records exist in this fixture, so layerAssuranceLabel says
    // verifiedActive=false for every control; the hero must not say otherwise.
    const pills = posture().layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    expect(pills.every((pill) => !pill.verified)).toBe(true);
    expect(pills.every((pill) => pill.tone !== "positive")).toBe(true);
  });

  it("shows each control in plain words with its scope name and check time", () => {
    const pill = controlPill(posture().layers[0], bootstrap(), generatedAt, true, evaluatedAt);
    expect(pill.name).toBe("Independent host execution");
    // "Working as set up", not "Enforcing": this fixture carries no claims
    // records, so the assurance rule does not agree that it is verified, and
    // the pill is not allowed to borrow the stronger word. The control is still
    // doing what it was told, which is why this is calm and not an alarm.
    expect(pill.mode).toBe("Working as set up");
    expect(pill.scope).toBe("OpenClaw workload");
    expect(pill.freshness).toMatch(/^as of \d{2}:\d{2}$/);
    // The producer freshness budget is contract bookkeeping; the summary never
    // mentions it.
    expect(pill.freshness).not.toContain("budget");
  });

  it("reads as refreshing, not as failure, while the snapshot is stale", () => {
    const pill = controlPill(posture().layers[0], bootstrap(), generatedAt, false, evaluatedAt);
    expect(pill.mode).toBe("Refreshing");
    expect(pill.verified).toBe(false);
  });
});

describe("mode words are user words", () => {
  it("maps modes to Enforcing, Watching, Rehearsing and Off", () => {
    expect(plainMode({ effective_mode: "enforce", desired_mode: "enforce" })).toBe("Enforcing");
    expect(plainMode({ effective_mode: "observe", desired_mode: "observe" })).toBe("Watching");
    expect(plainMode({ effective_mode: "rehearse", desired_mode: "rehearse" })).toBe("Rehearsing");
    expect(plainMode({ effective_mode: "disabled", desired_mode: "disabled" })).toBe("Off");
  });

  it("never borrows armed intent as a claim of enforcement", () => {
    // Returned "Enforcing, verifying", which a production host rendered
    // directly above a subtitle reading "not checked yet" and a coverage gap
    // reading "Degraded", all about the same control. Armed-but-unconfirmed is
    // a check that did not run, not a shade of working.
    expect(plainMode({ effective_mode: "unknown", desired_mode: "enforce" })).toBe("Not confirmed");
    expect(plainMode({ effective_mode: "unknown", desired_mode: "unknown" })).toBe("Not confirmed");
    expect(plainMode({ effective_mode: "unknown", desired_mode: "disabled" })).toBe("Off");
  });
});

describe("freshness is a wall clock, not a counter that resets as you watch", () => {
  it("stamps the observation time instead of counting seconds", () => {
    // Was relative, and with the screen refreshing every few seconds it read
    // "checked 0s ago" almost permanently, resetting as you looked at it. A
    // number that never settles reads as a system that never settles.
    const at = new Date("2026-08-17T14:32:05Z");
    const hh = String(at.getHours()).padStart(2, "0");
    expect(checkedAt({ ...fresh, observed_at: at.toISOString() })).toBe(`as of ${hh}:32`);
  });

  it("says never checked rather than inventing a time", () => {
    expect(checkedAt({ ...fresh, observed_at: null })).toBe("never checked");
  });
});

describe("scope summaries drop the verification parenthetical", () => {
  it("uses the display name only", () => {
    expect(scopeDisplay([agentScope])).toBe("OpenClaw workload");
    expect(scopeDisplay([])).toBe("No scope reported");
  });
});

describe("gap routing: amber is reserved for what the user must act on", () => {
  it("routes the permanent self-audit gaps to the quiet verification lane", () => {
    // These fire on EVERY healthy enterprise host. As amber cards they made a
    // working deployment look broken; nothing the operator clicks resolves
    // them.
    for (const entry of [assuranceGap, membershipGap, temporalGap, scopeStateGap]) {
      expect(gapAudience(entry)).toBe("verification");
    }
  });

  it("keeps a control that is on but not working amber", () => {
    expect(gapAudience(runtimeGap)).toBe("operator");
    expect(gapAudience(effectivenessGap)).toBe("operator");
    expect(gapAudience(visibilityGap)).toBe("operator");
  });

  it("keeps degraded, stale and not-covered states amber regardless of id", () => {
    expect(gapAudience(gap("some-new-gap", "degraded", "restore it"))).toBe("operator");
    expect(gapAudience(gap("some-new-gap", "stale", "refresh it"))).toBe("operator");
    expect(gapAudience(gap("some-new-gap", "not_covered", "cover it"))).toBe("operator");
  });
});

describe("the empty gaps state is one quiet line", () => {
  it("says the positive thing and stops", () => {
    expect(emptyGapsLine(0)).toBe("No coverage gaps in this snapshot.");
  });

  it("stays honest when only verification-lane gaps exist", () => {
    expect(emptyGapsLine(3)).toBe("No coverage gaps need attention in this snapshot.");
  });
});


describe("the poll cadence matches the evidence it renders", () => {
  it("refreshes slower than a second but faster than the proof goes stale", async () => {
    const { POSTURE_REFRESH_MS } = await import("../App");
    // The evidence behind this screen is the effect canary, which re-runs every
    // 1200s. Polling every 5s meant 239 of every 240 requests returned the same
    // proof, and the freshness line read "checked 0s ago" resetting as you
    // watched it: a number that never settles reads as a system that never
    // settles.
    const CANARY_INTERVAL_MS = 1_200_000;
    expect(POSTURE_REFRESH_MS).toBeGreaterThan(60_000);
    expect(POSTURE_REFRESH_MS).toBeLessThanOrEqual(CANARY_INTERVAL_MS);
  });
});

describe("the pill and the row tell one story", () => {
  it("puts every surface through the same assurance veto", () => {
    // Measured on a pilot box 2026-08-20: the summary pill read "Working as set
    // up" and the control row directly below it read "Protecting", for the same
    // control on the same render, because the pill applied the assurance veto
    // and the row called dispositionOf directly. A page that contradicts itself
    // is worse than a page that is wrong: the reader cannot tell which line to
    // believe, and a security product has nothing to sell once that happens.
    const layer = { ...FIVE_LAYERS[0], disposition: "proven" as const };

    // The host says proven; the assurance chain has not pinned it.
    expect(effectiveDisposition(layer, false)).toBe("working_as_configured");
    // With the chain agreeing, proven survives.
    expect(effectiveDisposition(layer, true)).toBe("proven");

    // And the pill the screen builds agrees with it, for this fixture where
    // layerAssuranceLabel reports verifiedActive=false for every control.
    const pill = controlPill(layer, bootstrap(), generatedAt, true, evaluatedAt);
    expect(pill.disposition).toBe(effectiveDisposition(layer, pill.verified));
    expect(pill.mode).toBe(dispositionLabel(effectiveDisposition(layer, pill.verified)));
  });

  it("never softens anything but an unbacked proven claim", () => {
    // The veto exists to stop over-claiming. It must not quietly downgrade a
    // control that is asking for the reader, which would hide real work.
    for (const disposition of ["working_as_configured", "not_enabled", "cannot_verify", "needs_operator"] as const) {
      const layer = { ...FIVE_LAYERS[0], disposition };
      expect(effectiveDisposition(layer, false)).toBe(disposition);
      expect(effectiveDisposition(layer, true)).toBe(disposition);
    }
  });
});

describe("no surface can bypass the assurance veto", () => {
  it("routes every read of a layer's disposition through effectiveDisposition", () => {
    // A structural check, because the failure is structural: the pill applied
    // the veto and the row did not, and no unit test of a pure function can see
    // that, since the row is a component. Both surfaces read the same layer, so
    // the invariant is "nothing but effectiveDisposition calls dispositionOf".
    //
    // If this fails, do not add a second veto at the new call site. Route the
    // new caller through effectiveDisposition, or the two drift again.
    const callSites = postureSource
      .split("\n")
      .map((line: string, index: number) => ({ line: line.trim(), number: index + 1 }))
      .filter((entry: { line: string; number: number }) => /\bdispositionOf\(/.test(entry.line))
      // Its own declaration, and the one function allowed to call it.
      .filter((entry: { line: string; number: number }) => !/^export function dispositionOf/.test(entry.line))
      .filter((entry: { line: string; number: number }) => !/^const reported = dispositionOf\(layer\);$/.test(entry.line))
      // dispositionReason compares against it to decide whether the host's
      // sentence still applies, and falls back through it for a default. Text
      // only: it never picks a colour and never makes a claim.
      .filter((entry: { line: string; number: number }) => !/^const effective = shown \?\? dispositionOf\(layer\);$/.test(entry.line))
      .filter((entry: { line: string; number: number }) => !/^if \(layer\.disposition_reason && effective === dispositionOf\(layer\)\) \{$/.test(entry.line));

    expect(callSites).toEqual([]);
  });
});

describe("the sentence never outranks the badge", () => {
  it("drops the host's stronger sentence when the veto softened the badge", () => {
    // Measured on a pilot box 2026-08-20: the row was badged "Working as set
    // up" and the line directly under it read "is enforcing, and that was
    // verified on this host". The badge had been through the assurance veto and
    // the sentence had not, so the words outranked the claim they sat beneath.
    const layer = {
      ...FIVE_LAYERS[0],
      label: "Independent host execution",
      disposition: "proven" as const,
      disposition_reason: "Independent host execution is enforcing, and that was verified on this host.",
    };

    // Veto applied: the sentence must come down with the badge.
    expect(dispositionReason(layer, "working_as_configured")).toBe(
      "Independent host execution is doing what it is set to do.",
    );
    // No veto: the host's own wording is richer and is kept.
    expect(dispositionReason(layer, "proven")).toBe(layer.disposition_reason);
  });

  it("keeps the host sentence whenever the shown state matches", () => {
    const layer = {
      ...FIVE_LAYERS[0],
      disposition: "not_enabled" as const,
      disposition_reason: "DNS resolution control is switched on but has nothing to act on yet.",
    };
    expect(dispositionReason(layer, "not_enabled")).toBe(layer.disposition_reason);
    // And the default caller, with no shown state, still gets it.
    expect(dispositionReason(layer)).toBe(layer.disposition_reason);
  });
});

describe("the headline names every state it counts", () => {
  it("never sweeps an unconfirmed control into a count of working ones", () => {
    // The headline read "N protecting, the rest working", and "the rest"
    // quietly swallowed a control in cannot_verify. On a real host that put a
    // control the page had just described as unreadable, in its own words "we
    // will not claim either way", inside a count of things that work.
    const layers = FIVE_LAYERS.map((layer, index) => ({
      ...layer,
      disposition: index === 0 ? ("cannot_verify" as const) : ("working_as_configured" as const),
    }));
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );

    const headline = postureHeadline(pills);
    expect(headline).toContain("1 we can't confirm");
    expect(headline).toContain("4 working");
    expect(headline).not.toMatch(/the rest/);
    // 4 + 1, never 5 working.
    expect(headline).not.toContain("5 working");
  });

  it("counts each disposition once and only once", () => {
    const layers = [
      { ...FIVE_LAYERS[0], disposition: "proven" as const },
      { ...FIVE_LAYERS[1], disposition: "working_as_configured" as const },
      { ...FIVE_LAYERS[2], disposition: "not_enabled" as const },
      { ...FIVE_LAYERS[3], disposition: "cannot_verify" as const },
    ];
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );

    // This fixture carries no claims records, so the assurance rule vetoes the
    // proven one down to working: 2 working, not 1 protecting + 1 working.
    expect(postureHeadline(pills)).toBe(
      "4 host controls: 2 working, 1 not turned on, 1 we can't confirm. Nothing needs you.",
    );
  });

  it("still leads with what needs the reader, above every other count", () => {
    const layers = FIVE_LAYERS.map((layer, index) => ({
      ...layer,
      disposition: index === 0 ? ("needs_operator" as const) : ("cannot_verify" as const),
    }));
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );
    expect(postureHeadline(pills)).toBe("1 of 5 host controls needs your attention");
  });
});
