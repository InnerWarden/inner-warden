import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
// The screen's own source, for the structural guard at the bottom of this file.
import postureSource from "./Posture.tsx?raw";
import type {
  AgentLayerReport,
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  EvidenceRef,
  LocalModelReport,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
  SourceRef,
  StageAnswer,
} from "../api/v1";
import {
  agentLayerFigures,
  checkedAt,
  controlCountLine,
  controlPill,
  dispositionLabel,
  dispositionOf,
  dispositionReason,
  dispositionTone,
  emptyGapsLine,
  gapAudience,
  effectiveDisposition,
  modelProvenance,
  needsOperator,
  plainMode,
  postureHeadline,
  Posture,
  scopeDisplay,
  sectionRows,
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

/**
 * The screen as the reader receives it: markup.
 *
 * Every guard on this page that only ever called a helper proved the helper and
 * left the call site free. `agentLayerFigures` was exhaustively tested as a pure
 * function while nothing pinned that its answer reached a pixel, and the coupling
 * guard read the source for one spelling of a field name while the component was
 * free to read it under any other. Rendering is the only check a rename, a
 * destructure or a deleted element cannot walk around.
 */
function render(value: DashboardPosture): string {
  return renderToStaticMarkup(
    createElement(Posture, { bootstrap: bootstrap(), posture: value, current: true, evaluatedAt }),
  );
}

/** The markup between an opening anchor and the first `end` after it. Used to
 *  name WHICH region moved when an equality fails, instead of diffing a page. */
function region(html: string, anchor: string, end: string): string {
  const from = html.indexOf(anchor);
  if (from < 0) throw new Error(`anchor not rendered: ${anchor}`);
  const to = html.indexOf(end, from);
  if (to < 0) throw new Error(`unterminated region: ${anchor}`);
  return html.slice(from, to + end.length);
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
    //
    // The tail is gone, and its absence is the point. This assertion used to end
    // "Nothing needs you." over a page listing a control that is not turned on,
    // which is the exact sentence spec-053 section 4.3 names: the claim was
    // unconditional, so one test pinned it in place and it read as intended
    // behaviour for as long as it shipped.
    expect(postureHeadline(pills)).toBe(
      "4 host controls: 2 working, 1 not turned on, 1 we can't confirm.",
    );
  });

  /**
   * "Nothing needs you" is a claim about every card on the page.
   *
   * A control that is off asks to be turned on, and one we cannot read asks to
   * be looked at. Neither is nothing.
   */
  it("only says nothing needs you when nothing on the page asks for anything", () => {
    const allWorking = FIVE_LAYERS.map((layer) => ({ ...layer, disposition: "working_as_configured" as const }));
    const working = posture(allWorking).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );
    expect(postureHeadline(working)).toContain("Nothing needs you.");

    for (const asking of ["not_enabled", "cannot_verify"] as const) {
      const mixed = FIVE_LAYERS.map((layer, index) => ({
        ...layer,
        disposition: index === 0 ? asking : ("working_as_configured" as const),
      }));
      const pills = posture(mixed).layers.map((entry) =>
        controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
      );
      expect(postureHeadline(pills)).not.toContain("Nothing needs you.");
    }
  });

  /**
   * The host is the only side that can see whether a remedy command still needs
   * running, so its sentence wins. This screen computing its own is how the two
   * came to disagree.
   */
  it("prefers the sentence the host computed over its own count", () => {
    const layers = FIVE_LAYERS.map((layer) => ({ ...layer, disposition: "working_as_configured" as const }));
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );
    expect(postureHeadline(pills, "2 of 5 host controls are off and protect nothing")).toBe(
      "2 of 5 host controls are off and protect nothing",
    );
  });

  it("falls back to its own count when the host sent no sentence", () => {
    const layers = FIVE_LAYERS.map((layer) => ({ ...layer, disposition: "working_as_configured" as const }));
    const pills = posture(layers).layers.map((entry) =>
      controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt),
    );
    for (const empty of [undefined, "", "   "]) {
      expect(postureHeadline(pills, empty)).toBe("5 host controls: 5 working. Nothing needs you.");
    }
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

// ───────── what runs inside the agent, and why it stays out of the rows ──────
//
// Measured on the shipped Enterprise bundle before this change: it contained no
// occurrence of `local_model` or `agent_layer`, on paid hosts that send both.
// The two features the site sells were invisible on the page a buyer opens to
// ask whether what they bought is working.
//
// Adding them is only safe if the page's footer rule survives intact: host
// controls are evaluated from host evidence only, and agent metadata never
// grants host trust. The tests below pin both halves: the sections render, and
// they touch nothing above them.

const EVIDENCE_BASIS =
  "Counted from the guardrail's own decision record on this host. It is what the guardrail "
  + "reports it did, not something the host proved, so nothing in this section changes a host "
  + "control above.";

const COVERS = "everything in the guardrail's decision record on this host; the record is "
  + "capped and drops its oldest entries";

const AGENT_LAYER_NAME = "Command and prompt screening, and MCP tool calls";

/** The seven figures the producer emits, at whatever counts are passed. */
function screeningFigures(counts: number[]): AgentLayerReport["measured"] {
  const labels = [
    ["commands_screened", "Commands screened"],
    ["commands_refused", "Commands the guardrail refused"],
    ["commands_would_refuse", "Commands it would have refused while only watching"],
    ["mcp_calls_screened", "MCP tool calls screened"],
    ["mcp_calls_refused", "MCP tool calls the guardrail refused"],
    ["mcp_calls_would_refuse", "MCP tool calls it would have refused while only watching"],
    ["agent_sessions", "AI agent sessions in the record"],
  ];
  return labels.map(([id, label], index) => ({ id, label, value: String(counts[index]), covers: COVERS }));
}

const STANDING_GAPS = [
  "prompts screened inside an agent conversation: the guardrail writes those to its event log, "
  + "and this section counts only its decision record",
  "whether a refusal counted here also stopped the process on this host: that is a host control, "
  + "and the controls above answer it from host evidence",
  "how many AI agents are connected: the record holds sessions, and one agent can open many of "
  + "them or none",
];

/** A busy host: the record was read and holds 601 screened commands. */
const SCREENING: AgentLayerReport = {
  state: "screening",
  reason: "agent_layer_screening",
  display_name: AGENT_LAYER_NAME,
  evidence_basis: EVIDENCE_BASIS,
  evidence_source: "/var/lib/innerwarden/graph.json",
  sessions: ["openclaw", "release-check"],
  measured: screeningFigures([601, 4, 9, 1, 0, 0, 2]),
  not_measured: STANDING_GAPS,
  summary: "The guardrail screened 601 commands and 1 MCP tool call on this host, across 2 agent "
    + "sessions. It refused 4, and recorded 9 more it would have refused had it been enforcing.",
};

/** A quiet host: the record WAS read, and it holds none. The zeroes are a
 *  measurement, and they are what makes this host different from the two
 *  below. */
const SCREENING_ZERO: AgentLayerReport = {
  ...SCREENING,
  sessions: [],
  measured: screeningFigures([0, 0, 0, 0, 0, 0, 0]),
  summary: "The guardrail's decision record on this host was read and holds no screened command "
    + "and no MCP tool call.",
};

/** A fresh install: the record is in place and nothing has been written to it. */
const NO_DECISIONS_YET: AgentLayerReport = {
  ...SCREENING,
  state: "no_decisions_yet",
  reason: "agent_layer_no_decisions_yet",
  sessions: [],
  measured: [],
  not_measured: [
    "anything the guardrail screened: its decision record is in place and nothing has been "
    + "written to it yet",
    ...STANDING_GAPS,
  ],
  summary: "The guardrail is recording and has not screened anything yet.",
};

/** A broken seam: the record could not be opened, so there are no figures. */
const RECORD_UNREADABLE: AgentLayerReport = {
  ...SCREENING,
  state: "record_unreadable",
  reason: "guard_record_permission_denied",
  sessions: [],
  measured: [],
  not_measured: [
    "anything the guardrail screened: its decision record could not be read, so this is not a "
    + "quiet host",
    ...STANDING_GAPS,
  ],
  summary: "The guardrail's decision record exists and this agent may not open it.",
};

const LOADED_MODEL: LocalModelReport = {
  state: "loaded",
  display_name: "Local Warden Model",
  provider: "local_classifier",
  model_id: "warden-student-v3",
  roles: ["decides what to do about an incident", "labels an incident"],
  measured: [
    {
      id: "ai_decision_count",
      label: "Decisions returned",
      value: "602",
      covers: "today, on this host: every decision the agent made went to this model",
    },
    {
      id: "avg_decision_latency_ms",
      label: "Average decision latency",
      value: "12 ms",
      covers: "today, on this host: every decision the agent made went to this model",
    },
  ],
  not_measured: [
    "how often the model agreed with the deterministic rules",
    "the model's accuracy on this host: scoring it needs outcomes labelled as right or wrong, "
    + "which this host does not have",
  ],
  summary: "The Local Warden Model is loaded and decides on this host. It scores, it does not "
    + "write, so a written explanation needs a language model connected as well.",
};

describe("the host's own control count is printed, not recomputed", () => {
  it("prints the count the host sent, under the host's own sentence", () => {
    expect(controlCountLine({ enforcing_count: 1, control_count: 5 }))
      .toBe("The host counts 1 of 5 controls actively containing.");
    expect(controlCountLine({ enforcing_count: 1, control_count: 1 }))
      .toBe("The host counts 1 of 1 control actively containing.");
  });

  it("prints nothing at all for a host that sends neither number", () => {
    // The alternative is this screen inventing a count of "actively containing"
    // out of pills that answer a different question, which is the drift the
    // host-side count exists to end.
    expect(controlCountLine({})).toBeNull();
    expect(controlCountLine({ enforcing_count: 1 })).toBeNull();
    expect(controlCountLine({ control_count: 5 })).toBeNull();
  });

  it("never becomes the headline", () => {
    // The headline is the host's summary sentence. The count is a caption under
    // it, and a caption that could replace the sentence would be a second
    // verdict on one page.
    const pills = posture().layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    expect(postureHeadline(pills, "2 of 5 host controls are off and protect nothing"))
      .toBe("2 of 5 host controls are off and protect nothing");
    expect(postureHeadline(pills, "2 of 5 host controls are off and protect nothing"))
      .not.toContain("actively containing");
  });
});

describe("the guardrail section keeps three answers apart", () => {
  /**
   * "Read, and it holds none" is not "could not be read", and neither is "in
   * place and never written to". The producer distinguishes all three; a screen
   * that collapsed them would report a quiet host to somebody whose files could
   * not be opened, and call a fresh install broken.
   */
  it("gives a different answer for each of the three hosts", () => {
    expect(agentLayerFigures(SCREENING)).toEqual({ kind: "counted" });
    expect(agentLayerFigures(SCREENING_ZERO)).toEqual({ kind: "counted" });
    expect(agentLayerFigures(NO_DECISIONS_YET))
      .toEqual({ kind: "nothing_recorded", label: "Nothing recorded yet" });
    expect(agentLayerFigures(RECORD_UNREADABLE))
      .toEqual({ kind: "unreadable", label: "Record could not be read" });

    const kinds = [NO_DECISIONS_YET, RECORD_UNREADABLE, SCREENING_ZERO].map((report) => agentLayerFigures(report).kind);
    expect(new Set(kinds).size).toBe(3);
  });

  it("keeps the zeroes of a record that WAS read", () => {
    // A zero here is a measurement: this host screened nothing. Hiding it would
    // make a quiet host look like a broken one.
    const rows = sectionRows(SCREENING_ZERO);
    const measured = rows.filter((row) => row.kind === "measured");
    expect(measured).toHaveLength(7);
    expect(measured.every((row) => row.kind === "measured" && row.value === "0")).toBe(true);
    expect(measured.map((row) => row.kind === "measured" && row.id)).toContain("mcp_calls_screened");
  });

  it("shows no figure at all when the record could not be read", () => {
    // A zero on THIS host would report a quiet host to somebody whose records
    // merely could not be opened.
    const rows = sectionRows(RECORD_UNREADABLE);
    expect(rows.filter((row) => row.kind === "measured")).toEqual([]);
    expect(rows.some((row) => row.kind === "measured" && row.value === "0")).toBe(false);
    // And the reason is the CAUSE, so the operator checks the right thing.
    expect(RECORD_UNREADABLE.reason).not.toBe(NO_DECISIONS_YET.reason);
  });

  it("shows no figure for a fresh install either, and says why", () => {
    const rows = sectionRows(NO_DECISIONS_YET);
    expect(rows.filter((row) => row.kind === "measured")).toEqual([]);
    expect(rows.map((row) => row.kind === "not_measured" && row.reason)).toContain(
      "anything the guardrail screened: its decision record is in place and nothing has been "
      + "written to it yet",
    );
  });

  /**
   * The three answers have to reach the SCREEN, not just the helper.
   *
   * `agentLayerFigures` was proved exhaustively above and the element that
   * prints its answer was pinned by nothing: deleting the whole badge block from
   * the section left the typechecker at 0 and every test passing, because the
   * only structural pin on that component matched on `evidence_basis` and
   * `evidence_source`, which the deletion did not touch. A proved helper whose
   * call site is unpinned is a feature that can ship removed.
   */
  it("tells the reader on the screen which of the three hosts this is", () => {
    const html = (report: AgentLayerReport) => render({ ...posture(), agent_layer: report });
    const unreadableHtml = html(RECORD_UNREADABLE);
    const freshInstallHtml = html(NO_DECISIONS_YET);
    const screeningHtml = html(SCREENING);

    // A record that could not be OPENED says so, and names the cause the host
    // sent, so the operator checks the right thing.
    expect(unreadableHtml).toContain("Record could not be read");
    expect(unreadableHtml).toContain(RECORD_UNREADABLE.reason);

    // A fresh install says something different, and it is not a fault.
    expect(freshInstallHtml).toContain("Nothing recorded yet");
    expect(freshInstallHtml).toContain(NO_DECISIONS_YET.reason);
    expect(freshInstallHtml).not.toContain("Record could not be read");
    expect(unreadableHtml).not.toContain("Nothing recorded yet");

    // And a host that IS screening claims neither: its figures are the answer.
    expect(screeningHtml).not.toContain("Record could not be read");
    expect(screeningHtml).not.toContain("Nothing recorded yet");
    expect(screeningHtml).toContain("601");

    // Three hosts, three renders. Any two collapsing into one is the defect.
    expect(new Set([unreadableHtml, freshInstallHtml, screeningHtml]).size).toBe(3);
  });

  it("carries the basis and the source the host sent, unrewritten", () => {
    expect(SCREENING.evidence_basis).toBe(EVIDENCE_BASIS);
    // The section renders `report.evidence_basis` verbatim; this pins that the
    // string the screen has to print is the host's, not one written here.
    expect(postureSource).toContain("{report.evidence_basis}");
    expect(postureSource).toContain("{report.evidence_source}");
  });
});

describe("a gap the host named is never rendered as a number", () => {
  it("keeps not-measured items out of the measured rows entirely", () => {
    // "how often the model agreed with the deterministic rules" as a 0 would be
    // a measurement nobody took, printed on the page whose whole job is telling
    // proven from assumed apart.
    const noCounters: LocalModelReport = { ...LOADED_MODEL, measured: [] };
    const rows = sectionRows(noCounters);

    expect(rows.every((row) => row.kind === "not_measured")).toBe(true);
    expect(rows.some((row) => row.kind === "measured" && row.value === "0")).toBe(false);
    expect(rows.map((row) => row.kind === "not_measured" && row.reason)).toEqual(noCounters.not_measured);
  });

  it("keeps the host's own words for each gap", () => {
    const rows = sectionRows(LOADED_MODEL);
    const gaps = rows.filter((row) => row.kind === "not_measured");
    expect(gaps.map((row) => row.kind === "not_measured" && row.reason)).toEqual([
      "how often the model agreed with the deterministic rules",
      "the model's accuracy on this host: scoring it needs outcomes labelled as right or wrong, "
      + "which this host does not have",
    ]);
  });

  it("keeps the population beside every number it does print", () => {
    // A count with no stated population is how a decision total gets read as a
    // claim about enforcement.
    const measured = sectionRows(LOADED_MODEL).filter((row) => row.kind === "measured");
    expect(measured).toHaveLength(2);
    expect(measured.every((row) => row.kind === "measured" && row.covers.length > 0)).toBe(true);
  });

  it("names the model even when the host could not name a build", () => {
    expect(modelProvenance(LOADED_MODEL)).toBe("provider local_classifier · build warden-student-v3");
    expect(modelProvenance({ provider: "local_classifier", model_id: null })).toBe("provider local_classifier");
    expect(modelProvenance({ provider: null, model_id: null })).toBeNull();
  });
});

describe("the agent sections never reach a host control", () => {
  /**
   * A tripwire, and explicitly NOT the proof.
   *
   * It was written as the proof, and it was not one: it filtered on
   * `posture.agent_layer`, the DOTTED spelling, so `const { agent_layer: a } =
   * posture` walked straight past it. A reviewer used exactly that to repaint
   * every host pill emerald and relabel it "Enforcing" from an agent-reported
   * field, with the typechecker at 0 and every test green. A guard pinned to one
   * spelling of a name protects the bug it is aimed at.
   *
   * What carries the invariant now is the render below, which compares bytes and
   * cannot be spelled around. This stays because it is cheap and it names the
   * two lines allowed to touch the fields at all, so a third call site has to be
   * argued for rather than slipped in. Non-comment lines only: the prose above
   * these fields names them on purpose.
   *
   * If this fails, do not widen the allowed list. The sections render from
   * their own report and nothing else.
   */
  it("reads the two sections in exactly two places, both of them renders", () => {
    const uses = postureSource
      .split("\n")
      .map((line: string) => line.trim())
      .filter((line: string) => !/^(\/\/|\*|\/\*)/.test(line))
      .filter((line: string) => /\b(agent_layer|local_model)\b/.test(line));

    expect(uses).toEqual([
      "{posture.local_model ? <LocalModelSection report={posture.local_model} /> : null}",
      "{posture.agent_layer ? <AgentLayerSection report={posture.agent_layer} /> : null}",
    ]);
  });

  /**
   * The proof: the host's half of the page is byte-identical with the agent
   * sections present and with them absent.
   *
   * This is behavioural on purpose. Narrowing the type the pill and headline code
   * may see was the other candidate and it cannot carry this alone: TypeScript is
   * structural, so the full posture still satisfies a narrowed parameter, and the
   * component keeps the whole object in scope whatever a helper is handed. The
   * forbidden path lives in the component, so the component is what has to be
   * measured.
   *
   * The two sections render last, inside the same wrapper, so everything the host
   * owns is a literal prefix of the longer render. Anything an agent-reported
   * field touches above them, a colour, a word, an ordering, breaks the prefix,
   * under any spelling of any field name.
   */
  it("renders identical host controls whether or not the agent sections are present", () => {
    const bare = posture();
    const withSections: DashboardPosture = { ...bare, local_model: LOADED_MODEL, agent_layer: SCREENING };

    const bareHtml = render(bare);
    const withHtml = render(withSections);

    // Not vacuous: the sections really did render, with the agent's figures.
    expect(withHtml).toContain("In the agent, not a host control");
    expect(withHtml).toContain(SCREENING.summary);
    expect(withHtml).toContain(LOADED_MODEL.display_name);
    expect(bareHtml).not.toContain("In the agent, not a host control");

    const CLOSE = "</div>";
    expect(bareHtml.endsWith(CLOSE)).toBe(true);
    const hostHalf = bareHtml.slice(0, -CLOSE.length);

    // Byte identity, and it is the whole assertion. 601 screened commands, 4
    // refusals, and not one byte of them anywhere the host speaks.
    expect(withHtml.startsWith(hostHalf)).toBe(true);
    expect(withHtml.slice(hostHalf.length).endsWith(CLOSE)).toBe(true);
    expect(hostHalf).not.toMatch(/601|refus/);

    // Named regions too, so a failure says which surface moved rather than
    // handing the reader two pages of markup to diff.
    const pills = (html: string) => region(html, 'aria-label="Host controls"', "</ul>");
    const verdict = (html: string) => region(html, '<h3 id="posture-verdict-title"', "</h3>");
    expect(pills(withHtml)).toBe(pills(bareHtml));
    expect(verdict(withHtml)).toBe(verdict(bareHtml));

    // And the specific over-claim the footer rule exists to prevent: this
    // fixture carries no claims records, so no host pill may be emerald and none
    // may say Enforcing, however busy the guardrail below it reports being.
    expect(pills(withHtml)).not.toContain("emerald");
    expect(pills(withHtml)).not.toContain("Enforcing");
  });

  it("leaves the host's verdict line reading only host material", () => {
    // The headline takes the pills and the host's own summary. Nothing else may
    // be passed to it: an agent-reported refusal count in this call is exactly
    // the trust leak the footer rule forbids.
    expect(postureSource).toContain("{postureHeadline(pills, posture.summary)}");
    const headlineCalls = postureSource
      .split("\n")
      .map((line: string) => line.trim())
      .filter((line: string) => /postureHeadline\(/.test(line))
      .filter((line: string) => !/^export function postureHeadline/.test(line));
    expect(headlineCalls).toEqual(["{postureHeadline(pills, posture.summary)}"]);
  });

  it("computes identical pills and headline whether or not the sections are present", () => {
    const withSections: DashboardPosture = {
      ...posture(),
      summary: undefined,
      local_model: LOADED_MODEL,
      agent_layer: SCREENING,
    };
    const bare = posture();

    const pillsWith = withSections.layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));
    const pillsBare = bare.layers.map((entry) => controlPill(entry, bootstrap(), generatedAt, true, evaluatedAt));

    expect(pillsWith).toEqual(pillsBare);
    expect(postureHeadline(pillsWith, withSections.summary))
      .toBe(postureHeadline(pillsBare, bare.summary));
    // 601 screened commands and 4 refusals, and not one of them in the verdict.
    expect(postureHeadline(pillsWith, withSections.summary)).not.toMatch(/601|refus/);
  });
});
