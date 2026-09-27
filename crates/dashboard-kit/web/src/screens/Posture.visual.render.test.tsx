import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import type { AgentLayerReport, CapabilityStatus, DashboardBootstrap, DashboardPosture, EvidenceRef, LayerDisposition, ProtectionLayer, ScopeRef } from "../api/v1";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { TONE_HEX } from "../components/viz";
import { controlPills, latestCheck, ringParts, stageMark, stateCounts, withCode, Posture } from "./Posture";

/**
 * Protection drawn: a ring with one segment per control, a count per state,
 * and a five-stage ladder on every row. A picture is read before a word is,
 * so every mark here says exactly what the chip beside it says and no more.
 */

afterEach(() => setTechnicalDetail(false));

const OBSERVED = "2026-07-18T12:00:00Z";
const GENERATED = "2026-07-18T12:00:01Z";
const matrix = { id: "innerwarden.assurance-matrix", version: "AM-090-v1", canonicalization: "YAML-TO-RFC8785-JCS" as const, digest: `sha256:${"a".repeat(64)}` };
const evidence: EvidenceRef = {
  id: "ev-1",
  kind: "runtime_verification",
  source: { id: "kernel_state", kind: "kernel_state", authority: "canonical", version: "1", completeness: "complete", limitations: [] },
  observed_at: OBSERVED,
  integrity: "verified",
  redaction: [],
  freshness: { observed_at: OBSERVED, budget_seconds: 30, state: "fresh", age_seconds: 1 },
};
const hostScope: ScopeRef = { id: "host-1", kind: "host", display_name: "this host", verification: "host_verified", evidence: [{ ...evidence }] };
const stage = (state: "yes" | "no" | "unknown" | "not_applicable" = "yes", reason: string | null = null) => ({ state, evidence: [{ ...evidence }], reason_code: reason });
const converged = () => ({ configured: stage(), loaded: stage(), running: stage(), enforcing: stage(), verified_effective: stage() });
const freshness = (observed: string | null = OBSERVED) => ({ observed_at: observed, budget_seconds: 30, state: "fresh" as const, age_seconds: 1 });

function capability(): CapabilityStatus {
  return {
    id: "kernel_execution_control",
    tier: "enterprise_core",
    availability: "available",
    entitlement: "valid",
    support: "supported",
    desired_mode: "enforce",
    effective_mode: "enforce",
    convergence: converged(),
    rollout_state: "enforcing",
    health: "healthy",
    scope: [{ ...hostScope }],
    covered_action_classes: ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: freshness(),
    last_evidence: { ...evidence },
    sources: [],
    claims: [{
      id: "claim-1", statement: "covered executions are blocked", semantic_key: null, status: "verified",
      versions: [{ ...matrix }], population: "host-1", environment: "linux",
      observed_at: OBSERVED, reviewed_at: OBSERVED, expires_at: "2026-07-18T13:00:00Z",
      scope: [{ ...hostScope }], action_classes: ["process_execution"], evidence: [{ ...evidence }], limitations: [],
    }],
    reason_code: null,
    summary: "fresh verified enforcement",
  };
}

/** A bootstrap that verifies the gate, or (`proof: false`) one whose matrix is unpinned. */
function bootstrap(proof = true): DashboardBootstrap {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: GENERATED,
    edition: "enterprise",
    product_version: "0.16.4",
    community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"d".repeat(64)}` },
    assurance_matrix: proof ? matrix : null,
    authorization_matrix: null,
    platform: { os: "linux", architecture: "x86_64", enterprise_candidate: true, reason_code: null },
    session: { authenticated: true, actor_id: "operator", role: "security_operator", scopes: [] },
    capabilities: [capability()],
    highest_priority_gap: null,
    privacy: { storage: [], redactions: [], egress: [] },
  };
}

function layer(id: string, capabilityId: string, disposition: LayerDisposition, over: Partial<ProtectionLayer> = {}): ProtectionLayer {
  return {
    id,
    label: id,
    capability_ids: [capabilityId],
    claim_state: disposition === "proven" ? "active" : "not_covered",
    disposition,
    effective_mode: "enforce",
    desired_mode: "enforce",
    effective_scope: [{ ...hostScope }],
    covered_action_classes: [],
    known_gaps: [],
    freshness: freshness(),
    convergence: converged(),
    evidence: [{ ...evidence }],
    ...over,
  };
}

const gate = () => layer("independent_host_execution", "kernel_execution_control", "proven", { covered_action_classes: ["process_execution"] });
const watcher = () => layer("host_visibility", "host_visibility", "working_as_configured", {
  convergence: { configured: stage(), loaded: stage(), running: stage(), enforcing: stage("not_applicable", "visibility_capability"), verified_effective: stage("not_applicable", "visibility_capability") },
});
const unreadable = () => layer("secret_access_control-layer", "secret_access_control", "cannot_verify", {
  convergence: { configured: stage(), loaded: stage(), running: stage(), enforcing: stage(), verified_effective: stage("unknown", "secret_read_gate_build_unrecognised") },
});
const needy = () => layer("dns_resolution_control-layer", "dns_resolution_control", "needs_operator");

function posture(layers: ProtectionLayer[]): DashboardPosture {
  return { schema_version: "innerwarden.dashboard.v1", generated_at: GENERATED, layers, gaps: [] };
}

const render = (value: DashboardPosture, reading = bootstrap(), current = true) =>
  renderToStaticMarkup(<Posture bootstrap={reading} posture={value} current={current} evaluatedAt={GENERATED} />);

/** The hero: from its section to the rows. */
const hero = (html: string) => html.slice(html.indexOf('aria-labelledby="posture-verdict-title"'), html.indexOf("posture-controls-title"));

/** The strokes the ring draws, in segment order. */
const strokes = (html: string) => [...hero(html).matchAll(/<g data-segment="\d+"><title>[^<]*<\/title>(.*?)<\/g>/g)].map((match) => match[1]);

describe("the ring of controls", () => {
  it("has one segment per control, each the colour of the chip it wears", () => {
    const value = posture([gate(), watcher(), unreadable(), needy()]);
    const { pills } = controlPills(value, bootstrap(), true, GENERATED);
    const parts = ringParts(pills, true);
    expect(parts.map((part) => part.tone)).toEqual(["proven", "working", "unknown", "attention"]);
    expect(parts[2].hollow).toBe(true);
    const drawn = strokes(render(value));
    expect(drawn).toHaveLength(4);
    expect(drawn[0]).toContain(`stroke="${TONE_HEX.proven}"`);
    expect(drawn[1]).toContain(`stroke="${TONE_HEX.working}"`);
    expect(drawn[3]).toContain(`stroke="${TONE_HEX.attention}"`);
  });

  /**
   * FAILS ON REVERT: colour the segment from the host's reported disposition
   * instead of the vetoed one and a control whose proof this page could not
   * pin is painted emerald in the one picture everyone reads first.
   */
  it("paints a control the veto softened as working, never as proven", () => {
    const value = posture([gate()]);
    const { pills } = controlPills(value, bootstrap(false), true, GENERATED);
    expect(pills[0].softened).toBe(true);
    const html = render(value, bootstrap(false));
    expect(strokes(html)[0]).toContain(`stroke="${TONE_HEX.working}"`);
    expect(hero(html)).not.toContain(TONE_HEX.proven);
    expect(hero(html)).toContain("Containing, not proven");
  });

  it("draws a control it cannot confirm as an outline, never a fill", () => {
    const drawn = strokes(render(posture([unreadable(), watcher()])))[0];
    expect(drawn).toContain("stroke-dasharray");
    expect(drawn).toContain(`stroke="${TONE_HEX.unknown}"`);
    expect(drawn).not.toContain(TONE_HEX.proven);
    expect(drawn).not.toContain(TONE_HEX.working);
  });

  it("counts the working controls in its centre, and the ones needing you first", () => {
    expect(hero(render(posture([gate(), watcher(), unreadable()])))).toContain(">2</span><span class=\"mt-0.5 text-xs font-medium text-slate-500\">of 3 working</span>");
    expect(hero(render(posture([gate(), needy()])))).toContain(">1</span><span class=\"mt-0.5 text-xs font-medium text-amber-800\">needs you</span>");
  });

  it("is all grey and says Refreshing on a read that is not current", () => {
    const html = render(posture([gate(), watcher()]), bootstrap(), false);
    for (const drawn of strokes(html)) expect(drawn).toContain(`stroke="${TONE_HEX.off}"`);
    expect(hero(html)).toContain(">Refreshing</span>");
    expect(hero(html)).not.toContain(TONE_HEX.proven);
  });
});

describe("the count per state", () => {
  /**
   * FAILS ON REVERT: drop the always-present entry and a page with nothing
   * for the reader leaves them to infer the zero.
   */
  it("always says how many controls need you, zero included", () => {
    const counts = stateCounts(controlPills(posture([gate(), watcher()]), bootstrap(), true, GENERATED).pills);
    expect(counts.map((entry) => [entry.key, entry.count])).toEqual([["proven", 1], ["working", 1], ["needs_operator", 0]]);
    expect(hero(render(posture([gate(), watcher()])))).toContain(">0</span> Need you");
  });

  it("wears amber only for a control that needs you", () => {
    const calm = hero(render(posture([gate(), watcher(), unreadable()])));
    expect(calm).not.toMatch(/amber/);
    const asking = hero(render(posture([gate(), needy()])));
    expect(asking).toMatch(/data-state="needs_operator" class="[^"]*amber/);
    expect(asking.match(/bg-amber-50(?!0)/g)).toHaveLength(1);
  });

  it("says when the newest control was checked", () => {
    expect(latestCheck([{ freshness: freshness("2026-07-18T11:00:00Z") }, { freshness: freshness(OBSERVED) }, { freshness: freshness(null) }])).toBe(OBSERVED);
    expect(latestCheck([{ freshness: freshness(null) }])).toBeUndefined();
    expect(hero(render(posture([gate()])))).toMatch(/Checked (\d{1,2} \S+ \d{4}, )?\d{2}:\d{2} \S+\./);
  });
});

describe("the ladder on each row", () => {
  const ladder = (html: string, name: string) => {
    const start = html.indexOf(`aria-label="How far ${name} is proven"`);
    return html.slice(start, html.indexOf("</ol>", start));
  };
  const marks = (html: string, name: string) => [...ladder(html, name).matchAll(/data-mark="([a-z_]+)"/g)].map((match) => match[1]);

  it("fills the stages that are so and makes Verified emerald when the chip agrees", () => {
    const html = render(posture([gate()]));
    expect(marks(html, "Execution Gate")).toEqual(["done", "done", "done", "done", "verified"]);
    expect(ladder(html, "Execution Gate")).toContain("bg-emerald-500");
  });

  /**
   * FAILS ON REVERT: mark the Verified stage from the host's answer alone and
   * a control the page could not pin wears an emerald dot under a chip that
   * says "not proven".
   */
  it("keeps Verified hollow when the veto softened the control", () => {
    const html = render(posture([gate()]), bootstrap(false));
    expect(marks(html, "Execution Gate")).toEqual(["done", "done", "done", "done", "unproven"]);
    expect(ladder(html, "Execution Gate")).not.toContain("emerald");
    expect(ladder(html, "Execution Gate")).toContain("this page could not pin the proof");
  });

  it("draws an unknown stage hollow and a stage that does not apply as a dash", () => {
    const html = render(posture([unreadable(), watcher()]));
    expect(marks(html, "Secret Read Guard")).toEqual(["done", "done", "done", "done", "unknown"]);
    expect(marks(html, "host_visibility")).toEqual(["done", "done", "done", "not_applicable", "not_applicable"]);
    expect(ladder(html, "Secret Read Guard")).not.toContain("emerald");
  });

  it("gives every mark its words for a screen reader and on hover", () => {
    expect(stageMark("no", false, false, true)).toBe("no");
    expect(stageMark("yes", true, false, false)).toBe("stale");
    const html = render(posture([unreadable()]));
    expect(ladder(html, "Secret Read Guard")).toContain('title="Verified: not known"');
    expect(ladder(html, "Secret Read Guard")).toContain('<span class="sr-only">Enforcing: yes</span>');
  });

  it("names the host's reason for a stage that is not yes only in the technical view", () => {
    expect(render(posture([unreadable()]))).not.toContain("Secret read gate build unrecognised");
    setTechnicalDetail(true);
    expect(render(posture([unreadable()]))).toContain("Verified: Secret read gate build unrecognised");
  });
});

describe("the row's words", () => {
  it("draws a backticked command as code, with no backtick printed", () => {
    const html = renderToStaticMarkup(<p>{withCode("When ready, run `innerwarden-config-sign dns-guard arm`.")}</p>);
    expect(html).toContain(">innerwarden-config-sign dns-guard arm</code>");
    expect(html).not.toContain("`");
  });

  it("says the scope only where it is narrower than the host", () => {
    const scoped = layer("x", "kernel_execution_control", "working_as_configured", {
      effective_scope: [{ ...hostScope, id: "cgroup:1", kind: "cgroup", display_name: "the AI agent's service, agent.service" }],
    });
    expect(render(posture([scoped]))).toContain("the AI agent&#x27;s service, agent.service");
    expect(render(posture([gate()]))).not.toContain("Covers ");
  });
});

describe("the agent's commands on Protection", () => {
  const report: AgentLayerReport = {
    state: "screening",
    reason: "agent_layer_screening",
    display_name: "Command and prompt screening, and MCP tool calls",
    evidence_basis: "Counted from the guardrail's own decision record on this host.",
    evidence_source: null,
    sessions: [],
    measured: [{ id: "commands_screened", label: "Commands screened", value: "8", covers: "the record" }],
    not_measured: ["prompts screened inside a conversation"],
    summary: "Your AI agent tried 8 commands in the last 7 days: InnerWarden refused 2 before they ran.",
  };
  const commands = {
    window: "7d" as const,
    count: 8,
    breakdown: [
      { key: "refused_before_run", count: 2, label: "Refused by InnerWarden before it ran" },
      { key: "kernel_stopped", count: 2, label: "Stopped by the kernel" },
      { key: "unsafe_may_have_run", count: 3, label: "Judged unsafe, and may have run" },
      { key: "held_for_review", count: 0, label: "Held for a review nobody answered" },
      { key: "allowed", count: 1, label: "Allowed" },
    ],
    unexplainedRefused: 4,
    sentence: "Your AI agent tried 8 commands in the last 7 days.",
  };
  const withCommands = { ...posture([gate()]), agent_layer: report, agent_commands: commands };

  /**
   * FAILS ON REVERT: lead with the host's paragraph again and the page reads
   * as a report; drop the figure and Protection no longer prints the
   * Overview card's number.
   */
  it("leads with the card's count drawn as a bar, and keeps the paragraph behind the switch", () => {
    const plain = render(withCommands);
    expect(plain).toMatch(/data-agent-commands-count="true"[^>]*>8<\/span>/);
    expect(plain).toContain("commands in the last 7 days");
    expect(plain).toContain('data-segment="unsafe_may_have_run"');
    expect(plain).toContain("<span class=\"font-semibold text-slate-600\">Zero: </span>Held for a review nobody answered.");
    expect(plain).toContain("The kernel also refused 4 program starts in the agent&#x27;s scope that no command explains.");
    expect(plain).not.toContain(report.summary);
    // That something is not measured is still said plainly.
    expect(plain).toContain("1 figure is not measured on this host.");
    setTechnicalDetail(true);
    const technical = render(withCommands);
    expect(technical).toContain(report.summary);
    expect(technical).toContain(">Commands screened</dt>");
  });

  it("reads as before on a host that sends no tally", () => {
    const plain = render({ ...posture([gate()]), agent_layer: report });
    expect(plain).toContain(report.summary);
    expect(plain).not.toContain("data-agent-commands-count");
  });

  it("never lets the tally reach the host half of the page", () => {
    const bare = render(posture([gate()]));
    const hostHalf = bare.slice(0, -"</div>".length);
    expect(render(withCommands).startsWith(hostHalf)).toBe(true);
  });
});
