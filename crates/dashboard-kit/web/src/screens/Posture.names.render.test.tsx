import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DashboardBootstrap, DashboardPosture, ProtectionLayer } from "../api/v1";
import { capabilityName, controlName, humanize, Posture } from "./Posture";

/**
 * The site sells Execution Gate, Secret Read Guard and DNS Guard. Protection
 * named the same three "Independent host execution", "Secret access control"
 * and "DNS resolution control", and a buyer looking for what they paid for
 * found none of the names.
 */

// The ids the paid host sends today, and the label it writes beside each.
const SENT: [string, string, string][] = [
  ["independent_host_execution", "kernel_execution_control", "Independent host execution"],
  ["secret_access_control", "secret_access_control", "Secret access control"],
  ["dns_resolution_control", "dns_resolution_control", "DNS resolution control"],
  ["host_visibility", "host_visibility", "Host visibility"],
  ["response_controls", "response_controls", "Response controls"],
];

function layer(id: string, capabilityId: string, label: string): ProtectionLayer {
  return {
    id,
    label,
    capability_ids: [capabilityId],
    claim_state: "visibility_only",
    disposition: "working_as_configured",
    effective_mode: "observe",
    desired_mode: "observe",
    effective_scope: [],
    covered_action_classes: [],
    known_gaps: [],
    freshness: { observed_at: null, budget_seconds: 30, state: "missing", age_seconds: null },
    convergence: {
      configured: { state: "unknown", evidence: [], reason_code: null },
      loaded: { state: "unknown", evidence: [], reason_code: null },
      running: { state: "unknown", evidence: [], reason_code: null },
      enforcing: { state: "unknown", evidence: [], reason_code: null },
      verified_effective: { state: "unknown", evidence: [], reason_code: null },
    },
    evidence: [],
  };
}

const bootstrap = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: "2026-07-18T12:00:01Z",
  edition: "enterprise",
  product_version: "0.16.4",
  community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"d".repeat(64)}` },
  assurance_matrix: null,
  authorization_matrix: null,
  platform: { os: "linux", architecture: "x86_64", enterprise_candidate: true, reason_code: null },
  session: { authenticated: true, actor_id: "operator", role: null, scopes: [] },
  capabilities: [],
  highest_priority_gap: null,
  privacy: { storage: [], redactions: [], egress: [] },
} as DashboardBootstrap;

describe("the names on Protection", () => {
  it("titles each control the host sends by the product name, with the general words under it", () => {
    const names = SENT.map(([id, capability, label]) => controlName(layer(id, capability, label)));
    expect(names).toEqual([
      { name: "Execution Gate", description: "Independent host execution control" },
      { name: "Secret Read Guard", description: "Secret access control" },
      { name: "DNS Guard", description: "DNS resolution control" },
      { name: "Host visibility" },
      { name: "Response controls" },
    ]);
  });

  /**
   * Matched on the ids, never the label: a relabelled control keeps its
   * product name, and a label alone names nothing.
   *
   * FAILS ON REVERT: match on the label and the reworded one loses its name.
   */
  it("matches on the ids the host sends, never on the label", () => {
    expect(controlName(layer("independent_host_execution", "kernel_execution_control", "Host execution")).name).toBe("Execution Gate");
    expect(controlName(layer("something_else", "something_else", "Execution Gate lookalike")).name).toBe("Execution Gate lookalike");
  });

  /**
   * FAILS ON REVERT: title the row with `layer.label` and the chips and rows
   * say "Independent host execution" again.
   */
  it("prints the product names on the chips and the rows, and the general words once under each", () => {
    const posture: DashboardPosture = {
      schema_version: "innerwarden.dashboard.v1",
      generated_at: "2026-07-18T12:00:01Z",
      layers: SENT.map(([id, capability, label]) => layer(id, capability, label)),
      gaps: [],
    };
    const html = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={posture} current evaluatedAt="2026-07-18T12:00:01Z" />);
    const chips = html.slice(html.indexOf('aria-label="Host controls"'), html.indexOf("posture-controls-title"));
    for (const name of ["Execution Gate", "Secret Read Guard", "DNS Guard", "Host visibility", "Response controls"]) {
      expect(chips).toContain(`>${name}</span>`);
      expect(html).toContain(`>${name}</h3>`);
    }
    expect(html.match(/>Independent host execution control</g)).toHaveLength(1);
  });

  it("names a capability by its product, and spells initials as people write them", () => {
    expect(capabilityName("kernel_execution_control")).toBe("Execution Gate");
    expect(capabilityName("dns_resolution_control")).toBe("DNS Guard");
    expect(capabilityName("host_visibility")).toBe("Host visibility");
    expect(humanize("dns_resolution_control")).toBe("DNS resolution control");
    expect(humanize("mcp.tool_calls")).toBe("MCP tool calls");
    expect(humanize("")).toBe("Unknown");
  });
});
