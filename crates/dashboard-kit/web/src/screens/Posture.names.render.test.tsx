import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DashboardBootstrap, DashboardPosture, ProtectionLayer } from "../api/v1";
import { capabilityName, controlName, dispositionReason, humanize, Posture, unconfirmedLine, withProductName } from "./Posture";

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

/**
 * Exactly the six ids the host sends for the three products. Three more
 * (`host_execution_layer`, `secret_guard_layer`, `dns_guard_layer`) existed
 * only in this repository's own fixtures.
 *
 * FAILS ON REVERT: keep the alias ids and a layer no host sends is named.
 */
describe("the ids that carry a product name", () => {
  it("are the host's six, and nothing else", () => {
    for (const alias of ["host_execution_layer", "secret_guard_layer", "dns_guard_layer"]) {
      expect(controlName(layer(alias, "something_else", "Plain label")).name, alias).toBe("Plain label");
    }
    for (const [id, name] of [
      ["independent_host_execution", "Execution Gate"], ["kernel_execution_control", "Execution Gate"],
      ["secret_access_control", "Secret Read Guard"], ["secret_read_guard", "Secret Read Guard"],
      ["dns_resolution_control", "DNS Guard"], ["dns_guard", "DNS Guard"],
    ]) {
      expect(controlName(layer("x", id, "Plain label")).name, id).toBe(name);
    }
  });

  it("draws one chip per layer, even for two layers of one product", () => {
    const posture: DashboardPosture = {
      schema_version: "innerwarden.dashboard.v1",
      generated_at: "2026-07-18T12:00:01Z",
      layers: [layer("independent_host_execution", "kernel_execution_control", "A"), layer("second_gate", "kernel_execution_control", "B")],
      gaps: [],
    };
    const html = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={posture} current evaluatedAt="2026-07-18T12:00:01Z" />);
    const chips = html.slice(html.indexOf('aria-label="Host controls"'), html.indexOf("posture-controls-title"));
    expect(chips.match(/>Execution Gate<\/span>/g)).toHaveLength(2);
  });
});

/**
 * The card's title said "Execution Gate" and the host's sentence under it
 * began "Independent host execution is blocking...": one card, one control,
 * two names.
 *
 * FAILS ON REVERT: print the host's sentence as sent and the generic name is
 * back under the product name.
 */
describe("the host's sentence under a product name", () => {
  it("calls the control by its product name where the sentence opens with the host's label", () => {
    const gate = { ...layer("independent_host_execution", "kernel_execution_control", "Independent host execution"), disposition_reason: "Independent host execution is blocking unlisted programs for 1 agent." };
    expect(dispositionReason(gate)).toBe("Execution Gate is blocking unlisted programs for 1 agent.");
    const dns = { ...layer("dns_resolution_control", "dns_resolution_control", "DNS resolution control"), disposition: "cannot_verify" as const, disposition_reason: "DNS resolution control could not be read on this host." };
    expect(dispositionReason(dns)).toBe("DNS Guard could not be read on this host.");
    // The general words under the title count as the control's name too.
    expect(withProductName("Secret access control is set up.", layer("secret_access_control", "secret_access_control", "Secrets"))).toBe("Secret Read Guard is set up.");
  });

  it("touches nothing else", () => {
    const gate = layer("independent_host_execution", "kernel_execution_control", "Independent host execution");
    expect(withProductName("The kernel checks independent host execution on exec.", gate)).toBe("The kernel checks independent host execution on exec.");
    expect(withProductName("Independent host executions are counted.", gate)).toBe("Independent host executions are counted.");
    // A control with no product name keeps the host's words.
    expect(withProductName("Host visibility is reporting.", layer("host_visibility", "host_visibility", "Host visibility"))).toBe("Host visibility is reporting.");
  });
});

/**
 * "Coverage gaps: No gaps reported by the host controls above" sat under
 * "DNS Guard · Can't confirm · never checked", and a buyer read it as: the
 * DNS Guard I paid for is unchecked, and there are no gaps.
 *
 * FAILS ON REVERT: read `posture.gaps` alone and the section says there are
 * no gaps under a control the page cannot confirm.
 */
describe("the coverage gaps section", () => {
  const checked = { observed_at: "2026-07-18T12:00:00Z", budget_seconds: 30, state: "fresh" as const, age_seconds: 1 };
  const visible = { ...layer("host_visibility", "host_visibility", "Host visibility"), freshness: checked };
  const dns = { ...layer("dns_resolution_control", "dns_resolution_control", "DNS resolution control"), disposition: "cannot_verify" as const, effective_mode: "unknown" as const };
  const gaps = (layers: ProtectionLayer[]) => {
    const html = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={{ schema_version: "innerwarden.dashboard.v1", generated_at: "2026-07-18T12:00:01Z", layers, gaps: [] }} current evaluatedAt="2026-07-18T12:00:01Z" />);
    return html.slice(html.indexOf('id="posture-gaps-title"'));
  };

  it("names a control it can't confirm as a gap, and does not say there are none", () => {
    const html = gaps([visible, dns]);
    expect(html).toContain("1 control we can&#x27;t confirm: DNS Guard. We will not claim it either way.");
    expect(html).not.toContain("No gaps");
  });

  it("counts a control claimed as working that was never checked", () => {
    const html = gaps([visible, layer("secret_access_control", "secret_access_control", "Secret access control"), dns]);
    expect(html).toContain("2 controls we can&#x27;t confirm: Secret Read Guard and DNS Guard. We will not claim them either way.");
  });

  it("does not count a control that is off, and says no gaps only when every control is known", () => {
    const off = { ...layer("dns_resolution_control", "dns_resolution_control", "DNS resolution control"), disposition: "not_enabled" as const, effective_mode: "disabled" as const, desired_mode: "disabled" as const };
    const html = gaps([visible, off]);
    expect(html).toContain("No gaps reported by the host controls above.");
    expect(html).not.toContain("can&#x27;t confirm:");
  });

  /**
   * A failed refresh left the page on an older read and the section said "No
   * gaps ... need your attention" under a DNS Guard reading "Can't confirm".
   * FAILS ON REVERT: render emptyGapsLine whatever `current` is.
   */
  it("never says there are no gaps on a read that is not current", () => {
    const html = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={{ schema_version: "innerwarden.dashboard.v1", generated_at: "2026-07-18T12:00:01Z", layers: [visible, dns], gaps: [] }} current={false} evaluatedAt="2026-07-18T12:00:01Z" />);
    const section = html.slice(html.indexOf('id="posture-gaps-title"'));
    expect(section).not.toContain("No gaps");
    expect(section).toContain("cannot say there are no gaps");
  });

  it("lists three or more in plain words", () => {
    expect(unconfirmedLine(["A", "B", "C"])).toBe("3 controls we can't confirm: A, B and C. We will not claim them either way.");
  });
});
