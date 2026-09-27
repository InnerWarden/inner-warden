import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import type { AgentLayerReport, DashboardBootstrap, DashboardPosture } from "../api/v1";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { figureLayout, Posture, sectionRows } from "./Posture";

/**
 * Protection was about 5,000 px tall at 1440 wide and over 10,000 at 320.
 * Seven tiles in the guardrail's section, six of them zero, each repeated the
 * same forty-word caption, and the lists of what was not measured, the
 * session ids and the evidence policy ran on under them. The page says each
 * thing once now: a tile for a figure that reads something, one line for the
 * zeros, the shared caption once, and the auditor's material behind the
 * technical switch.
 */

afterEach(() => setTechnicalDetail(false));

const COVERS = "everything in the guardrail's decision record on this host; the record is capped and drops its oldest entries";
const BASIS = "Counted from the guardrail's own decision record on this host.";

function figures(counts: number[]): AgentLayerReport["measured"] {
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

const REPORT: AgentLayerReport = {
  state: "screening",
  reason: "agent_layer_screening",
  display_name: "Command and prompt screening, and MCP tool calls",
  evidence_basis: BASIS,
  evidence_source: "/var/lib/innerwarden/guard/graph.json",
  sessions: ["wren-visitor-a1097d83"],
  measured: figures([7, 2, 0, 0, 0, 0, 4]),
  not_measured: ["how many AI agents are connected: the record holds sessions"],
  summary: "The guardrail screened 7 commands from 4 agent sessions on this host.",
};

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

const posture: DashboardPosture = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: "2026-07-18T12:00:01Z",
  layers: [],
  gaps: [],
  agent_layer: REPORT,
};

/** The text as the markup carries it. */
const esc = (text: string) => text.replace(/'/g, "&#x27;");

const render = () => renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={posture} current evaluatedAt="2026-07-18T12:00:01Z" />);

describe("the figures in an agent-side section", () => {
  it("gives a tile to each figure that reads something, and lists the zeros", () => {
    const layout = figureLayout(sectionRows(REPORT));
    expect(layout.tiles.map((row) => row.id)).toEqual(["commands_screened", "commands_refused", "agent_sessions"]);
    expect(layout.zeros.map((row) => row.id)).toEqual([
      "commands_would_refuse", "mcp_calls_screened", "mcp_calls_refused", "mcp_calls_would_refuse",
    ]);
    expect(layout.sharedCovers).toBe(COVERS);
  });

  /**
   * FAILS ON REVERT: print the caption on every tile again and it appears
   * seven times.
   */
  it("says the shared caption once, and keeps every zero on the page as a zero", () => {
    const html = render();
    expect(html.split(esc(COVERS))).toHaveLength(2);
    expect(html).toContain("Zero: </span>Commands it would have refused while only watching; MCP tool calls screened; MCP tool calls the guardrail refused; MCP tool calls it would have refused while only watching.");
    expect(html.match(/<dt /g)).toHaveLength(3);
  });

  it("prints each caption beside its figure when the figures cover different things", () => {
    const mixed = { ...REPORT, measured: [...figures([7, 2, 0, 0, 0, 0, 4]).slice(0, 6), { id: "x", label: "Other", value: "3", covers: "today" }] };
    const layout = figureLayout(sectionRows(mixed));
    expect(layout.sharedCovers).toBeUndefined();
    const html = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={{ ...posture, agent_layer: mixed }} current evaluatedAt="2026-07-18T12:00:01Z" />);
    expect(html).toContain(">today</dd>");
    expect(html).toContain(esc(`Commands it would have refused while only watching; MCP tool calls screened; MCP tool calls the guardrail refused; MCP tool calls it would have refused while only watching (${COVERS}).`));
  });
});

describe("the auditor's material", () => {
  /**
   * FAILS ON REVERT: render the not-measured list, the session ids, the
   * basis or the file outside the switch and the plain view carries them.
   */
  it("is behind the technical switch, and all of it is there when asked for", () => {
    const plain = render();
    for (const hidden of ["Not measured", "wren-visitor-a1097d83", esc(BASIS), "/var/lib/innerwarden/guard/graph.json", "agent metadata never grants host trust"]) {
      expect(plain).not.toContain(hidden);
    }
    setTechnicalDetail(true);
    const technical = render();
    for (const shown of ["Not measured", "wren-visitor-a1097d83", esc(BASIS), "/var/lib/innerwarden/guard/graph.json", "agent metadata never grants host trust"]) {
      expect(technical).toContain(shown);
    }
  });

  it("leaves the section's summary and figures in the plain view", () => {
    const plain = render();
    expect(plain).toContain(REPORT.summary);
    expect(plain).toContain("In the agent, not a host control");
    expect(plain).toContain(">7</dd>");
  });
});
