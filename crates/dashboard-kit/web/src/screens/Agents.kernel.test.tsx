import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { AgentInventory, AgentKernel, AgentSubject } from "../api/v1";
import { parseAgentInventory } from "../api/validate";
import { Agents } from "./Agents";

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);

const SUBJECT: AgentSubject = {
  agent_id: "claude-code",
  principal: null,
  product: "Claude Code",
  provider: null,
  agent_class: "coding",
  runtime: null,
  model: null,
  identity_confidence: "declared",
  identity_evidence: [],
  sessions: [],
  capabilities: [],
  guardrail_mode: null,
  guardrail_configured_at: null,
  guardrail_recorded_activity: null,
  guardrail_last_observed_at: null,
};

const KERNEL: AgentKernel = {
  mode: "enforce",
  strict: true,
  parts: [{ key: "programs", effective: "enforce" }],
  watch: { since: "2026-10-18T08:00:00Z", sessions: 3, agent_starts: 20, would_refuse: [{ key: "programs", n: 2 }] },
  ready: true,
  blockers: [],
  checked_at: "2026-10-18T09:00:00Z",
};

function inventory(subject: AgentSubject): AgentInventory {
  return {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-10-18T12:00:00Z",
    availability: "available",
    discovery_limited: false,
    subjects: [subject],
  };
}

describe("the host's kernel protection on the kit's Agents screen", () => {
  /**
   * Community never shows the field: the screen a subject renders with it
   * is the screen it renders without it, byte for byte, and no word of it
   * reaches the page.
   */
  it("renders exactly what the subject renders without it", () => {
    const parsed = parseAgentInventory(JSON.parse(JSON.stringify(inventory({ ...SUBJECT, kernel: KERNEL }))));
    expect(parsed.subjects[0].kernel).toEqual(KERNEL);
    const withKernel = renderToStaticMarkup(<Agents inventory={parsed} nowMs={NOW} />);
    const without = renderToStaticMarkup(<Agents inventory={inventory(SUBJECT)} nowMs={NOW} />);
    expect(withKernel).toBe(without);
    expect(withKernel).not.toMatch(/kernel|protected|strict|watch/i);
  });
});
