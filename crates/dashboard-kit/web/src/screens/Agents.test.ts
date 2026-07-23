import { describe, expect, it } from "vitest";
import { agentIdentitySummary } from "./Agents";

describe("agentIdentitySummary", () => {
  it.each([
    ["unknown-subject", null, null, "unattributed"],
    ["renamed-wrapper", "Codex", "OpenAI", "declared"],
    ["spoofed-claude", "Claude Code", "Anthropic", "conflicting"],
  ] as const)("does not turn reported metadata for %s into a trusted heading", (agentId, product, provider, confidence) => {
    expect(agentIdentitySummary({
      agent_id: agentId,
      product,
      provider,
      identity_confidence: confidence,
    })).toEqual({
      heading: `Observed agent ${agentId}`,
      product: product ?? "Not reported",
      provider: provider ?? "Not reported",
      confidence,
    });
  });
});
